package tcp

import (
	"math/rand"
	"testing"
)

// TestRTOResetsOnNewACK is a regression test for a bug where prevUNA was
// captured AFTER ControlBlock.Recv updated snd.UNA, making the "new ACK"
// condition (seg.ACK != prevUNA) always false. This caused the RTO to never
// reset per RFC 6298 §5.3, leading to exponential backoff escalation even
// when the network was healthy.
//
// The fix: capture prevUNA before calling scb.Recv in Handler.Recv.
func TestRTOResetsOnNewACK(t *testing.T) {
	const mtu = 1500
	const maxpackets = 3
	rng := rand.New(rand.NewSource(100))
	client, server := newHandler(t, mtu, maxpackets), newHandler(t, mtu, maxpackets)
	setupClientServer(t, rng, client, server)
	var rawbuf [mtu]byte
	establish(t, client, server, rawbuf[:])

	// Write and send data from client.
	data := []byte("hello retransmit")
	n, err := client.Write(data)
	if err != nil {
		t.Fatal("client write:", err)
	} else if n != len(data) {
		t.Fatal("short write")
	}

	clear(rawbuf[:])
	n, err = client.Send(rawbuf[:])
	if err != nil {
		t.Fatal("client send:", err)
	}

	// Simulate prior retransmissions: RTO has been backed off and nRetx > 0.
	client.rto = rtoInitial * 4
	client.nRetx = 2

	// Server receives data and sends ACK.
	err = server.Recv(rawbuf[:n])
	if err != nil {
		t.Fatal("server recv:", err)
	}
	clear(rawbuf[:])
	n, err = server.Send(rawbuf[:])
	if err != nil {
		t.Fatal("server send ACK:", err)
	}
	if n == 0 {
		t.Fatal("expected server to send ACK")
	}

	// Client receives ACK — RTO and nRetx should reset.
	err = client.Recv(rawbuf[:n])
	if err != nil {
		t.Fatal("client recv ACK:", err)
	}

	if client.rto != rtoInitial {
		t.Fatalf("BUG: RTO not reset on new ACK: got %d, want %d (RFC 6298 §5.3)", client.rto, rtoInitial)
	}
	if client.nRetx != 0 {
		t.Fatalf("BUG: nRetx not reset on new ACK: got %d, want 0", client.nRetx)
	}
	if client.dupACKs != 0 {
		t.Fatalf("dupACKs not reset on new ACK: got %d, want 0", client.dupACKs)
	}
}

// TestPostRetransmitACKAccepted is a regression test for a bug where after
// Retransmit() rewound snd.NXT to snd.UNA, a valid cumulative ACK from the
// remote (acknowledging data sent pre-rewind) was rejected as "acks unsent
// data" because seg.ACK > snd.NXT.
//
// The fix: in validateIncomingSegment, when snd.NXT == snd.UNA (retransmit
// active) and seg.ACK is within the send window, accept the ACK and advance
// snd.NXT to seg.ACK.
func TestPostRetransmitACKAccepted(t *testing.T) {
	const mtu = 1500
	const maxpackets = 3
	rng := rand.New(rand.NewSource(200))
	client, server := newHandler(t, mtu, maxpackets), newHandler(t, mtu, maxpackets)
	setupClientServer(t, rng, client, server)
	var rawbuf [mtu]byte
	establish(t, client, server, rawbuf[:])

	// Client writes and sends data.
	data := []byte("data before rewind")
	n, err := client.Write(data)
	if err != nil {
		t.Fatal("client write:", err)
	} else if n != len(data) {
		t.Fatal("short write")
	}
	clear(rawbuf[:])
	n, err = client.Send(rawbuf[:])
	if err != nil {
		t.Fatal("client send:", err)
	}

	// Server receives data — its next ACK will acknowledge up to the
	// original snd.NXT.
	err = server.Recv(rawbuf[:n])
	if err != nil {
		t.Fatal("server recv:", err)
	}

	// Client triggers retransmit: snd.NXT rewound to snd.UNA.
	preRewindNXT := client.scb.snd.NXT
	client.triggerRetransmit()
	if client.scb.snd.NXT != client.scb.snd.UNA {
		t.Fatal("retransmit did not rewind snd.NXT to snd.UNA")
	}

	// Server sends ACK for the data it already received. seg.ACK = preRewindNXT,
	// which is > client.snd.NXT (now rewound to snd.UNA).
	clear(rawbuf[:])
	n, err = server.Send(rawbuf[:])
	if err != nil {
		t.Fatal("server send ACK:", err)
	}
	if n == 0 {
		t.Fatal("expected server to send ACK")
	}

	// Client receives ACK — should NOT be rejected.
	err = client.Recv(rawbuf[:n])
	if err != nil {
		t.Fatalf("BUG: post-retransmit ACK rejected: %v\n"+
			"After Retransmit() rewound snd.NXT to snd.UNA, the remote's cumulative\n"+
			"ACK (for data sent pre-rewind) exceeds the rewound snd.NXT and was\n"+
			"incorrectly rejected as 'acks unsent data'.", err)
	}

	// snd.NXT should have advanced back to where it was before the rewind.
	if client.scb.snd.NXT != preRewindNXT {
		t.Fatalf("snd.NXT not restored: got %d, want %d", client.scb.snd.NXT, preRewindNXT)
	}
	// snd.UNA should have advanced to acknowledge the data.
	if client.scb.snd.UNA != preRewindNXT {
		t.Fatalf("snd.UNA not advanced: got %d, want %d", client.scb.snd.UNA, preRewindNXT)
	}
}

// TestFastRetransmitOncePerLoss is a regression test for
// https://github.com/soypat/lneto/issues/58
// where fast retransmit was triggered multiple times for the same lost segment.
//
// When N packets are in flight and one is lost, up to N dup ACKs arrive.
// The bug: triggerRetransmit() reset dupACKs to 0, so every 3 dup ACKs
// triggered another fast retransmit of the same sequence. With 10 packets
// in flight, a single loss caused 3 retransmissions instead of 1.
//
// Per RFC 5681 §3.2, fast retransmit should fire once per loss event.
// Subsequent dup ACKs (beyond the 3rd) should NOT re-trigger it.
func TestFastRetransmitOncePerLoss(t *testing.T) {
	const mtu = 60  // Small MTU: 20 byte header + 40 bytes payload per packet.
	const txBuf = 2048
	const maxpackets = 10
	rng := rand.New(rand.NewSource(58))

	client := new(Handler)
	server := new(Handler)
	err := client.SetBuffers(make([]byte, txBuf), make([]byte, txBuf), maxpackets)
	if err != nil {
		t.Fatal(err)
	}
	client.rto = rtoInitial
	err = server.SetBuffers(make([]byte, txBuf), make([]byte, txBuf), maxpackets)
	if err != nil {
		t.Fatal(err)
	}
	server.rto = rtoInitial

	err = server.OpenListen(uint16(rng.Uint32()), 0)
	if err != nil {
		t.Fatal(err)
	}
	err = client.OpenActive(uint16(rng.Uint32()), server.LocalPort(), 0)
	if err != nil {
		t.Fatal(err)
	}

	var rawbuf [mtu]byte
	establish(t, client, server, rawbuf[:])

	// With MSS=40 (mtu-20), write enough to fill several packets.
	data := make([]byte, 40*maxpackets)
	for i := range data {
		data[i] = byte(i)
	}
	// Write in chunks since TX buffer may limit us.
	written := 0
	var packets [][]byte
	for written < len(data) {
		n, werr := client.Write(data[written:])
		if werr != nil {
			t.Fatal("client write:", werr)
		}
		written += n
		// Send as many packets as possible.
		for {
			clear(rawbuf[:])
			ns, serr := client.Send(rawbuf[:])
			if serr != nil {
				t.Fatal("client send:", serr)
			}
			if ns == 0 {
				break
			}
			packets = append(packets, append([]byte(nil), rawbuf[:ns]...))
		}
	}
	if len(packets) < 6 {
		t.Fatal("need at least 6 data packets, got", len(packets))
	}
	t.Logf("sent %d data packets", len(packets))

	// Server receives only the first packet so it ACKs it, advancing client's lastACK.
	err = server.Recv(packets[0])
	if err != nil {
		t.Fatal("server recv first packet:", err)
	}
	clear(rawbuf[:])
	n, err := server.Send(rawbuf[:])
	if err != nil {
		t.Fatal("server send ACK:", err)
	}
	if n == 0 {
		t.Fatal("expected server to send ACK")
	}
	// Client receives the ACK for the first packet, establishing lastACK.
	err = client.Recv(rawbuf[:n])
	if err != nil {
		t.Fatal("client recv ACK:", err)
	}
	dupACKValue := client.lastACK
	t.Logf("lastACK established at %d, client.dupACKs=%d", dupACKValue, client.dupACKs)

	// Craft 9 identical dup ACKs: same ACK value, no data, no SYN/FIN.
	// These simulate what the server would send on receiving out-of-order packets.
	const numDupAcks = 9
	var dupAcks [numDupAcks][]byte
	for i := range dupAcks {
		var buf [mtu]byte
		frm, ferr := NewFrame(buf[:])
		if ferr != nil {
			t.Fatal("new frame:", ferr)
		}
		frm.SetSourcePort(server.LocalPort())
		frm.SetDestinationPort(client.LocalPort())
		frm.SetSegment(Segment{
			SEQ:   server.scb.snd.NXT,
			ACK:   dupACKValue,
			Flags: FlagACK,
			WND:   65535,
		}, 5)
		dupAcks[i] = append([]byte(nil), buf[:sizeHeaderTCP]...)
	}
	t.Logf("crafted %d dup ACKs", numDupAcks)

	// Feed all dup ACKs to client, counting how many times fast retransmit fires.
	// Between dup ACKs, call Send() to transmit retransmitted packets (as a real
	// stack would do). This makes BufferedSent > 0 again, which is required for
	// the dup ACK condition to be met.
	retransmitCount := 0
	prevNRetx := client.nRetx
	for i, ack := range dupAcks[:] {
		rerr := client.Recv(ack)
		if rerr != nil {
			continue
		}
		if client.nRetx > prevNRetx {
			retransmitCount++
			t.Logf("fast retransmit #%d triggered at dup ACK %d (nRetx=%d)", retransmitCount, i+1, client.nRetx)
			prevNRetx = client.nRetx
		}
		// Simulate real behavior: Send() is called between receives,
		// which re-sends retransmitted data and makes BufferedSent > 0.
		clear(rawbuf[:])
		client.Send(rawbuf[:])
	}

	if retransmitCount == 0 {
		t.Fatal("fast retransmit never triggered (expected exactly 1)")
	}
	if retransmitCount > 1 {
		t.Fatalf("BUG (issue #58): fast retransmit triggered %d times for a single loss event, want 1.\n"+
			"triggerRetransmit() resets dupACKs to 0, causing every 3rd dup ACK to\n"+
			"re-trigger fast retransmit for the same lost sequence.", retransmitCount)
	}
}

// TestFastRetransmitResetsOnNewACK verifies that after recovering from a loss
// event (new data ACKed), the dup-ACK counter resets so that a subsequent loss
// can trigger fast retransmit again.
//
// Without the dupACKs=0 reset on new ACK (handler.go line 219), the counter
// would stay above 3 after the first loss event and never reach ==3 again,
// disabling fast retransmit for all subsequent losses.
func TestFastRetransmitResetsOnNewACK(t *testing.T) {
	const mtu = 60 // Small MTU: 20 byte header + 40 bytes payload per packet.
	const txBuf = 2048
	const maxpackets = 10
	rng := rand.New(rand.NewSource(59))

	client := new(Handler)
	server := new(Handler)
	err := client.SetBuffers(make([]byte, txBuf), make([]byte, txBuf), maxpackets)
	if err != nil {
		t.Fatal(err)
	}
	client.rto = rtoInitial
	err = server.SetBuffers(make([]byte, txBuf), make([]byte, txBuf), maxpackets)
	if err != nil {
		t.Fatal(err)
	}
	server.rto = rtoInitial

	err = server.OpenListen(uint16(rng.Uint32()), 0)
	if err != nil {
		t.Fatal(err)
	}
	err = client.OpenActive(uint16(rng.Uint32()), server.LocalPort(), 0)
	if err != nil {
		t.Fatal(err)
	}

	var rawbuf [mtu]byte
	establish(t, client, server, rawbuf[:])

	// Helper: craft a dup ACK packet from server to client for the given ACK value.
	craftDupACK := func(ackVal Value) []byte {
		var buf [mtu]byte
		frm, ferr := NewFrame(buf[:])
		if ferr != nil {
			t.Fatal("new frame:", ferr)
		}
		frm.SetSourcePort(server.LocalPort())
		frm.SetDestinationPort(client.LocalPort())
		frm.SetSegment(Segment{
			SEQ:   server.scb.snd.NXT,
			ACK:   ackVal,
			Flags: FlagACK,
			WND:   65535,
		}, 5)
		return append([]byte(nil), buf[:sizeHeaderTCP]...)
	}

	// Helper: write data, send packets, return them.
	sendPackets := func(payload []byte) [][]byte {
		written := 0
		var pkts [][]byte
		for written < len(payload) {
			n, werr := client.Write(payload[written:])
			if werr != nil {
				t.Fatal("client write:", werr)
			}
			written += n
			for {
				clear(rawbuf[:])
				ns, serr := client.Send(rawbuf[:])
				if serr != nil {
					t.Fatal("client send:", serr)
				}
				if ns == 0 {
					break
				}
				pkts = append(pkts, append([]byte(nil), rawbuf[:ns]...))
			}
		}
		return pkts
	}

	// Helper: deliver packet to server, get ACK, deliver ACK to client.
	deliverAndACK := func(pkt []byte) {
		rerr := server.Recv(pkt)
		if rerr != nil {
			t.Fatal("server recv:", rerr)
		}
		clear(rawbuf[:])
		n, serr := server.Send(rawbuf[:])
		if serr != nil {
			t.Fatal("server send:", serr)
		}
		if n == 0 {
			t.Fatal("expected server to send ACK")
		}
		rerr = client.Recv(rawbuf[:n])
		if rerr != nil {
			t.Fatal("client recv ACK:", rerr)
		}
	}

	// === Loss event #1 ===
	packets1 := sendPackets(make([]byte, 40*4))
	if len(packets1) < 4 {
		t.Fatal("need at least 4 packets for loss event #1, got", len(packets1))
	}
	// Deliver the first packet to establish lastACK.
	deliverAndACK(packets1[0])
	ackVal1 := client.lastACK

	// Send 3 dup ACKs to trigger fast retransmit.
	for i := 0; i < 3; i++ {
		err = client.Recv(craftDupACK(ackVal1))
		if err != nil {
			t.Fatalf("loss #1: dup ACK %d recv: %v", i+1, err)
		}
		clear(rawbuf[:])
		client.Send(rawbuf[:]) // Keep BufferedSent > 0.
	}
	if client.nRetx != 1 {
		t.Fatalf("loss #1: expected nRetx=1 after 3 dup ACKs, got %d", client.nRetx)
	}
	t.Logf("loss #1: fast retransmit triggered (nRetx=%d)", client.nRetx)

	// === Recovery: retransmit the lost packet, server ACKs all data ===
	// Re-send all the packets that server missed (client retransmits from UNA).
	for {
		clear(rawbuf[:])
		n, serr := client.Send(rawbuf[:])
		if serr != nil {
			t.Fatal("client retransmit send:", serr)
		}
		if n == 0 {
			break
		}
		_ = server.Recv(rawbuf[:n]) // Deliver retransmitted + new data.
	}
	// Deliver remaining original packets too.
	for i := 1; i < len(packets1); i++ {
		_ = server.Recv(packets1[i])
	}
	// Server sends cumulative ACK for all received data.
	clear(rawbuf[:])
	n, serr := server.Send(rawbuf[:])
	if serr != nil {
		t.Fatal("server send recovery ACK:", serr)
	}
	if n == 0 {
		t.Fatal("expected server to send recovery ACK")
	}
	err = client.Recv(rawbuf[:n])
	if err != nil {
		t.Fatal("client recv recovery ACK:", err)
	}
	t.Logf("recovery: nRetx=%d, lastACK=%d", client.nRetx, client.lastACK)

	// === Loss event #2 ===
	packets2 := sendPackets(make([]byte, 40*4))
	if len(packets2) < 4 {
		t.Fatal("need at least 4 packets for loss event #2, got", len(packets2))
	}
	// Deliver the first packet to advance lastACK.
	deliverAndACK(packets2[0])
	ackVal2 := client.lastACK
	if ackVal2 == ackVal1 {
		t.Fatal("lastACK did not advance between loss events")
	}

	// Send 3 dup ACKs — fast retransmit should trigger again.
	prevNRetx := client.nRetx
	for i := 0; i < 3; i++ {
		err = client.Recv(craftDupACK(ackVal2))
		if err != nil {
			t.Fatalf("loss #2: dup ACK %d recv: %v", i+1, err)
		}
		clear(rawbuf[:])
		client.Send(rawbuf[:]) // Keep BufferedSent > 0.
	}
	if client.nRetx <= prevNRetx {
		t.Fatalf("BUG: fast retransmit did NOT trigger for loss event #2.\n"+
			"nRetx=%d (was %d).\n"+
			"The dup-ACK counter was not reset after recovery from loss event #1,\n"+
			"so it never reached the threshold again.", client.nRetx, prevNRetx)
	}
	t.Logf("loss #2: fast retransmit triggered (nRetx=%d)", client.nRetx)
}
