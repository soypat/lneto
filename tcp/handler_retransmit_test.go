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

// TestRecoveryACKSkipsSpuriousRetransmit verifies that after fast retransmit
// rewinds snd.NXT and the client re-sends the lost segment, a cumulative ACK
// from the remote (acknowledging all data received before and after the hole)
// is accepted — even though it exceeds the rewound snd.NXT.
//
// Without this fix, lneto rejects the cumulative ACK as "acks unsent data"
// and then spuriously retransmits data that was already received by the remote.
//
// Timeline:
//  1. Client sends packets 0..N; packet 1 is lost (the "hole")
//  2. Server ACKs packet 0; sends 3 dup ACKs → fast retransmit fires
//  3. Client rewinds to snd.UNA, re-sends lost segment → snd.NXT advances by 1 MSS
//  4. Server (having received all other packets) sends cumulative ACK for ALL data
//  5. Client should accept this ACK (not reject it) and NOT send spurious retransmissions
func TestRecoveryACKSkipsSpuriousRetransmit(t *testing.T) {
	const mtu = 60 // 20-byte header + 40-byte payload per packet.
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

	// Send enough data to fill several packets (MSS=40).
	data := make([]byte, 40*6) // 6 packets worth of data.
	for i := range data {
		data[i] = byte(i)
	}
	written := 0
	var packets [][]byte
	for written < len(data) {
		n, werr := client.Write(data[written:])
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
			packets = append(packets, append([]byte(nil), rawbuf[:ns]...))
		}
	}
	if len(packets) < 4 {
		t.Fatalf("need at least 4 data packets, got %d", len(packets))
	}
	t.Logf("sent %d data packets", len(packets))

	// Record the sequence endpoint: this is the ACK value the server will
	// send once it receives all data (including the "lost" packet).
	preRewindNXT := client.scb.snd.NXT
	t.Logf("pre-rewind snd.NXT=%d, snd.UNA=%d", preRewindNXT, client.scb.snd.UNA)

	// Server receives only packet 0 → ACKs it. This establishes lastACK on client.
	err = server.Recv(packets[0])
	if err != nil {
		t.Fatal("server recv pkt0:", err)
	}
	clear(rawbuf[:])
	n, err := server.Send(rawbuf[:])
	if err != nil {
		t.Fatal("server send ACK:", err)
	}
	if n == 0 {
		t.Fatal("expected server to send ACK")
	}
	err = client.Recv(rawbuf[:n])
	if err != nil {
		t.Fatal("client recv ACK:", err)
	}
	dupACKValue := client.lastACK
	t.Logf("lastACK=%d after first ACK", dupACKValue)

	// Craft 3 dup ACKs (packet 1 is "lost", server keeps acking dupACKValue).
	for i := 0; i < 3; i++ {
		var buf [mtu]byte
		frm, ferr := NewFrame(buf[:])
		if ferr != nil {
			t.Fatal(ferr)
		}
		frm.SetSourcePort(server.LocalPort())
		frm.SetDestinationPort(client.LocalPort())
		frm.SetSegment(Segment{
			SEQ:   server.scb.snd.NXT,
			ACK:   dupACKValue,
			Flags: FlagACK,
			WND:   65535,
		}, 5)
		rerr := client.Recv(buf[:sizeHeaderTCP])
		if rerr != nil {
			t.Logf("dup ACK %d recv err (expected): %v", i+1, rerr)
		}
	}
	if client.nRetx == 0 {
		t.Fatal("fast retransmit did not fire after 3 dup ACKs")
	}
	t.Logf("fast retransmit fired: snd.NXT=%d, snd.UNA=%d", client.scb.snd.NXT, client.scb.snd.UNA)

	// Client re-sends the lost segment. After this, snd.NXT > snd.UNA
	// (advanced by one MSS), but still < preRewindNXT.
	clear(rawbuf[:])
	n, err = client.Send(rawbuf[:])
	if err != nil {
		t.Fatal("client retransmit send:", err)
	}
	if n == 0 {
		t.Fatal("expected client to send retransmit packet")
	}
	if client.scb.snd.NXT == client.scb.snd.UNA {
		t.Fatal("expected snd.NXT to advance past snd.UNA after re-send")
	}
	t.Logf("after retransmit send: snd.NXT=%d, snd.UNA=%d (preRewind=%d)",
		client.scb.snd.NXT, client.scb.snd.UNA, preRewindNXT)

	// Craft cumulative ACK from server for ALL data (as if server had received
	// everything and the lost packet just arrived, filling the hole).
	{
		var buf [mtu]byte
		frm, ferr := NewFrame(buf[:])
		if ferr != nil {
			t.Fatal(ferr)
		}
		frm.SetSourcePort(server.LocalPort())
		frm.SetDestinationPort(client.LocalPort())
		frm.SetSegment(Segment{
			SEQ:   server.scb.snd.NXT,
			ACK:   preRewindNXT, // ACKs all data sent before the rewind.
			Flags: FlagACK,
			WND:   65535,
		}, 5)

		err = client.Recv(buf[:sizeHeaderTCP])
		if err != nil {
			t.Fatalf("BUG: cumulative recovery ACK rejected: %v\n"+
				"After fast retransmit rewound snd.NXT and client re-sent one packet,\n"+
				"the remote's cumulative ACK (seg.ACK=%d) exceeds the current snd.NXT=%d\n"+
				"and is incorrectly rejected as 'acks unsent data'.\n"+
				"This causes spurious retransmissions of already-received data.",
				err, preRewindNXT, client.scb.snd.NXT)
		}
	}

	// snd.UNA should have advanced to cover all original data.
	if client.scb.snd.UNA != preRewindNXT {
		t.Fatalf("snd.UNA not advanced: got %d, want %d", client.scb.snd.UNA, preRewindNXT)
	}
	// snd.NXT should be at least preRewindNXT.
	if client.scb.snd.NXT.LessThan(preRewindNXT) {
		t.Fatalf("snd.NXT behind preRewindNXT: got %d, want >= %d", client.scb.snd.NXT, preRewindNXT)
	}

	// No more data should be sent — any Send() output here is a spurious retransmission.
	clear(rawbuf[:])
	n, err = client.Send(rawbuf[:])
	if err != nil {
		t.Fatal("client send after recovery:", err)
	}
	if n != 0 {
		t.Fatalf("BUG: spurious retransmission after recovery ACK: sent %d bytes.\n"+
			"All data was already acknowledged by the cumulative ACK, but the client\n"+
			"still has 'unsent' data in the TX buffer that was actually received.", n)
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
