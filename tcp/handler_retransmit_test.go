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
