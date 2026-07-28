package tcp

import (
	"math/rand"
	"testing"

	"github.com/soypat/lneto"
)

// TestRecvUnbufferableSegmentIsAcknowledged verifies a segment that arrives in
// window but does not fit the receive buffer is still acknowledged. RFC 9293
// §3.10.7.4 requires an acknowledgement in reply to a segment that cannot be
// accepted; dropping it in silence leaves the sender unable to distinguish a lost
// segment from a closed window.
func TestRecvUnbufferableSegmentIsAcknowledged(t *testing.T) {
	const mtu = 128
	rng := rand.New(rand.NewSource(21))
	client, server := newHandler(t, mtu, 4), newHandler(t, mtu, 4)
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	// Fill the server's receive buffer, draining its acknowledgements so no ACK
	// is left pending from ordinary data flow.
	payload := make([]byte, 32)
	filled := false
	for round := 0; round < 32 && !filled; round++ {
		if _, err := client.Write(payload); err != nil {
			t.Fatal("client write:", err)
		}
		n, err := client.Send(buf[:])
		if err != nil {
			t.Fatal("client send:", err)
		}
		if n == 0 {
			break
		}
		switch err = server.Recv(buf[:n]); err {
		case nil:
		case lneto.ErrBufferFull:
			filled = true
			continue // Leave the reply in the queue; it is what this test asserts.
		default:
			t.Fatal("server recv:", err)
		}
		clear(buf[:])
		m, err := server.Send(buf[:])
		if err != nil {
			t.Fatal("server send:", err)
		}
		if m > 0 {
			if err = client.Recv(buf[:m]); err != nil {
				t.Fatal("client recv:", err)
			}
		}
	}
	if !filled {
		t.Skip("could not fill the receive buffer; adjust the fixture")
	}

	// The rejected segment must have left an ACK pending.
	clear(buf[:])
	n, err := server.Send(buf[:])
	if err != nil {
		t.Fatal("server send after rejection:", err)
	}
	if n == 0 {
		t.Fatal("segment dropped without acknowledgement")
	}
	seg := mustSegment(t, buf[:n], n-sizeHeaderTCP)
	if !seg.Flags.HasAny(FlagACK) {
		t.Errorf("reply flags %s, want an ACK", seg.Flags.String())
	}
	if seg.ACK != server.scb.rcv.NXT {
		t.Errorf("reply ACK=%d, want rcv.NXT=%d", seg.ACK, server.scb.rcv.NXT)
	}
	if seg.DATALEN != 0 {
		t.Errorf("reply carries %d octets, want a bare ACK", seg.DATALEN)
	}
}
