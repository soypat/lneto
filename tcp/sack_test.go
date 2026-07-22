package tcp

import (
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

// sackBlocksFromOptions parses the SACK blocks advertised in a segment's TCP
// options (RFC 2018 §3).
func sackBlocksFromOptions(h *Handler, opts []byte) (blocks []sackBlock) {
	h.optcodec.ForEachOption(opts, func(kind OptionKind, data []byte) error {
		if kind == OptSACK {
			for off := 0; off+8 <= len(data); off += 8 {
				blocks = append(blocks, sackBlock{
					start: Value(binary.BigEndian.Uint32(data[off:])),
					end:   Value(binary.BigEndian.Uint32(data[off+4:])),
				})
			}
		}
		return nil
	})
	return blocks
}

// TestSACK_Negotiated verifies SACK is negotiated on the handshake when both
// peers permit it.
func TestSACK_Negotiated(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(1))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	if err := client.EnableSACK(true); err != nil {
		t.Fatal(err)
	}
	if err := server.EnableSACK(true); err != nil {
		t.Fatal(err)
	}
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	if !client.SACKEnabled() {
		t.Error("client did not negotiate SACK")
	}
	if !server.SACKEnabled() {
		t.Error("server did not negotiate SACK")
	}
}

// TestSACK_NotNegotiatedWhenOneSideOff verifies SACK stays off for the whole
// connection when either peer does not permit it.
func TestSACK_NotNegotiatedWhenOneSideOff(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(2))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	if err := client.EnableSACK(true); err != nil { // only the client permits SACK.
		t.Fatal(err)
	}
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	if client.SACKEnabled() {
		t.Error("client negotiated SACK without server support")
	}
	if server.SACKEnabled() {
		t.Error("server negotiated SACK though it was disabled")
	}
}

// TestSACK_AdvertisesBlocks verifies a receiver holding out-of-order data
// advertises the buffered range as a SACK block on its ACK (RFC 2018 §3).
func TestSACK_AdvertisesBlocks(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(3))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	if err := client.EnableSACK(true); err != nil {
		t.Fatal(err)
	}
	if err := server.EnableSACK(true); err != nil {
		t.Fatal(err)
	}
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	// Client sends two segments; the second is delivered first so the server
	// holds it out of order.
	d1, d2 := []byte("hello"), []byte("world")
	if _, err := client.Write(d1); err != nil {
		t.Fatal("write d1:", err)
	}
	clear(buf[:])
	n1, err := client.Send(buf[:])
	if err != nil {
		t.Fatal("send seg1:", err)
	}
	seg1 := mustSegment(t, buf[:n1], n1-sizeHeaderTCP)

	var buf2 [mtu]byte
	if _, err := client.Write(d2); err != nil {
		t.Fatal("write d2:", err)
	}
	n2, err := client.Send(buf2[:])
	if err != nil {
		t.Fatal("send seg2:", err)
	}
	seg2 := mustSegment(t, buf2[:n2], n2-sizeHeaderTCP)

	// Deliver only the second segment: it lands ahead of rcv.NXT.
	if err := server.Recv(buf2[:n2]); err != nil {
		t.Fatal("server recv seg2:", err)
	}

	// The server's ACK must advertise the buffered out-of-order range.
	clear(buf[:])
	na, err := server.Send(buf[:])
	if err != nil {
		t.Fatal("server send ack:", err)
	}
	frame, err := NewFrame(buf[:na])
	if err != nil {
		t.Fatal("parse ack:", err)
	}
	blocks := sackBlocksFromOptions(server, frame.Options())
	if len(blocks) != 1 {
		t.Fatalf("got %d SACK blocks, want 1", len(blocks))
	}
	wantStart, wantEnd := seg2.SEQ, seg2.SEQ+Value(len(d2))
	if blocks[0].start != wantStart || blocks[0].end != wantEnd {
		t.Errorf("SACK block = [%d,%d), want [%d,%d)", blocks[0].start, blocks[0].end, wantStart, wantEnd)
	}
	_ = seg1
}
