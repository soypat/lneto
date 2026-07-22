package tcp

import (
	"bytes"
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

// TestSACK_SelectiveRetransmit drives a full recovery: the client sends four
// segments, the first is dropped, the server SACKs the three that arrive, and
// on fast recovery the client retransmits only the dropped hole (not go-back-N).
// The server then delivers the whole stream intact.
func TestSACK_SelectiveRetransmit(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(4))
	client, server := newHandler(t, mtu, 8), newHandler(t, mtu, 8)
	if err := client.EnableSACK(true); err != nil {
		t.Fatal(err)
	}
	if err := server.EnableSACK(true); err != nil {
		t.Fatal(err)
	}
	setupClientServer(t, rng, client, server)
	var hs [mtu]byte
	establish(t, client, server, hs[:])

	// Send four distinct segments, one per Send so each is its own packet.
	segs := [][]byte{[]byte("AAAA"), []byte("BBBB"), []byte("CCCC"), []byte("DDDD")}
	pkts := make([][]byte, len(segs))
	seq := make([]Value, len(segs))
	for i, d := range segs {
		if _, err := client.Write(d); err != nil {
			t.Fatalf("write seg %d: %v", i, err)
		}
		buf := make([]byte, mtu)
		n, err := client.Send(buf)
		if err != nil {
			t.Fatalf("send seg %d: %v", i, err)
		}
		pkts[i] = buf[:n]
		seq[i] = mustSegment(t, buf[:n], n-sizeHeaderTCP).SEQ
	}

	// Deliver segments 1..3 (drop segment 0). Each lands out of order, so the
	// server replies with a dup ACK carrying SACK blocks; feed those back to the
	// client so it accumulates dup ACKs and marks its scoreboard.
	var ack [mtu]byte
	for i := 1; i < len(segs); i++ {
		if err := server.Recv(pkts[i]); err != nil {
			t.Fatalf("server recv seg %d: %v", i, err)
		}
		clear(ack[:])
		na, err := server.Send(ack[:])
		if err != nil {
			t.Fatalf("server send dupack %d: %v", i, err)
		}
		if err := client.Recv(ack[:na]); err != nil {
			t.Fatalf("client recv dupack %d: %v", i, err)
		}
	}

	// Fast recovery: the client must retransmit exactly the dropped hole (seg 0).
	rbuf := make([]byte, mtu)
	nr, err := client.Send(rbuf)
	if err != nil {
		t.Fatal("client selective retransmit:", err)
	}
	rseg := mustSegment(t, rbuf[:nr], nr-sizeHeaderTCP)
	if rseg.SEQ != seq[0] {
		t.Fatalf("retransmit SEQ = %d, want dropped hole %d (go-back-N?)", rseg.SEQ, seq[0])
	}
	if int(rseg.DATALEN) != len(segs[0]) {
		t.Fatalf("retransmit DATALEN = %d, want %d", rseg.DATALEN, len(segs[0]))
	}

	// Deliver the retransmitted hole; the server now has a contiguous stream.
	if err := server.Recv(rbuf[:nr]); err != nil {
		t.Fatal("server recv retransmit:", err)
	}
	got := make([]byte, 0, len(segs)*4)
	rd := make([]byte, mtu)
	for {
		n, _ := server.Read(rd)
		if n == 0 {
			break
		}
		got = append(got, rd[:n]...)
	}
	want := []byte("AAAABBBBCCCCDDDD")
	if !bytes.Equal(got, want) {
		t.Fatalf("delivered stream = %q, want %q", got, want)
	}
}
