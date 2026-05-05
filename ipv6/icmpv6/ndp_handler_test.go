package icmpv6

import (
	"bytes"
	"testing"
)

func TestNDPHandler(t *testing.T) {
	addr1 := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	addr2 := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	mac1 := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	mac2 := [6]byte{0xc0, 0xff, 0xee, 0xc0, 0xff, 0x02}

	var h1, h2 NDPHandler
	if err := h1.Reset(NDPHandlerConfig{Addr: addr1, MAC: mac1, MaxCache: 2}); err != nil {
		t.Fatal(err)
	}
	if err := h2.Reset(NDPHandlerConfig{Addr: addr2, MAC: mac2, MaxCache: 2}); err != nil {
		t.Fatal(err)
	}

	var buf [64]byte

	// No pending work: both handlers should be silent.
	n, err := h1.Encapsulate(buf[:], -1, 0)
	if err != nil || n > 0 {
		t.Fatal("expected no data before query:", err, n)
	}
	n, err = h2.Encapsulate(buf[:], -1, 0)
	if err != nil || n > 0 {
		t.Fatal("expected no data before query:", err, n)
	}

	// h1 queries h2's MAC.
	if err = h1.StartQuery(addr2, false); err != nil {
		t.Fatal(err)
	}

	// h1 sends a Neighbor Solicitation.
	n, err = h1.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal("h1 encapsulate NS:", err)
	} else if n == 0 {
		t.Fatal("expected NS to be written")
	}
	validateNDP(t, buf[:n], TypeNeighborSolicitation)

	// Verify NS target address is addr2.
	ifrm, _ := NewFrame(buf[:n])
	nsfrm := FrameNeighborSolicitation{Frame: ifrm}
	if *nsfrm.TargetAddr() != addr2 {
		t.Errorf("NS target addr mismatch: want %x, got %x", addr2, *nsfrm.TargetAddr())
	}

	// h2 receives the NS (no IP carrier, so CRC covers only ICMPv6 body).
	if err = h2.Demux(buf[:n], 0); err != nil {
		t.Fatal("h2 demux NS:", err)
	}

	// h2 sends a Neighbor Advertisement.
	n, err = h2.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal("h2 encapsulate NA:", err)
	} else if n == 0 {
		t.Fatal("expected NA to be written")
	}
	validateNDP(t, buf[:n], TypeNeighborAdvertisement)

	// Verify NA target address is addr2 (h2's own address).
	ifrm, _ = NewFrame(buf[:n])
	nafrm := FrameNeighborAdvertisement{Frame: ifrm}
	if *nafrm.TargetAddr() != addr2 {
		t.Errorf("NA target addr mismatch: want %x, got %x", addr2, *nafrm.TargetAddr())
	}
	_, solicited, _ := nafrm.Flags()
	if !solicited {
		t.Error("expected solicited flag set in NA")
	}

	// Verify double-tap: h2 should have nothing left to send.
	n2, err := h2.Encapsulate(buf[:], -1, 0)
	if err != nil || n2 > 0 {
		t.Fatal("double tap: expected no more data from h2:", err, n2)
	}

	// h1 receives the NA and resolves h2's MAC.
	if err = h1.Demux(buf[:n], 0); err != nil {
		t.Fatal("h1 demux NA:", err)
	}
	mac, err := h1.CacheLookup(addr2)
	if err != nil {
		t.Fatal("cache lookup after resolution:", err)
	}
	if !bytes.Equal(mac[:], mac2[:]) {
		t.Errorf("resolved MAC mismatch: want %x, got %x", mac2, mac)
	}

	// h1 should have nothing left to send.
	n, err = h1.Encapsulate(buf[:], -1, 0)
	if err != nil || n > 0 {
		t.Fatal("expected no data after completion:", err, n)
	}
}

func validateNDP(t *testing.T, buf []byte, wantType Type) {
	t.Helper()
	if len(buf) < sizeNDP {
		t.Errorf("NDP frame too short: %d < %d", len(buf), sizeNDP)
		return
	}
	ifrm, err := NewFrame(buf)
	if err != nil {
		t.Error("NewFrame:", err)
		return
	}
	if ifrm.Type() != wantType {
		t.Errorf("type mismatch: want %s, got %s", wantType, ifrm.Type())
	}
	if ifrm.Code() != 0 {
		t.Errorf("code must be zero, got %d", ifrm.Code())
	}
}
