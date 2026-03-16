package ipv6

import (
	"net/netip"
	"testing"
)

func TestAppendFormatAddr(t *testing.T) {
	tests := []struct {
		addr [16]byte
		want string
	}{
		// All zeros → "::".
		{addr: [16]byte{}, want: "::"},
		// Loopback → "::1".
		{addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, want: "::1"},
		// Full address, no compression.
		{addr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06}, want: "2001:db8:1:2:3:4:5:6"},
		// Trailing zero run.
		{addr: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, want: "fe80::"},
		// Leading non-zero + middle compression.
		{addr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, want: "2001:db8::1"},
		// Link-local with interface ID.
		{addr: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, want: "fe80::1"},
		// Two zero runs; compress the longer one (groups 3-6 len=4 vs group 1 len=1).
		{addr: [16]byte{0x20, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, want: "2001:0:1::1"},
		// Single zero group should NOT compress (RFC 5952 §4.2.2).
		{addr: [16]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06}, want: "1:0:1:2:3:4:5:6"},
		// All ff → no compression.
		{addr: [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		// IPv4-mapped ::ffff:192.168.1.1 — we format as pure hex groups.
		{addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xc0, 0xa8, 0x01, 0x01}, want: "::ffff:c0a8:101"},
		// Two equal-length zero runs; first one wins.
		{addr: [16]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, want: "1::1:2:0:0:1"},
	}

	for _, tc := range tests {
		got := string(AppendFormatAddr(nil, tc.addr))
		if got != tc.want {
			t.Errorf("AppendFormatAddr(%v):\n got  %q\n want %q", tc.addr, got, tc.want)
		}
	}
}

func TestAppendFormatAddr_matchesNetip(t *testing.T) {
	// Verify output matches netip.Addr.AppendTo for non-IPv4-mapped addresses.
	addrs := [][16]byte{
		{},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x01},
		{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb},
		{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	for _, addr := range addrs {
		got := string(AppendFormatAddr(nil, addr))
		want := netip.AddrFrom16(addr).String()
		if got != want {
			t.Errorf("mismatch for %v:\n got  %q\n want %q", addr, got, want)
		}
	}
}

func TestAppendFormatAddr_noAllocs(t *testing.T) {
	var buf [64]byte
	addr := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	allocs := testing.AllocsPerRun(100, func() {
		_ = AppendFormatAddr(buf[:0], addr)
	})
	if allocs != 0 {
		t.Errorf("expected 0 allocs, got %v", allocs)
	}
}
