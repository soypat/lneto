package ipv4

import (
	"net/netip"
	"testing"
)

func TestAppendFormatAddr(t *testing.T) {
	tests := []struct {
		addr [4]byte
		want string
	}{
		{addr: [4]byte{0, 0, 0, 0}, want: "0.0.0.0"},
		{addr: [4]byte{127, 0, 0, 1}, want: "127.0.0.1"},
		{addr: [4]byte{192, 168, 1, 1}, want: "192.168.1.1"},
		{addr: [4]byte{255, 255, 255, 255}, want: "255.255.255.255"},
		{addr: [4]byte{10, 0, 0, 1}, want: "10.0.0.1"},
		{addr: [4]byte{1, 2, 3, 4}, want: "1.2.3.4"},
		{addr: [4]byte{100, 99, 9, 0}, want: "100.99.9.0"},
	}
	for _, tc := range tests {
		got := string(AppendFormatAddr(nil, tc.addr))
		if got != tc.want {
			t.Errorf("AppendFormatAddr(%v): got %q, want %q", tc.addr, got, tc.want)
		}
		// Cross-check with netip.
		want := netip.AddrFrom4(tc.addr).String()
		if got != want {
			t.Errorf("AppendFormatAddr(%v) disagrees with netip: got %q, want %q", tc.addr, got, want)
		}
	}
}

func TestAppendFormatAddr_noAllocs(t *testing.T) {
	var buf [24]byte
	addr := [4]byte{192, 168, 1, 1}
	allocs := testing.AllocsPerRun(100, func() {
		_ = AppendFormatAddr(buf[:0], addr)
	})
	if allocs != 0 {
		t.Errorf("expected 0 allocs, got %v", allocs)
	}
}
