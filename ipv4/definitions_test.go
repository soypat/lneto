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
		{addr: UnspecifiedAddr(), want: "0.0.0.0"},
		{addr: BroadcastAddr(), want: "255.255.255.255"},
		{addr: [4]byte{127, 0, 0, 1}, want: "127.0.0.1"},
		{addr: [4]byte{192, 168, 1, 1}, want: "192.168.1.1"},
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

// TestFlagsWireLayout checks Flags against the RFC 791 wire layout of header bytes 6:8:
// bit 0 (MSB) reserved/evil (RFC 3514), bit 1 DF, bit 2 MF, then a 13-bit fragment offset.
func TestFlagsWireLayout(t *testing.T) {
	tests := []struct {
		wire     uint16
		evil     bool
		df, mf   bool
		fragOff  uint16
		newFlags Flags // NewFlags(fragOff, df, mf).
	}{
		{wire: 0x8000, evil: true, newFlags: 0},
		{wire: 0x4000, df: true, newFlags: 0x4000},
		{wire: 0x2000, mf: true, newFlags: 0x2000},
		{wire: 0x2001, mf: true, fragOff: 1, newFlags: 0x2001},
		{wire: 0x1fff, fragOff: 0x1fff, newFlags: 0x1fff},
	}
	for _, tc := range tests {
		f := Flags(tc.wire)
		if f.IsEvil() != tc.evil || f.DontFragment() != tc.df || f.MoreFragments() != tc.mf || f.FragmentOffset() != tc.fragOff {
			t.Errorf("%#04x: got evil=%v df=%v mf=%v off=%d, want evil=%v df=%v mf=%v off=%d", tc.wire,
				f.IsEvil(), f.DontFragment(), f.MoreFragments(), f.FragmentOffset(), tc.evil, tc.df, tc.mf, tc.fragOff)
		}
		if got := NewFlags(tc.fragOff, tc.df, tc.mf); got != tc.newFlags {
			t.Errorf("NewFlags(%d, %v, %v) = %#04x, want %#04x", tc.fragOff, tc.df, tc.mf, got, tc.newFlags)
		}
	}
}

func TestIsLinkLocal(t *testing.T) {
	tests := []struct {
		addr [4]byte
		want bool
	}{
		{addr: [4]byte{169, 254, 0, 0}, want: true},
		{addr: [4]byte{169, 254, 1, 1}, want: true},
		{addr: [4]byte{169, 254, 254, 255}, want: true},
		{addr: [4]byte{169, 254, 255, 255}, want: true},
		{addr: [4]byte{169, 253, 1, 1}, want: false},
		{addr: [4]byte{169, 255, 1, 1}, want: false},
		{addr: [4]byte{192, 168, 1, 1}, want: false},
		{addr: [4]byte{0, 0, 0, 0}, want: false},
	}
	for _, tc := range tests {
		if got := IsLinkLocal(tc.addr); got != tc.want {
			t.Errorf("IsLinkLocal(%v): got %v, want %v", tc.addr, got, tc.want)
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
