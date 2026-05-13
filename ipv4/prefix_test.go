package ipv4

import (
	"net/netip"
	"testing"
)

func TestPrefixFrom(t *testing.T) {
	tests := []struct {
		addr      [4]byte
		bits      uint8
		wantValid bool
		wantBits  uint8
		wantAddr  [4]byte
	}{
		{[4]byte{192, 168, 1, 0}, 24, true, 24, [4]byte{192, 168, 1, 0}},
		{[4]byte{10, 0, 0, 0}, 8, true, 8, [4]byte{10, 0, 0, 0}},
		{[4]byte{0, 0, 0, 0}, 0, true, 0, [4]byte{0, 0, 0, 0}},
		{[4]byte{1, 2, 3, 4}, 32, true, 32, [4]byte{1, 2, 3, 4}},
		{[4]byte{1, 2, 3, 4}, 33, true, 0, [4]byte{1, 2, 3, 4}}, // >32 clamped to 0
	}
	for _, tc := range tests {
		p := PrefixFrom(tc.addr, tc.bits)
		if p.IsValid() != tc.wantValid {
			t.Errorf("PrefixFrom(%v, %d).IsValid() = %v, want %v", tc.addr, tc.bits, p.IsValid(), tc.wantValid)
		}
		if p.Bits() != tc.wantBits {
			t.Errorf("PrefixFrom(%v, %d).Bits() = %d, want %d", tc.addr, tc.bits, p.Bits(), tc.wantBits)
		}
		if p.Addr() != tc.wantAddr {
			t.Errorf("PrefixFrom(%v, %d).Addr() = %v, want %v", tc.addr, tc.bits, p.Addr(), tc.wantAddr)
		}
	}
}

func TestPrefixZeroValue(t *testing.T) {
	var p Prefix
	if p.IsValid() {
		t.Error("zero Prefix should be invalid")
	}
}

func TestPrefixFromNetip(t *testing.T) {
	tests := []struct {
		in        string
		wantValid bool
	}{
		{"192.168.1.0/24", true},
		{"10.0.0.0/8", true},
		{"0.0.0.0/0", true},
		{"1.2.3.4/32", true},
		{"::1/128", false}, // IPv6 should yield invalid
	}
	for _, tc := range tests {
		npfx, err := netip.ParsePrefix(tc.in)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", tc.in, err)
		}
		p := PrefixFromNetip(npfx)
		if p.IsValid() != tc.wantValid {
			t.Errorf("PrefixFromNetip(%q).IsValid() = %v, want %v", tc.in, p.IsValid(), tc.wantValid)
		}
		if !tc.wantValid {
			continue
		}
		if p.NetipPrefix() != npfx {
			t.Errorf("PrefixFromNetip(%q).NetipPrefix() = %v, want %v", tc.in, p.NetipPrefix(), npfx)
		}
	}
}

func TestPrefixNetipRoundtrip(t *testing.T) {
	inputs := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "0.0.0.0/0", "1.2.3.4/32"}
	for _, s := range inputs {
		npfx := netip.MustParsePrefix(s)
		p := PrefixFromNetip(npfx)
		if got := p.NetipPrefix(); got != npfx {
			t.Errorf("roundtrip %q: got %v", s, got)
		}
	}
}

func TestPrefixContains(t *testing.T) {
	p := PrefixFrom([4]byte{192, 168, 1, 0}, 24)
	tests := []struct {
		addr [4]byte
		want bool
	}{
		{[4]byte{192, 168, 1, 0}, true},
		{[4]byte{192, 168, 1, 1}, true},
		{[4]byte{192, 168, 1, 255}, true},
		{[4]byte{192, 168, 2, 0}, false},
		{[4]byte{10, 0, 0, 1}, false},
	}
	for _, tc := range tests {
		if got := p.Contains(tc.addr); got != tc.want {
			t.Errorf("%v.Contains(%v) = %v, want %v", p.NetipPrefix(), tc.addr, got, tc.want)
		}
	}

	var invalid Prefix
	if invalid.Contains([4]byte{0, 0, 0, 0}) {
		t.Error("invalid Prefix.Contains should return false")
	}
}

func TestPrefixMasked(t *testing.T) {
	// Address with host bits set.
	p := PrefixFrom([4]byte{192, 168, 1, 5}, 24)
	m := p.Masked()
	want := [4]byte{192, 168, 1, 0}
	if m.Addr() != want {
		t.Errorf("Masked().Addr() = %v, want %v", m.Addr(), want)
	}
	if m.Bits() != 24 {
		t.Errorf("Masked().Bits() = %d, want 24", m.Bits())
	}
}

func TestPrefixIsSingleIP(t *testing.T) {
	if !PrefixFrom([4]byte{1, 2, 3, 4}, 32).IsSingleIP() {
		t.Error("/32 should be single IP")
	}
	if PrefixFrom([4]byte{1, 2, 3, 4}, 31).IsSingleIP() {
		t.Error("/31 should not be single IP")
	}
	var invalid Prefix
	if invalid.IsSingleIP() {
		t.Error("invalid Prefix.IsSingleIP should return false")
	}
}

func TestPrefixOverlaps(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"192.168.0.0/16", "192.168.1.0/24", true},
		{"10.0.0.0/8", "10.1.2.0/24", true},
		{"10.0.0.0/8", "192.168.0.0/16", false},
		{"0.0.0.0/0", "1.2.3.4/32", true},
		{"1.2.3.4/32", "1.2.3.4/32", true},
		{"1.2.3.4/32", "1.2.3.5/32", false},
	}
	for _, tc := range tests {
		a := PrefixFromNetip(netip.MustParsePrefix(tc.a))
		b := PrefixFromNetip(netip.MustParsePrefix(tc.b))
		if got := a.Overlaps(b); got != tc.want {
			t.Errorf("%s.Overlaps(%s) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
		// Symmetry.
		if got := b.Overlaps(a); got != tc.want {
			t.Errorf("%s.Overlaps(%s) [symmetric] = %v, want %v", tc.b, tc.a, got, tc.want)
		}
	}

	var invalid Prefix
	valid := PrefixFrom([4]byte{10, 0, 0, 0}, 8)
	if invalid.Overlaps(valid) || valid.Overlaps(invalid) {
		t.Error("invalid Prefix.Overlaps should return false")
	}
}

func TestPrefixNext(t *testing.T) {
	tests := []struct {
		prefix string
		addr   [4]byte
		want   [4]byte
	}{
		// Normal increment within /24.
		{"192.168.1.0/24", [4]byte{192, 168, 1, 0}, [4]byte{192, 168, 1, 1}},
		{"192.168.1.0/24", [4]byte{192, 168, 1, 1}, [4]byte{192, 168, 1, 2}},
		{"192.168.1.0/24", [4]byte{192, 168, 1, 254}, [4]byte{192, 168, 1, 255}},
		// Wrap-around: last host addr in /24 wraps to first.
		{"192.168.1.0/24", [4]byte{192, 168, 1, 255}, [4]byte{192, 168, 1, 0}},
		// /32: only one host, wraps to itself.
		{"1.2.3.4/32", [4]byte{1, 2, 3, 4}, [4]byte{1, 2, 3, 4}},
		// /31: two hosts, wraps.
		{"10.0.0.0/31", [4]byte{10, 0, 0, 0}, [4]byte{10, 0, 0, 1}},
		{"10.0.0.0/31", [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 0}},
		// /8: increment and wrap within the network.
		{"10.0.0.0/8", [4]byte{10, 0, 0, 255}, [4]byte{10, 0, 1, 0}},
		{"10.0.0.0/8", [4]byte{10, 255, 255, 255}, [4]byte{10, 0, 0, 0}},
	}
	for _, tc := range tests {
		p := PrefixFromNetip(netip.MustParsePrefix(tc.prefix))
		got := p.Next(tc.addr)
		if got != tc.want {
			t.Errorf("%s.Next(%v) = %v, want %v", tc.prefix, tc.addr, got, tc.want)
		}
	}
}

func TestPrefixCompare(t *testing.T) {
	var invalid Prefix
	a := PrefixFromNetip(netip.MustParsePrefix("10.0.0.0/8"))
	b := PrefixFromNetip(netip.MustParsePrefix("192.168.0.0/16"))

	// invalid < valid
	if invalid.Compare(a) != -1 {
		t.Error("invalid.Compare(valid) should be -1")
	}
	if a.Compare(invalid) != 1 {
		t.Error("valid.Compare(invalid) should be 1")
	}
	// two invalids are equal
	if invalid.Compare(Prefix{}) != 0 {
		t.Error("invalid.Compare(invalid) should be 0")
	}
	// reflexive
	if a.Compare(a) != 0 {
		t.Error("a.Compare(a) should be 0")
	}
	// ordering
	if got := a.Compare(b); got >= 0 {
		t.Errorf("10/8.Compare(192.168/16) should be negative, got %d", got)
	}
	if got := b.Compare(a); got <= 0 {
		t.Errorf("192.168/16.Compare(10/8) should be positive, got %d", got)
	}

	// shorter prefix < longer prefix when masked addr is equal
	a8 := PrefixFromNetip(netip.MustParsePrefix("10.0.0.0/8"))
	a16 := PrefixFromNetip(netip.MustParsePrefix("10.0.0.0/16"))
	if a8.Compare(a16) >= 0 {
		t.Error("10/8 should sort before 10/16")
	}
}
