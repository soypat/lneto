package ethernet

import (
	"net"
	"testing"
)

func TestString(t *testing.T) {
	for _, tc := range []struct {
		addr [6]byte
		want string
	}{
		{addr: [6]byte{}, want: "00:00:00:00:00:00"},
		{addr: [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, want: "ff:ff:ff:ff:ff:ff"},
		{addr: [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}, want: "de:ad:be:ef:00:01"},
		{addr: [6]byte{0x01, 0x00, 0x5e, 0x7f, 0x00, 0x0f}, want: "01:00:5e:7f:00:0f"},
	} {
		got := String(tc.addr)
		if got != tc.want {
			t.Errorf("String(%v): got %q, want %q", tc.addr, got, tc.want)
		}
		if want := net.HardwareAddr(tc.addr[:]).String(); got != want {
			t.Errorf("String(%v) disagrees with net: got %q, want %q", tc.addr, got, want)
		}
		if got := string(AppendAddr(nil, tc.addr)); got != tc.want {
			t.Errorf("AppendAddr(%v): got %q, want %q", tc.addr, got, tc.want)
		}
	}
}

func TestString_singleAlloc(t *testing.T) {
	addr := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	var sink string
	allocs := testing.AllocsPerRun(100, func() {
		sink = String(addr)
	})
	_ = sink
	// Only the returned string allocates; the scratch buffer must stay on the stack.
	if allocs != 1 {
		t.Errorf("expected 1 alloc, got %v", allocs)
	}
}
