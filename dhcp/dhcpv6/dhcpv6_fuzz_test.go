package dhcpv6

import "testing"

// FuzzFrame checks that the options of a frame passing ValidateSize stay
// within its buffer.
func FuzzFrame(f *testing.F) {
	f.Add([]byte{1, 0, 0, 1, 0, 1, 0, 2, 0xab, 0xcd})
	f.Fuzz(func(t *testing.T, b []byte) {
		frm, err := NewFrame(b)
		if err != nil || frm.ValidateSize() != nil {
			return
		}
		frm.ForEachOption(func(int, OptCode, []byte) error { return nil })
	})
}
