package dhcpv4

import (
	"testing"

	"github.com/soypat/lneto"
)

// FuzzFrame checks that the accessors of a frame passing ValidateSize stay
// within its buffer.
func FuzzFrame(f *testing.F) {
	seed := make([]byte, OptionsOffset+4)
	copy(seed[magicCookieOffset:], []byte{0x63, 0x82, 0x53, 0x63})
	copy(seed[OptionsOffset:], []byte{53, 1, 1, 255})
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		frm, err := NewFrame(b)
		if err != nil {
			return
		}
		var v lneto.Validator
		frm.ValidateSize(&v)
		if v.HasError() {
			return
		}
		frm.CHAddr()
		_ = frm.OptionsPayload()
		frm.ForEachOption(func(int, OptNum, []byte) error { return nil })
	})
}
