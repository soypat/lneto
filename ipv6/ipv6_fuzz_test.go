package ipv6

import (
	"testing"

	"github.com/soypat/lneto"
)

// FuzzFrame checks that the accessors of a frame passing ValidateSize stay
// within its buffer.
func FuzzFrame(f *testing.F) {
	f.Add(append([]byte{0x60, 0, 0, 0, 0, 4, 17, 64}, make([]byte, 36)...))
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
		frm.SourceAddr()
		frm.DestinationAddr()
		_ = frm.Payload()
	})
}
