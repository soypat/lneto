package udp

import (
	"testing"

	"github.com/soypat/lneto"
)

// FuzzFrame checks that the accessors of a frame passing ValidateSize stay
// within its buffer.
func FuzzFrame(f *testing.F) {
	f.Add([]byte{0, 53, 0, 53, 0, 12, 0, 0, 1, 2, 3, 4})
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
		_ = frm.Payload()
	})
}
