package ipv4

import (
	"testing"

	"github.com/soypat/lneto"
)

// FuzzFrame checks that the accessors of a frame passing ValidateSize stay
// within its buffer.
func FuzzFrame(f *testing.F) {
	f.Add([]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2})
	f.Add(append([]byte{0x46, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 1, 1, 1, 0}, 0, 0, 0, 0))
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
		frm.CalculateHeaderCRC()
		_ = frm.Options()
		_ = frm.Payload()
		_ = frm.String()
	})
}
