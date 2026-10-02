package ethernet

import (
	"testing"

	"github.com/soypat/lneto"
)

// FuzzFrame checks that the accessors of a frame passing ValidateSize stay
// within its buffer.
func FuzzFrame(f *testing.F) {
	f.Add(make([]byte, sizeHeaderNoVLAN))
	f.Add(append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 1, 0x81, 0x00, 0, 1, 0x08, 0x00}, make([]byte, 46)...))
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
		frm.DestinationHardwareAddr()
		frm.SourceHardwareAddr()
		if frm.IsVLAN() {
			frm.VLAN()
		}
		_ = frm.Payload()
	})
}
