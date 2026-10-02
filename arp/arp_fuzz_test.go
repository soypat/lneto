package arp

import (
	"testing"

	"github.com/soypat/lneto"
)

// FuzzFrame checks that the accessors of a frame passing ValidateSize stay
// within its buffer.
func FuzzFrame(f *testing.F) {
	f.Add(append([]byte{0, 1, 0x08, 0x00, 6, 4, 0, 1}, make([]byte, sizeHeaderv4-sizeHeader)...))
	f.Add(append([]byte{0, 1, 0x86, 0xdd, 6, 16, 0, 2}, make([]byte, sizeHeaderv6-sizeHeader)...))
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
		frm.Sender()
		frm.Target()
		_ = frm.Clip()
		_ = frm.String()
	})
}
