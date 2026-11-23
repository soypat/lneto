package vxlan

import (
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
)

const (
	sizeVNIHeader = 8
)

// Frame encapsulates the raw data of a VXLAN frame
// and provides methods for manipulating, validating and
// retreiving fields and ethernet data. See [RFC7348].
//
// [RFC7348]: https://tools.ietf.org/html/rfc7348
type Frame struct {
	buf []byte
}

// NewFrame returns a VXLAN [Frame] with data set to buf.
// An error is returned if the buffer size is smaller than the VXLAN header size (8 bytes).
func NewFrame(buf []byte) (Frame, error) {
	if len(buf) < sizeVNIHeader {
		return Frame{}, lneto.ErrTruncatedFrame
	}
	return Frame{
		buf: buf,
	}, nil
}

// Flags returns the [Flags] of the VXLAN frame.
func (v Frame) Flags() Flags {
	return Flags(v.buf[0])
}

// SetFlags sets the VXLAN flags field. See [Flags].
func (v Frame) SetFlags(f Flags) {
	v.buf[0] = byte(f)
}

// VNI returns the VXLAN Network Identifier of the [Frame].
func (v Frame) VNI() uint32 {
	return uint32(v.buf[4])<<16 | uint32(v.buf[5])<<8 | uint32(v.buf[6])
}

// SetVNI sets the VXLAN Network Identifier of the [Frame].
// It returns an error if the VNI is larger than the max allowed value (0xFFFFFF).
func (v Frame) SetVNI(vni uint32) error {
	if vni > 0xFFFFFF {
		return lneto.ErrUnsupported
	}
	v.buf[4] = byte(vni >> 16)
	v.buf[5] = byte(vni >> 8)
	v.buf[6] = byte(vni)
	return nil
}

// EthernetFrame returns the encapsulated [ethernet.Frame] within the VXLAN [Frame].
// Creating the underlying Ethernet frame may return an error which is propagated here from [ethernet.NewFrame].
func (v Frame) EthernetFrame() (ethernet.Frame, error) {
	return ethernet.NewFrame(v.buf[sizeVNIHeader:])
}
