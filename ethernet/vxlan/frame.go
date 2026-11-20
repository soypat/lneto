package vxlan

import (
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
)

const (
	sizeVNIHeader = 8
)

type Frame struct {
	buf []byte
}

func NewFrame(buf []byte) (Frame, error) {
	if len(buf) < sizeVNIHeader {
		return Frame{}, lneto.ErrTruncatedFrame
	}
	return Frame{
		buf: buf,
	}, nil
}

func (v Frame) Flags() Flags {
	return Flags(v.buf[0])
}

func (v Frame) SetFlags(f Flags) {
	v.buf[0] = byte(f)
}

func (v Frame) VNI() uint32 {
	return uint32(v.buf[4])<<16 | uint32(v.buf[5])<<8 | uint32(v.buf[6])
}

func (v Frame) SetVNI(vni uint32) error {
	if vni > 0xFFFFFF {
		return lneto.ErrUnsupported
	}
	v.buf[4] = byte(vni >> 16)
	v.buf[5] = byte(vni >> 8)
	v.buf[6] = byte(vni)
	return nil
}

func (v Frame) EthernetFrame() (ethernet.Frame, error) {
	return ethernet.NewFrame(v.buf[sizeVNIHeader:])
}
