package vxlan

import (
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
)

const (
	sizeVNIHeader      = 8
	sizeEthernetHeader = 14
)

type VXLAN struct {
	buf           []byte
	EthernetFrame ethernet.Frame
}

func NewVXLAN(buf []byte) (VXLAN, error) {
	if len(buf) < sizeVNIHeader+sizeEthernetHeader {
		return VXLAN{}, lneto.ErrTruncatedFrame
	}
	ethFrame, err := ethernet.NewFrame(buf[sizeVNIHeader:])
	if err != nil {
		return VXLAN{}, err
	}
	return VXLAN{
		buf:           buf,
		EthernetFrame: ethFrame,
	}, nil
}

func (v VXLAN) VNI() uint32 {
	return uint32(v.buf[4])<<16 | uint32(v.buf[5])<<8 | uint32(v.buf[6])
}

func (v VXLAN) SetVNI(vni uint32) error {
	if vni > 0xFFFFFF {
		return lneto.ErrUnsupported
	}
	v.buf[4] = byte(vni >> 16)
	v.buf[5] = byte(vni >> 8)
	v.buf[6] = byte(vni)
	return nil
}

func (v VXLAN) IFlag() bool {
	return v.buf[0]&0b00001000 != 0
}

func (v VXLAN) SetIFlag(valid bool) {
	if valid {
		v.buf[0] |= 0b00001000
	} else {
		v.buf[0] &= 0b11110111
	}
}
