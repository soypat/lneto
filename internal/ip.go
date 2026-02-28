package internal

import (
	"encoding/binary"

	"github.com/soypat/lneto"
)

func GetIPAddr(buf []byte) (src, dst []byte, id, ipEndOff uint16, err error) {
	b0 := buf[0]
	version := b0 >> 4
	switch version {
	case 4:
		ihl := b0 & 0xf
		ipEndOff = 4 * uint16(ihl)
		id = binary.BigEndian.Uint16(buf[4:6])
		src = buf[12:16]
		dst = buf[16:20]
	case 6:
		src = buf[8:24]
		dst = buf[24:40]
		ipEndOff = 40
	default:
		err = lneto.ErrUnsupported
	}
	return src, dst, id, ipEndOff, err
}

func SetIPAddrs(buf []byte, id uint16, src, dst []byte) (err error) {
	var dstaddr, srcaddr []byte
	version := buf[0] >> 4
	switch version {
	case 4:
		srcaddr = buf[12:16]
		dstaddr = buf[16:20]
		if id > 0 {
			binary.BigEndian.PutUint16(buf[4:6], id)
		}
	case 6:
		srcaddr = buf[8:24]
		dstaddr = buf[24:40]
	default:
		return lneto.ErrUnsupported
	}
	if src != nil && len(srcaddr) != len(src) {
		return lneto.ErrMismatchLen
	}
	if dst != nil && len(dstaddr) != len(dst) {
		return lneto.ErrMismatchLen
	}
	copy(srcaddr, src)
	copy(dstaddr, dst)
	return nil
}
