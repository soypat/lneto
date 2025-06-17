package internal

import (
	"encoding/binary"
	"errors"
)

var (
	errUnsupportedIP             = errors.New("unsupported IP version")
	errInvalidIPVersionToSetAddr = errors.New("invalid ip version to setDstAddr")
)

func GetIPSourceAddr(buf []byte) (addr []byte, id, ipEndOff uint16, err error) {
	b0 := buf[0]
	version := b0 >> 4
	switch version {
	case 4:
		ihl := b0 & 0xf
		ipEndOff = 4 * uint16(ihl)
		id = binary.BigEndian.Uint16(buf[4:6])
		addr = buf[12:16]
	case 6:
		addr = buf[8:24]
		ipEndOff = 40
	default:
		err = errUnsupportedIP
	}
	return addr, id, ipEndOff, err
}

func SetIPDestinationAddr(buf []byte, id uint16, addr []byte) (err error) {
	var dstaddr []byte
	version := buf[0] >> 4
	switch version {
	case 4:
		dstaddr = buf[16:20]
		if id > 0 {
			binary.BigEndian.PutUint16(buf[4:6], id)
		}
	case 6:
		dstaddr = buf[24:40]
	default:
		err = errUnsupportedIP
	}
	if err == nil && len(dstaddr) != len(addr) {
		return errInvalidIPVersionToSetAddr
	}
	copy(dstaddr, addr)
	return nil
}
