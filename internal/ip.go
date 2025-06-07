package internal

import (
	"encoding/binary"
	"errors"
)

var (
	errUnsupportedIP             = errors.New("unsupported IP version")
	errInvalidIPVersionToSetAddr = errors.New("invalid ip version to setDstAddr")
)

func GetIPSourceAddr(buf []byte) (addr []byte, id uint16, err error) {
	version := buf[0] >> 4
	switch version { //
	case 4:
		addr = buf[12:16]
		id = binary.BigEndian.Uint16(buf[4:6])
	case 6:
		addr = buf[8:24]
	default:
		err = errUnsupportedIP
	}
	return addr, id, err
}

func SetIPDestinationAddr(buf []byte, id uint16, addr []byte) (err error) {
	var dstaddr []byte
	version := buf[0] >> 4
	switch version {
	case 4:
		dstaddr = buf[16:20]
		binary.BigEndian.PutUint16(buf[4:6], id)
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
