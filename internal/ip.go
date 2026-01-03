package internal

import (
	"encoding/binary"
	"errors"
)

var (
	errUnsupportedIP             = errors.New("unsupported IP version")
	errInvalidIPVersionToSetAddr = errors.New("invalid ip version to setDstAddr")
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
		err = errUnsupportedIP
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
		return errUnsupportedIP
	}
	if src != nil && len(srcaddr) != len(src) {
		return errors.New("mismatched length of ip src addr")
	}
	if dst != nil && len(dstaddr) != len(dst) {
		return errors.New("mismatched length of ip dst addr")
	}
	copy(srcaddr, src)
	copy(dstaddr, dst)
	return nil
}

// IsZeroed returns true if all arguments are set to their zero value.
func IsZeroed[T comparable](a ...T) bool {
	var z T
	for i := range a {
		if a[i] != z {
			return false
		}
	}
	return true
}

// DeleteZeroed deletes zero values in-place contained within the
// slice and returns the modified slice without zero values.
// Does not modify capacity.
func DeleteZeroed[T comparable](a []T) []T {
	var z T
	off := 0
	deleted := false
	for i := 0; i < len(a); i++ {
		if a[i] != z {
			if deleted {
				a[off] = a[i]
			}
			off++
		} else if !deleted {
			deleted = true
		}
	}
	return a[:off]
}
