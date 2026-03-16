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

// SetMulticast sets the IP destination to multicastAddr and derives the
// Ethernet destination MAC from it. It supports IPv4 (RFC 1112 §6.4) and
// IPv6 (RFC 2464 §7) multicast MAC mapping.
func SetMulticast(ethernetCarrier []byte, ipOff int, multicastAddr []byte) (err error) {
	ip := ethernetCarrier[ipOff:]
	mac := ethernetCarrier[0:6]
	version := ip[0] >> 4
	switch version {
	case 4:
		if len(multicastAddr) != 4 {
			return lneto.ErrMismatchLen
		}
		copy(ip[16:20], multicastAddr)
		// IPv4 multicast MAC: 01:00:5e + low 23 bits of IP destination.
		mac[0] = 0x01
		mac[1] = 0x00
		mac[2] = 0x5e
		mac[3] = multicastAddr[1] & 0x7f
		mac[4] = multicastAddr[2]
		mac[5] = multicastAddr[3]
	case 6:
		if len(multicastAddr) != 16 {
			return lneto.ErrMismatchLen
		}
		copy(ip[24:40], multicastAddr)
		// IPv6 multicast MAC: 33:33 + last 4 bytes of IP destination.
		mac[0] = 0x33
		mac[1] = 0x33
		mac[2] = multicastAddr[12]
		mac[3] = multicastAddr[13]
		mac[4] = multicastAddr[14]
		mac[5] = multicastAddr[15]
	default:
		return lneto.ErrUnsupported
	}
	return nil
}
