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

// IsMulticastIPAddr reports whether addr is an IPv4 or IPv6 multicast address.
func IsMulticastIPAddr(addr []byte) bool {
	switch len(addr) {
	case 4:
		return addr[0]&0xf0 == 0xe0
	case 16:
		return addr[0] == 0xff
	default:
		return false
	}
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

// ECN codepoints of RFC 3168 §5, carried in the low two bits of the IPv4 Type of
// Service octet and of the IPv6 Traffic Class field.
const (
	// ECNNotECT marks a packet whose endpoints do not use ECN. A router with a full
	// queue drops it rather than marking it.
	ECNNotECT uint8 = 0b00
	// ECNECT1 and ECNECT0 both mark a packet as ECN-capable. A router experiencing
	// congestion may change either to ECNCE instead of dropping the packet.
	ECNECT1 uint8 = 0b01
	ECNECT0 uint8 = 0b10
	// ECNCE is Congestion Experienced: a router on the path has signalled
	// congestion by marking this packet instead of discarding it.
	ECNCE uint8 = 0b11
)

// GetIPECN returns the ECN codepoint of an IPv4 or IPv6 header.
func GetIPECN(buf []byte) (ecn uint8, err error) {
	switch buf[0] >> 4 {
	case 4:
		return buf[1] & 0b11, nil
	case 6:
		// The Traffic Class field straddles two octets: its top four bits are the
		// low nibble of octet 0 and its bottom four are the top nibble of octet 1,
		// so the ECN bits are bits 5 and 4 of octet 1.
		return (buf[1] >> 4) & 0b11, nil
	}
	return 0, lneto.ErrUnsupported
}

// SetIPECN sets the ECN codepoint of an IPv4 or IPv6 header, leaving the
// differentiated services bits alone.
//
// The IPv4 header checksum is not recalculated: it is computed after this by the
// stack that owns the frame. Setting it here would be undone.
func SetIPECN(buf []byte, ecn uint8) error {
	if ecn > 0b11 {
		return lneto.ErrInvalidField
	}
	switch buf[0] >> 4 {
	case 4:
		buf[1] = buf[1]&^0b11 | ecn
		return nil
	case 6:
		buf[1] = buf[1]&^(0b11<<4) | ecn<<4
		return nil
	}
	return lneto.ErrUnsupported
}
