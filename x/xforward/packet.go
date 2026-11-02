package xforward

import (
	"encoding/binary"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/ipv6"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

// maxExtHeaders bounds the IPv6 extension headers walked before the transport header.
const maxExtHeaders = 4

// Packet is an IPv4 or IPv6 packet checked by [ValidatePacket].
// Handlers only accept Packets so wire data is validated before use.
type Packet struct {
	buf   []byte // IP header to end of IP payload; link padding trimmed.
	toff  uint16 // transport header offset, past IPv6 extension headers.
	proto lneto.IPProto
}

// ValidatePacket checks IP and transport headers in buf and returns a [Packet] view over it.
// Fragments, v4-mapped addresses in IPv6, zero ports and bad checksums are rejected.
// IPv6 Hop-by-Hop, Routing and Destination Options headers are skipped up to a fixed depth.
// Only TCP, UDP and ICMP payloads are accepted; ICMP is not checked past the IP header.
func ValidatePacket(buf []byte, v *lneto.Validator) (Packet, error) {
	if len(buf) == 0 {
		return Packet{}, lneto.ErrTruncatedFrame
	}
	var p Packet
	var toff int
	switch buf[0] >> 4 {
	case 4:
		ifrm, err := ipv4.NewFrame(buf)
		if err != nil {
			return Packet{}, err
		}
		ifrm.ValidateExceptCRC(v)
		if err = v.ErrPop(); err != nil {
			return Packet{}, err
		}
		toff = ifrm.HeaderLength()
		var crc lneto.CRC791
		crc.WriteEven(buf[:toff])
		if crc.Sum16() != 0 {
			return Packet{}, lneto.ErrBadCRC
		} else if flags := ifrm.Flags(); flags.MoreFragments() || flags.FragmentOffset() != 0 {
			return Packet{}, lneto.ErrUnsupported // uspfilter-style callers never inject fragments.
		}
		p.buf = buf[:ifrm.TotalLength()]
		p.proto = ifrm.Protocol()
	case 6:
		i6frm, err := ipv6.NewFrame(buf)
		if err != nil {
			return Packet{}, err
		}
		i6frm.ValidateSize(v)
		if err = v.ErrPop(); err != nil {
			return Packet{}, err
		} else if isV4Mapped(i6frm.SourceAddr()) || isV4Mapped(i6frm.DestinationAddr()) {
			return Packet{}, lneto.ErrInvalidAddr
		}
		p.buf = buf[:sizeIPv6Header+int(i6frm.PayloadLength())]
		p.proto, toff, err = skipExtHeaders(p.buf, i6frm.NextHeader())
		if err != nil {
			return Packet{}, err
		}
	default:
		return Packet{}, lneto.ErrUnsupported
	}
	if toff > len(p.buf) {
		return Packet{}, lneto.ErrTruncatedFrame
	}
	p.toff = uint16(toff)
	if err := p.validateTransport(v); err != nil {
		return Packet{}, err
	}
	return p, nil
}

// skipExtHeaders walks IPv6 extension headers from next and returns the transport protocol and its offset.
func skipExtHeaders(pkt []byte, next lneto.IPProto) (proto lneto.IPProto, off int, err error) {
	off = sizeIPv6Header
	for n := 0; ; n++ {
		switch next {
		case lneto.IPProtoHopByHop, lneto.IPProtoIPv6Route, lneto.IPProtoIPv6Opts:
		case lneto.IPProtoIPv6Frag:
			return 0, 0, lneto.ErrUnsupported
		default:
			return next, off, nil
		}
		if n == maxExtHeaders {
			return 0, 0, lneto.ErrUnsupported
		} else if off+8 > len(pkt) {
			return 0, 0, lneto.ErrTruncatedFrame
		}
		next = lneto.IPProto(pkt[off])
		off += 8 + 8*int(pkt[off+1]) // Hdr Ext Len counts 8-octet units past the first.
	}
}

// validateTransport checks the TCP or UDP header and checksum.
// Bytes past the UDP length field are left in place, as RawData follows the IP header.
func (p *Packet) validateTransport(v *lneto.Validator) error {
	transport := p.buf[p.toff:]
	var crc lneto.CRC791
	switch p.proto {
	case lneto.IPProtoTCP:
		tfrm, err := tcp.NewFrame(transport)
		if err != nil {
			return err
		}
		tfrm.ValidateExceptCRC(v)
		if err = v.ErrPop(); err != nil {
			return err
		}
		writePseudo(&crc, p.buf, p.proto, len(transport))
		if crc.PayloadSum16(transport) != 0 {
			return lneto.ErrBadCRC
		}
	case lneto.IPProtoUDP:
		ufrm, err := udp.NewFrame(transport)
		if err != nil {
			return err
		}
		ufrm.ValidateSize(v)
		if err = v.ErrPop(); err != nil {
			return err
		} else if ufrm.DestinationPort() == 0 {
			return lneto.ErrZeroDestination
		} else if ufrm.SourcePort() == 0 {
			return lneto.ErrZeroSource
		}
		ulen := int(ufrm.Length())
		if ufrm.CRC() == 0 {
			if p.buf[0]>>4 == 6 {
				return lneto.ErrBadCRC // Mandatory over IPv6 (RFC 8200 §8.1).
			}
		} else {
			writePseudo(&crc, p.buf, p.proto, ulen)
			if crc.PayloadSum16(transport[:ulen]) != 0 {
				return lneto.ErrBadCRC
			}
		}
	case lneto.IPProtoICMP, lneto.IPProtoIPv6ICMP:
	default:
		return lneto.ErrUnsupported
	}
	return nil
}

// Proto returns the transport protocol following the IP headers.
func (p Packet) Proto() lneto.IPProto { return p.proto }

// TransportOffset returns the offset in [Packet.RawData] of the transport header.
func (p Packet) TransportOffset() int { return int(p.toff) }

// RawData returns the packet from IP header to end of IP payload.
func (p Packet) RawData() []byte { return p.buf }

// ID returns the packet's flow as the peer addressed it. Ports are zero for ICMP.
func (p Packet) ID() FlowID {
	if len(p.buf) == 0 {
		return FlowID{}
	}
	k := p.key()
	return k.id()
}

// key returns the packet's flow in wire form.
func (p Packet) key() (k flowKey) {
	if p.buf[0]>>4 == 4 {
		k.laddr = mapV4(p.buf[16:20])
		k.raddr = mapV4(p.buf[12:16])
	} else {
		k.laddr = [16]byte(p.buf[24:40])
		k.raddr = [16]byte(p.buf[8:24])
	}
	if p.proto == lneto.IPProtoTCP || p.proto == lneto.IPProtoUDP {
		transport := p.buf[p.toff:]
		k.rport = binary.BigEndian.Uint16(transport[0:2])
		k.lport = binary.BigEndian.Uint16(transport[2:4])
	}
	return k
}

// mapV4 returns the IPv4-mapped IPv6 form of addr4.
func mapV4(addr4 []byte) [16]byte {
	m := [16]byte{10: 0xff, 11: 0xff}
	copy(m[12:], addr4)
	return m
}

func isV4Mapped(addr *[16]byte) bool { return [12]byte(addr[:12]) == v4InV6 }
