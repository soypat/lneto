package xforward

import (
	"github.com/soypat/lneto"
)

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
func ValidatePacket(buf []byte, v *lneto.Validator) (Packet, error) {
	return Packet{}, lneto.ErrUnsupported
}

// Proto returns the transport protocol following the IP headers.
func (p Packet) Proto() lneto.IPProto { return p.proto }

// TransportOffset returns the offset in [Packet.RawData] of the transport header.
func (p Packet) TransportOffset() int { return int(p.toff) }

// RawData returns the packet from IP header to end of IP payload.
func (p Packet) RawData() []byte { return p.buf }

// ID returns the packet's flow as the peer addressed it. Ports are zero for ICMP.
func (p Packet) ID() FlowID {
	return FlowID{}
}

// key returns the packet's flow in wire form.
func (p Packet) key() flowKey {
	panic("unimplemented")
}
