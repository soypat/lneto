/*
Package xforward terminates TCP and relays UDP for IP packets addressed to
any destination, answering as that destination. It owns IP framing: replies
are sourced from the address the peer originally targeted.

The *Handler types are synchronous and unsynchronized: no goroutines, locks,
deadlines or blocking. Work happens only when the caller calls in, so a
microcontroller can drive everything from one loop:

	for {
		n := dev.Recv(buf)
		pkt, err := xforward.ValidatePacket(buf[:n], &vld)
		if err == nil && pkt.Proto() == lneto.IPProtoTCP {
			flow, isNew, _ := th.Demux(pkt)
			if isNew {
				th.Accept(flow, rxbuf, txbuf) // Or dial upstream first, then Accept/Reject.
			}
		}
		for {
			n, _ = th.Encapsulate(out[:mtu], 0)
			if n == 0 {
				break
			}
			dev.Send(out[:n])
		}
	}

[TCPForwarder] wraps [TCPHandler] for concurrent use, handing out blocking
[FlowConn]s. A desktop pump goroutine then looks like:

	for {
		n, _ := tf.Encapsulate(out[:mtu], 0)
		if n > 0 {
			dev.Send(out[:n])
			continue
		}
		select { // Wake does a non-blocking send on wake.
		case <-wake:
		case <-timerUntil(tf.NextDeadline()):
		case <-ctx.Done():
			return
		}
	}
*/
package xforward

import (
	"net/netip"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/ipv6"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

const (
	// maxFlows bounds flow slots so slot+1 fits a uint16 index entry at load factor 1/2.
	maxFlows       = 1 << 15
	sizeIPv4Header = 20
	sizeIPv6Header = 40
	sizeUDPHeader  = 8
	sizeTCPHeader  = 20
	ttl            = 64
)

// v4InV6 is the prefix of IPv4-mapped IPv6 addresses (RFC 4291 §2.5.5.2).
var v4InV6 = [12]byte{10: 0xff, 11: 0xff}

// FlowID identifies a flow as the peer addressed it.
type FlowID struct {
	Local  netip.AddrPort // original destination; replies are sourced from it.
	Remote netip.AddrPort // peer that sent the packet.
}

// flowKey is FlowID in wire form. IPv4 is stored v4-mapped, see [flowKey.is4].
// lport==0 marks a free slot: [ValidatePacket] rejects port 0.
type flowKey struct {
	laddr, raddr [16]byte
	lport, rport uint16
}

// is4 reports whether k is an IPv4 flow. IPv4 flows store both addresses v4-mapped;
// [ValidatePacket] rejects v4-mapped addresses in IPv6 packets so the two never mix.
func (k *flowKey) is4() bool {
	return [12]byte(k.raddr[:12]) == v4InV6
}

// addrs returns the local and remote addresses in wire length.
func (k *flowKey) addrs() (laddr, raddr []byte) {
	if k.is4() {
		return k.laddr[12:], k.raddr[12:]
	}
	return k.laddr[:], k.raddr[:]
}

// id converts k to its unmapped [FlowID].
func (k *flowKey) id() FlowID {
	return FlowID{
		Local:  netip.AddrPortFrom(netip.AddrFrom16(k.laddr).Unmap(), k.lport),
		Remote: netip.AddrPortFrom(netip.AddrFrom16(k.raddr).Unmap(), k.rport),
	}
}

// nextGen returns the slot generation after g, skipping 0 so zero-value handles never match.
func nextGen(g uint16) uint16 {
	g++
	if g == 0 {
		g = 1
	}
	return g
}

// putIPHeader writes an IPv4 or IPv6 header sourced from k.laddr to k.raddr into dst
// and returns its length. Lengths and checksums are left to [finishIP].
func putIPHeader(dst []byte, k *flowKey, proto lneto.IPProto, id uint16) (hdrLen int) {
	if k.is4() {
		ifrm, _ := ipv4.NewFrame(dst)
		ifrm.ClearHeader()
		ifrm.SetVersionAndIHL(4, 5)
		ifrm.SetID(id)
		ifrm.SetFlags(ipv4.FlagDontFragment)
		ifrm.SetTTL(ttl)
		ifrm.SetProtocol(proto)
		copy(ifrm.SourceAddr()[:], k.laddr[12:])
		copy(ifrm.DestinationAddr()[:], k.raddr[12:])
		return sizeIPv4Header
	}
	i6frm, _ := ipv6.NewFrame(dst)
	i6frm.SetVersionTrafficAndFlow(6, 0, 0)
	i6frm.SetNextHeader(proto)
	i6frm.SetHopLimit(ttl)
	*i6frm.SourceAddr() = k.laddr
	*i6frm.DestinationAddr() = k.raddr
	return sizeIPv6Header
}

// finishIP sets IP and transport lengths and checksums once a transport frame
// of transportLen bytes follows the hdrLen byte IP header in pkt.
func finishIP(pkt []byte, hdrLen, transportLen int, proto lneto.IPProto) {
	if pkt[0]>>4 == 4 {
		ifrm, _ := ipv4.NewFrame(pkt)
		ifrm.SetTotalLength(uint16(hdrLen + transportLen))
		ifrm.SetCRC(0)
		ifrm.SetCRC(ifrm.CalculateHeaderCRC())
	} else {
		i6frm, _ := ipv6.NewFrame(pkt)
		i6frm.SetPayloadLength(uint16(transportLen))
	}
	transport := pkt[hdrLen : hdrLen+transportLen]
	var crc lneto.CRC791
	writePseudo(&crc, pkt, proto, transportLen)
	if proto == lneto.IPProtoUDP {
		ufrm, _ := udp.NewFrame(transport)
		ufrm.SetCRC(0)
		ufrm.SetCRC(lneto.NeverZeroSum(crc.PayloadSum16(transport)))
	} else {
		tfrm, _ := tcp.NewFrame(transport)
		tfrm.SetCRC(0)
		tfrm.SetCRC(crc.PayloadSum16(transport))
	}
}

// writePseudo writes the pseudo-header of a transport frame of transportLen bytes into crc.
// Unlike [ipv6.Frame.CRCWritePseudo] it holds with extension headers present (RFC 8200 §8.1).
func writePseudo(crc *lneto.CRC791, ipPkt []byte, proto lneto.IPProto, transportLen int) {
	if ipPkt[0]>>4 == 4 {
		crc.WriteEven(ipPkt[12:20])
	} else {
		crc.WriteEven(ipPkt[8:40])
	}
	crc.AddUint32(uint32(transportLen))
	crc.AddUint16(uint16(proto))
}
