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
)

const (
	// maxFlows bounds flow slots so slot+1 fits a uint16 index entry at load factor 1/2.
	maxFlows       = 1 << 15
	sizeIPv4Header = 20
	sizeIPv6Header = 40
	sizeUDPHeader  = 8
)

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

// is4 reports whether both addresses are v4-mapped.
func (k *flowKey) is4() bool {
	panic("unimplemented")
}

// id converts k to its unmapped [FlowID].
func (k *flowKey) id() FlowID {
	panic("unimplemented")
}

// putIPHeader writes an IPv4 or IPv6 header sourced from k.laddr to k.raddr into dst
// and returns its length. Lengths and checksums are left to [finishIP].
func putIPHeader(dst []byte, k *flowKey, proto lneto.IPProto, id uint16) (hdrLen int) {
	panic("unimplemented")
}

// finishIP sets IP and transport lengths and checksums once a transport frame
// of transportLen bytes follows the hdrLen byte IP header in pkt.
func finishIP(pkt []byte, hdrLen, transportLen int, proto lneto.IPProto) {
	panic("unimplemented")
}
