package xnet

import (
	"encoding/binary"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/ipv4"
)

// subnetTable manages both passively learned peer MAC/IP tuples and in-flight async ARP resolves.
//
// Layout of resolves slice:
//
//	[0 : passivePeers]       — owned MAC+IP, permanently retained (learned passively from ingress)
//	[passivePeers : len]     — externally-owned MAC, evicted by age (pending ARP queries)
type subnetTable struct {
	subnet4   ipv4.Prefix
	resolves4 []struct {
		mac []byte // externally owned for pending entries; owned for passive entries.
		ip  [4]byte
		age uint16
	}
	passivePeers uint8
}

func (a *subnetTable) reset(arpentries int, passivePeers uint8) {
	a.passivePeers = passivePeers
	if a.resolves4 == nil {
		internal.SliceReuse(&a.resolves4, arpentries+int(passivePeers))
		a.resolves4 = a.resolves4[:cap(a.resolves4)]
	}
}

func (a *subnetTable) learnFromIngressEthernet(ethernetFrame []byte) {
	if len(ethernetFrame) > 14+20 &&
		binary.BigEndian.Uint16(ethernetFrame[12:14]) == uint16(ethernet.TypeIPv4) {
		src, _, _, _, _ := internal.GetIPAddr(ethernetFrame[14:])
		a.learnPassive(src, ethernetFrame[6:12])
	}
}

// learnPassive stores or updates a passively observed MAC/IP tuple in the reserved slots.
// It is a no-op if passivePeers is zero, src is not in the local subnet, or all slots are taken.
func (a *subnetTable) learnPassive(src, mac []byte) {
	if a.passivePeers == 0 || len(src) != 4 {
		return
	}
	addr := [4]byte(src)
	if !a.subnet4.Contains(addr) {
		return
	}
	for i := range a.passivePeers {
		v := &a.resolves4[i]
		if v.ip == addr {
			copy(v.mac, mac) // update in case MAC changed (e.g. NIC swap)
			return
		}
		if v.ip == ([4]byte{}) {
			v.ip = addr
			v.mac = append(v.mac, mac...)
			return
		}
	}
}

// startQuery copies the MAC into mac immediately if the IP was passively learned,
// otherwise issues an ARP query via h and registers mac as the externally-owned destination.
func (a *subnetTable) startQuery(mac, ip []byte, h *arp.Handler) error {
	if len(ip) != 4 {
		return lneto.ErrUnsupported
	}
	addr := [4]byte(ip)
	for i := range a.passivePeers {
		v := &a.resolves4[i]
		if v.ip == addr {
			copy(mac, v.mac)
			return nil
		}
	}
	if err := h.StartQuery(ip, true); err != nil {
		return err
	}
	n := int(a.passivePeers)
	oldest := n
	for i := n; i < len(a.resolves4); i++ {
		v := &a.resolves4[i]
		if len(v.mac) == 0 {
			oldest = i
			break
		} else if v.age > a.resolves4[oldest].age {
			oldest = i
		}
	}
	for i := n; i < len(a.resolves4); i++ {
		a.resolves4[i].age++
	}
	v := &a.resolves4[oldest]
	v.mac = mac
	v.ip = addr
	v.age = 1
	return nil
}

// onResolve is the arp.Handler resolve callback; called when an ARP response arrives.
func (a *subnetTable) onResolve(mac, ip []byte) {
	if len(ip) != 4 {
		return
	}
	addr := [4]byte(ip)
	for i := int(a.passivePeers); i < len(a.resolves4); i++ {
		v := &a.resolves4[i]
		if v.ip == addr {
			copy(v.mac, mac)
			v.mac = nil
			v.ip = [4]byte{}
			v.age = 0
			return
		}
	}
}

// patchEgressMAC is registered as the OnEncapsulate callback on StackEthernet.
// It runs after the payload is written but before CRC is appended, so the CRC
// covers the corrected destination MAC.
func (a *subnetTable) patchEgressMAC(frame []byte) {
	if a.passivePeers == 0 || len(frame) < 14+20 ||
		binary.BigEndian.Uint16(frame[12:14]) != uint16(ethernet.TypeIPv4) {
		return
	}
	efrm, _ := ethernet.NewFrame(frame)
	if efrm.IsBroadcast() {
		return // broadcast stays broadcast (e.g. DHCP discover).
	}
	// Server-side connections have no registered MAC; fill from passively learned entries.
	_, dstIP, _, _, err := internal.GetIPAddr(frame[14:])
	if err != nil {
		return
	}
	for i := range a.passivePeers {
		v := &a.resolves4[i]
		if internal.BytesEqual(v.ip[:], dstIP) {
			*efrm.DestinationHardwareAddr() = [6]byte(v.mac)
			return
		}
	}
}
