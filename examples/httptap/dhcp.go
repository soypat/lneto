//go:build !tinygo && linux

package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/dhcpv4"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/udp"
)

const (
	sizeEthernet = 14
	sizeIPv4     = 20
	sizeUDP      = 8
	sizeARPv4    = 28
	sizeDHCPMin  = dhcpv4.OptionsOffset + 256 // Minimum space for DHCP frame + options.
)

// dhcpInterceptor wraps an ltesto.Interface and intercepts DHCP traffic.
// DHCP packets from the client are handled by an embedded dhcpv4.Server
// and never forwarded to the real interface. DHCP responses are returned
// on subsequent Read calls. All non-DHCP traffic passes through unchanged.
type dhcpInterceptor struct {
	mu    sync.Mutex
	inner ltesto.Interface
	sv    dhcpv4.Server

	// Server network identity.
	svMAC [6]byte
	svIP  [4]byte

	// Pending ARP reply.
	arpReply [sizeEthernet + sizeARPv4]byte
	arpReady bool

	// ARP cache for gateway forwarding: maps IP→MAC from snooped traffic.
	arpCache [8]arpEntry
}

type arpEntry struct {
	mac [6]byte
	ip  [4]byte
}

// newDHCPInterceptor creates a dhcpInterceptor that wraps iface and serves
// DHCP from the given server address and subnet.
func newDHCPInterceptor(iface ltesto.Interface, svIP [4]byte, svMAC [6]byte, subnet netip.Prefix) (*dhcpInterceptor, error) {
	d := &dhcpInterceptor{
		inner: iface,
		svMAC: svMAC,
		svIP:  svIP,
	}
	err := d.sv.Configure(dhcpv4.ServerConfig{
		ServerAddr: svIP,
		Gateway:    svIP,
		DNS:        [4]byte{8, 8, 8, 8},
		Subnet:     subnet,
	})
	return d, err
}

func (d *dhcpInterceptor) Write(b []byte) (int, error) {
	if d.isARPRequestForUs(b) {
		d.mu.Lock()
		d.buildARPReply(b)
		d.mu.Unlock()
		return len(b), nil
	}
	if isDHCPRequest(b) {
		d.mu.Lock()
		defer d.mu.Unlock()
		dhcpOff := dhcpOffset(b)
		if dhcpOff < 0 {
			return d.inner.Write(b) // Malformed, pass through.
		}
		err := d.sv.Demux(b, dhcpOff)
		if err != nil {
			return 0, fmt.Errorf("dhcp server demux: %w", err)
		}
		return len(b), nil // Consumed by DHCP server, don't forward.
	}
	d.rewriteEthernetDst(b)
	return d.inner.Write(b)
}

func (d *dhcpInterceptor) Read(b []byte) (int, error) {
	d.mu.Lock()
	if d.arpReady {
		n := copy(b, d.arpReply[:])
		d.arpReady = false
		d.mu.Unlock()
		return n, nil
	}
	n, err := d.buildDHCPResponse(b)
	d.mu.Unlock()
	if n > 0 {
		return n, nil
	}
	if err != nil {
		return 0, err
	}
	n, err = d.inner.Read(b)
	if n >= sizeEthernet+sizeARPv4 && binary.BigEndian.Uint16(b[12:14]) == uint16(ethernet.TypeARP) {
		d.snoopARP(b[:n])
	}
	return n, err
}

// buildDHCPResponse tries to get a pending DHCP response from the server and
// wraps it in Ethernet + IPv4 + UDP headers. Returns 0 if no response pending.
// Caller must hold d.mu.
func (d *dhcpInterceptor) buildDHCPResponse(buf []byte) (int, error) {
	if len(buf) < sizeEthernet+sizeIPv4+sizeUDP+sizeDHCPMin {
		return 0, nil
	}
	// Build Ethernet+IPv4 headers since DHCP server may use hardware/ip addr.
	efrm, _ := ethernet.NewFrame(buf)
	*efrm.DestinationHardwareAddr() = [6]byte{}
	*efrm.SourceHardwareAddr() = d.svMAC
	efrm.SetEtherType(ethernet.TypeIPv4)

	ifrm, _ := ipv4.NewFrame(buf[sizeEthernet:])
	ifrm.SetVersionAndIHL(4, 5)
	ifrm.SetToS(0)
	ifrm.SetFlags(ipv4.FlagDontFragment)
	ifrm.SetTTL(64)
	ifrm.SetProtocol(lneto.IPProtoUDP)
	*ifrm.SourceAddr() = d.svIP
	*ifrm.DestinationAddr() = [4]byte{}

	// Build UDP header.
	ufrm, _ := udp.NewFrame(buf[sizeEthernet+sizeIPv4:])
	ufrm.SetSourcePort(dhcpv4.DefaultServerPort)
	ufrm.SetDestinationPort(dhcpv4.DefaultClientPort)

	dhcpStart := sizeEthernet + sizeIPv4 + sizeUDP
	// Ask DHCP server to fill in the payload. offsetToIP=sizeEthernet so
	// the server can set IP src/dst via internal.SetIPAddrs.
	dhcpLen, err := d.sv.Encapsulate(buf, sizeEthernet, dhcpStart)
	if err != nil {
		return 0, fmt.Errorf("dhcp server encapsulate: %w", err)
	}
	if dhcpLen == 0 {
		return 0, nil // No pending response.
	}

	totalIPLen := uint16(sizeIPv4 + sizeUDP + dhcpLen)
	udpLen := uint16(sizeUDP + dhcpLen)
	totalFrameLen := sizeEthernet + int(totalIPLen)

	// DHCP responses must be broadcast since the client doesn't have
	// an IP configured yet and the stack would drop unicast packets.
	*efrm.DestinationHardwareAddr() = ethernet.BroadcastAddr()
	*ifrm.DestinationAddr() = [4]byte{255, 255, 255, 255}
	ifrm.SetTotalLength(totalIPLen)
	ufrm.SetLength(udpLen)
	// Source and destination IPs already set by dhcpv4.Server.Encapsulate.
	ifrm.SetCRC(0)
	prelimCRC := ifrm.CalculateHeaderCRC()
	ifrm.SetID(^(^prelimCRC * 37))
	ifrm.SetCRC(0)
	ifrm.SetCRC(ifrm.CalculateHeaderCRC())
	// Compute UDP checksum (required, the lneto stack validates it on Demux).
	ufrm.SetCRC(0)
	var udpCRC lneto.CRC791
	ifrm.CRCWriteUDPPseudo(&udpCRC, udpLen)
	ufrm.SetCRC(lneto.NeverZeroSum(udpCRC.PayloadSum16(ufrm.RawData()[:udpLen])))
	return totalFrameLen, nil
}

// isDHCPRequest checks if a raw Ethernet frame is a DHCP request (client → server).
// Checks: EtherType=IPv4, IP proto=UDP, UDP dst port=67, DHCP magic cookie.
func isDHCPRequest(b []byte) bool {
	if len(b) < sizeEthernet+sizeIPv4+sizeUDP+dhcpv4.OptionsOffset {
		return false
	}
	// EtherType must be IPv4.
	if binary.BigEndian.Uint16(b[12:14]) != uint16(ethernet.TypeIPv4) {
		return false
	}
	// IP header length (IHL) to find UDP header.
	ihl := int(b[sizeEthernet]&0xf) * 4
	if ihl < sizeIPv4 {
		return false
	}
	ipStart := sizeEthernet
	// IP protocol must be UDP.
	if b[ipStart+9] != uint8(lneto.IPProtoUDP) {
		return false
	}
	udpStart := ipStart + ihl
	if len(b) < udpStart+sizeUDP {
		return false
	}
	// UDP destination port must be DHCP server port (67).
	dstPort := binary.BigEndian.Uint16(b[udpStart+2 : udpStart+4])
	if dstPort != dhcpv4.DefaultServerPort {
		return false
	}
	// Verify DHCP magic cookie.
	dhcpStart := udpStart + sizeUDP
	return dhcpv4.PayloadIsDHCPv4(b[dhcpStart:])
}

// dhcpOffset returns the byte offset where the DHCP payload begins
// within a raw Ethernet frame. Returns -1 if the frame is too short.
func dhcpOffset(b []byte) int {
	if len(b) < sizeEthernet+sizeIPv4+sizeUDP {
		return -1
	}
	ihl := int(b[sizeEthernet]&0xf) * 4
	off := sizeEthernet + ihl + sizeUDP
	if off > len(b) {
		return -1
	}
	return off
}

// isARPRequestForUs checks if b is an ARP request targeting d.svIP.
func (d *dhcpInterceptor) isARPRequestForUs(b []byte) bool {
	if len(b) < sizeEthernet+sizeARPv4 {
		return false
	}
	if binary.BigEndian.Uint16(b[12:14]) != uint16(ethernet.TypeARP) {
		return false
	}
	afrm, err := arp.NewFrame(b[sizeEthernet:])
	if err != nil {
		return false
	}
	if afrm.Operation() != arp.OpRequest {
		return false
	}
	_, targetIP := afrm.Target4()
	return *targetIP == d.svIP
}

// buildARPReply constructs an ARP reply in d.arpReply from the given ARP request.
// Caller must hold d.mu.
func (d *dhcpInterceptor) buildARPReply(request []byte) {
	reqARP, _ := arp.NewFrame(request[sizeEthernet:])
	senderHW, senderIP := reqARP.Sender4()

	buf := d.arpReply[:]
	// Ethernet header: reply to requester.
	efrm, _ := ethernet.NewFrame(buf)
	*efrm.DestinationHardwareAddr() = *senderHW
	*efrm.SourceHardwareAddr() = d.svMAC
	efrm.SetEtherType(ethernet.TypeARP)

	// ARP reply.
	afrm, _ := arp.NewFrame(buf[sizeEthernet:])
	afrm.SetHardware(1, 6)                 // Ethernet, 6-byte addresses
	afrm.SetProtocol(ethernet.TypeIPv4, 4) // IPv4, 4-byte addresses
	afrm.SetOperation(arp.OpReply)
	replySndrHW, replySndrIP := afrm.Sender4()
	*replySndrHW = d.svMAC
	*replySndrIP = d.svIP
	replyTgtHW, replyTgtIP := afrm.Target4()
	*replyTgtHW = *senderHW
	*replyTgtIP = *senderIP

	d.arpReady = true
}

// snoopARP records the sender's IP→MAC mapping from an ARP packet.
func (d *dhcpInterceptor) snoopARP(b []byte) {
	afrm, err := arp.NewFrame(b[sizeEthernet:])
	if err != nil {
		return
	}
	senderHW, senderIP := afrm.Sender4()
	if *senderIP == ([4]byte{}) {
		return
	}
	d.mu.Lock()
	d.arpCacheStore(*senderHW, *senderIP)
	d.mu.Unlock()
}

// rewriteEthernetDst rewrites the Ethernet destination MAC for frames
// addressed to the gateway (svMAC). Acts as a basic IP forwarder by
// looking up the destination IP in the ARP cache.
func (d *dhcpInterceptor) rewriteEthernetDst(b []byte) {
	if len(b) < sizeEthernet+sizeIPv4 {
		return
	}
	// Only rewrite frames addressed to the gateway.
	if *(*[6]byte)(b[0:6]) != d.svMAC {
		return
	}
	// Only rewrite IPv4 frames.
	if binary.BigEndian.Uint16(b[12:14]) != uint16(ethernet.TypeIPv4) {
		return
	}
	dstIP := *(*[4]byte)(b[sizeEthernet+16 : sizeEthernet+20])
	d.mu.Lock()
	mac, ok := d.arpCacheLookup(dstIP)
	d.mu.Unlock()
	if ok {
		copy(b[0:6], mac[:])
	}
}

// arpCacheLookup finds a MAC for the given IP. Caller must hold d.mu.
func (d *dhcpInterceptor) arpCacheLookup(ip [4]byte) ([6]byte, bool) {
	for i := range d.arpCache {
		if d.arpCache[i].ip == ip {
			return d.arpCache[i].mac, true
		}
	}
	return [6]byte{}, false
}

// arpCacheStore adds or updates an IP→MAC entry. Caller must hold d.mu.
func (d *dhcpInterceptor) arpCacheStore(mac [6]byte, ip [4]byte) {
	// Update existing entry.
	for i := range d.arpCache {
		if d.arpCache[i].ip == ip {
			d.arpCache[i].mac = mac
			return
		}
	}
	// Find empty slot.
	for i := range d.arpCache {
		if d.arpCache[i].ip == ([4]byte{}) {
			d.arpCache[i] = arpEntry{mac: mac, ip: ip}
			return
		}
	}
	// Evict first entry.
	copy(d.arpCache[:], d.arpCache[1:])
	d.arpCache[len(d.arpCache)-1] = arpEntry{mac: mac, ip: ip}
}

// Delegate remaining ltesto.Interface methods to inner.

func (d *dhcpInterceptor) Close() error                       { return d.inner.Close() }
func (d *dhcpInterceptor) HardwareAddress6() ([6]byte, error) { return d.inner.HardwareAddress6() }
func (d *dhcpInterceptor) MTU() (int, error)                  { return d.inner.MTU() }
func (d *dhcpInterceptor) IPMask() (netip.Prefix, error)      { return d.inner.IPMask() }
