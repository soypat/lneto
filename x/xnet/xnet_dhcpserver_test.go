package xnet

import (
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dhcp/dhcpv4"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/udp"
)

// Reproduces the AP-mode DHCP server failure observed on hardware (espradio.log):
// clients broadcast DISCOVER to 255.255.255.255 every few seconds and the AP never
// answers. Only the stack-level behaviour is tested here; the DORA state machine and
// address allocation are covered by the dhcpv4 package tests. What those cannot see
// is a packet that never reaches dhcpv4.Server at all, plus the layer interactions
// on the way out (Ethernet writes gwmac and IPv4 writes the source address and both
// checksums around the server's own writes to those same fields).

const (
	apEthSize  = 14
	apIPv4Size = 20
	apUDPSize  = 8
	apSubnetBi = 24
)

var (
	apAddr    = [4]byte{192, 168, 4, 1}
	apMAC     = [6]byte{0x02, 0x00, 0xde, 0xad, 0xbe, 0xef}
	apGWMAC   = [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01} // Dummy AP-mode gateway MAC, as espradio sets.
	dhcpClMAC = [6]byte{0xe4, 0xc7, 0x67, 0x65, 0x0e, 0x46} // MAC from espradio.log.
	macBcast  = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	apBufSize = int(ethernet.MaxMTU) + ethernet.MaxOverheadSize
)

// newAPStack returns a StackAsync configured as an access point with a dhcpv4.Server
// registered on the DHCP server port.
func newAPStack(t testing.TB, acceptBroadcast bool) *StackAsync {
	t.Helper()
	s := new(StackAsync)
	err := s.Reset(StackConfig{
		Hostname:            "apstack",
		RandSeed:            42,
		StaticAddress4:      apAddr,
		HardwareAddress:     apMAC,
		MTU:                 ethernet.MaxMTU,
		MaxActiveUDPPorts:   2,
		AcceptIPv4Broadcast: acceptBroadcast,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.SetSubnet4(apAddr, apSubnetBi)
	// No upstream gateway in AP mode; a non-broadcast dummy still gets written into
	// the egress Ethernet destination, so the server must overwrite it with chaddr.
	s.SetGatewayHardwareAddr(apGWMAC)
	sv := new(dhcpv4.Server)
	err = sv.Configure(dhcpv4.ServerConfig{
		ServerAddr: apAddr,
		Gateway:    apAddr,
		Subnet:     ipv4.PrefixFrom(apAddr, apSubnetBi),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Zero remote address disables the source-IP filter: DHCP clients send from 0.0.0.0.
	err = s.RegisterUDP4(sv, [4]byte{}, dhcpv4.DefaultClientPort)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// broadcastDiscover builds the DISCOVER of a client with no address: Ethernet and IPv4
// destinations both broadcast, source 0.0.0.0, with valid checksums.
func broadcastDiscover(t testing.TB, xid uint32) []byte {
	t.Helper()
	var cl dhcpv4.Client
	err := cl.BeginRequest(xid, dhcpv4.RequestConfig{ClientHardwareAddr: dhcpClMAC})
	if err != nil {
		t.Fatal(err)
	}
	pkt := make([]byte, apBufSize)
	efrm, err := ethernet.NewFrame(pkt)
	if err != nil {
		t.Fatal(err)
	}
	*efrm.DestinationHardwareAddr() = macBcast
	*efrm.SourceHardwareAddr() = dhcpClMAC
	efrm.SetEtherType(ethernet.TypeIPv4)

	ifrm, err := ipv4.NewFrame(pkt[apEthSize:])
	if err != nil {
		t.Fatal(err)
	}
	ifrm.SetVersionAndIHL(4, 5)
	ifrm.SetToS(0)
	ifrm.SetFlags(0x4000)
	ifrm.SetTTL(64)
	ifrm.SetProtocol(lneto.IPProtoUDP)

	ufrm, err := udp.NewFrame(pkt[apEthSize+apIPv4Size:])
	if err != nil {
		t.Fatal(err)
	}
	ufrm.SetSourcePort(dhcpv4.DefaultClientPort)
	ufrm.SetDestinationPort(dhcpv4.DefaultServerPort)

	// Client sets its own IP addresses (0.0.0.0 -> 255.255.255.255).
	dhcpLen, err := cl.Encapsulate(pkt, apEthSize, apEthSize+apIPv4Size+apUDPSize)
	if err != nil {
		t.Fatal(err)
	}
	if dhcpLen == 0 {
		t.Fatal("client produced no DISCOVER")
	}
	udpLen := apUDPSize + dhcpLen
	ifrm.SetTotalLength(uint16(apIPv4Size + udpLen))
	ufrm.SetLength(uint16(udpLen))
	ifrm.SetCRC(0)
	ifrm.SetCRC(ifrm.CalculateHeaderCRC())
	var crc lneto.CRC791
	ifrm.CRCWriteUDPPseudo(&crc, uint16(udpLen))
	ufrm.SetCRC(0)
	ufrm.SetCRC(lneto.NeverZeroSum(crc.PayloadSum16(ifrm.Payload())))
	return pkt[:apEthSize+apIPv4Size+udpLen]
}

// TestDHCPServerAPBroadcastOffer feeds a broadcast DISCOVER through the whole
// Ethernet/IPv4/UDP demux chain and checks the reply that comes back out of
// EgressEthernet is a well formed OFFER: unicast to the client's hardware address
// (over the gateway MAC the Ethernet layer wrote), from the server address to the
// offered address, ports swapped, and both checksums valid despite the server
// writing addresses inside the IPv4 layer's encapsulation.
func TestDHCPServerAPBroadcastOffer(t *testing.T) {
	ap := newAPStack(t, true)
	err := ap.IngressEthernet(broadcastDiscover(t, 0xeee8f531))
	if err != nil {
		t.Fatalf("ingress discover: %v", err)
	}
	buf := make([]byte, apBufSize)
	n, err := ap.EgressEthernet(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("AP produced no OFFER for broadcast DISCOVER")
	}

	efrm, err := ethernet.NewFrame(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if got := *efrm.DestinationHardwareAddr(); got != dhcpClMAC {
		t.Errorf("OFFER ethernet dst=%v want client MAC %v", got, dhcpClMAC)
	}
	ifrm, err := ipv4.NewFrame(efrm.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if ifrm.CalculateHeaderCRC() != 0 {
		t.Error("OFFER has invalid IPv4 header checksum")
	}
	if got := *ifrm.SourceAddr(); got != apAddr {
		t.Errorf("OFFER src=%v want server address %v", got, apAddr)
	}
	ufrm, err := udp.NewFrame(ifrm.Payload())
	if err != nil {
		t.Fatal(err)
	}
	var crc lneto.CRC791
	ifrm.CRCWriteUDPPseudo(&crc, ufrm.Length())
	if crc.PayloadSum16(ufrm.RawData()[:ufrm.Length()]) != 0 {
		t.Error("OFFER has invalid UDP checksum")
	}
	if got := ufrm.DestinationPort(); got != dhcpv4.DefaultClientPort {
		t.Errorf("OFFER udp dst port=%d want %d", got, dhcpv4.DefaultClientPort)
	}
	if got := ufrm.SourcePort(); got != dhcpv4.DefaultServerPort {
		t.Errorf("OFFER udp src port=%d want %d", got, dhcpv4.DefaultServerPort)
	}
	dfrm, err := dhcpv4.NewFrame(ufrm.Payload())
	if err != nil {
		t.Fatal(err)
	}
	// The client has no address yet, so the OFFER must be addressed to the address
	// it is being offered.
	if got, want := *ifrm.DestinationAddr(), *dfrm.YIAddr(); got != want {
		t.Errorf("OFFER dst=%v want offered address %v", got, want)
	}
	var msgType dhcpv4.MessageType
	err = dfrm.ForEachOption(func(off int, op dhcpv4.OptNum, data []byte) error {
		if op == dhcpv4.OptMessageType && len(data) == 1 {
			msgType = dhcpv4.MessageType(data[0])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if msgType != dhcpv4.MsgOffer {
		t.Errorf("want OFFER, got %s", msgType.String())
	}
}

// TestDHCPServerAPRequiresBroadcastAccept pins the espradio.log failure: a stack that
// does not opt into StackConfig.AcceptIPv4Broadcast drops DISCOVERs at the IPv4 layer,
// so dhcpv4.Server never sees them and never answers.
func TestDHCPServerAPRequiresBroadcastAccept(t *testing.T) {
	ap := newAPStack(t, false)
	err := ap.IngressEthernet(broadcastDiscover(t, 0x65be2ff3))
	if err != lneto.ErrPacketDrop {
		t.Fatalf("want ErrPacketDrop for broadcast DISCOVER without AcceptIPv4Broadcast, got %v", err)
	}
	buf := make([]byte, apBufSize)
	n, err := ap.EgressEthernet(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("AP answered a DISCOVER it should have dropped (%d bytes)", n)
	}
}
