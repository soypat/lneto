package xnet

import (
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/dhcp/dhcpv4"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internet"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/ipv4/icmpv4"
	"github.com/soypat/lneto/ntp"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

const (
	minTCPBuffer = 256
	icmpEchoSize = 64
)

type StackAsync struct {
	mu       sync.Mutex
	hostname string
	clientID string
	link     internet.StackEthernet
	ip4      internet.StackIPv4

	arp      arp.Handler
	icmp     icmpv4.Client
	icmp6buf []byte
	udps     internet.StackPortsMACFiltered
	tcps     internet.StackPortsMACFiltered

	defaultValidator lneto.Validator

	dhcpUDP     internet.StackUDPPort
	dhcp        dhcpv4.Client
	dhcpResults DHCPResults
	arpt        subnetTable

	dnsUDP  internet.StackUDPPort
	dns     dns.Client
	ednsopt dns.Resource
	lookup  dns.Message
	dnssv   netip.Addr

	ntpUDP internet.StackUDPPort
	ntp    ntp.Client

	userUDPs []internet.StackUDPPort

	sysprec int8 // NTP system precision.

	prng uint32

	addrBuf    [6]byte // Temporary buffer for As4()/HardwareAddr6() results to avoid heap escapes.
	addrbufnip [4]netip.Addr

	stats Statistics

	ipv6enabled bool
	stack6      Stack6
}

type StackConfig struct {
	HardwareAddress [6]byte
	StaticAddress4  [4]byte
	StaticAddress6  [16]byte

	IPv6Stack Stack6

	DNSServer netip.Addr
	NTPServer netip.Addr
	RandSeed  int64
	// Hostname is used for DHCP hostname and ICMP ID.
	Hostname string

	EthernetTxCRC32Update func(crc uint32, b []byte) uint32

	// ICMPQueueLimit sets maximum number of input/output packets queued for processing.
	// If set to zero ICMP cannot be enabled on the stack.
	ICMPQueueLimit int
	// PassivePeers limits how many subnet peers the stack passively learns MAC addresses for.
	// Passively learned entries skip ARP round-trips on the first DialTCP/DialUDP to that peer.
	PassivePeers int

	// MaxActiveTCPPorts and MaxActiveUDPPorts are a memory guardrail to limit
	// number of simultaneous open TCP/UDP ports. The memory impact at the stack level
	// of a port corresponds to ~64 bytes excluding the registered StackNode i.e: [tcp.Conn] or [udp.Conn].
	MaxActiveTCPPorts, MaxActiveUDPPorts uint16
	// MTU sets the maximum transmission unit, which is the maximum size of the Ethernet payload
	// not including ethernet header, ethernet CRC. It is determined by the NIC hardware and the route the packets take over the network.
	// By far the most common value for MTU is 1500 as specified by IEEE 802.3.
	MTU uint16
	// Accept multicast ethernet and IP packets. Needed for MDNS.
	AcceptMulticast bool
}

func (cfg *StackConfig) id() uint16 {
	return uint16(cfg.Hostname[len(cfg.Hostname)-1] - '0')
}

func (s *StackAsync) Hostname() string {
	return s.hostname
}

// IngressEthernet receives an Ethernet frame from the network and processes it through the stack. The frame should include the Ethernet header and payload and CRC if enabled.
func (s *StackAsync) IngressEthernet(ethernetFrame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.TotalReceived += uint64(len(ethernetFrame))
	err := s.link.Demux(ethernetFrame, 0)
	if err == nil {
		s.arpt.learnFromIngressEthernet(ethernetFrame)
	}
	return err
}

// EgressEthernet writes the next ethernet frame to send into dstEthernetFrame from the stack.
// The length of dstEthernetFrame should be at least MTU + Ethernet header (14) + CRC (4 if enabled).
func (s *StackAsync) EgressEthernet(dstEthernetFrame []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.link.Encapsulate(dstEthernetFrame, -1, 0)
	s.stats.TotalSent += uint64(n)
	return n, err
}

// IngressIP processes an incoming IP frame through the stack and omits ethernet header processing.
func (s *StackAsync) IngressIP(ipFrame []byte) error {
	if len(ipFrame) < 1 {
		return lneto.ErrTruncatedFrame
	}
	version := ipFrame[0] >> 4
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.TotalReceived += uint64(len(ipFrame))
	switch version {
	case 4:
		return s.ip4.Demux(ipFrame, 0)
	case 6:
		if s.ipv6enabled {
			return s.stack6.IngressIPv6(ipFrame)
		}
	}
	return lneto.ErrPacketDrop
}

// EgressIP writes the next IP frame to send into dstIPFrame from the stack. The length of dstIPFrame should be at least MTU.
func (s *StackAsync) EgressIP(dstIPFrame []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(dstIPFrame) < s.link.MTU() {
		return 0, lneto.ErrShortBuffer
	}
	n, err := s.ip4.Encapsulate(dstIPFrame, 0, 0)
	if s.ipv6enabled && n == 0 {
		n, err = s.stack6.EgressIPv6(dstIPFrame)
	}
	s.stats.TotalSent += uint64(n)
	return n, err
}

// MTU is the Maximum Transmission Unit of the stack corresponding
// to the maximum payload size of an ethernet frame that can be sent through the stack.
// Important to note that the actual ethernet frame size is MTU + Ethernet header (14) + CRC (4 if enabled), this is known as the Maximum Frame Length.
func (s *StackAsync) MTU() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.link.MTU()
}

func (s *StackAsync) Reset(cfg StackConfig) (err error) {
	ipv6Enabled := cfg.IPv6Stack != nil
	if cfg.RandSeed == 0 || cfg.Hostname == "" || cfg.PassivePeers > 255 {
		return lneto.ErrInvalidConfig
	} else if !internal.IsZeroed(cfg.StaticAddress6) && !ipv6Enabled {
		return lneto.ErrBug // Forgot to EnableIPv6 after setting static IPv6 address.
	}
	mac := cfg.HardwareAddress
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prng = uint32(cfg.RandSeed)
	s.hostname = cfg.Hostname
	// Treat last character of hostname as number.
	id := cfg.id()
	linkNodes := 2 // ARP and IPv4 nodes
	s.ipv6enabled = ipv6Enabled
	s.stack6 = nil
	if s.ipv6enabled {
		linkNodes = 3 // IPv6
		s.Debug("ipv6 enabled")
		err = cfg.IPv6Stack.Reset6(&cfg)
		if err != nil {
			s.ipv6enabled = false
			return err
		}
	}
	s.stack6 = cfg.IPv6Stack
	ecfg := internet.StackEthernetConfig{
		MTU:         int(cfg.MTU),
		MaxNodes:    linkNodes,
		MAC:         mac,
		Gateway:     ethernet.BroadcastAddr(),
		AppendCRC32: cfg.EthernetTxCRC32Update != nil,
		CRC32Update: cfg.EthernetTxCRC32Update,
	}
	err = s.link.Configure(ecfg)
	if err != nil {
		return err
	}
	if cfg.PassivePeers == 0 {
		s.link.OnEncapsulate(nil)
	} else {
		s.link.OnEncapsulate(s.arpt.patchEgressMAC)
	}
	const ipNodes = 3 // 3 IP protocols possible: UDP, TCP, ICMP.
	err = s.ip4.Reset(&s.defaultValidator, ipNodes)
	if err != nil {
		return err
	}
	s.ip4.SetAddr4(cfg.StaticAddress4)
	s.setAcceptMulticast4(cfg.AcceptMulticast)

	s.arpt.passivePeers = uint8(cfg.PassivePeers)
	err = s.resetARP()
	if err != nil {
		return err
	}
	udpConns := 3 + cfg.MaxActiveUDPPorts // DHCP, DNS, NTP + user-registered.
	s.udps.ResetUDP(udpConns)

	internal.SliceReuse(&s.userUDPs, int(cfg.MaxActiveUDPPorts))

	// Enable TCP if connections present.
	if cfg.MaxActiveTCPPorts > 0 {
		s.tcps.ResetTCP(cfg.MaxActiveTCPPorts)
		err = s.ip4.Register4(&s.tcps)
		if err != nil {
			return err
		}
	}

	// Now setup stacks.
	// ARP registered in resetARP.
	err = s.link.RegisterEthernet(&s.ip4) // IPv4
	if err != nil {
		return err
	}

	err = s.ip4.Register4(&s.udps)
	if err != nil {
		return err
	}
	if cfg.ICMPQueueLimit > 0 {
		err = s.icmp.Configure(icmpv4.ClientConfig{
			ResponseQueueBuffer: make([]byte, cfg.ICMPQueueLimit*icmpEchoSize),
			ResponseQueueLimit:  cfg.ICMPQueueLimit,
			HashSeed:            s.prand32(),
			ID:                  id,
		})
		if err != nil {
			return err
		}
	}
	var timebuf [4]int64
	s.sysprec = ntp.CalculateSystemPrecision(nil, timebuf[:])
	if s.clientID == "" {
		s.clientID = "lneto-" + s.hostname
	}
	s.stats = Statistics{}
	if cfg.DNSServer.IsValid() {
		s.dnssv = cfg.DNSServer
	}
	if s.ipv6enabled {
		s.Debug("registering IPv6 to ethernet")
		err = s.link.RegisterEthernet(s.stack6.IPv6Stack())
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *StackAsync) resetARP() error {
	mac := s.link.HardwareAddr6()
	addr := s.ip4.Addr4()
	proto := ethernet.TypeIPv4
	err := s.arp.Reset(arp.HandlerConfig{
		HardwareAddr: mac[:],
		ProtocolAddr: addr[:],
		MaxQueries:   5,
		MaxPending:   5,
		HardwareType: 1,
		ProtocolType: proto,
	})
	if err != nil {
		return err
	}
	s.arpt.reset(10, s.arpt.passivePeers)
	s.arp.SetOnResolveCallback(s.arpt.onResolve)
	err = s.link.RegisterEthernet(&s.arp)
	if err != nil {
		return err
	}
	return nil
}

func (s *StackAsync) prandRead(buf []byte) {
	i := 0
	for ; i+3 < len(buf); i += 4 {
		binary.LittleEndian.PutUint32(buf[i:], s.prand32())
	}
	v := s.prand32()
	for i < len(buf) {
		buf[i] = byte(v >> (8 * (i % 4)))
		i++
	}
}

// Prand32 generates a pseudo random 32-bit unsigned integer from the internal state and advances the seed.
func (s *StackAsync) Prand32() (randval uint32) {
	s.mu.Lock()
	randval = s.prand32()
	s.mu.Unlock()
	return randval
}

func (s *StackAsync) prand32() uint32 {
	/* Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs" */
	seed := internal.Prand32(s.prng)
	s.prng = seed
	return seed
}

func (s *StackAsync) SetAddr4(addr [4]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setIPAddr4(addr)
}

func (s *StackAsync) setIPAddr4(addr [4]byte) error {
	s.ip4.SetAddr4(addr)
	return s.arp.UpdateProtoAddr(addr[:])
}

func (s *StackAsync) Addr4() [4]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ip4.Addr4()
}

func (s *StackAsync) SetAddr6(addr [16]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ipv6enabled {
		return s.stack6.SetAddr6(addr)
	}
	return lneto.ErrUnsupported
}

func (s *StackAsync) Addr6() [16]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ipv6enabled {
		return s.stack6.Addr6()
	}
	return [16]byte{}
}

func (s *StackAsync) SetSubnet4(addr [4]byte, prefixBits uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arpt.subnet4 = ipv4.PrefixFrom(addr, prefixBits)
}

func (s *StackAsync) SetHardwareAddr(hw [6]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.link.SetHardwareAddr6(hw)
	return s.resetARP()
}

func (s *StackAsync) HardwareAddr() (hw [6]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.link.HardwareAddr6()
}

func (s *StackAsync) SetGatewayHardwareAddr(gwhw [6]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.link.SetGateway6(gwhw)
}

func (s *StackAsync) GatewayHardwareAddr() [6]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.link.Gateway6()
}

func (s *StackAsync) IsIPv6Enabled() bool {
	s.mu.Lock()
	enabled := s.ipv6enabled
	s.mu.Unlock()
	return enabled
}

// EnableICMP registers an ICMP handler to the stack when enabled is true.
// If enabled=false the currently registered ICMP handler is unregistered and state reset.
func (s *StackAsync) EnableICMP(enabled bool) (err error) {
	if s.icmp.IncomingEchoCapacity() == 0 {
		err = lneto.ErrInvalidConfig
		enabled = false // ensure aborted.
	}
	if enabled {
		if !s.ip4.IsRegistered4(lneto.IPProtoICMP) {
			err = s.ip4.Register4(&s.icmp)
		}
	} else {
		s.icmp.Abort()
	}
	if s.ipv6enabled {
		if err2 := s.stack6.EnableICMP6(enabled); err2 != nil && err == nil {
			err = err2
		}
	}
	return err
}

func (s *StackAsync) DialUDP(conn *udp.Conn, localPort uint16, addrp netip.AddrPort) (err error) {
	addr := addrp.Addr()
	if addr.Is4() {
		return s.DialUDP4(conn, localPort, addrp.Addr().As4(), addrp.Port())
	} else if s.ipv6enabled && addr.Is6() {
		// stack6 is guarded by s.mu (the single stack lock), just like the IPv4
		// path locks inside DialUDP4. Hold it here so the port-handler mutation is
		// serialized against the Ingress/Egress demux.
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.stack6.DialUDP6(conn, localPort, addr.As16(), addrp.Port())
	}
	return lneto.ErrInvalidAddr
}

func (s *StackAsync) DialTCP(conn *tcp.Conn, localPort uint16, addrp netip.AddrPort) (err error) {
	addr := addrp.Addr()
	if addr.Is4() {
		return s.DialTCP4(conn, localPort, addrp.Addr().As4(), addrp.Port())
	} else if s.ipv6enabled && addr.Is6() {
		// stack6 is guarded by s.mu (the single stack lock), just like the IPv4
		// path locks inside DialTCP4. Hold it here so the port-handler mutation is
		// serialized against the Ingress/Egress demux. Use the unlocked prand32
		// since we already hold s.mu (Prand32 would deadlock).
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.stack6.DialTCP6(conn, localPort, addr.As16(), addrp.Port(), tcp.Value(s.prand32()))
	}
	return lneto.ErrInvalidAddr
}

func (s *StackAsync) DialUDP4(conn *udp.Conn, localPort uint16, raddr [4]byte, rport uint16) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mac, err := s.arpt.hwDynamicResolve(raddr, &s.arp)
	if err != nil {
		return err
	}
	err = conn.Open(localPort, netip.AddrPortFrom(netip.AddrFrom4(raddr), rport))
	if err != nil {
		return err
	}
	err = s.udps.RegisterMACFiltered(conn, mac)
	if err != nil {
		conn.Abort()
		return err
	}
	return nil
}

func (s *StackAsync) DialTCP4(conn *tcp.Conn, localPort uint16, raddr [4]byte, rport uint16) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mac, err := s.arpt.hwDynamicResolve(raddr, &s.arp)
	if err != nil {
		return err
	}
	err = conn.OpenActive(localPort, netip.AddrPortFrom(netip.AddrFrom4(raddr), rport), tcp.Value(s.prand32()))
	if err != nil {
		return err
	}
	err = s.tcps.RegisterMACFiltered(conn, mac) // MAC is set later on by ARP response arriving to our network.
	if err != nil {
		conn.Abort()
		return err
	}
	return nil
}

func (s *StackAsync) ListenTCP4(conn *tcp.Conn, localPort uint16) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err = conn.OpenListen(localPort, tcp.Value(s.prand32()))
	if err != nil {
		return err
	}
	err = s.tcps.RegisterMACFiltered(conn, nil)
	if err != nil {
		conn.Abort()
		return err
	}
	return nil
}

func (s *StackAsync) RegisterListenerTCP(listener *tcp.Listener) (err error) {
	// TODO(pato): Possible to forward both IPv4 and IPv6 packets to the listener and have it selectively mux out correctly?
	// Can try changing listener to inspect carrierData on demux and get the IPversion to know which tcp.Conns match the IP version.
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tcps.RegisterMACFiltered(listener, nil)
}

// RegisterUDP4 registers a StackNode on a UDP port with the given remote address and port.
// The StackUDPPort wrapping is handled internally. The number of user-registered UDP ports
// is limited by [StackConfig.MaxUDPConns].
func (s *StackAsync) RegisterUDP4(node lneto.StackNode, remoteAddr [4]byte, remotePort uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := len(s.userUDPs)
	if idx >= cap(s.userUDPs) {
		return lneto.ErrExhausted
	}
	s.userUDPs = s.userUDPs[:idx+1]
	s.userUDPs[idx].SetStackNode(node, remoteAddr[:], remotePort)
	return s.udps.RegisterMACFiltered(&s.userUDPs[idx], nil)
}

func (s *StackAsync) RegisterListenerUDP(pktconn *udp.PacketConn) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udps.RegisterMACFiltered(pktconn, nil)
}

func (s *StackAsync) RegisterListenerTCP6(listener *tcp.Listener) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ipv6enabled {
		return lneto.ErrUnsupported
	}
	return s.stack6.RegisterListenerTCP6(listener)
}

func (s *StackAsync) RegisterListenerUDP6(pktconn *udp.PacketConn) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ipv6enabled {
		return lneto.ErrUnsupported
	}
	return s.stack6.RegisterListenerUDP6(pktconn)
}

var errNoDNSServer = errors.New("no DNS server- did DHCP complete? You can set a predetermined DNS server in Stack configuration")

var errDNSv6Transport = errors.New("DNS query over IPv6 transport not supported; configure an IPv4 DNS server")

func (s *StackAsync) StartLookupIP(host string) error {
	return s.StartLookupIPType(host, dns.TypeA)
}

// StartLookupIPType begins resolving host for the given record type (e.g. dns.TypeA
// or dns.TypeAAAA). The DNS query is always carried over IPv4 to the configured DNS
// server; resolving over an IPv6 DNS transport is not yet supported.
func (s *StackAsync) StartLookupIPType(host string, qtype dns.Type) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dnssv.IsValid() {
		return errNoDNSServer
	}
	if !s.dnssv.Is4() {
		return errDNSv6Transport
	}
	name, err := dns.NewName(host)
	if err != nil {
		return err
	}

	// EDNS0 buffer size: MTU minus overhead for IP+UDP headers and safety margin.
	// 100 bytes covers IPv4 max header (60) + UDP (8) + 32 byte margin.
	s.ednsopt.SetEDNS0(uint16(s.link.MTU())-100, 0, 0, nil)
	rand := s.prand32()
	err = s.dns.StartResolve(uint16(rand>>1)+1024, uint16(rand), dns.ResolveConfig{
		Questions: []dns.Question{
			{
				Name:  name,
				Type:  qtype,
				Class: dns.ClassINET,
			},
		},
		Additional: []dns.Resource{
			s.ednsopt,
		},
		EnableRecursion: true,
	})
	if err != nil {
		return err
	}
	*(*[4]byte)(s.addrBuf[:4]) = s.dnssv.As4()
	s.dnsUDP.SetStackNode(&s.dns, s.addrBuf[:4], dns.ServerPort)
	err = s.udps.RegisterMACFiltered(&s.dnsUDP, nil)
	return err
}

var (
	errDNSNotDone = errors.New("DNS not done")
	errDNSNoAns   = errors.New("no address in DNS answer")
)

func (s *StackAsync) ResultLookupIP(host string) ([]netip.Addr, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.dns.ResponseFlags()
	if !ok {
		return nil, false, errDNSNotDone
	}
	n, err := s.dns.ResponseAnswerLookup(s.addrbufnip[:], host)
	if n == 0 && err == nil {
		err = errDNSNoAns
	}
	return s.addrbufnip[:n], true, err
}

func (s *StackAsync) StartDHCPv4Request(request [4]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dhcp.Reset()
	xid := s.prand32()
	err := s.dhcp.BeginRequest(xid, dhcpv4.RequestConfig{
		RequestedAddr:      request,
		ClientHardwareAddr: s.link.HardwareAddr6(),
		Hostname:           s.hostname,
		ClientID:           s.clientID,
	})
	if err != nil {
		return err
	}

	s.dhcpUDP.SetStackNode(&s.dhcp, nil, dhcpv4.DefaultServerPort)
	err = s.udps.RegisterMACFiltered(&s.dhcpUDP, nil)
	if err != nil {
		return err
	}
	return err
}

func (s *StackAsync) StartNTP(addr netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ntp.Reset(s.sysprec, time.Now)

	*(*[4]byte)(s.addrBuf[:4]) = addr.As4()
	s.ntpUDP.SetStackNode(&s.ntp, s.addrBuf[:4], ntp.ServerPort)
	err := s.udps.RegisterMACFiltered(&s.ntpUDP, nil)
	return err
}

// ResultNTPOffset returns the result of the NTP protocol such that the following code returns the corrected time.
// If the bool is false then the NTP has not yet completed.
//
//	nowCorrected := time.Now().Add(resultNTP)
func (s *StackAsync) ResultNTPOffset() (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ntp.Offset(), s.ntp.IsDone()
}

func (s *StackAsync) StartResolveHardwareAddress6(ip netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ip.Is4() {
		return lneto.ErrUnsupported
	}
	addr := ip.As4()
	return s.arp.StartQuery(addr[:], false)
}

// ResultResolveHardwareAddress6
func (s *StackAsync) ResultResolveHardwareAddress6(ip netip.Addr) (hw [6]byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ip.Is4() {
		return hw, lneto.ErrUnsupported
	}
	addr := ip.As4()
	hwslice, err := s.arp.CacheLookup(addr[:])
	if err != nil {
		return hw, err
	} else if len(hwslice) != 6 {
		panic("unreachable slice hw length")
	}
	return [6]byte(hwslice), nil
}

// DiscardResolveHardwareAddress6 discards a pending ARP query for the given IP address.
func (s *StackAsync) DiscardResolveHardwareAddress6(ip netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ip.Is4() {
		return lneto.ErrUnsupported
	}
	addr := ip.As4()
	return s.arp.CacheRemove(addr[:])
}

func (s *StackAsync) SetAcceptMulticast4(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setAcceptMulticast4(enabled)
}

func (s *StackAsync) setAcceptMulticast4(enabled bool) {
	s.link.SetAcceptMulticast(enabled)
	s.ip4.SetAcceptMulticast4(enabled)
}

type DHCPResults struct {
	DNSServers    []netip.Addr
	Router        netip.Addr
	AssignedAddr4 [4]byte
	ServerAddr    netip.Addr
	BroadcastAddr netip.Addr
	Gateway       netip.Addr
	Subnet        netip.Prefix
	TRebind       uint32 // [seconds]
	TRenewal      uint32
	TLease        uint32 // IP lease time [seconds].
}

func (s *StackAsync) ResultDHCP() (*DHCPResults, error) {
	err := s.populateDHCPResults()
	if err != nil {
		return nil, err
	}
	return &s.dhcpResults, nil
}

type Statistics struct {
	// Total amount of bytes sent over encapsulate.
	TotalSent uint64
	// Total amount of bytes received over demux.
	TotalReceived uint64
}

func (s *StackAsync) ReadStatistics(stats *Statistics) {
	s.mu.Lock()
	*stats = s.stats
	s.mu.Unlock()
}

// AssimilateDHCPResults sets the stack's following parameters:
//   - IPv4 address.
//   - DNS server.
//   - Subnet (for ARP resolution of local addresses).
func (stack *StackAsync) AssimilateDHCPResults(results *DHCPResults) error {
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if results.Subnet.IsValid() && results.Subnet.Addr().Is4() {
		stack.arpt.subnet4 = ipv4.PrefixFromNetip(results.Subnet)
	}
	if !internal.IsZeroed(results.AssignedAddr4) {
		err := stack.setIPAddr4(results.AssignedAddr4)
		if err != nil {
			return err
		}
	}
	if len(results.DNSServers) > 0 {
		if !results.DNSServers[0].IsValid() || !results.DNSServers[0].Is4() {
			return lneto.ErrInvalidAddr
		}
		stack.dnssv = results.DNSServers[0]
	}
	return nil
}

func (s *StackAsync) populateDHCPResults() error {
	if !s.dhcp.State().HasIP() {
		return errors.New("DHCP not completed")
	}
	router4, ok := s.dhcp.RouterAddr()
	if !ok {
		return errors.New("no DHCP router address")
	}
	assigned4, ok := s.dhcp.AssignedAddr()
	if !ok {
		return errors.New("no DHCP assigned address")
	}
	router := netip.AddrFrom4(router4)
	subnet := s.dhcp.SubnetPrefix()
	s.dhcpResults = DHCPResults{
		Router:        router,
		Subnet:        subnet.NetipPrefix(),
		AssignedAddr4: assigned4,
		ServerAddr:    addr4(s.dhcp.ServerAddr()),
		BroadcastAddr: addr4(s.dhcp.BroadcastAddr()),
		Gateway:       addr4(s.dhcp.GatewayAddr()),
		TRebind:       s.dhcp.RebindingSeconds(),
		TRenewal:      s.dhcp.RenewalSeconds(),
		TLease:        s.dhcp.IPLeaseSeconds(),
		DNSServers:    s.dhcpResults.DNSServers[:0], // reuse field capacity.
	}
	s.dhcpResults.DNSServers = s.dhcp.AppendDNSServers(s.dhcpResults.DNSServers)
	return nil
}

func addr4(addr [4]byte, ok bool) netip.Addr {
	if !ok {
		return netip.Addr{}
	}
	return netip.AddrFrom4(addr)
}

// Debug prints debugging information. Very useful for users when coupled with
// the debugheaplog build tag. See [internal.LogAttrs] debugheaplog version.
//
//	go build -tags=debugheaplog ./yourprogram
func (s *StackAsync) Debug(msg string) {
	internal.LogAttrs(slog.Default(), slog.LevelDebug, "stackasync",
		slog.String("umsg", msg),
		slog.Uint64("sent", s.stats.TotalSent),
		slog.Uint64("recv", s.stats.TotalReceived),
	)
}

// DebugErr prints debugging and error info. Very useful for users when coupled with
// the debugheaplog build tag. See [internal.LogAttrs] debugheaplog version.
//
//	go build -tags=debugheaplog ./yourprogram
func (s *StackAsync) DebugErr(msg, err string) {
	internal.LogAttrs(slog.Default(), slog.LevelError, "stackasync",
		slog.String("umsg", msg),
		slog.String("err", err),
		slog.Uint64("sent", s.stats.TotalSent),
		slog.Uint64("recv", s.stats.TotalReceived),
	)
}
