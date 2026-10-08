package xnet

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/dhcp/dhcpv4"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/dns/edns0"
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
	dnssv   netip.Addr
	dnsCtr  uint64 // Input to keyed hash for unpredictable DNS txids and ports, see [StackAsync.dnsRand16].

	// ephPort drives sequential ephemeral-port allocation (see
	// [StackAsync.ephemeralPort]); zero means not yet seeded.
	ephPort uint32

	ntpUDP internet.StackUDPPort
	ntp    ntp.Client

	userUDPs []internet.StackUDPPort

	sysprec int8 // NTP system precision.

	mono internal.Monotonic
	prng uint32
	key  [16]byte // See [tcp.ISN].

	addrBuf [6]byte // Temporary buffer for As4()/HardwareAddr6() results to avoid heap escapes.

	stats Statistics

	ipv6enabled bool
	stack6      Stack6

	log *slog.Logger
}

type StackConfig struct {
	HardwareAddress [6]byte
	StaticAddress4  [4]byte
	StaticAddress6  [16]byte

	IPv6Stack Stack6

	DNSServer netip.Addr
	NTPServer netip.Addr
	// RandSeed used to generate pseudo-random numbers for protocol functioning. See [StackConfig.Entropy].
	RandSeed int64
	// Entropy reads from a source of true randomness to dst. Must return data read n=len(dst) or an error indicating why buffer was not filled.
	// "Good" entropy is required for compliance with RFC 6528 ISN generation.
	Entropy func(dst []byte) (n int, _ error)
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
	// By far the most common value for MTU is 1500 as specified by IEEE 802.3. Jumbo/TUN MTUs up to 65535 allowed.
	MTU uint16
	// MaxDNSQueries limits how many DNS lookups may be active at once. Zero defaults to 2.
	MaxDNSQueries uint16
	// Accept multicast ethernet and IP packets. Needed for MDNS.
	AcceptMulticast bool
	// Accept broadcast IPv4 packets. Needed for managing access points and DHCPv4 servers.
	AcceptIPv4Broadcast bool
	// Nanotime provides a monotonic time source to StackAsync. Since Nanotime is required for secure TCP operation
	// if not provided will use [time.Since] in its stead.
	Nanotime func() int64
	// Logger receives the stack's Debug and DebugErr output. A nil Logger silences
	// them; the heap allocation probe still runs so allocation bisection keeps working.
	Logger *slog.Logger
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
	debugPacket("IN ", ethernetFrame)
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
	if n > 0 {
		debugPacket("OUT", dstEthernetFrame[:n])
	}
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
	mtu := s.link.MTU()
	if len(dstIPFrame) < mtu {
		return 0, lneto.ErrShortBuffer
	}
	// Clip to MTU so downstream layers cannot emit an IP datagram larger than the
	// link MTU (mirrors StackEthernet.Encapsulate). This also bounds the TCP frame
	// budget, so the advertised MSS becomes MTU-ipHdr-20 instead of the buffer size.
	dstIPFrame = dstIPFrame[:mtu]
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
	s.log = cfg.Logger
	// Treat last character of hostname as number.
	id := cfg.id()
	linkNodes := 2 // ARP and IPv4 nodes
	s.ipv6enabled = ipv6Enabled
	s.stack6 = nil
	s.mono.Config(cfg.Nanotime)
	if cfg.Entropy != nil {
		n, err := cfg.Entropy(s.key[:])
		if err == nil && n != len(s.key) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return err
		}
	} else {
		// Best attempt at randomness.
		binary.LittleEndian.PutUint64(s.key[:], uint64(cfg.RandSeed))
		binary.LittleEndian.PutUint64(s.key[8:], uint64(s.mono.Nanotime()))
	}

	if s.ipv6enabled {
		linkNodes = 3 // IPv6
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
	s.ip4.SetAcceptBroadcast4(cfg.AcceptIPv4Broadcast)
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
	maxDNSQueries := cfg.MaxDNSQueries
	if maxDNSQueries == 0 {
		maxDNSQueries = 2
	}

	err = s.dns.Configure(dns.ClientConfig{MaxQueries: int(maxDNSQueries)})
	if err != nil {
		return err
	}
	if s.ipv6enabled {
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

// ephemeralPort returns the next port of the IANA dynamic range (49152-65535,
// RFC 6335 §6), allocated sequentially from a random per-stack start so a port is
// revisited only after the full 16384-port cycle. Random selection instead reuses
// a recent port at birthday-paradox rates, and a reused 4-tuple can collide with
// state the previous conversation left behind (a TIME-WAIT, a NAT flow entry)
// which swallows the new SYN.
func (s *StackAsync) ephemeralPort() uint16 {
	s.mu.Lock()
	if s.ephPort == 0 {
		s.ephPort = s.prand32()%16384 | 1
	}
	port := 49152 + s.ephPort%16384
	s.ephPort++
	s.mu.Unlock()
	return uint16(port)
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

func (s *StackAsync) DialTCP(conn *tcp.Conn, localPort uint16, raddrp netip.AddrPort) (err error) {
	addr := raddrp.Addr()
	if addr.Is4() {
		return s.DialTCP4(conn, localPort, raddrp.Addr().As4(), raddrp.Port())
	} else if s.ipv6enabled && addr.Is6() {
		// stack6 is guarded by s.mu (the single stack lock), just like the IPv4
		// path locks inside DialTCP4. Hold it here so the port-handler mutation is
		// serialized against the Ingress/Egress demux. Use the unlocked prand32
		// since we already hold s.mu (Prand32 would deadlock).
		s.mu.Lock()
		defer s.mu.Unlock()
		raddr := addr.As16()
		laddr := s.stack6.Addr6()
		return s.stack6.DialTCP6(conn, localPort, raddr, raddrp.Port(), tcp.ISN(&s.key, s.mono.Nanotime(), laddr[:], raddr[:], localPort, raddrp.Port()))
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
	err = conn.OpenActive(localPort, netip.AddrPortFrom(netip.AddrFrom4(raddr), rport), s.isn4(raddr[:], rport, localPort))
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
	err = conn.OpenListen(localPort, s.isn4(conn.RemoteAddr(), uint16(s.prand32()), localPort))
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

func (s *StackAsync) isn4(raddr []byte, rport, lport uint16) tcp.Value {
	var localaddr [10]byte
	ip4 := s.ip4.Addr4()
	localmac := s.link.HardwareAddr6()
	copy(localaddr[:], ip4[:])
	copy(localaddr[4:], localmac[:]) // MAC is added safety against spoofers.
	if len(raddr) == 0 {
		raddr = s.addrBuf[:] // use garbage in addrBuf.
	}
	return tcp.ISN(&s.key, s.mono.Nanotime(), localaddr[:], raddr, lport, rport)
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
	raddr := remoteAddr[:]
	if remoteAddr == [4]byte{} {
		raddr = nil
	}
	s.userUDPs = s.userUDPs[:idx+1]
	s.userUDPs[idx].SetStackNode(node, raddr, remotePort)
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

var (
	errDNSv6Transport = errors.New("DNS query over IPv6 transport not supported; configure an IPv4 DNS server")
	errNoDNSServer    = errors.New("no DNS server- did DHCP complete? You can set a predetermined DNS server in Stack configuration")
	errDNSNotDone     = errors.New("DNS not done")
	errDNSNoLookup    = errors.New("no such DNS lookup")
	errDNSNoAns       = errors.New("no address in DNS answer")
	// errDNSOnlyCNAME is returned when the answer ends in a CNAME without address.
	errDNSOnlyCNAME = errors.New("DNS answer is CNAME without address")
)

// newDNSTxid returns a txid that is non-zero, unused by active lookups and unpredictable.
func (s *StackAsync) newDNSTxid() uint16 {
	for {
		txid := s.dnsRand16()
		if _, active := s.dns.LookupPeek(txid); txid != 0 && !active {
			return txid
		}
	}
}

// dnsRand16 returns secure keyed hash to prevent spoofing attacks via DNS port/txid.
func (s *StackAsync) dnsRand16() uint16 {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], s.dnsCtr)
	s.dnsCtr++
	return uint16(internal.SipHash24(&s.key, buf[:]))
}

// LookupIPStart starts host resolution for type dns.TypeA/dns.TypeAAAA returning the lookup key for [StackAsync.LookupIPResult].
// nans limits answer records decoded from response; CNAME records precede addresses so leave headroom for them.
// Up to [StackConfig.MaxDNSQueries] lookups may be active at once after which [lneto.ErrExhausted] is returned.
func (s *StackAsync) LookupIPStart(host dns.Name, qtype dns.Type, nans uint16) (txid uint16, err error) {
	// No defer: TinyGo will not inline functions with defer and emits unlock code per return.
	s.mu.Lock()
	txid, err = s.lookupIPStart(host, qtype, nans)
	s.mu.Unlock()
	return txid, err
}

func (s *StackAsync) lookupIPStart(host dns.Name, qtype dns.Type, nans uint16) (txid uint16, err error) {
	if !s.dnssv.IsValid() {
		return 0, errNoDNSServer
	} else if !s.dnssv.Is4() {
		return 0, errDNSv6Transport
	} else if s.dns.NumLookups() == s.dns.MaxLookups() {
		return 0, lneto.ErrExhausted
	}
	if s.dns.NumLookups() == 0 {
		// Idle: pick a new unpredictable source port, which adds to the
		// txid in protecting against spoofed responses (RFC 5452).
		port := 1024 + s.dnsRand16()%(math.MaxUint16-1024)
		err = s.dns.Configure(dns.ClientConfig{LocalPort: port, MaxQueries: s.dns.MaxLookups()})
		if err != nil {
			return 0, err
		}
		*(*[4]byte)(s.addrBuf[:4]) = s.dnssv.As4()
		s.dnsUDP.SetStackNode(&s.dns, s.addrBuf[:4], dns.ServerPort)
		err = s.udps.RegisterMACFiltered(&s.dnsUDP, nil)
		if err != nil {
			return 0, err
		}
	}
	// EDNS0 buffer size: MTU minus overhead for IP+UDP headers and safety margin.
	// 100 bytes covers IPv4 max header (60) + UDP (8) + 32 byte margin.
	edns0.SetResource(&s.ednsopt, uint16(s.link.MTU())-100, 0, 0, nil)
	txid = s.newDNSTxid()
	err = s.dns.LookupStart(txid, dns.LookupConfig{
		Questions: []dns.Question{
			{
				Name:  host,
				Type:  qtype,
				Class: dns.ClassINET,
			},
		},
		Additional: []dns.Resource{
			s.ednsopt,
		},
		EnableRecursion: true,
		// CNAME records occupy answer slots before the addresses they alias.
		MaxResponseAnswers: nans,
	})
	if err != nil {
		return 0, err
	}
	return txid, nil
}

// LookupIPFollowCNAME restarts lookup txid if response held CNAME but no address.
func (s *StackAsync) LookupIPFollowCNAME(txid uint16) (newTxid uint16, err error) {
	s.mu.Lock()
	newTxid = s.newDNSTxid()
	err = s.dns.LookupCanonicalRestart(txid, newTxid)
	s.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return newTxid, nil
}

// LookupIPPop removes the lookup txid, freeing it for another lookup, and reports whether
// it had completed. ok is false if no such lookup is active. Every lookup started must be popped.
func (s *StackAsync) LookupIPPop(txid uint16) (completed, ok bool) {
	s.mu.Lock()
	completed, ok = s.dns.LookupPop(txid)
	s.mu.Unlock()
	return completed, ok
}

// LookupIPPeek checks on query txid returning completed=true if response was received.
func (s *StackAsync) LookupIPPeek(txid uint16) (completed, ok bool) {
	s.mu.Lock()
	completed, ok = s.dns.LookupPeek(txid)
	s.mu.Unlock()
	return completed, ok
}

// LookupIPResponse returns the [dns.Message] containing the response for query txid.
// [dns.Message] is owned by the stack and only valid until the next Lookup method is called on txid.
func (s *StackAsync) LookupIPResponse(txid uint16) (resp *dns.Message, flags dns.HeaderFlags, ok bool) {
	s.mu.Lock()
	resp, flags, ok = s.dns.LookupResponse(txid)
	s.mu.Unlock()
	return resp, flags, ok
}

// LookupIPResult writes the addresses answering the lookup txid into dst and returns how many were written.
// done is false while the lookup awaits its response. Once done it returns errDNSOnlyCNAME
// if the answer is a CNAME without address, see [StackAsync.LookupIPFollowCNAME], and
// [lneto.ErrExhausted] along with the addresses written if dst filled up.
// The lookup stays active until removed with [StackAsync.LookupIPPop].
func (s *StackAsync) LookupIPResult(txid uint16, dst []netip.Addr) (n int, done bool, err error) {
	s.mu.Lock()
	n, done, err = s.lookupIPResult(txid, dst)
	s.mu.Unlock()
	return n, done, err
}

func (s *StackAsync) lookupIPResult(txid uint16, dst []netip.Addr) (n int, done bool, err error) {
	resp, flags, ok := s.dns.LookupResponse(txid)
	if !ok {
		if _, active := s.dns.LookupPeek(txid); !active {
			return 0, true, errDNSNoLookup
		}
		return 0, false, errDNSNotDone
	} else if rcode := flags.ResponseCode(); rcode != 0 {
		return 0, true, rcode
	} else if len(resp.Questions) == 0 {
		return 0, true, errDNSNoAns
	}
	// The response echoes the question, which after following a CNAME holds the canonical name.
	host := resp.Questions[0].Name
	nans, err := resp.WriteAnswers(dst, host)
	if nans == 0 && err == nil {
		err = errDNSNoAns
		if cname := resp.CanonicalName(host); cname.Len() != 0 {
			err = errDNSOnlyCNAME
		}
	}
	return int(nans), true, err
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

// Debug prints debugging and heap information.
//
// The heap allocation probe runs unconditionally; only the log line is gated on
// the configured Logger's level. Building the slog.Attr list allocates, so the
// gate must come first or the allocation happens even when nothing is logged.
func (s *StackAsync) Debug(msg string) {
	internal.LogAllocs(msg)
	if !internal.LogEnabled(s.log, slog.LevelDebug) {
		return
	}
	internal.LogAttrsAndAllocs(msg, s.log, slog.LevelDebug, "stackasync",
		slog.String("umsg", msg),
		slog.Uint64("sent", s.stats.TotalSent),
		slog.Uint64("recv", s.stats.TotalReceived),
	)
}

// DebugErr prints debugging and heap information with [slog.LevelError] level. See [StackAsync.Debug] on gating.
func (s *StackAsync) DebugErr(msg, err string) {
	internal.LogAllocs(msg)
	if !internal.LogEnabled(s.log, slog.LevelError) {
		return
	}
	internal.LogAttrsAndAllocs(msg, s.log, slog.LevelError, "stackasync",
		slog.String("umsg", msg),
		slog.String("err", err),
		slog.Uint64("sent", s.stats.TotalSent),
		slog.Uint64("recv", s.stats.TotalReceived),
	)
}

// LogAllocs is an lneto-tracked allocation logger. If there was an allocation between this call and a previous call
// to LogAllocs it will be printed. This is called globally by StackAsync.Debug methods and by all logging calls in lneto
// when build tag debugheaplog is set.
func LogAllocs(msg string) {
	internal.LogAllocs(msg)
}
