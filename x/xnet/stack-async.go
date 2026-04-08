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
	"github.com/soypat/lneto/dhcpv4"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internet"
	"github.com/soypat/lneto/ipv4/icmpv4"
	"github.com/soypat/lneto/ntp"
	"github.com/soypat/lneto/tcp"
)

const (
	minTCPBuffer = 256
)

type StackAsync struct {
	mu       sync.Mutex
	hostname string
	clientID string
	link     internet.StackEthernet
	ip       internet.StackIP
	arp      arp.Handler
	icmp     icmpv4.Client
	udps     internet.StackPorts
	tcps     internet.StackPortsMACFiltered

	dhcpUDP     internet.StackUDPPort
	dhcp        dhcpv4.Client
	dhcpResults DHCPResults
	subnet      netip.Prefix // Local subnet for ARP resolution.

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

	addrBuf [6]byte // Temporary buffer for As4()/HardwareAddr6() results to avoid heap escapes.

	totalsent uint64
	totalrecv uint64
}

type StackConfig struct {
	StaticAddress         netip.Addr
	DNSServer             netip.Addr
	NTPServer             netip.Addr
	RandSeed              int64
	Hostname              string
	MaxTCPConns           int
	MaxUDPConns           int
	EthernetTxCRC32Update func(crc uint32, b []byte) uint32

	HardwareAddress [6]byte
	MTU             uint16
	// Accept multicast ethernet and IP packets. Needed for MDNS.
	AcceptMulticast bool
	// ICMPQueueLimit sets maximum number of input/output packets queued for processing.
	// If set to zero ICMP cannot be enabled on the stack.
	ICMPQueueLimit int
}

func (s *StackAsync) Hostname() string {
	return s.hostname
}

// IngressEthernet receives an Ethernet frame from the network and processes it through the stack. The frame should include the Ethernet header and payload and CRC if enabled.
func (s *StackAsync) IngressEthernet(ethernetFrame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totalrecv += uint64(len(ethernetFrame))
	return s.link.Demux(ethernetFrame, 0)
}

// EgressEthernet writes the next ethernet frame to send into dstEthernetFrame from the stack.
// The length of dstEthernetFrame should be at least MTU + Ethernet header (14) + CRC (4 if enabled).
func (s *StackAsync) EgressEthernet(dstEthernetFrame []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.link.Encapsulate(dstEthernetFrame, -1, 0)
	s.totalsent += uint64(n)
	return n, err
}

// IngressIP processes an incoming IP frame through the stack and omits ethernet header processing.
func (s *StackAsync) IngressIP(ipFrame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totalrecv += uint64(len(ipFrame))
	return s.ip.Demux(ipFrame, 0)
}

// EgressIP writes the next IP frame to send into dstIPFrame from the stack. The length of dstIPFrame should be at least MTU.
func (s *StackAsync) EgressIP(dstIPFrame []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(dstIPFrame) < s.link.MTU() {
		return 0, lneto.ErrShortBuffer
	}
	n, err := s.ip.Encapsulate(dstIPFrame, 0, 0)
	s.totalsent += uint64(n)
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

func (s *StackAsync) Reset(cfg StackConfig) error {
	if cfg.RandSeed == 0 {
		return lneto.ErrInvalidConfig
	}
	mac := cfg.HardwareAddress
	addr := cfg.StaticAddress
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prng = uint32(cfg.RandSeed)
	s.hostname = cfg.Hostname
	if !addr.IsValid() {
		addr = netip.AddrFrom4([4]byte{}) // If static not set DHCP will be performed and address will be zero.
	} else if addr.Is6() {
		return lneto.ErrUnsupported
	}
	const linkNodes = 2 // ARP and IP nodes
	ecfg := internet.StackEthernetConfig{
		MTU:         int(cfg.MTU),
		MaxNodes:    linkNodes,
		MAC:         mac,
		Gateway:     ethernet.BroadcastAddr(),
		AppendCRC32: cfg.EthernetTxCRC32Update != nil,
		CRC32Update: cfg.EthernetTxCRC32Update,
	}
	err := s.link.Configure(ecfg)
	if err != nil {
		return err
	}
	s.link.SetAcceptMulticast(cfg.AcceptMulticast)
	const ipNodes = 2 // UDP, TCP ports.
	err = s.ip.Reset(addr, ipNodes)
	if err != nil {
		return err
	}
	s.ip.SetAcceptMulticast(cfg.AcceptMulticast)
	err = s.resetARP()
	if err != nil {
		return err
	}
	udpConns := 3 + cfg.MaxUDPConns // DHCP, DNS, NTP + user-registered.
	err = s.udps.ResetUDP(udpConns)
	if err != nil {
		return err
	}
	internal.SliceReuse(&s.userUDPs, cfg.MaxUDPConns)

	// Enable TCP if connections present.
	if cfg.MaxTCPConns > 0 {
		err = s.tcps.ResetTCP(cfg.MaxTCPConns)
		if err != nil {
			return err
		}
		err = s.ip.Register(&s.tcps)
		if err != nil {
			return err
		}
	}

	// Now setup stacks.
	// ARP registered in resetARP.
	err = s.link.Register(&s.ip) // IPv4 | IPv6
	if err != nil {
		return err
	}
	err = s.ip.Register(&s.udps)
	if err != nil {
		return err
	}
	if cfg.ICMPQueueLimit > 0 {
		err = s.icmp.Configure(icmpv4.ClientConfig{
			ResponseQueueBuffer: make([]byte, cfg.ICMPQueueLimit*64),
			ResponseQueueLimit:  cfg.ICMPQueueLimit,
			HashSeed:            s.Prand32(),
		})
		if err != nil {
			return err
		}
	}
	var timebuf [32]time.Time
	s.sysprec = ntp.CalculateSystemPrecision(time.Now, timebuf[:])
	if s.clientID == "" {
		s.clientID = "lneto-" + s.hostname
	}
	s.totalrecv = 0
	s.totalsent = 0
	if cfg.DNSServer.IsValid() {
		s.dnssv = cfg.DNSServer
	}
	return nil
}

func (s *StackAsync) resetARP() error {
	mac := s.link.HardwareAddr6()
	addr := s.ip.Addr()
	if !addr.IsValid() {
		return lneto.ErrInvalidAddr
	}
	proto := ethernet.TypeIPv4
	if addr.Is6() {
		proto = ethernet.TypeIPv6
	}
	err := s.arp.Reset(arp.HandlerConfig{
		HardwareAddr: mac[:],
		ProtocolAddr: addr.AsSlice(),
		MaxQueries:   3,
		MaxPending:   3,
		HardwareType: 1,
		ProtocolType: proto,
	})
	if err != nil {
		return err
	}
	err = s.link.Register(&s.arp)
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

func (s *StackAsync) SetIPAddr(addr netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setIPAddr(addr)
}

func (s *StackAsync) setIPAddr(addr netip.Addr) error {
	err := s.ip.SetAddr(addr)
	if err != nil {
		return err
	}
	ip := addr.As4()
	err = s.arp.UpdateProtoAddr(ip[:])
	return err
}

func (s *StackAsync) Addr() netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ip.Addr()
}

func (s *StackAsync) SetSubnet(subnetMask netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subnet = subnetMask
}

func (s *StackAsync) SetHardwareAddress(hw [6]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.link.SetHardwareAddr6(hw)
	return s.resetARP()
}

func (s *StackAsync) HardwareAddress() (hw [6]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.link.HardwareAddr6()
}

func (s *StackAsync) SetGateway6(gwhw [6]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.link.SetGateway6(gwhw)
}

func (s *StackAsync) Gateway6() [6]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.link.Gateway6()
}

// EnableICMP registers an ICMP handler to the stack when enabled is true.
// If enabled=false the currently registered ICMP handler is unregistered and state reset.
func (s *StackAsync) EnableICMP(enabled bool) (err error) {
	if enabled {
		if s.ip.IsRegistered(lneto.IPProtoICMP) {
			err = lneto.ErrAlreadyRegistered
		} else {
			err = s.ip.Register(&s.icmp)
		}

	} else {
		s.icmp.Abort()
	}
	return err
}

func (s *StackAsync) DialTCP(conn *tcp.Conn, localPort uint16, addrp netip.AddrPort) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var mac []byte
	if s.subnet.Contains(addrp.Addr()) {
		mac = make([]byte, 6)
		ip := addrp.Addr().As4()
		// StartQuery starts an ARP query for addresses in this network.
		// On finishing query MAC is set and thus the StackPort will allow encapsulating
		// data on that connection.
		err = s.arp.StartQuery(mac, ip[:])
		if err != nil {
			return err
		}
	}
	err = conn.OpenActive(localPort, addrp, tcp.Value(s.prand32()))
	if err != nil {
		return err
	}
	err = s.tcps.Register(conn, mac) // MAC is set later on by ARP response arriving to our network.
	if err != nil {
		conn.Abort()
		return err
	}
	return nil
}

func (s *StackAsync) ListenTCP(conn *tcp.Conn, localPort uint16) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err = conn.OpenListen(localPort, tcp.Value(s.prand32()))
	if err != nil {
		return err
	}
	err = s.tcps.Register(conn, nil)
	if err != nil {
		conn.Abort()
		return err
	}
	return nil
}

func (s *StackAsync) RegisterListener(listener *tcp.Listener) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lport := listener.LocalPort()
	if lport == 0 {
		return lneto.ErrZeroSource
	}
	return s.tcps.Register(listener, nil)
}

// RegisterUDP registers a StackNode on a UDP port with the given remote address and port.
// The StackUDPPort wrapping is handled internally. The number of user-registered UDP ports
// is limited by [StackConfig.MaxUDPConns].
func (s *StackAsync) RegisterUDP(node lneto.StackNode, remoteAddr []byte, remotePort uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := len(s.userUDPs)
	if idx >= cap(s.userUDPs) {
		return lneto.ErrBufferFull
	}
	s.userUDPs = s.userUDPs[:idx+1]
	s.userUDPs[idx].SetStackNode(node, remoteAddr, remotePort)
	return s.udps.Register(&s.userUDPs[idx])
}

var errNoDNSServer = errors.New("no DNS server- did DHCP complete? You can set a predetermined DNS server in Stack configuration")

func (s *StackAsync) StartLookupIP(host string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dnssv.IsValid() {
		return errNoDNSServer
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
				Type:  dns.TypeA,
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
	err = s.udps.Register(&s.dnsUDP)
	return err
}

var errDNSNotDone = errors.New("DNS not done")

func (s *StackAsync) ResultLookupIP(host string) ([]netip.Addr, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	done, err := s.dns.MessageCopyTo(&s.lookup)
	if err != nil {
		return nil, done, err
	} else if !done {
		return nil, done, errDNSNotDone
	}

	var addrs []netip.Addr
	ans := s.lookup.Answers
	for i := range ans {
		data := ans[i].RawData()
		if len(data) == 4 {
			addrs = append(addrs, netip.AddrFrom4([4]byte(data)))
		} else if len(data) == 16 {
			addrs = append(addrs, netip.AddrFrom16([16]byte(data)))
		} else {
			err = lneto.ErrInvalidAddr
		}
	}
	if err == nil && len(addrs) == 0 {
		err = errors.New("no address in DNS answer")
	}
	return addrs, done, err
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
	err = s.udps.Register(&s.dhcpUDP)
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
	err := s.udps.Register(&s.ntpUDP)
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
	return s.arp.StartQuery(nil, addr[:])
}

// ResultResolveHardwareAddress6
func (s *StackAsync) ResultResolveHardwareAddress6(ip netip.Addr) (hw [6]byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ip.Is4() {
		return hw, lneto.ErrUnsupported
	}
	addr := ip.As4()
	hwslice, err := s.arp.QueryResult(addr[:])
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
	return s.arp.DiscardQuery(addr[:])
}

type DHCPResults struct {
	DNSServers    []netip.Addr
	Router        netip.Addr
	AssignedAddr  netip.Addr
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
	stats.TotalReceived = s.totalrecv
	stats.TotalSent = s.totalsent
}

// AssimilateDHCPResults sets the stack's following parameters:
//   - IPv4 address.
//   - DNS server.
//   - Subnet (for ARP resolution of local addresses).
func (stack *StackAsync) AssimilateDHCPResults(results *DHCPResults) error {
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if results.Subnet.IsValid() {
		stack.subnet = results.Subnet
	}
	if results.AssignedAddr.IsValid() {
		err := stack.setIPAddr(results.AssignedAddr)
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
	s.dhcpResults = DHCPResults{
		Router:        router,
		Subnet:        s.dhcp.SubnetPrefix(),
		AssignedAddr:  netip.AddrFrom4(assigned4),
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
		slog.Uint64("sent", s.totalsent),
		slog.Uint64("recv", s.totalrecv),
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
		slog.Uint64("sent", s.totalsent),
		slog.Uint64("recv", s.totalrecv),
	)
}
