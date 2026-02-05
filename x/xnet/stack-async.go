package xnet

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/dhcpv4"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internet"
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

	sysprec int8 // NTP system precision.

	prng uint32

	totalsent uint64
	totalrecv uint64
}

type StackConfig struct {
	StaticAddress         netip.Addr
	DNSServer             netip.Addr
	NTPServer             netip.Addr
	Hostname              string
	MaxTCPConns           int
	RandSeed              int64
	HardwareAddress       [6]byte
	MTU                   uint16
	EthernetTxCRC32Update func(crc uint32, b []byte) uint32
}

func (s *StackAsync) Hostname() string {
	return s.hostname
}

func (s *StackAsync) Demux(carrierData []byte, etherOff int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totalrecv += uint64(len(carrierData) - etherOff)
	return s.link.Demux(carrierData, etherOff)
}

func (s *StackAsync) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, err := s.link.Encapsulate(carrierData, offsetToIP, offsetToFrame)
	s.totalsent += uint64(n)
	return n, err
}

func (s *StackAsync) MTU() int {
	return s.link.MTU()
}

func (s *StackAsync) Reset(cfg StackConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	mac := cfg.HardwareAddress
	addr := cfg.StaticAddress
	s.prng = uint32(cfg.RandSeed)
	if s.prng == 0 {
		return errors.New("zero random seed")
	}
	s.hostname = cfg.Hostname
	if !addr.IsValid() {
		addr = netip.AddrFrom4([4]byte{}) // If static not set DHCP will be performed and address will be zero.
	} else if addr.Is6() {
		return errors.New("IPv6 unsupported as of yet")
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
	const ipNodes = 2 // UDP, TCP ports.
	err = s.ip.Reset(addr, ipNodes)
	if err != nil {
		return err
	}
	//
	err = s.resetARP()
	if err != nil {
		return err
	}
	const udpMaintenanceConns = 3 // DHCP, DNS, NTP.
	err = s.udps.ResetUDP(udpMaintenanceConns)
	if err != nil {
		return err
	}

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

var errInvalidIPAddr = errors.New("invaldi IP address")

func (s *StackAsync) resetARP() error {
	mac := s.link.HardwareAddr6()
	addr := s.ip.Addr()
	if !addr.IsValid() {
		return errInvalidIPAddr
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

// Prand32 generates a pseudo random 32-bit unsigned integer from the internal state and advances the seed.
func (s *StackAsync) Prand32() (randval uint32) {
	s.mu.Lock()
	randval = s.prand32()
	s.mu.Unlock()
	return randval
}

func (s *StackAsync) prand32() uint32 {
	/* Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs" */
	seed := s.prng
	seed ^= seed << 13
	seed ^= seed >> 17
	seed ^= seed << 5
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
	dns4 := s.dnssv.As4()
	s.dnsUDP.SetStackNode(&s.dns, dns4[:], dns.ServerPort)
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
			err = errors.New("bogus IP")
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

	addr4 := addr.As4()
	s.ntpUDP.SetStackNode(&s.ntp, addr4[:], ntp.ServerPort)
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
		return errors.New("unsupported or invalid IP address")
	}
	addr := ip.As4()
	return s.arp.StartQuery(nil, addr[:])
}

// ResultResolveHardwareAddress6
func (s *StackAsync) ResultResolveHardwareAddress6(ip netip.Addr) (hw [6]byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ip.Is4() {
		return hw, errors.New("unsupported or invalid IP address")
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
		return errors.New("unsupported or invalid IP address")
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
			return errors.New("bad DNS server address, IPv6 or invalid")
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
