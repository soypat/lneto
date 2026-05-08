package xnet

import (
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"sync"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/dhcpv4"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internet"
	"github.com/soypat/lneto/ipv4/icmpv4"
	"github.com/soypat/lneto/ipv6/icmpv6"
	"github.com/soypat/lneto/ntp"
)

type StackBigAsync struct {
	mu       sync.Mutex
	hostname string
	clientID string
	link     internet.StackEthernet
	ip       internet.StackIP
	arp      arp.Handler
	icmp     icmpv4.Client
	icmp6    icmpv6.Client
	udps     internet.StackPortsMACFiltered
	tcps     internet.StackPortsMACFiltered

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

	prng rand.ChaCha8

	addrBuf [6]byte // Temporary buffer for As4()/HardwareAddr6() results to avoid heap escapes.

	stats Statistics
}

func (sb *StackBigAsync) Reset(cfg StackConfig) error {
	mac := cfg.HardwareAddress
	if !cfg.StaticAddress.IsValid() {
		cfg.StaticAddress = netip.AddrFrom4([4]byte{})
	}
	if cfg.RandSeed == 0 || cfg.Hostname == "" || cfg.PassivePeers > 255 ||
		internal.IsZeroed(mac) {
		return lneto.ErrInvalidConfig
	}
	sb.mu.Lock()
	defer sb.mu.Unlock()
	id := uint16(cfg.Hostname[len(cfg.Hostname)-1]) - '0' // Treat last character of hostname as number.
	// Seed random generator.
	var seed [32]byte
	binary.LittleEndian.PutUint64(seed[:], uint64(cfg.RandSeed))
	copy(seed[8:], mac[:])
	n := copy(seed[8+6:], cfg.StaticAddress.AsSlice())
	n += copy(seed[8+6+n:], cfg.Hostname)
	sb.prng.Seed(seed)
	// configure link.
	err := cfg.ConfigureLink(&sb.link, sb.arpt.patchEgressMAC)
	if err != nil {
		return err
	}
	sb.hostname = cfg.Hostname
	err = cfg.ConfigureIP(&sb.ip)
	if err != nil {
		return err
	}

	sb.arpt.passivePeers = uint8(cfg.PassivePeers)
	err = sb.resetARP()
	if err != nil {
		return err
	}
	udpConns := 3 + cfg.MaxActiveUDPPorts // DHCP, DNS, NTP + user-registered.
	sb.udps.ResetUDP(udpConns)
	internal.SliceReuse(&sb.userUDPs, int(cfg.MaxActiveUDPPorts))
	tcpConns := 1 + cfg.MaxActiveTCPPorts // DNS/TCP + user-registered.
	sb.tcps.ResetTCP(tcpConns)

	// Register IP to Link, UDP/TCP to IP.
	err = sb.link.Register(&sb.ip)
	if err != nil {
		return err
	}
	err = sb.ip.Register(&sb.udps)
	if err != nil {
		return err
	}
	err = sb.ip.Register(&sb.tcps)
	if err != nil {
		return err
	}
	if cfg.ICMPQueueLimit > 0 {
		// shared buffer since only one or the other are active at a time.
		icmpBuf := make([]byte, cfg.ICMPQueueLimit*64)
		err = sb.icmp.Configure(icmpv4.ClientConfig{
			ResponseQueueBuffer: icmpBuf,
			ResponseQueueLimit:  cfg.ICMPQueueLimit,
			HashSeed:            sb.prand32(),
			ID:                  id,
		})
		if err != nil {
			return err
		}
		err = sb.icmp6.Configure(icmpv6.ClientConfig{
			ResponseQueueBuffer: icmpBuf,
			ResponseQueueLimit:  cfg.ICMPQueueLimit,
			HashSeed:            sb.prand32(),
			ID:                  id,
			NDPCache:            32,
		})
		if err != nil {
			return err
		}
	}
	err = sb.setIP(cfg.StaticAddress)
	if err != nil {
		return err
	}

	var timebuf [4]int64
	sb.sysprec = ntp.CalculateSystemPrecision(nil, timebuf[:])
	if sb.clientID == "" {
		sb.clientID = "lneto-" + sb.hostname
	}
	sb.stats = Statistics{}
	sb.dnssv = cfg.DNSServer
	return nil
}

func (sb *StackBigAsync) Hostname() string { return sb.hostname }

// IngressEthernet receives an Ethernet frame from the network and processes it through the stack. The frame should include the Ethernet header and payload and CRC if enabled.
func (sb *StackBigAsync) IngressEthernetPackets(bufs [][]byte, offset int) (lastErr error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	for _, buf := range bufs {
		err := sb.link.Demux(buf, offset)
		if err != nil {
			lastErr = err
		}
		sb.stats.TotalReceived += uint64(len(buf))
	}
	return lastErr
}

func (sb *StackBigAsync) EgressEthernetPackets(bufs [][]byte, sizes []int, offset int) (lastErr error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	for i, buf := range bufs {
		var err error
		sizes[i], err = sb.link.Encapsulate(buf, -1, offset)
		if err != nil {
			lastErr = err
		} else if sizes[i] == 0 {
			break
		}
		sb.stats.TotalSent += uint64(sizes[i])
	}
	return lastErr
}

func (s *StackBigAsync) resetARP() error {
	mac := s.link.HardwareAddr6()
	addr := s.ip.Addr()
	if !addr.IsValid() {
		return lneto.ErrInvalidAddr
	}
	proto := ethernet.TypeIPv4
	if addr.Is6() {
		proto = ethernet.TypeIPv6
		s.icmp6.Abort()
	}
	err := s.arp.Reset(arp.HandlerConfig{
		HardwareAddr: mac[:],
		ProtocolAddr: addr.AsSlice(),
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
	err = s.link.Register(&s.arp)
	if err != nil {
		return err
	}
	return nil
}

func (sb *StackBigAsync) setIP(addr netip.Addr) error {
	err := sb.ip.SetAddr(addr)
	if err != nil {
		return err
	}
	if addr.Is6() {
		sb.icmp.Abort()
		sb.icmp6.SetAddr(addr.As16()) // Needs address to set.
		sb.icmp6.SetNDPResolveCallback(func(mac [6]byte, addr [16]byte) {
			sb.arpt.onResolve(mac[:], addr[:])
		})
		err = sb.ip.Register(&sb.icmp6)
	} else {
		sb.icmp6.Abort()
		err = sb.ip.Register(&sb.icmp)
	}
	if err != nil {
		return err
	}
	err = sb.resetARP()
	return err
}

func (sb *StackBigAsync) Addr() netip.Addr {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.ip.Addr()
}

func (sb *StackBigAsync) SetAddr(addr netip.Addr) error {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.setIP(addr)
}

func (s *StackBigAsync) SetSubnet(subnetMask netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()
}

func (sb *StackBigAsync) Prand64() uint64 {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.prand64()
}

func (s *StackBigAsync) SetHardwareAddress(hw [6]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.link.SetHardwareAddr6(hw)
	return s.resetARP()
}

func (s *StackBigAsync) HardwareAddress() (hw [6]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.link.HardwareAddr6()
}

func (s *StackBigAsync) SetGateway6(gwhw [6]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.link.SetGateway6(gwhw)
}

func (s *StackBigAsync) Gateway6() [6]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.link.Gateway6()
}

// EnableICMP registers an ICMP handler to the stack when enabled is true.
// If enabled=false the currently registered ICMP handler is unregistered and state reset.
func (s *StackBigAsync) EnableICMP(enabled bool) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.icmpCapable() {
		err = lneto.ErrInvalidConfig
		enabled = false // ensure aborted.
	}
	if enabled {

	} else {
		s.icmp.Abort()
		s.icmp6.Abort()
	}
	return err
}

func (s *StackBigAsync) icmpCapable() bool {

	if s.is4() {
		return s.icmp.IncomingEchoCapacity() > 0
	}
	return s.icmp6.PingIncomingCapacity() > 0
}

func (s *StackBigAsync) is4() bool {
	return s.ip.Addr().Is4()
}

func (sb *StackBigAsync) prand64() uint64 { return sb.prng.Uint64() }
func (sb *StackBigAsync) prand32() uint32 { return uint32(sb.prng.Uint64()) }
