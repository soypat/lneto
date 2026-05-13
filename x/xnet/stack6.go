package xnet

import (
	"net/netip"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internet"
	"github.com/soypat/lneto/ipv6/icmpv6"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

var _ Stack6 = (*stack6)(nil)

func DefaultStack6() Stack6 {
	return new(stack6)
}

type Stack6 interface {
	Reset6(cfg *StackConfig) error
	Addr6() [16]byte
	SetAddr6(addr [16]byte)

	EnableICMP6(enabled bool) error
	Register6(node lneto.StackNode) error
	DialUDP6(conn *udp.Conn, localPort uint16, raddr [16]byte, rport uint16) error
	DialTCP6(conn *tcp.Conn, localPort uint16, raddr [16]byte, rport uint16, iss tcp.Value) error
	IngressIPv6(ipframe []byte) error
	EgressIPv6(ipframe []byte) (int, error)
	IPv6Stack() lneto.StackNode
}

type stack6 struct {
	ip6      internet.StackIPv6
	udps6    internet.StackPortsMACFiltered
	tcps6    internet.StackPortsMACFiltered
	vld      lneto.Validator
	icmp6buf []byte
	icmp6    icmpv6.Client
	// ndpPending tracks in-flight NDP MAC resolves for outbound connections.
	// macBuf is shared with the registered node so macResolve patches it in place.
	ndpPending []struct {
		addr   [16]byte
		macBuf []byte
	}
}

func (s *stack6) Register6(node lneto.StackNode) error { return s.ip6.Register6(node) }
func (s *stack6) Addr6() [16]byte                      { return s.ip6.Addr6() }
func (s *stack6) SetAddr6(addr [16]byte)               { s.ip6.SetAddr6(addr) }

func (s *stack6) IPv6Stack() lneto.StackNode { return &s.ip6 }

func (s *stack6) Reset6(cfg *StackConfig) error {
	const ipnodes = 3 // ICMP, TCP, UDP.
	err := s.ip6.Reset(&s.vld, ipnodes)
	if err != nil {
		return err
	}
	s.ip6.SetAddr6(cfg.StaticAddress6)
	s.ip6.SetAcceptMulticast6(true) // IPv6 needs multicast to work.

	s.tcps6.ResetTCP(cfg.MaxActiveTCPPorts)
	if cfg.MaxActiveTCPPorts > 0 {
		err = s.ip6.Register6(&s.tcps6)
		if err != nil {
			return err
		}
	}
	s.udps6.ResetUDP(cfg.MaxActiveUDPPorts)
	if cfg.MaxActiveUDPPorts > 0 {
		err = s.ip6.Register6(&s.udps6)
		if err != nil {
			return err
		}
	}

	if cfg.ICMPQueueLimit > 0 {
		minSize := cfg.ICMPQueueLimit * icmpEchoSize
		internal.SliceReuse(&s.icmp6buf, minSize)
		err = s.icmp6.Configure(icmpv6.ClientConfig{
			ResponseQueueBuffer: s.icmp6buf[:cap(s.icmp6buf)],
			ResponseQueueLimit:  cfg.ICMPQueueLimit,
			HashSeed:            uint32(cfg.RandSeed),
			ID:                  cfg.id(),
			OurAddr:             cfg.StaticAddress6,
			OurMAC:              cfg.HardwareAddress,
			NDPCache:            16,
		})
		if err != nil {
			return err
		}
		s.icmp6.SetNDPResolveCallback(s.macResolve)
		ndpSlots := int(cfg.MaxActiveTCPPorts) + int(cfg.MaxActiveUDPPorts)
		internal.SliceReuse(&s.ndpPending, ndpSlots)
		s.ndpPending = s.ndpPending[:cap(s.ndpPending)] // all slots available for scan
	}
	return nil
}

func (s *stack6) EnableICMP6(enabled bool) (err error) {
	if s.icmp6.PingIncomingCapacity() == 0 {
		err = lneto.ErrInvalidConfig
		enabled = false // ensure aborted.
	}
	if enabled {
		if !s.ip6.IsRegistered6(lneto.IPProtoIPv6ICMP) {
			err = s.ip6.Register6(&s.icmp6)
		}
	} else {
		s.icmp6.Abort()
	}
	return err
}

func (s *stack6) IngressIPv6(ipFrame []byte) error {
	return s.ip6.Demux(ipFrame, 0)
}

func (s *stack6) EgressIPv6(ipFrame []byte) (int, error) {
	return s.ip6.Encapsulate(ipFrame, 0, 0)
}

// DialTCP6 opens an active TCP connection to raddr:rport. iss is the initial
// sequence number; the caller supplies a random value. NDP MAC resolution is
// attempted immediately; if the peer MAC is not yet cached a Neighbor
// Solicitation is queued and the connection is held until macResolve fires.
func (s *stack6) DialTCP6(conn *tcp.Conn, localPort uint16, raddr [16]byte, rport uint16, iss tcp.Value) error {
	mac, err := s.ndpDynamicResolve(raddr)
	if err != nil {
		return err
	}
	err = conn.OpenActive(localPort, netip.AddrPortFrom(netip.AddrFrom16(raddr), rport), iss)
	if err != nil {
		return err
	}
	err = s.tcps6.RegisterMACFiltered(conn, mac)
	if err != nil {
		conn.Abort()
		return err
	}
	return nil
}

// DialUDP6 opens a UDP connection to raddr:rport. NDP MAC resolution follows
// the same deferred strategy as DialTCP6.
func (s *stack6) DialUDP6(conn *udp.Conn, localPort uint16, raddr [16]byte, rport uint16) error {
	mac, err := s.ndpDynamicResolve(raddr)
	if err != nil {
		return err
	}
	err = conn.Open(localPort, netip.AddrPortFrom(netip.AddrFrom16(raddr), rport))
	if err != nil {
		return err
	}
	err = s.udps6.RegisterMACFiltered(conn, mac)
	if err != nil {
		conn.Abort()
		return err
	}
	return nil
}

// macResolve is the NDP resolve callback. It patches the shared macBuf of any
// pending outbound connection to addr so StackPortsMACFiltered begins forwarding.
func (s *stack6) macResolve(mac [6]byte, addr [16]byte) {
	for i := range s.ndpPending {
		e := &s.ndpPending[i]
		if e.addr == addr && e.macBuf != nil {
			// macbuf is externally owned and expects it to be written to on resolve.
			copy(e.macBuf, mac[:])
			e.macBuf = nil // free slot for future NDP resolution.
			e.addr = [16]byte{}
		}
	}
}

// ndpDynamicResolve mirrors hwDynamicResolve for IPv6. It returns a
// heap-allocated MAC slice shared with the ndpPending table so that macResolve
// can patch the destination MAC in place once NDP resolves, exactly as the ARP
// subnetTable does for IPv4. Returns nil (no MAC filtering) when NDP is not
// configured.
func (s *stack6) ndpDynamicResolve(raddr [16]byte) ([]byte, error) {
	if !s.ip6.IsRegistered6(lneto.IPProtoIPv6ICMP) {
		return nil, nil // NDP unavailable; routing layer handles MAC.
	}
	mac, err := s.icmp6.NDPCacheLookup(raddr)
	macBuf := make([]byte, 6)
	if err == nil {
		copy(macBuf, mac[:])
		return macBuf, nil
	}
	if err = s.icmp6.NDPStartQuery(raddr, true); err != nil {
		return nil, err
	}
	// Find a freed slot or grow the pending slice.
	idx := -1
	for i := range s.ndpPending {
		if s.ndpPending[i].macBuf == nil {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, lneto.ErrExhausted
	}
	e := &s.ndpPending[idx]
	e.addr = raddr
	e.macBuf = macBuf
	return macBuf, nil
}
