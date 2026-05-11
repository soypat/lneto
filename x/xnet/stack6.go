package xnet

import (
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internet"
	"github.com/soypat/lneto/ipv6/icmpv6"
)

type stack6 struct {
	ip6      internet.StackIPv6
	udps6    internet.StackPortsMACFiltered
	tcps6    internet.StackPortsMACFiltered
	icmp6buf []byte
	icmp6    icmpv6.Client
}

func (s *stack6) Reset6(cfg *StackConfig, vld *lneto.Validator) error {
	const ipnodes = 3 // ICMP, TCP, UDP.
	err := s.ip6.Reset(vld, ipnodes)
	if err != nil {
		return err
	}

	s.ip6.SetAddr6(cfg.StaticAddress6)
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

	s.ip6.SetAcceptMulticast6(true) // IPv6 needs multicast to work.
	if cfg.ICMPQueueLimit > 0 {
		if len(s.icmp6buf) == 0 {
			s.icmp6buf = make([]byte, cfg.ICMPQueueLimit*icmpEchoSize)
		}
		err = s.icmp6.Configure(icmpv6.ClientConfig{
			ResponseQueueBuffer: s.icmp6buf,
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
	}
	return nil
}

func (s *stack6) enableICMP(enabled bool) (err error) {
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

func (s *stack6) IngressIP(ipFrame []byte) error {
	return s.ip6.Demux(ipFrame, 0)
}

func (s *stack6) EgressIP(ipFrame []byte) (int, error) {
	return s.ip6.Encapsulate(ipFrame, 0, 0)
}
