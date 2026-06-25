package xnet

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dhcp/dhcpv4"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/tcp"
)

const (
	maxIter = 1000
)

var (
	errDeadlineExceed = errors.New("cywnet: deadline exceeded")
)

func (s *StackAsync) StackBlocking(stackProtoBackoff lneto.BackoffStrategy) StackBlocking {
	if stackProtoBackoff == nil {
		panic("nil backoff to StackBlocking")
	}
	return StackBlocking{
		async:    s,
		_backoff: stackProtoBackoff,
	}
}

type StackBlocking struct {
	async    *StackAsync
	_backoff lneto.BackoffStrategy
}

func (s StackBlocking) nanotime() int64 {
	return time.Now().UnixNano()
}

func (s StackBlocking) deadlineTO(timeout time.Duration) int64 {
	return int64(timeout) + s.nanotime()
}

func (s StackBlocking) DoDHCPv4(reqAddr [4]byte, timeout time.Duration) (*DHCPResults, error) {
	err := s.async.StartDHCPv4Request(reqAddr)
	if err != nil {
		return nil, err
	}
	var backoffs uint
	deadline := s.deadlineTO(timeout)
	requested := false
	var lastState dhcpv4.ClientState
	for range maxIter {
		s.async.mu.Lock()
		state := s.async.dhcp.State()
		s.async.mu.Unlock()
		if state == lastState {
			if err = s.checkDeadline(deadline); err != nil {
				return nil, err
			}
			s.backoff(backoffs)
			backoffs++
		} else {
			// State change indicates something happened.
			backoffs = 0
			lastState = state
			requested = requested || state > dhcpv4.StateInit
			if requested && state == dhcpv4.StateInit {
				return nil, errors.New("DHCP NACK")
			} else if state == dhcpv4.StateBound {
				break // DHCP done succesfully.
			}
		}
	}
	return s.async.ResultDHCP()
}

func (s StackBlocking) DoPing(hostAddr netip.Addr, timeout time.Duration) (roundtrip time.Duration, err error) {
	if !hostAddr.Is4() {
		return 0, lneto.ErrInvalidAddr
	}
	var buf [16]byte
	s.async.mu.Lock()
	s.async.prandRead(buf[:])
	key, err := s.async.icmp.PingStart(hostAddr.As4(), buf[:], 56) // size=56 so ICMP size is 64, like linux.
	s.async.mu.Unlock()
	if err != nil {
		return 0, err
	}
	start := time.Now()
	var backoffs uint
	for range maxIter {
		s.async.mu.Lock()
		completed, exists := s.async.icmp.PingPop(key)
		s.async.mu.Unlock()
		if !exists {
			return 0, net.ErrClosed // lneto.ErrAborted
		}
		elapsed := time.Since(start)
		if completed {
			return elapsed, nil
		} else if elapsed > timeout {
			break
		}
		s.backoff(backoffs)
		backoffs++
	}
	return 0, errDeadlineExceed
}

func (s StackBlocking) DoNTP(hostAddr netip.Addr, timeout time.Duration) (offset time.Duration, err error) {
	err = s.async.StartNTP(hostAddr)
	if err != nil {
		return -1, err
	}

	deadline := s.deadlineTO(timeout)
	var done bool
	var backoffs uint
	for range maxIter {
		offset, done = s.async.ResultNTPOffset()
		if done {
			return offset, nil
		} else if err = s.checkDeadline(deadline); err != nil {
			return -1, err
		}
		s.backoff(backoffs)
		backoffs++
	}
	return -1, errDeadlineExceed
}

func (s StackBlocking) DoResolveHardwareAddress6(addr netip.Addr, timeout time.Duration) (hw [6]byte, err error) {
	err = s.async.StartResolveHardwareAddress6(addr)
	if err != nil {
		return hw, err
	}
	var backoffs uint
	deadline := s.deadlineTO(timeout)
	for range maxIter {
		hw, err = s.async.ResultResolveHardwareAddress6(addr)
		if err == nil {
			break
		} else if err = s.checkDeadline(deadline); err != nil {
			break
		}
		s.backoff(backoffs)
		backoffs++
		err = errDeadlineExceed // Ensure that if iterations done error is returned.
	}
	ip4 := addr.As4()
	s.async.arp.CacheRemove(ip4[:])
	return hw, err
}

func (s StackBlocking) DoLookupIP(host string, timeout time.Duration) (addrs []netip.Addr, err error) {
	return s.DoLookupIPType(host, timeout, dns.TypeA)
}

// DoLookupIPType resolves host for the given record type (dns.TypeA or dns.TypeAAAA),
// blocking until a response arrives or the timeout elapses.
func (s StackBlocking) DoLookupIPType(host string, timeout time.Duration, qtype dns.Type) (addrs []netip.Addr, err error) {
	err = s.async.StartLookupIPType(host, qtype)
	if err != nil {
		return nil, err
	}

	deadline := s.deadlineTO(timeout)
	var backoffs uint
	for range maxIter {
		addrs, completed, err := s.async.ResultLookupIP(host)
		if completed {
			return addrs, err
		} else if err = s.checkDeadline(deadline); err != nil {
			return nil, err
		}
		s.backoff(backoffs)
		backoffs++
	}
	return nil, errDeadlineExceed
}

var errTCPFailedToConnect = errors.New("tcp failed to connect")

func (s StackBlocking) DoDialTCP(conn *tcp.Conn, localPort uint16, addrp netip.AddrPort, timeout time.Duration) (err error) {
	err = s.async.DialTCP(conn, localPort, addrp)
	if err != nil {
		return err
	}
	err = s.waitDialTCP(conn, timeout)
	if err != nil {
		conn.Abort()
	}
	return err
}

func (s StackBlocking) waitDialTCP(conn *tcp.Conn, timeout time.Duration) (err error) {
	deadline := s.deadlineTO(timeout)
	var backoffs uint
	for range maxIter {
		state := conn.State()
		if state == tcp.StateEstablished {
			return nil
		} else if state == tcp.StateSynSent || state == tcp.StateSynRcvd || conn.AwaitingSynSend() {
			if err = s.checkDeadline(deadline); err != nil {
				return err
			}
		} else {
			// Unexpected state, abort and terminate connection.
			return errTCPFailedToConnect
		}
		s.backoff(backoffs)
		backoffs++
	}
	return errDeadlineExceed
}

func (s StackBlocking) checkDeadline(deadline int64) error {
	if s.nanotime() > deadline {
		return errDeadlineExceed
	}
	return nil
}

func (s StackBlocking) backoff(consecutiveBackoffs uint) {
	backoff(s._backoff, consecutiveBackoffs)
}

func backoff(bo lneto.BackoffStrategy, consecutiveBackoffs uint) {
	bo.Do(consecutiveBackoffs)
}
