package xnet

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dhcpv4"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/tcp"
)

const (
	maxIter = 1000
)

var (
	errDeadlineExceed = errors.New("cywnet: deadline exceeded")
)

func (s *StackAsync) StackBlocking(stackProtoBackoff lneto.BackoffStrategy) StackBlocking {
	return StackBlocking{
		async:    s,
		_backoff: stackProtoBackoff,
	}
}

type StackBlocking struct {
	async    *StackAsync
	_backoff lneto.BackoffStrategy
}

func (s StackBlocking) DoDHCPv4(reqAddr [4]byte, timeout time.Duration) (*DHCPResults, error) {
	err := s.async.StartDHCPv4Request(reqAddr)
	if err != nil {
		return nil, err
	}
	var backoffs uint
	deadline := time.Now().Add(timeout)
	requested := false
	var lastState dhcpv4.ClientState
	for i := 0; i < maxIter; i++ {
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
	for i := 0; i < maxIter; i++ {
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

	deadline := time.Now().Add(timeout)
	var done bool
	var backoffs uint
	for i := 0; i < maxIter; i++ {
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
	deadline := time.Now().Add(timeout)
	for i := 0; i < maxIter; i++ {
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
	s.async.arp.DiscardQuery(ip4[:])
	return hw, err
}

func (s StackBlocking) DoLookupIP(host string, timeout time.Duration) (addrs []netip.Addr, err error) {
	err = s.async.StartLookupIP(host)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	var backoffs uint
	for i := 0; i < maxIter; i++ {
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
	deadline := time.Now().Add(timeout)
	var backoffs uint
	for i := 0; i < maxIter; i++ {
		state := conn.State()
		if state == tcp.StateEstablished {
			return nil
		} else if state == tcp.StateSynSent || state == tcp.StateSynRcvd || conn.InternalHandler().AwaitingSynSend() {
			if err = s.checkDeadline(deadline); err != nil {
				conn.Abort()
				return err
			}
			s.backoff(backoffs)
			backoffs++
		} else {
			// Unexpected state, abort and terminate connection.
			conn.Abort()
			return errTCPFailedToConnect
		}
	}
	return errDeadlineExceed
}

func (s StackBlocking) checkDeadline(deadline time.Time) error {
	if time.Since(deadline) > 0 {
		return errDeadlineExceed
	}
	return nil
}

func (s StackBlocking) backoff(consecutiveBackoffs uint) {
	backoff(s._backoff, consecutiveBackoffs)
}

func backoff(bo lneto.BackoffStrategy, consecutiveBackoffs uint) {
	if bo != nil {
		bo.Do(consecutiveBackoffs)
	} else {
		internal.BackoffStackProto(consecutiveBackoffs)
	}
}
