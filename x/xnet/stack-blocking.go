package xnet

import (
	"errors"
	"net/netip"
	"time"

	"github.com/soypat/lneto/dhcpv4"
	"github.com/soypat/lneto/tcp"
)

const (
	maxIter = 1000
)

var (
	errDeadlineExceed = errors.New("cywnet: deadline exceeded")
)

func (s *StackAsync) StackBlocking(loopSleep time.Duration) StackBlocking {
	if loopSleep < 0 {
		panic("invalid sleep")
	} else if loopSleep > 3*time.Second {
		// loopSleep should be a very small amount of time for stack to remain responsive.
		panic("StackBlocking sleep too large")
	}
	return StackBlocking{
		async:     s,
		loopSleep: loopSleep,
	}
}

type StackBlocking struct {
	async     *StackAsync
	loopSleep time.Duration
}

func (s StackBlocking) DoDHCPv4(reqAddr [4]byte, timeout time.Duration) (*DHCPResults, error) {
	err := s.async.StartDHCPv4Request(reqAddr)
	if err != nil {
		return nil, err
	}
	sleep := s.loopSleep
	deadline := time.Now().Add(timeout)
	requested := false
	for i := 0; i < maxIter; i++ {
		state := s.async.dhcp.State()
		requested = requested || state > dhcpv4.StateInit
		if requested && state == dhcpv4.StateInit {
			return nil, errors.New("DHCP NACK")
		} else if state == dhcpv4.StateBound {
			break // DHCP done succesfully.
		} else if err = s.checkDeadline(deadline); err != nil {
			return nil, err
		}
		time.Sleep(sleep)
	}
	return s.async.ResultDHCP()
}

func (s StackBlocking) DoNTP(hostAddr netip.Addr, timeout time.Duration) (offset time.Duration, err error) {
	err = s.async.StartNTP(hostAddr)
	if err != nil {
		return -1, err
	}
	sleep := s.loopSleep
	deadline := time.Now().Add(timeout)
	var done bool
	for i := 0; i < maxIter; i++ {
		offset, done = s.async.ResultNTPOffset()
		if done {
			return offset, nil
		} else if err = s.checkDeadline(deadline); err != nil {
			return -1, err
		}
		time.Sleep(sleep)
	}
	return -1, errDeadlineExceed
}

func (s StackBlocking) DoResolveHardwareAddress6(addr netip.Addr, timeout time.Duration) (hw [6]byte, err error) {
	err = s.async.StartResolveHardwareAddress6(addr)
	if err != nil {
		return hw, err
	}
	sleep := s.loopSleep
	deadline := time.Now().Add(timeout)
	for i := 0; i < maxIter; i++ {
		hw, err = s.async.ResultResolveHardwareAddress6(addr)
		if err == nil {
			break
		} else if err = s.checkDeadline(deadline); err != nil {
			break
		}
		time.Sleep(sleep)
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
	sleep := s.loopSleep
	deadline := time.Now().Add(timeout)
	for i := 0; i < maxIter; i++ {
		addrs, completed, err := s.async.ResultLookupIP(host)
		if completed {
			return addrs, err
		} else if err = s.checkDeadline(deadline); err != nil {
			return nil, err
		}
		time.Sleep(sleep)
	}
	return nil, errDeadlineExceed
}

var errTCPFailedToConnect = errors.New("tcp failed to connect")

func (s StackBlocking) DoDialTCP(conn *tcp.Conn, localPort uint16, addrp netip.AddrPort, timeout time.Duration) (err error) {
	err = s.async.DialTCP(conn, localPort, addrp)
	if err != nil {
		return err
	}
	sleep := s.loopSleep
	deadline := time.Now().Add(timeout)
	for i := 0; i < maxIter; i++ {
		state := conn.State()
		if state == tcp.StateEstablished {
			return nil
		} else if state == tcp.StateSynSent || state == tcp.StateSynRcvd || conn.InternalHandler().AwaitingSynSend() {
			if err = s.checkDeadline(deadline); err != nil {
				conn.Abort()
				return err
			}
			time.Sleep(sleep)
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
