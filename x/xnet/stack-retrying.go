package xnet

import (
	"errors"
	"net/netip"
	"time"

	"github.com/soypat/lneto/tcp"
)

func (s *StackAsync) StackRetrying() StackRetrying {
	return StackRetrying{
		block: s.StackBlocking(),
	}
}

var (
	errRetriesExceeded = errors.New("cywnet: retries exceeded")
)

type StackRetrying struct {
	block StackBlocking
}

func (s StackRetrying) DoDHCPv4(reqAddr [4]byte, timeout time.Duration, retries int) (results *DHCPResults, err error) {
	expectEnd := time.Now().Add(timeout * time.Duration(retries))
	for i := 0; i < retries; i++ {
		if i > 0 {
			println("Retrying DHCP")
		}
		results, err = s.block.DoDHCPv4(reqAddr, timeout)
		if err == nil {
			return results, nil
		}
	}
	if time.Now().Before(expectEnd) {
		return nil, err
	}
	return nil, errRetriesExceeded
}

func (s StackRetrying) DoNTP(ntpHost netip.Addr, timeout time.Duration, retries int) (offset time.Duration, err error) {
	expectEnd := time.Now().Add(timeout * time.Duration(retries))
	for i := 0; i < retries; i++ {
		if i > 0 {
			println("Retrying DHCP")
		}
		offset, err = s.block.DoNTP(ntpHost, timeout)
		if err == nil {
			return offset, nil
		}
	}
	if time.Now().Before(expectEnd) {
		return -1, err
	}
	return -1, errRetriesExceeded
}
func (s StackRetrying) DoLookupIP(host string, timeout time.Duration, retries int) (addrs []netip.Addr, err error) {
	expectEnd := time.Now().Add(timeout * time.Duration(retries))
	for i := 0; i < retries; i++ {
		addrs, err = s.block.DoLookupIP(host, timeout)
		if err == nil {
			return addrs, nil
		}
	}
	if time.Now().Before(expectEnd) {
		return addrs, err
	}
	return nil, errRetriesExceeded
}

func (s StackRetrying) DoResolveHardwareAddress6(addr netip.Addr, timeout time.Duration, retries int) (hw [6]byte, err error) {
	expectEnd := time.Now().Add(timeout * time.Duration(retries))
	for i := 0; i < retries; i++ {
		hw, err = s.block.DoResolveHardwareAddress6(addr, timeout)
		if err == nil {
			return hw, nil
		}
	}
	if time.Now().Before(expectEnd) {
		return hw, err
	}
	return hw, errRetriesExceeded
}

func (s StackRetrying) DoDialTCP(conn *tcp.Conn, localPort uint16, addrp netip.AddrPort, timeout time.Duration, retries int) (err error) {
	expectEnd := time.Now().Add(timeout * time.Duration(retries))
	var firstErr error
	for i := 0; i < retries; i++ {
		err = s.block.DoDialTCP(conn, localPort, addrp, timeout)
		if err == nil {
			return nil
		} else if firstErr == nil {
			firstErr = err
		}
	}
	if time.Now().Before(expectEnd) {
		if err != firstErr {
			return errors.Join(firstErr, err)
		}
		return err
	}
	return errRetriesExceeded
}
