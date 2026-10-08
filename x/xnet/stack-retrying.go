package xnet

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/tcp"
)

func (s *StackAsync) StackRetrying(stackProtoBackoff lneto.BackoffStrategy) StackRetrying {
	if stackProtoBackoff == nil {
		panic("nil backoff to StackRetrying")
	}
	return s.StackBlocking(stackProtoBackoff).StackRetrying()
}

func (s StackBlocking) StackRetrying() StackRetrying {
	return StackRetrying{block: s}
}

var (
	errRetriesExceeded = errors.New("cywnet: retries exceeded")
)

type StackRetrying struct {
	block StackBlocking
}

func (s StackRetrying) DoDHCPv4(reqAddr [4]byte, timeout time.Duration, retries int) (results *DHCPResults, err error) {
	expectEnd := time.Now().Add(timeout * time.Duration(retries))
	for i := range retries {
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
	for i := range retries {
		if i > 0 {
			println("Retrying NTP")
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

// DoLookupIP resolves host's IPv4 addresses, retrying on failure. See [StackBlocking.DoLookupIPType].
func (s StackRetrying) DoLookupIP(dst []netip.Addr, host dns.Name, timeout time.Duration, retries int) (naddr int, err error) {
	if !s.block.async.dnssv.IsValid() {
		return 0, errNoDNSServer
	}
	expectEnd := time.Now().Add(timeout * time.Duration(retries))
	for range retries {
		naddr, err = s.block.DoLookupIP(dst, host, timeout)
		if err == nil {
			return naddr, nil
		}
	}
	if time.Now().Before(expectEnd) {
		return naddr, err
	}
	return 0, errRetriesExceeded
}

func (s StackRetrying) DoResolveHardwareAddress6(addr netip.Addr, timeout time.Duration, retries int) (hw [6]byte, err error) {
	expectEnd := time.Now().Add(timeout * time.Duration(retries))
	for range retries {
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

func (s StackRetrying) DoDialTCP(ctx context.Context, conn *tcp.Conn, localPort uint16, addrp netip.AddrPort, timeout time.Duration, retries int) (err error) {
	err = s.doDialTCP(ctx, conn, localPort, addrp, timeout, retries)
	if err != nil {
		conn.Abort()
	}
	return err
}

func (s StackRetrying) doDialTCP(ctx context.Context, conn *tcp.Conn, localPort uint16, addrp netip.AddrPort, timeout time.Duration, retries int) (err error) {
	expectEnd := time.Now().Add(timeout * time.Duration(retries))
	var firstErr error
	for i := range retries {
		if err = ctx.Err(); err != nil {
			return err
		}
		if i == 0 || conn.State().IsClosed() {
			err = s.block.async.DialTCP(conn, localPort, addrp)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
		} else if conn.IsAwaitingControl() {
			conn.RequeueControl()
		}

		err = s.block.waitDialTCP(ctx, conn, timeout)
		if err == nil || err == lneto.ErrConnRefused || ctx.Err() != nil {
			return err // Success or final failure: retrying cannot help.
		} else if firstErr == nil {
			firstErr = err
		}
		if !conn.IsAwaitingControl() {
			conn.Abort()
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
