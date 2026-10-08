package xnet

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dhcp/dhcpv4"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/tcp"
)

// Blocking waits below are bounded by their deadline instead of an iteration
// count: with a non-sleeping backoff such as [lneto.BackoffFlagGosched] a cap
// of N spins expires well before the caller's timeout (~20ms for the former
// 1000 iterations), so the timeout argument had no effect.

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
	return s.async.mono.Nanotime()
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
	for ok := true; ok; ok = s.checkDeadline(deadline) == nil {
		s.async.mu.Lock()
		state := s.async.dhcp.State()
		s.async.mu.Unlock()
		if state == lastState {
			s.backoff(backoffs)
			backoffs++
			continue
		}
		// State change indicates something happened.
		backoffs = 0
		lastState = state
		requested = requested || state > dhcpv4.StateInit
		if requested && state == dhcpv4.StateInit {
			return nil, errors.New("DHCP NACK")
		} else if state == dhcpv4.StateBound {
			return s.async.ResultDHCP() // DHCP done succesfully.
		}
	}
	return nil, errDeadlineExceed
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
	for ok := true; ok; ok = time.Since(start) <= timeout {
		s.async.mu.Lock()
		completed, exists := s.async.icmp.PingPop(key)
		s.async.mu.Unlock()
		if !exists {
			return 0, net.ErrClosed // lneto.ErrAborted
		} else if completed {
			return time.Since(start), nil
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
	for ok := true; ok; ok = s.checkDeadline(deadline) == nil {
		offset, done = s.async.ResultNTPOffset()
		if done {
			return offset, nil
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
	for ok := true; ok; ok = s.checkDeadline(deadline) == nil {
		hw, err = s.async.ResultResolveHardwareAddress6(addr)
		if err == nil {
			break
		}
		s.backoff(backoffs)
		backoffs++
	}
	if err != nil {
		err = errDeadlineExceed // Loop only ends on the deadline; err is stale.
	}
	ip4 := addr.As4()
	s.async.arp.CacheRemove(ip4[:])
	return hw, err
}

func (s StackBlocking) DoLookupIP(dst []netip.Addr, host dns.Name, timeout time.Duration) (naddr int, err error) {
	return s.DoLookupIPType(dst, host, timeout, dns.TypeA)
}

const (
	// maxCNAMEqueries is the maximum number of queries DoLookupIPType sends while
	// following CNAME-only answers, including the query for the original host.
	maxCNAMEqueries = 3
	// cnameAnswerHeadroom is how many answer records DoLookupIPType decodes beyond len(dst)
	// for the CNAME records that precede the addresses they alias in a response.
	cnameAnswerHeadroom = 8
)

// DoLookupIPType resolves host for the given record type (dns.TypeA or dns.TypeAAAA),
// blocking until a response arrives or the timeout elapses. It writes up to len(dst) addresses
// into dst and returns how many were written. CNAME-only answers are followed with a new
// query for the canonical name.
func (s StackBlocking) DoLookupIPType(dst []netip.Addr, host dns.Name, timeout time.Duration, qtype dns.Type) (naddr int, err error) {
	if len(dst) == 0 {
		return 0, lneto.ErrShortBuffer
	}
	deadline := s.deadlineTO(timeout)
	nans := min(len(dst)+cnameAnswerHeadroom, math.MaxUint16)
	txid, err := s.async.LookupIPStart(host, qtype, uint16(nans))
	if err != nil {
		return 0, err
	}
	// Pop whichever lookup is current on return so its slot is freed, timeouts included.
	defer func() { s.async.LookupIPPop(txid) }()
	for queries := 1; ; queries++ {
		n, err := s.waitLookupIP(txid, deadline, dst)
		if err != dns.ErrUnresolvedCNAME || queries == maxCNAMEqueries {
			return n, err // nil(OK) or non-only-cname error.
		}
		hopTxid, err := s.async.LookupIPFollowCNAME(txid)
		if err != nil {
			return 0, err // txid still active: popped by defer.
		}
		txid = hopTxid
	}
}

// waitLookupIP polls the lookup txid until it is done or the deadline passes.
func (s StackBlocking) waitLookupIP(txid uint16, deadline int64, dst []netip.Addr) (n int, err error) {
	var backoffs uint
	for ok := true; ok; ok = s.checkDeadline(deadline) == nil {
		n, state, err := s.async.LookupIPResult(txid, dst)
		if !state.InProgress() {
			return n, err
		}
		s.backoff(backoffs)
		backoffs++
	}
	return 0, errDeadlineExceed
}

var errTCPFailedToConnect = errors.New("tcp failed to connect")

func (s StackBlocking) DoDialTCP(ctx context.Context, conn *tcp.Conn, localPort uint16, addrp netip.AddrPort, timeout time.Duration) (err error) {
	err = s.async.DialTCP(conn, localPort, addrp)
	if err != nil {
		return err
	}
	err = s.waitDialTCP(ctx, conn, timeout)
	if err != nil {
		conn.Abort()
	}
	return err
}

func (s StackBlocking) waitDialTCP(ctx context.Context, conn *tcp.Conn, timeout time.Duration) (err error) {
	deadline := s.deadlineTO(timeout)
	var backoffs uint
	for ok := true; ok; ok = s.checkDeadline(deadline) == nil {
		if err = ctx.Err(); err != nil {
			return err
		}
		state := conn.State()
		if state == tcp.StateEstablished {
			return nil
		} else if state != tcp.StateSynSent && state != tcp.StateSynRcvd && !conn.AwaitingSynSend() {
			// Unexpected state, abort and terminate connection.
			if err = conn.Err(); err != nil {
				return err
			}
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
