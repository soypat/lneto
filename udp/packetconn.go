package udp

import (
	"math"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/soypat/lneto"
)

// lnetopacketconn is the lneto interpretation of
// [net.PacketConn], making use of better types.
type lnetopacketconn interface { // size=16 (0x10)
	ReadFrom(p []byte) (n int, addr netip.AddrPort, err error)
	WriteTo(p []byte, addr netip.AddrPort) (n int, err error)
	Close() error
	LocalAddr() netip.AddrPort
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

var (
	_ lnetopacketconn = (*PacketConn)(nil)
	_ lneto.StackNode = (*PacketConn)(nil)
)

// PacketConn is the UDP equivalent of [net.PacketConn] and implements
// [lnetopacketconn] and [lneto.StackNode]. It is thread safe.
type PacketConn struct {
	mu        sync.Mutex
	m         muxHandler
	localAddr netip.AddrPort
	_backoff  lneto.BackoffStrategy
	rdead     time.Time
	wdead     time.Time
}

// PacketConnConfig configures a [PacketConn] with pre-allocated buffers and queue sizes.
type PacketConnConfig struct {
	RxBuf       []byte
	TxBuf       []byte
	RxQueueSize int
	TxQueueSize int
	// RWBackoff sets the backoff policy when data is unavailable on ReadFrom or buffer is full on WriteTo.
	// If not set a default backoff strategy will be used. See [internal.BackoffConnRW].
	RWBackoff lneto.BackoffStrategy
}

// Configure initializes the PacketConn with the given buffer and queue configuration.
// Must be called before [PacketConn.Open]. Calling Configure on an active connection aborts it.
func (pc *PacketConn) Configure(cfg PacketConnConfig) error {
	if cfg.RWBackoff == nil {
		return lneto.ErrMissingHALConfig
	}
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.abort()
	err := pc.m.Configure(MuxConfig{
		RxBuf:       cfg.RxBuf,
		TxBuf:       cfg.TxBuf,
		RxQueueSize: cfg.RxQueueSize,
		TxQueueSize: cfg.TxQueueSize,
	})
	if err != nil {
		return err
	}
	pc._backoff = cfg.RWBackoff
	return nil
}

// Open sets the local address and enables port filtering for incoming datagrams.
func (pc *PacketConn) Open(localAddr netip.AddrPort) error {
	return pc.OpenPortRange(localAddr, 1)
}

// OpenPortRange is [PacketConn.Open] for ports [localAddr.Port(), localAddr.Port()+numPorts).
func (pc *PacketConn) OpenPortRange(localAddr netip.AddrPort, numPorts uint16) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.localAddr.IsValid() {
		return errStillOpen
	}
	if !localAddr.IsValid() || localAddr.Port() == 0 {
		return lneto.ErrZeroSource
	} else if numPorts == 0 || int(localAddr.Port())+int(numPorts) > math.MaxUint16+1 {
		return lneto.ErrInvalidConfig
	}
	pc.localAddr = localAddr
	pc.m.FilterResetLocalPorts()
	pc.m.FilterAddLocalPort(localAddr.Port(), numPorts)
	return nil
}

// LocalPortRange returns the ports set by [PacketConn.OpenPortRange] as [start, start+numPorts).
func (pc *PacketConn) LocalPortRange() (start, numPorts uint16) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if len(pc.m.filterLPorts) == 0 {
		return 0, 0
	}
	return pc.m.filterLPorts[0].startPort, pc.m.filterLPorts[0].nports
}

// Abort resets the connection, discarding all buffered data and clearing deadlines.
func (pc *PacketConn) Abort() {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.abort()
}

func (pc *PacketConn) abort() {
	pc.m.Abort()
	pc.rdead = time.Time{}
	pc.wdead = time.Time{}
	pc.localAddr = netip.AddrPort{}
}

// Close marks the PacketConn as closed. Subsequent WriteTo calls return [net.ErrClosed].
// ReadFrom continues to drain buffered datagrams until exhausted, then returns [net.ErrClosed].
func (pc *PacketConn) Close() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.m.Close()
	return nil
}

// LocalAddr returns the local address set by [PacketConn.Open].
func (pc *PacketConn) LocalAddr() netip.AddrPort {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.localAddr
}

// LocalPort implements [lneto.StackNode].
func (pc *PacketConn) LocalPort() uint16 {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.localAddr.Port()
}

// Protocol implements [lneto.StackNode].
func (pc *PacketConn) Protocol() uint64 { return uint64(lneto.IPProtoUDP) }

// ConnectionID implements [lneto.StackNode].
func (pc *PacketConn) ConnectionID() *atomic.Uint32 { return &pc.m.connid }

// Demux implements [lneto.StackNode].
func (pc *PacketConn) Demux(carrierData []byte, frameOffset int) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.m.Demux(carrierData, frameOffset)
}

// Encapsulate implements [lneto.StackNode].
func (pc *PacketConn) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.m.Encapsulate(carrierData, offsetToIP, offsetToFrame)
}

// ReadFrom dequeues the next received datagram into p and returns the sender's address.
// Blocks until a datagram is available or the read deadline is exceeded.
func (pc *PacketConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	n, _, addr, err = pc.ReadFromLocal(p)
	return n, addr, err
}

// ReadFromLocal is [PacketConn.ReadFrom] that also returns the local port the datagram was sent to.
func (pc *PacketConn) ReadFromLocal(p []byte) (n int, lport uint16, raddr netip.AddrPort, err error) {
	connID, err := pc.lockConnID()
	if err != nil {
		return 0, 0, netip.AddrPort{}, err
	}
	var backoffs uint
	for {
		pc.mu.Lock()
		if (pc.m.closeCalled && pc.m.BufferedInput() == 0) || connID != pc.m.connid.Load() {
			pc.mu.Unlock()
			return 0, 0, netip.AddrPort{}, net.ErrClosed
		}
		n, _, lport, raddr = pc.m.ReadNext(p)
		pc.mu.Unlock()
		if n > 0 {
			return n, lport, raddr, nil
		}
		if pc.deadlineExceeded(&pc.rdead) {
			return 0, 0, netip.AddrPort{}, os.ErrDeadlineExceeded
		}
		pc.backoff(backoffs)
		backoffs++
	}
}

// WriteTo enqueues a datagram for transmission to addr from the first port of [PacketConn.LocalPortRange].
// Blocks until buffer space is available or the write deadline is exceeded.
func (pc *PacketConn) WriteTo(p []byte, addr netip.AddrPort) (n int, err error) {
	return pc.WriteToLocal(p, 0, addr)
}

// WriteToLocal is [PacketConn.WriteTo] sending from local port lport, which must be in [PacketConn.LocalPortRange].
// lport 0 sends from the first port of the range.
func (pc *PacketConn) WriteToLocal(p []byte, lport uint16, raddr netip.AddrPort) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	connID, err := pc.lockConnID()
	if err != nil {
		return 0, err
	}
	var backoffs uint
	for {
		pc.mu.Lock()
		if pc.m.closeCalled || connID != pc.m.connid.Load() {
			pc.mu.Unlock()
			return 0, net.ErrClosed
		}
		src := lport
		if src == 0 {
			src = pc.localAddr.Port()
		} else if pc.m.FilterLocalPort(src) {
			pc.mu.Unlock()
			return 0, lneto.ErrInvalidAddr
		}
		werr := pc.m.WriteTo(p, src, raddr)
		pc.mu.Unlock()
		if werr == nil {
			return len(p), nil
		}
		if werr != lneto.ErrExhausted && werr != lneto.ErrBufferFull {
			return 0, werr
		}
		if pc.deadlineExceeded(&pc.wdead) {
			return 0, os.ErrDeadlineExceeded
		}
		pc.backoff(backoffs)
		backoffs++
	}
}

// SetDeadline sets both the read and write deadlines. A zero value disables the deadline.
func (pc *PacketConn) SetDeadline(t time.Time) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.m.closeCalled {
		return net.ErrClosed
	}
	pc.rdead = t
	pc.wdead = t
	return nil
}

// SetReadDeadline sets the read deadline. A zero value disables the deadline.
func (pc *PacketConn) SetReadDeadline(t time.Time) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.m.closeCalled {
		return net.ErrClosed
	}
	pc.rdead = t
	return nil
}

// SetWriteDeadline sets the write deadline. A zero value disables the deadline.
func (pc *PacketConn) SetWriteDeadline(t time.Time) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.m.closeCalled {
		return net.ErrClosed
	}
	pc.wdead = t
	return nil
}

func (pc *PacketConn) deadlineExceeded(deadline *time.Time) bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return !deadline.IsZero() && time.Since(*deadline) > 0
}

func (pc *PacketConn) backoff(n uint) {
	pc._backoff.Do(n)
}

func (pc *PacketConn) lockConnID() (uint32, error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.m.closeCalled && pc.m.BufferedInput() == 0 {
		return 0, net.ErrClosed
	}
	return pc.m.connid.Load(), nil
}
