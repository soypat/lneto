package udp

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

var _ lneto.StackNode = (*Conn)(nil)

// Conn implements a UDP datagram socket with SOCK_DGRAM semantics.
// Each [Conn.Write] enqueues one datagram and each [Conn.Read] dequeues one complete datagram.
type Conn struct {
	mu sync.Mutex
	h  Handler

	remoteAddr []byte

	rdead time.Time
	wdead time.Time

	ipID uint16
}

// ConnConfig configures a [Conn] or [Handler] with pre-allocated buffers and queue sizes.
type ConnConfig struct {
	// RxBuf is the buffer for incoming datagrams.
	RxBuf []byte
	// TxBuf is the buffer for outgoing datagrams.
	TxBuf []byte
	// RxQueueSize is the maximum number of incoming datagrams that can be queued.
	RxQueueSize int
	// TxQueueSize is the maximum number of outgoing datagrams that can be queued.
	TxQueueSize int
}

// Configure initializes the connection with the given buffer and queue configuration.
// Must be called before [Conn.Open]. Calling Configure on an active connection aborts it.
func (conn *Conn) Configure(cfg ConnConfig) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.abort()
	err := conn.h.Configure(cfg)
	if err != nil {
		return err
	}
	return nil
}

// Abort resets the connection, discarding all buffered data and clearing deadlines.
func (conn *Conn) Abort() {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.abort()
}

func (conn *Conn) abort() {
	conn.h.Abort()
	conn.rdead = time.Time{}
	conn.wdead = time.Time{}
	conn.remoteAddr = conn.remoteAddr[:0]
}

var errStillOpen = errors.New("close udp conn before opening")

// Open sets the local port and remote address for the connection.
func (conn *Conn) Open(localPort uint16, remoteAddr netip.AddrPort) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.h.IsOpen() {
		return errStillOpen
	}
	err := conn.h.SetPorts(localPort, remoteAddr.Port())
	if err != nil {
		return err
	}
	conn.remoteAddr = append(conn.remoteAddr[:0], remoteAddr.Addr().AsSlice()...)
	return nil
}

func (conn *Conn) IsOpen() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.h.IsOpen()
}

// LocalPort returns the local port set by [Conn.Open].
func (conn *Conn) LocalPort() uint16 {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.h.lport
}

// RemotePort returns the remote port set by [Conn.Open].
func (conn *Conn) RemotePort() uint16 { return conn.h.rport }

// RemoteAddr returns the remote address set by [Conn.Open].
func (conn *Conn) RemoteAddr() []byte {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.remoteAddr
}

// Protocol returns [lneto.IPProtoUDP].
func (conn *Conn) Protocol() uint64 { return uint64(lneto.IPProtoUDP) }

// ConnectionID returns a pointer to the connection ID. The value changes on
// each [Conn.Configure] or [Conn.Abort] call, signaling to the stack that the
// previous registration is no longer valid.
func (conn *Conn) ConnectionID() *uint64 { return &conn.h.connid }

// Write enqueues a single datagram to be sent. The entire payload is queued atomically.
func (conn *Conn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	backoff := internal.NewBackoff(internal.BackoffTCPConn)
	for {
		if conn.deadlineExceeded(&conn.wdead) {
			return 0, os.ErrDeadlineExceeded
		}
		conn.mu.Lock()
		if conn.h.closeCalled {
			conn.mu.Unlock()
			return 0, net.ErrClosed
		}
		n, err := conn.h.Write(b)
		conn.mu.Unlock()
		if n > 0 {
			return n, err
		}
		backoff.Miss()
	}
}

// Read dequeues a single datagram. If the buffer is smaller than the datagram,
// the remaining bytes are discarded (SOCK_DGRAM semantics).
func (conn *Conn) Read(b []byte) (int, error) {
	backoff := internal.NewBackoff(internal.BackoffTCPConn)
	for {
		if conn.deadlineExceeded(&conn.rdead) {
			return 0, os.ErrDeadlineExceeded
		}
		conn.mu.Lock()
		if conn.h.closeCalled && conn.h.BufferedInput() == 0 {
			conn.mu.Unlock()
			return 0, net.ErrClosed
		}
		n, err := conn.h.Read(b)
		conn.mu.Unlock()
		if n > 0 {
			return n, err
		}
		backoff.Miss()
	}
}

// Close marks the connection as closed. Subsequent calls to [Conn.Write] and
// [Conn.Demux] return [net.ErrClosed]. [Conn.Read] continues to return buffered
// data until exhausted, then returns [net.ErrClosed].
func (conn *Conn) Close() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.h.Close()
	return nil
}

// Demux receives an incoming UDP payload into the rx ring buffer.
func (conn *Conn) Demux(carrierData []byte, frameOffset int) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.h.closeCalled {
		return net.ErrClosed
	}
	return conn.h.Recv(carrierData[frameOffset:])
}

// Encapsulate writes a queued outgoing datagram into the carrier buffer.
func (conn *Conn) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.h.closeCalled {
		return 0, net.ErrClosed
	}
	n, err := conn.h.Send(carrierData[offsetToFrame:])
	if err != nil || n == 0 {
		return 0, err
	}
	if offsetToIP >= 0 && len(conn.remoteAddr) > 0 {
		err = internal.SetIPAddrs(carrierData[offsetToIP:], conn.ipID, nil, conn.remoteAddr)
		if err != nil {
			return 0, err
		}
		conn.ipID++
	}
	return n, nil
}

// SetDeadline sets both the read and write deadlines. A zero value disables the deadline.
func (conn *Conn) SetDeadline(t time.Time) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.h.closeCalled {
		return net.ErrClosed
	}
	conn.rdead = t
	conn.wdead = t
	return nil
}

// SetReadDeadline sets the read deadline. A zero value disables the deadline.
func (conn *Conn) SetReadDeadline(t time.Time) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.h.closeCalled {
		return net.ErrClosed
	}
	conn.rdead = t
	return nil
}

// SetWriteDeadline sets the write deadline. A zero value disables the deadline.
func (conn *Conn) SetWriteDeadline(t time.Time) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.h.closeCalled {
		return net.ErrClosed
	}
	conn.wdead = t
	return nil
}

func (conn *Conn) deadlineExceeded(deadline *time.Time) bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return !deadline.IsZero() && time.Since(*deadline) > 0
}

// BufferedInput returns the number of unread bytes in the receive buffer.
func (conn *Conn) BufferedInput() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.h.BufferedInput()
}

// BufferedUnsent returns the number of written but unsent bytes in the transmit buffer.
func (conn *Conn) BufferedOutput() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.h.BufferedOutput()
}

// SizeInput returns the total size of the receive ring buffer.
func (conn *Conn) SizeInput() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.h.SizeInput()
}

// SizeOutput returns the total size of the transmit ring buffer.
func (conn *Conn) SizeOutput() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.h.SizeOutput()
}

// FreeOutput returns the number of free bytes in the transmit buffer.
// This tells the user how many bytes can be written with Write method before write failing.
func (conn *Conn) FreeOutput() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.h.FreeOutput()
}

// FreeInput returns the number of free bytes in the receive buffer.
func (conn *Conn) FreeInput() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.h.FreeInput()
}
