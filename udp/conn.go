package udp

import (
	"net"
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

func (conn *Conn) Abort() {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.h.Abort()
	conn.abort()
}

func (conn *Conn) abort() {
	conn.rdead = time.Time{}
	conn.wdead = time.Time{}
	conn.remoteAddr = conn.remoteAddr[:0]
}

// Open sets the local port and remote address for the connection.
func (conn *Conn) Open(localPort, remotePort uint16, remoteAddr []byte) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.abort()
	err := conn.h.SetPorts(localPort, remotePort)
	if err != nil {
		return err
	}
	conn.remoteAddr = append(conn.remoteAddr[:0], remoteAddr...)
	return nil
}

func (conn *Conn) LocalPort() uint16 {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.h.lport
}

func (conn *Conn) RemotePort() uint16 { return conn.h.rport }

func (conn *Conn) RemoteAddr() []byte {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.remoteAddr
}

func (conn *Conn) Protocol() uint64 { return uint64(lneto.IPProtoUDP) }

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

func (conn *Conn) SetReadDeadline(t time.Time) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.h.closeCalled {
		return net.ErrClosed
	}
	conn.rdead = t
	return nil
}

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
