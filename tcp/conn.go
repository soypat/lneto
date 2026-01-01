package tcp

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

var (
	errDeadlineExceeded    = os.ErrDeadlineExceeded
	errNoRemoteAddr        = errors.New("tcp: no remote address established")
	errInvalidIP           = errors.New("tcp: invalid IP")
	errMismatchedIPVersion = errors.New("mismatched IP version")
)

// Conn builds on the [Handler] abstraction and adds IP header knowledge, time management, and familiar user facing API
// like Write and Read methods.
//
// Note that the complete emulation of [net.TCPConn] at this level of abstraction is yet a non-goal,
// even though the functionality provided is similar.
type Conn struct {
	mu         sync.Mutex
	h          Handler
	remoteAddr []byte

	rdead    time.Time
	wdead    time.Time
	abortErr error
	logger

	ipID uint16
}

type ConnConfig struct {
	RxBuf             []byte
	TxBuf             []byte
	TxPacketQueueSize int
	Logger            *slog.Logger
}

func (conn *Conn) Configure(config ConnConfig) (err error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	err = conn.h.SetBuffers(config.TxBuf, config.RxBuf, config.TxPacketQueueSize)
	if err != nil {
		return err
	}
	conn.logger.log = config.Logger
	return nil
}

// LocalPort returns the local port on which the socket is listening or connected to.
func (conn *Conn) LocalPort() uint16 {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.h.LocalPort()
}

// RemotePort returns the port of the incoming remote connection. Is non-zero if connection is established.
func (conn *Conn) RemotePort() uint16 {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.h.RemotePort()
}

func (conn *Conn) RemoteAddr() []byte {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.remoteAddr
}

// State returns the TCP state of the socket.
func (conn *Conn) State() State {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.h.State()
}

// BufferedInput returns the number of bytes in the socket's receive(input) buffer
// and available to read via a [Conn.Read] call.
func (conn *Conn) BufferedInput() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.h.BufferedInput()
}

// BufferedUnsent returns the number of bytes in the socket's transmit(output) buffer
// that has yet to be sent.
func (conn *Conn) BufferedUnsent() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.h.BufferedUnsent()
}

func (conn *Conn) AvailableInput() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.h.FreeRx()
}

// AvailableOutput returns amount of bytes available to write to output
// before [Conn.Write] returns an error due to insufficient space to store outgoing data.
func (conn *Conn) AvailableOutput() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.h.AvailableOutput()
}

// OpenActive opens a connection to a remote peer with a known IP address and port combination.
// iss is the initial send sequence number which is ideally a random number which is far away from the last sequence number used on a connection to the same host.
func (conn *Conn) OpenActive(localPort uint16, remote netip.AddrPort, iss Value) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if !remote.IsValid() {
		return errInvalidIP
	}
	err := conn.h.OpenActive(localPort, remote.Port(), iss)
	if err != nil {
		return err
	}
	conn.reset(conn.h)
	raddr := remote.Addr()
	if raddr.Is4() {
		addr4 := raddr.As4()
		conn.remoteAddr = append(conn.remoteAddr[:0], addr4[:]...)
	} else if raddr.Is6() {
		addr6 := raddr.As16()
		conn.remoteAddr = append(conn.remoteAddr[:0], addr6[:]...)
	}
	return nil
}

// OpenListen opens a passive connection which listens for the first SYN packet to be received on a local port.
// iss is the initial send sequence number which is usually a randomly chosen number.
func (conn *Conn) OpenListen(localPort uint16, iss Value) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	err := conn.h.OpenListen(localPort, iss)
	if err != nil {
		return err
	}
	conn.reset(conn.h)
	return nil
}

func (conn *Conn) Close() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.trace("TCPConn.Close")
	return conn.h.Close()
}

// Abort terminates all state of the connection forcibly.
func (conn *Conn) Abort() {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.h.Abort()
	*conn = Conn{
		mu:         conn.mu,
		h:          conn.h,
		remoteAddr: conn.remoteAddr[:0],
		logger:     conn.logger,
		ipID:       conn.ipID,
	}
}

// InternalHandler returns the internal [Handler] instance. The Handler contains lower level implementation logic for a TCP connection.
// Typical users should not be using this method unless implementing a stack which manages several TCP connections and thus need
// access to low level internals for careful memory management.
func (conn *Conn) InternalHandler() *Handler {
	return &conn.h
}

// Write writes argument data to the TCPConns's output buffer which is queued to be sent.
func (conn *Conn) Write(b []byte) (int, error) {
	connid, err := conn.lockPipeConnID()
	if err != nil {
		return 0, err
	}
	plen := len(b)
	conn.trace("TCPConn.Write:start")
	if conn.deadlineExceeded(&conn.wdead) {
		return 0, errDeadlineExceeded
	} else if plen == 0 {
		return 0, nil
	}
	backoff := internal.NewBackoff(internal.BackoffTCPConn)
	n := 0
	for {
		if err := conn.checkPipe(connid, &conn.wdead); err != nil {
			return 0, err
		}
		conn.mu.Lock()
		ngot, _ := conn.h.Write(b)
		conn.mu.Unlock()
		n += ngot
		b = b[ngot:]
		if n == plen {
			break
		} else if ngot > 0 {
			backoff.Hit()
			runtime.Gosched() // Do a little yield since we won't have data for sure otherwise.
		} else {
			backoff.Miss()
		}
		conn.trace("TCPConn.Write:insuf-buf", slog.Int("missing", plen-n))
		if conn.deadlineExceeded(&conn.wdead) {
			return n, errDeadlineExceeded
		}
	}
	return n, nil
}

func (conn *Conn) Flush() error {
	connid, err := conn.lockPipeConnID()
	if err != nil {
		return err
	}
	if conn.deadlineExceeded(&conn.wdead) {
		return errDeadlineExceeded
	} else if conn.BufferedUnsent() == 0 {
		return nil
	}
	backoff := internal.NewBackoff(internal.BackoffTCPConn)
	for conn.BufferedUnsent() != 0 {
		if err := conn.checkPipe(connid, &conn.wdead); err != nil {
			return err
		}
		backoff.Miss()
	}
	return nil
}

// Read reads data from the socket's input buffer. If the buffer is empty,
// Read will block until data is available or connection closes.
func (conn *Conn) Read(b []byte) (int, error) {
	connid, err := conn.lockPipeConnID()
	if err != nil {
		return 0, err
	}
	conn.trace("TCPConn.Read:start")
	backoff := internal.NewBackoff(internal.BackoffTCPConn)
	for conn.h.BufferedInput() == 0 && conn.State() == StateEstablished {
		if err := conn.checkPipe(connid, &conn.rdead); err != nil {
			return 0, err
		}
		backoff.Miss()
	}
	conn.mu.Lock()
	n, err := conn.h.Read(b)
	conn.mu.Unlock()
	return n, err
}

func (conn *Conn) lockPipeConnID() (uint64, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	err := conn.checkPipeOpen()
	if err != nil {
		return 0, err
	}
	return conn.h.connid, nil
}

func (conn *Conn) checkPipe(connID uint64, deadline *time.Time) (err error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.abortErr != nil {
		err = conn.abortErr
	} else if connID != conn.h.connid {
		err = net.ErrClosed
	} else if !deadline.IsZero() && time.Since(*deadline) > 0 {
		err = errDeadlineExceeded
	}
	return nil
}

func (conn *Conn) checkPipeOpen() error {
	if conn.abortErr != nil {
		return conn.abortErr
	}
	state := conn.h.State()
	if state.IsClosed() {
		return net.ErrClosed
	}
	return nil
}

func (conn *Conn) Demux(buf []byte, off int) (err error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.trace("tcpconn.Recv:start")
	if off >= len(buf) {
		return errors.New("bad offset in TCPConn.Recv")
	}
	raddr, _, id, _, err := internal.GetIPAddr(buf[:off])
	if err != nil {
		return err
	}
	if conn.isRaddrSet() && !bytes.Equal(conn.remoteAddr, raddr) {
		return errors.New("IP addr mismatch on TCPConn")
	}
	err = conn.h.Recv(buf[off:])
	if err != nil {
		return err
	}
	if !conn.isRaddrSet() && conn.h.RemotePort() != 0 {
		conn.remoteAddr = append(conn.remoteAddr[:0], raddr...)
		conn.ipID = ^(id - 1)
	}
	return nil
}

func (conn *Conn) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (n int, err error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.remoteAddr) == 0 {
		return 0, errNoRemoteAddr
	}
	if offsetToIP < 0 {
		return 0, errNoRemoteAddr // No IP layer present.
	}
	ipFrame := carrierData[offsetToIP:offsetToFrame]
	raddr, _, _, _, err := internal.GetIPAddr(ipFrame)
	if err != nil {
		return 0, err
	} else if len(raddr) != len(conn.remoteAddr) {
		return 0, errMismatchedIPVersion
	}
	n, err = conn.h.Send(carrierData[offsetToFrame:])
	if err != nil {
		return 0, err
	}
	err = internal.SetIPAddrs(ipFrame, conn.ipID, nil, conn.remoteAddr)
	if err != nil {
		return 0, err
	}
	conn.ipID++
	return n, nil
}

func (conn *Conn) Protocol() uint64 {
	return uint64(lneto.IPProtoTCP)
}

func (conn *Conn) isRaddrSet() bool {
	return len(conn.remoteAddr) != 0
}

func (conn *Conn) reset(h Handler) {
	if conn.mu.TryLock() {
		panic("reset must be called from within locked conn")
	}
	*conn = Conn{
		h:          h,
		mu:         conn.mu,
		remoteAddr: conn.remoteAddr[:0],
		logger:     conn.logger,
	}
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline. Implements [net.Conn].
func (conn *Conn) SetDeadline(t time.Time) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	err := conn.setReadDeadline(t)
	if err != nil {
		return err
	}
	return conn.setWriteDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call. A zero value for t means Read will not time out.
func (conn *Conn) SetReadDeadline(t time.Time) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.setReadDeadline(t)
}

func (conn *Conn) setReadDeadline(t time.Time) error {
	conn.trace("TCPConn.setReadDeadline:start")
	err := conn.checkPipeOpen()
	if err == nil {
		conn.rdead = t
	}
	return err
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (conn *Conn) SetWriteDeadline(t time.Time) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.setWriteDeadline(t)
}

func (conn *Conn) setWriteDeadline(t time.Time) error {
	conn.trace("TCPConn.SetWriteDeadline:start")
	err := conn.checkPipeOpen()
	if err == nil {
		conn.wdead = t
	}
	return err
}

func (conn *Conn) deadlineExceeded(deadline *time.Time) bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return !deadline.IsZero() && time.Since(*deadline) > 0
}

func (conn *Conn) ConnectionID() *uint64 {
	return conn.h.ConnectionID()
}
