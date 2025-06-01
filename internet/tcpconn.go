package internet

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"time"

	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/ipv6"
	"github.com/soypat/lneto/tcp"
)

var (
	errDeadlineExceeded = os.ErrDeadlineExceeded
)

type TCPConn struct {
	// deprecated: here for debugging purposes only.
	h          tcp.Handler
	remoteAddr []byte

	rdead  time.Time
	wdead  time.Time
	lastTx time.Time
	lastRx time.Time

	ipID     uint16
	abortErr error
	logger
}

type TCPConnConfig struct {
	RxBuf             []byte
	TxBuf             []byte
	TxPacketQueueSize int
	Logger            *slog.Logger
}

func (conn *TCPConn) Configure(config *TCPConnConfig) (err error) {
	err = conn.h.SetBuffers(config.TxBuf, config.RxBuf, config.TxPacketQueueSize)
	if err != nil {
		return err
	}
	conn.logger.log = config.Logger
	return nil
}

// LocalPort returns the local port on which the socket is listening or connected to.
func (conn *TCPConn) LocalPort() uint16 { return conn.h.LocalPort() }

// RemotePort returns the port of the incoming remote connection. Is non-zero if connection is established.
func (conn *TCPConn) RemotePort() uint16 { return conn.h.RemotePort() }

// State returns the TCP state of the socket.
func (conn *TCPConn) State() tcp.State { return conn.h.State() }

// BufferedInput returns the number of bytes in the socket's receive/input buffer.
func (conn *TCPConn) BufferedInput() int { return conn.h.BufferedInput() }

// OpenActive opens a connection to a remote peer with a known IP address and port combination.
// iss is the initial send sequence number which is ideally a random number which is far away from the last sequence number used on a connection to the same host.
func (conn *TCPConn) OpenActive(remote netip.AddrPort, localPort uint16, iss tcp.Value) error {
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
func (conn *TCPConn) OpenListen(localPort uint16, iss tcp.Value) error {
	err := conn.h.OpenListen(localPort, iss)
	if err != nil {
		return err
	}
	conn.reset(conn.h)
	return nil
}

func (conn *TCPConn) Close() error {
	conn.trace("TCPConn.Close")
	return conn.h.Close()
}

func (conn *TCPConn) RecvIP(buf []byte, off int) (err error) {
	conn.trace("tcpconn.Recv:start")
	if off >= len(buf) {
		return errors.New("bad offset in TCPConn.Recv")
	}
	raddr, id, err := getIPAddr(buf[:off])
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

// Write writes argument data to the TCPConns's output buffer which is queued to be sent.
func (conn *TCPConn) Write(b []byte) (int, error) {
	err := conn.checkPipeOpen()
	if err != nil {
		return 0, err
	}
	plen := len(b)
	conn.trace("TCPConn.Write:start")
	connid := conn.h.ConnectionID()
	if conn.deadlineExceeded(conn.wdead) {
		return 0, errDeadlineExceeded
	} else if plen == 0 {
		return 0, nil
	}
	backoff := internal.NewBackoff(internal.BackoffTCPConn)
	n := 0
	for {
		if conn.abortErr != nil {
			return n, conn.abortErr
		} else if connid != conn.h.ConnectionID() {
			return n, net.ErrClosed
		}
		ngot, _ := conn.h.Write(b)
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
		if conn.deadlineExceeded(conn.wdead) {
			return n, errDeadlineExceeded
		}
	}
	return n, nil
}

// Read reads data from the socket's input buffer. If the buffer is empty,
// Read will block until data is available or connection closes.
func (conn *TCPConn) Read(b []byte) (int, error) {
	err := conn.checkPipeOpen()
	if err != nil {
		return 0, err
	}
	conn.trace("TCPConn.Read:start")
	connid := conn.h.ConnectionID()
	backoff := internal.NewBackoff(internal.BackoffTCPConn)
	for conn.h.BufferedInput() == 0 && conn.State() == tcp.StateEstablished {
		if conn.abortErr != nil {
			return 0, conn.abortErr
		} else if connid != conn.h.ConnectionID() {
			return 0, net.ErrClosed
		}
		if conn.deadlineExceeded(conn.rdead) {
			return 0, errDeadlineExceeded
		}
		backoff.Miss()
	}
	n, err := conn.h.Read(b)
	return n, err
}

func (conn *TCPConn) checkPipeOpen() error {
	if conn.abortErr != nil {
		return conn.abortErr
	}
	state := conn.State()
	if state.IsClosed() {
		return net.ErrClosed
	}
	return nil
}

func (conn *TCPConn) HandleIP(buf []byte, off int) (n int, err error) {
	if len(conn.remoteAddr) == 0 {
		return 0, errors.New("unset IP address")
	}
	raddr, _, err := getIPAddr(buf[:off])
	if err != nil {
		return 0, err
	} else if len(raddr) != len(conn.remoteAddr) {
		return 0, errors.New("mismatched IP version")
	}
	n, err = conn.h.Send(buf[off:])
	if err != nil {
		return 0, err
	}

	err = setDstAddr(buf[:off], conn.ipID, conn.remoteAddr)
	if err != nil {
		return 0, err
	}
	conn.ipID++
	return n, nil
}

func (conn *TCPConn) Send(response []byte) (n int, err error) {
	conn.trace("tcpconn.Send:start")
	return conn.h.Send(response)
}

func getIPAddr(buf []byte) (addr []byte, id uint16, err error) {
	switch buf[0] >> 4 {
	case 4:
		ifrm4, err := ipv4.NewFrame(buf)
		if err != nil {
			return addr, 0, err
		}
		addr = ifrm4.SourceAddr()[:]
		id = ifrm4.ID()
	case 6:
		ifrm6, err := ipv6.NewFrame(buf)
		if err != nil {
			return addr, 0, err
		}
		addr = ifrm6.SourceAddr()[:]
	default:
		err = errors.New("unsupported IP version")
	}
	return addr, id, err
}

func setDstAddr(buf []byte, id uint16, addr []byte) (err error) {
	var dstaddr []byte
	switch buf[0] >> 4 {
	case 4:
		ifrm4, err := ipv4.NewFrame(buf)
		if err != nil {
			return err
		}
		dstaddr = ifrm4.DestinationAddr()[:]
		ifrm4.SetID(id)
	case 6:
		ifrm6, err := ipv6.NewFrame(buf)
		if err != nil {
			return err
		}
		dstaddr = ifrm6.DestinationAddr()[:]
	default:
		err = errors.New("unsupported IP version")
	}
	if err == nil && len(dstaddr) != len(addr) {
		return errors.New("invalid ip version to setDstAddr")
	}
	copy(dstaddr, addr)
	return nil
}

func (conn *TCPConn) isRaddrSet() bool {
	return len(conn.remoteAddr) != 0
}

func (conn *TCPConn) reset(h tcp.Handler) {
	*conn = TCPConn{
		h:          h,
		remoteAddr: conn.remoteAddr[:0],
		logger:     conn.logger,
	}
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline. Implements [net.Conn].
func (conn *TCPConn) SetDeadline(t time.Time) error {
	err := conn.SetReadDeadline(t)
	if err != nil {
		return err
	}
	return conn.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call. A zero value for t means Read will not time out.
func (conn *TCPConn) SetReadDeadline(t time.Time) error {
	conn.trace("TCPConn.SetReadDeadline:start")
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
func (conn *TCPConn) SetWriteDeadline(t time.Time) error {
	conn.trace("TCPConn.SetWriteDeadline:start")
	err := conn.checkPipeOpen()
	if err == nil {
		conn.wdead = t
	}
	return err
}

func (conn *TCPConn) deadlineExceeded(deadline time.Time) bool {
	return !deadline.IsZero() && time.Since(deadline) > 0
}
