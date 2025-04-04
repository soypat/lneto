package internet

import (
	"bytes"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/ipv6"
	"github.com/soypat/lneto/tcp"
)

type TCPConn struct {
	h          tcp.Handler
	remoteAddr []byte
	logger

	rdead  time.Time
	wdead  time.Time
	lastTx time.Time
	lastRx time.Time
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

func (conn *TCPConn) RecvIP(buf []byte, off int) (err error) {
	conn.trace("tcpconn.Recv:start")
	if off >= len(buf) {
		return errors.New("bad offset in TCPConn.Recv")
	}
	raddr, err := getIPAddr(buf[:off])
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
	}
	return nil
}

func (conn *TCPConn) HandleIP(buf []byte, off int) (n int, err error) {
	if len(conn.remoteAddr) == 0 {
		return 0, errors.New("unset IP address")
	}
	raddr, err := getIPAddr(buf[:off])
	if err != nil {
		return 0, err
	} else if len(raddr) != len(conn.remoteAddr) {
		return 0, errors.New("mismatched IP version")
	}
	n, err = conn.h.Send(buf[off:])
	if err != nil {
		return 0, err
	}
	copy(raddr, conn.remoteAddr)
	return n, nil
}

func (conn *TCPConn) Send(response []byte) (n int, err error) {
	conn.trace("tcpconn.Send:start")
	return conn.h.Send(response)
}

func getIPAddr(buf []byte) (addr []byte, err error) {
	switch buf[0] >> 4 {
	case 4:
		ifrm4, err := ipv4.NewFrame(buf)
		if err != nil {
			return addr, err
		}
		addr = ifrm4.SourceAddr()[:]
	case 6:
		ifrm6, err := ipv6.NewFrame(buf)
		if err != nil {
			return addr, err
		}
		addr = ifrm6.SourceAddr()[:]
	default:
		err = errors.New("unsupported IP version")
	}
	return addr, err
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
