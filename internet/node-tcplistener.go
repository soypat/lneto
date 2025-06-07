package internet

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/tcp"
)

var _ StackNode = (*NodeTCPListener)(nil)

type NodeTCPListener struct {
	connID   uint64
	conns    []tcp.Conn
	accepted []bool
	port     uint16
	getISS   func() uint32
}

func (listener *NodeTCPListener) AcceptRaw() (*tcp.Conn, error) {
	connid := listener.connID
	for {
		if listener.isClosed() || connid != listener.connID {
			return nil, net.ErrClosed
		}
		for i := range listener.conns {
			isAvailable := listener.connReceivedSyn(i) && !listener.connAccepted(i)
			if !isAvailable {
				continue
			}
			// Connection received as SYN and is not yet accepted.
			listener.accepted[i] = true
			return &listener.conns[i], nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	panic("unreachable")
}

func (listener *NodeTCPListener) Close() error {
	if listener.isClosed() {
		return errors.New("already closed")
	}
	listener.connID++
	listener.port = 0
	return nil
}

func (listener *NodeTCPListener) LocalPort() uint16 { return listener.port }

func (listener *NodeTCPListener) ConnectionID() *uint64 { return &listener.connID }

func (listener *NodeTCPListener) Protocol() uint64 { return uint64(lneto.IPProtoTCP) }

func (listener *NodeTCPListener) Encapsulate(carrierData []byte, tcpFrameOffset int) (int, error) {
	if listener.isClosed() {
		return 0, net.ErrClosed
	}
	for i := range listener.conns {
		conn := &listener.conns[i]
		if conn.State().IsClosed() {
			continue
		}
		n, err := conn.Encapsulate(carrierData, tcpFrameOffset)
		if err != nil {
			listener.maintainConn(i, err)
		}
		if n == 0 {
			continue
		}
		return n, err
	}
	return 0, nil
}

func (listener *NodeTCPListener) Demux(carrierData []byte, tcpFrameOffset int) error {
	if listener.isClosed() {
		return net.ErrClosed
	}
	tfrm, err := tcp.NewFrame(carrierData[tcpFrameOffset:])
	if err != nil {
		return err
	}
	addr, _, err := internal.GetIPSourceAddr(carrierData)
	if err != nil {
		return err
	}
	dst := tfrm.DestinationPort()
	if dst != listener.port {
		return errors.New("not our port")
	}
	src := tfrm.DestinationPort()
	_, flags := tfrm.OffsetAndFlags()
	for i := range listener.conns {
		if listener.conns[i].RemotePort() != src || !bytes.Equal(listener.conns[i].RemoteAddr(), addr) {
			continue
		}
		conn := &listener.conns[i]
		err := conn.Demux(carrierData, tcpFrameOffset)
		if err != nil {
			listener.maintainConn(i, err)
		}
		return err
	}
	if !flags.HasAll(tcp.FlagSYN) {
		return nil // Not a synchronizing packet, drop it.
	}
	// New connection must be assigned.
	for i := range listener.conns {
		conn := &listener.conns[i]
		isOpen := !conn.State().IsClosed()
		if isOpen {
			continue
		}
		if conn.State() == tcp.StateTimeWait {
			conn.Abort()
		}

		err = conn.OpenListen(dst, tcp.Value(listener.getISS()))
		if err != nil {
			return err
		}
		return conn.Demux(carrierData, tcpFrameOffset)
	}
	slog.Error("tcpListener:no-free-conn")
	return nil
}

func (listener *NodeTCPListener) maintainConn(connIdx int, err error) {
	if err == net.ErrClosed {
		listener.conns[connIdx].Abort()
	}
}

func (listener *NodeTCPListener) isClosed() bool {
	return listener.port == 0
}

func (listener *NodeTCPListener) connReceivedSyn(idx int) bool {
	return listener.conns[idx].RemotePort() != 0
}
func (listener *NodeTCPListener) connAccepted(idx int) bool {
	return listener.accepted[idx]
}
