package internet

import (
	"bytes"
	"errors"
	"log/slog"
	"net"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/tcp"
)

var _ StackNode = (*NodeTCPListener)(nil)

type tcpPool interface {
	GetTCP() (*tcp.Conn, tcp.Value)
	PutTCP(*tcp.Conn)
}

type NodeTCPListener struct {
	connID uint64
	// ready have received a
	ready    []*tcp.Conn
	accepted []*tcp.Conn

	port       uint16
	poolGet    func() (*tcp.Conn, tcp.Value)
	poolReturn func(*tcp.Conn)
}

// LocalPort implements [StackNode].
func (listener *NodeTCPListener) LocalPort() uint16 { return listener.port }

// ConnectionID implements [StackNode].
func (listener *NodeTCPListener) ConnectionID() *uint64 { return &listener.connID }

// Protocol implements [StackNode].
func (listener *NodeTCPListener) Protocol() uint64 { return uint64(lneto.IPProtoTCP) }

func (listener *NodeTCPListener) Close() error {
	if listener.isClosed() {
		return errors.New("already closed")
	}
	listener.connID++
	listener.port = 0
	return nil
}

func (listener *NodeTCPListener) Reset(port uint16, pool tcpPool) error {
	if port == 0 {
		return errZeroPort
	} else if pool == nil {
		return errors.New("nil TCP pool")
	}
	*listener = NodeTCPListener{
		connID:     listener.connID + 1,
		port:       port,
		poolGet:    pool.GetTCP,
		poolReturn: pool.PutTCP,
		ready:      listener.ready[:0],
		accepted:   listener.accepted[:0],
	}
	return nil
}

func (listener *NodeTCPListener) NumberOfReadyToAccept() (nready int) {
	if listener.isClosed() {
		return 0
	}
	for _, conn := range listener.ready {
		if conn == nil {
			continue
		}
		nready++
	}
	return nready
}

func (listener *NodeTCPListener) TryAccept() (*tcp.Conn, error) {
	if listener.isClosed() {
		return nil, net.ErrClosed
	}
	listener.maintainConns()
	for i, conn := range listener.ready {
		if conn == nil {
			continue
		}
		listener.accepted = append(listener.accepted, conn)
		listener.ready[i] = nil // discard from ready.
		return conn, nil
	}
	return nil, errors.New("no conns available")
}

// CheckEncapsulate implements [StackNode].
func (listener *NodeTCPListener) CheckEncapsulate(*internal.EncData) bool {
	return !listener.isClosed()
}

// DoEncapsulate implements [StackNode].
func (listener *NodeTCPListener) DoEncapsulate(carrierData []byte, tcpFrameOffset int) (int, error) {
	if listener.isClosed() {
		// this shouldn't happen if CheckEncapsulate is called beforehand
		return 0, net.ErrClosed
	}
	for i, conn := range listener.accepted {
		if conn == nil {
			continue
		}
		n, err := conn.DoEncapsulate(carrierData, tcpFrameOffset)
		if err != nil {
			err = listener.maintainConn(listener.accepted, i, err)
		}
		if n == 0 {
			continue
		}
		return n, err
	}
	return 0, nil
}

// Demux implements [StackNode].
func (listener *NodeTCPListener) Demux(carrierData []byte, tcpFrameOffset int) error {
	if listener.isClosed() {
		return net.ErrClosed
	}
	tfrm, err := tcp.NewFrame(carrierData[tcpFrameOffset:])
	if err != nil {
		return err
	}
	srcaddr, _, _, _, err := internal.GetIPAddr(carrierData)
	if err != nil {
		return err
	}
	dst := tfrm.DestinationPort()
	if dst != listener.port {
		return errors.New("not our port")
	}
	src := tfrm.SourcePort()
	// Try to demux in accepted:
	demuxed, err := listener.tryDemux(listener.accepted, src, srcaddr, carrierData, tcpFrameOffset)
	if demuxed {
		return err
	}
	demuxed, err = listener.tryDemux(listener.ready, src, srcaddr, carrierData, tcpFrameOffset)
	if demuxed {
		return err
	}
	// Connection not in ready nor accepted.
	_, flags := tfrm.OffsetAndFlags()
	if flags != tcp.FlagSYN {
		return nil // Not a synchronizing packet, drop it.
	}
	conn, iss := listener.poolGet()
	if conn == nil {
		slog.Error("tcpListener:no-free-conn")
		return nil
	}
	err = conn.OpenListen(dst, iss)
	if err != nil {
		slog.Error("NodeTCPListener:open", slog.String("err", err.Error()))
		return err // This should not happend
	}
	err = conn.Demux(carrierData, tcpFrameOffset)
	if err != nil {
		conn.Abort()
		slog.Error("NodeTCPListener:demux", slog.String("err", err.Error()))
		return nil
	}
	listener.ready = append(listener.ready, conn)
	return nil
}

func (listener *NodeTCPListener) tryDemux(conns []*tcp.Conn, remotePort uint16, remoteAddr, carrierData []byte, tcpFrameOffset int) (demuxed bool, err error) {
	idx := getConn(conns, remotePort, remoteAddr)
	if idx >= 0 {
		err := conns[idx].Demux(carrierData, tcpFrameOffset)
		if err != nil {
			err = listener.maintainConn(conns, idx, err)
		}
		return true, err
	}
	return false, nil
}

func (listener *NodeTCPListener) maintainAccepted(connIdx int, err error) {
	if err == net.ErrClosed {
		conn := listener.accepted[connIdx]
		listener.poolReturn(conn)
		listener.accepted[connIdx] = nil
	}
}

func (listener *NodeTCPListener) isClosed() bool {
	return listener.port == 0
}

func (listener *NodeTCPListener) maintainConns() {
	listener.accepted = removeZeros(listener.accepted)
	listener.ready = removeZeros(listener.ready)
}

func removeZeros[S ~[]E, E comparable](s S) S {
	var z E
	putIdx := 0
	for i := range s {
		if s[i] != z {
			s[putIdx] = s[i]
			putIdx++
		}
	}
	return s[:putIdx]
}

func getConn(conns []*tcp.Conn, remotePort uint16, remoteAddr []byte) int {
	for i, conn := range conns {
		if conn == nil {
			continue
		}
		gotPort := conn.RemotePort()
		gotaddr := conn.RemoteAddr()
		if remotePort == gotPort && bytes.Equal(remoteAddr, gotaddr) {
			return i
		}
	}
	return -1
}

func (listener *NodeTCPListener) maintainConn(conns []*tcp.Conn, idx int, err error) error {
	if err == net.ErrClosed {
		println("CLOSING CONN")
		conn := conns[idx]
		listener.poolReturn(conn)
		conns[idx] = nil
		return nil // avoid closing listener entirely.
	}
	return err
}
