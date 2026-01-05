package tcp

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"sync"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

// pool is a [sync.Pool] like
type pool interface {
	GetTCP() (*Conn, Value)
	PutTCP(*Conn)
}

type Listener struct {
	connID uint64
	mu     sync.Mutex
	// incoming stores connections that are potential candidates for acceptance.
	incoming []*Conn
	// accepted stores all connections that have been accepted and are open.
	accepted   []*Conn
	port       uint16
	poolGet    func() (*Conn, Value)
	poolReturn func(*Conn)
	logger
}

func (listener *Listener) reset(port uint16, tcppool pool) {
	listener.accepted = listener.accepted[:0]
	listener.incoming = listener.incoming[:0]
	listener.connID++
	listener.port = port
	listener.poolGet = tcppool.GetTCP
	listener.poolReturn = tcppool.PutTCP
}

func (listener *Listener) SetLogger(logger *slog.Logger) {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	listener.logger.log = logger
}

// LocalPort implements [StackNode].
func (listener *Listener) LocalPort() uint16 {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	return listener.port
}

// ConnectionID implements [StackNode].
func (listener *Listener) ConnectionID() *uint64 { return &listener.connID }

// Protocol implements [StackNode].
func (listener *Listener) Protocol() uint64 { return uint64(lneto.IPProtoTCP) }

func (listener *Listener) Close() error {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.isClosed() {
		return errors.New("already closed")
	}
	listener.debug("listener:reset", slog.Uint64("port", uint64(listener.port)))
	listener.connID++
	listener.port = 0
	return nil
}

func (listener *Listener) Reset(port uint16, pool pool) error {
	if port == 0 {
		return errZeroDstPort
	} else if pool == nil {
		return errors.New("nil TCP pool")
	}
	listener.mu.Lock()
	defer listener.mu.Unlock()
	listener.debug("listener:reset", slog.Uint64("port", uint64(port)))
	listener.reset(port, pool)
	return nil
}

func (listener *Listener) NumberOfReadyToAccept() (nready int) {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.isClosed() {
		return 0
	}
	for _, conn := range listener.incoming {
		if conn == nil || conn.State() != StateEstablished {
			continue
		}
		nready++
	}
	return nready
}

// TryAccept polls the list of ready connections that have been established
func (listener *Listener) TryAccept() (*Conn, error) {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.isClosed() {
		return nil, net.ErrClosed
	}
	listener.debug("listener:tryaccept", slog.Uint64("port", uint64(listener.port)))
	listener.maintainConns()
	for i, conn := range listener.incoming {
		if conn == nil || conn.State() != StateEstablished {
			continue
		}
		listener.accepted = append(listener.accepted, conn)
		listener.incoming[i] = nil // discard from ready.
		return conn, nil
	}
	return nil, errors.New("no conns available")
}

// Encapsulate implements [StackNode].
func (listener *Listener) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.isClosed() {
		return 0, net.ErrClosed
	}
	//listener.trace("listener:encaps", slog.Uint64("port", uint64(listener.port)))
	// First try incoming connections (for handshake SYN-ACK).
	for i, conn := range listener.incoming {
		if conn == nil || conn.State() == StateEstablished {
			// Nil or already established.
			continue
		}
		n, err := conn.Encapsulate(carrierData, offsetToIP, offsetToFrame)
		if err != nil {
			err = listener.maintainConn(listener.incoming, i, err)
		}
		if n == 0 {
			continue
		}
		listener.debug("listener:encaps", slog.Uint64("port", uint64(listener.port)), slog.Int("plen", n), slog.String("list", "incoming"))
		return n, err
	}
	// Then try accepted connections.
	for i, conn := range listener.accepted {
		if conn == nil {
			continue
		}
		n, err := conn.Encapsulate(carrierData, offsetToIP, offsetToFrame)
		if err != nil {
			err = listener.maintainConn(listener.accepted, i, err)
		}
		if n == 0 {
			continue
		}
		listener.debug("listener:encaps", slog.Uint64("port", uint64(listener.port)), slog.Int("plen", n), slog.String("list", "accepted"))
		return n, err
	}
	return 0, nil
}

// Demux implements [StackNode].
func (listener *Listener) Demux(carrierData []byte, tcpFrameOffset int) error {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.isClosed() {
		return net.ErrClosed
	}
	tfrm, err := NewFrame(carrierData[tcpFrameOffset:])
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
	accepted := true
	demuxed, err := listener.tryDemux(listener.accepted, src, srcaddr, carrierData, tcpFrameOffset)
	if !demuxed {
		accepted = false
		demuxed, err = listener.tryDemux(listener.incoming, src, srcaddr, carrierData, tcpFrameOffset)
	}
	if demuxed {
		listener.debug("tcplistener:demux", slog.Uint64("lport", uint64(listener.port)), slog.Uint64("rport", uint64(src)), slog.Bool("accepted", accepted))
		return err
	}

	// Connection not in ready nor accepted.
	_, flags := tfrm.OffsetAndFlags()
	if flags != FlagSYN {
		return lneto.ErrPacketDrop // Not a synchronizing packet, drop it.
	}
	conn, iss := listener.poolGet()
	if conn == nil {
		slog.Error("tcpListener:no-free-conn")
		return lneto.ErrPacketDrop
	}
	err = conn.OpenListen(dst, iss)
	if err != nil {
		listener.poolReturn(conn)
		slog.Error("Listener:open", slog.String("err", err.Error()))
		return err // This should not happend
	}
	err = conn.Demux(carrierData, tcpFrameOffset)
	if err != nil {
		listener.poolReturn(conn)
		slog.Error("Listener:demux", slog.String("err", err.Error()))
		return lneto.ErrPacketDrop
	}
	listener.incoming = append(listener.incoming, conn)
	listener.debug("tcplistener:demux-new", slog.Uint64("lport", uint64(listener.port)), slog.Uint64("rport", uint64(src)))
	return nil
}

func (listener *Listener) tryDemux(conns []*Conn, remotePort uint16, remoteAddr, carrierData []byte, tcpFrameOffset int) (demuxed bool, err error) {
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

func (listener *Listener) isClosed() bool {
	return listener.port == 0
}

func (listener *Listener) maintainConns() {
	listener.accepted = internal.DeleteZeroed(listener.accepted)
	for i := range listener.incoming {
		if listener.incoming[i] == nil {
			continue
		}
		state := listener.incoming[i].State()
		if state > StateEstablished || state.IsClosed() {
			// Something went wrong in handshake or pool aborted/closed the connection.
			listener.poolReturn(listener.incoming[i])
			listener.incoming[i] = nil
		}
	}
	listener.incoming = internal.DeleteZeroed(listener.incoming)
}

func getConn(conns []*Conn, remotePort uint16, remoteAddr []byte) int {
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

func (listener *Listener) maintainConn(conns []*Conn, idx int, err error) error {
	if err == net.ErrClosed {
		listener.poolReturn(conns[idx])
		conns[idx] = nil
		return nil // avoid closing listener entirely.
	}
	return err
}
