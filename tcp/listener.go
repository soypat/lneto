package tcp

import (
	"log/slog"
	"net"
	"sync"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

// pool is a [sync.Pool] like
type pool interface {
	GetTCP(laddr, raddr []byte, lport, rport uint16) (*Conn, any, Value)
	PutTCP(*Conn)
	// CheckTimeouts aborts acquired connections past their deadline; called by the listener while idle.
	CheckTimeouts()
}

type Listener struct {
	connID uint64
	mu     sync.Mutex
	// incoming stores connections that are potential candidates for acceptance.
	incoming []ConnHandle
	// accepted stores all connections that have been accepted and are open.
	accepted   []ConnHandle
	port       uint16
	poolGet    func(laddr, raddr []byte, lport, rport uint16) (*Conn, any, Value)
	poolReturn func(*Conn)
	poolCheck  func()
	logger
	// rstQueue stores pending RST responses for rejected segments.
	// Per RFC 9293 §3.10.7.1 (CLOSED state processing).
	rstQueue RSTQueue
}

func (listener *Listener) reset(port uint16, tcppool pool) {
	if listener.poolReturn != nil {
		// Conns still held belong to the previous pool: return them before replacing its callbacks.
		listener.incoming = listener.returnAll(listener.incoming)
		listener.accepted = listener.returnAll(listener.accepted)
	}
	listener.connID++
	listener.port = port
	listener.poolGet = tcppool.GetTCP
	listener.poolReturn = tcppool.PutTCP
	listener.poolCheck = tcppool.CheckTimeouts
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
		return net.ErrClosed
	}
	listener.debug("listener:close", slog.Uint64("port", uint64(listener.port)))
	listener.port = 0                                         // Stops accepting; node lives until accepted conns are returned.
	listener.incoming = listener.returnAll(listener.incoming) // discard these pending conns, only keep already active(accepted).
	listener.accepted = internal.DeleteZeroed(listener.accepted)
	if len(listener.accepted) == 0 {
		listener.connID++ // Can drop node immediately. Else we keep accepted active until closed.
	}
	return nil
}

// Abort closes the listener and aborts all its pending and accepted connections.
func (listener *Listener) Abort() {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	listener.debug("listener:abort", slog.Uint64("port", uint64(listener.port)))
	listener.incoming = listener.returnAll(listener.incoming)
	listener.accepted = listener.returnAll(listener.accepted)
	listener.port = 0
	listener.connID++
}

func (listener *Listener) Reset(port uint16, pool pool) error {
	if port == 0 {
		return lneto.ErrZeroSource
	} else if pool == nil {
		return lneto.ErrInvalidConfig
	}
	listener.mu.Lock()
	defer listener.mu.Unlock()
	listener.debug("listener:reset", slog.Uint64("port", uint64(port)))
	listener.reset(port, pool)
	return nil
}

// NumberOfActiveAccepted returns number of connections still active having been accepted by user via [Listener.TryAccept].
func (listener *Listener) NumberOfActiveAccepted() (nActive int) {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	for i := range listener.accepted {
		h := &listener.accepted[i]
		if h.c != nil && h.c.h.connid == h.id {
			nActive++
		}
	}
	return nActive
}

// NumberOfReadyToAccept returns number of connections held by Listener that are pending being accepted via user call to [Listener.TryAccept].
func (listener *Listener) NumberOfReadyToAccept() (nready int) {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.isClosed() {
		return 0
	}
	for i := range listener.incoming {
		conn := listener.incoming[i].c
		if conn == nil || conn.State() != StateEstablished {
			continue
		}
		nready++
	}
	return nready
}

// TryAccept polls the list of ready connections that have been established.
// The pool's user data for the connection is available via [ConnHandle.UserData].
func (listener *Listener) TryAccept() (ConnHandle, error) {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.isClosed() {
		return ConnHandle{}, net.ErrClosed
	}
	listener.debug("listener:tryaccept", slog.Uint64("port", uint64(listener.port)))
	listener.maintainConns()
	for i := range listener.incoming {
		pinned := listener.incoming[i]
		if pinned.c == nil || pinned.c.State() != StateEstablished {
			continue
		}
		listener.accepted = append(listener.accepted, pinned)
		listener.incoming[i] = ConnHandle{} // discard from ready.
		return pinned, nil
	}
	return ConnHandle{}, lneto.ErrExhausted
}

// Encapsulate implements [StackNode].
func (listener *Listener) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (n int, err error) {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	// First try incoming connections (for handshake SYN-ACK).
	for i := range listener.incoming {
		conn := listener.incoming[i].c
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
	for i := range listener.accepted {
		conn := listener.accepted[i].c
		if conn == nil {
			continue
		} else if conn.h.connid != listener.accepted[i].id {
			listener.returnAccepted(i)
			continue
		}
		n, err = conn.Encapsulate(carrierData, offsetToIP, offsetToFrame)
		if n > 0 {
			listener.debug("listener:encaps", slog.Uint64("port", uint64(listener.port)), slog.Int("plen", n), slog.String("list", "accepted"))
			break
		} else if err == net.ErrClosed {
			listener.returnAccepted(i)
			err = nil
		}
	}
	// Drain one RST entry if no connection data was sent. Lower priority than connection traffic.
	if n == 0 {
		n, _ = listener.rstQueue.Drain(carrierData, offsetToIP, offsetToFrame)
	}
	if n == 0 {
		listener.maintainConns()
		if listener.isClosed() && len(listener.accepted) == 0 {
			return 0, net.ErrClosed // Last accepted conn returned: stack drops node.
		}
	}
	return n, err
}

// Demux implements [StackNode].
func (listener *Listener) Demux(carrierData []byte, tcpFrameOffset int) error {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	tfrm, err := NewFrame(carrierData[tcpFrameOffset:])
	if err != nil {
		return err
	}
	srcaddr, dstaddr, _, _, err := internal.GetIPAddr(carrierData)
	if err != nil {
		return err
	}
	dst := tfrm.DestinationPort()
	src := tfrm.SourcePort()
	if listener.isClosed() {
		// Closed: serve accepted conns only. Stack answers dropped SYNs with RST.
		if demuxed, err := listener.tryDemux(listener.accepted, src, srcaddr, carrierData, tcpFrameOffset); demuxed {
			return err
		}
		return lneto.ErrPacketDrop
	} else if dst != listener.port {
		return lneto.ErrMismatch
	}

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
	if !flags.HasAll(FlagSYN) || flags.HasAny(FlagACK) {
		// RFC 9293 §3.10.7.1: CLOSED state — send RST for non-RST segments.
		if !flags.HasAny(FlagRST) && flags.HasAny(FlagACK) {
			listener.rstQueue.Queue(srcaddr, src, listener.port, tfrm.Ack(), 0, FlagRST)
		}
		return lneto.ErrPacketDrop
	}
	conn, userData, iss := listener.poolGet(dstaddr, srcaddr, dst, src)
	if conn == nil {
		listener.logerr("tcpListener:no-free-conn")
		listener.rstQueue.Queue(srcaddr, src, listener.port, 0, tfrm.Seq()+1, FlagRST|FlagACK)
		return lneto.ErrPacketDrop
	}
	err = conn.OpenListen(dst, iss)
	if err != nil {
		listener.poolReturn(conn)
		listener.logerr("Listener:open", slog.String("err", err.Error()))
		return err // This should not happend
	}
	err = conn.Demux(carrierData, tcpFrameOffset)
	if err != nil {
		listener.poolReturn(conn)
		listener.logerr("Listener:demux", slog.String("err", err.Error()))
		return lneto.ErrPacketDrop
	}
	debuglog("tcplistener:demux-append")
	listener.incoming = append(listener.incoming, conn.HandleWith(userData))
	listener.debug("tcplistener:demux-new", slog.Uint64("lport", uint64(listener.port)), slog.Uint64("rport", uint64(src)))
	return nil
}

func (listener *Listener) tryDemux(conns []ConnHandle, remotePort uint16, remoteAddr, carrierData []byte, tcpFrameOffset int) (demuxed bool, err error) {
	idx := getConn(conns, remotePort, remoteAddr)
	if idx >= 0 {
		err := conns[idx].c.Demux(carrierData, tcpFrameOffset)
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
	listener.poolCheck() // Timed out conns are aborted and returned below.
	listener.accepted = internal.DeleteZeroed(listener.accepted)
	for i := range listener.incoming {
		conn := listener.incoming[i].c
		if conn == nil {
			continue
		}
		state := conn.State()
		if state > StateEstablished || state.IsClosed() || state == StateListen {
			// Something went wrong in handshake, pool aborted/closed the connection,
			// or RST reverted the connection to LISTEN (RFC 9293 §3.5.3).
			listener.returnIncoming(i)
		}
	}
	listener.incoming = internal.DeleteZeroed(listener.incoming)
}

func getConn(conns []ConnHandle, remotePort uint16, remoteAddr []byte) int {
	for i := range conns {
		conn := conns[i].c
		if conn == nil {
			continue
		}
		gotPort := conn.RemotePort()
		gotaddr := conn.RemoteAddr()
		if remotePort == gotPort && internal.BytesEqual(remoteAddr, gotaddr) {
			return i
		}
	}
	return -1
}

func (listener *Listener) maintainConn(conns []ConnHandle, idx int, err error) error {
	if err == net.ErrClosed {
		listener.poolReturn(conns[idx].c)
		conns[idx] = ConnHandle{}
		return nil // avoid closing listener entirely.
	}
	return err
}

func (listener *Listener) returnAccepted(idx int) {
	listener.poolReturn(listener.accepted[idx].c)
	listener.accepted[idx] = ConnHandle{}
}

// returnAll returns every conn in conns to the pool and empties the list.
func (listener *Listener) returnAll(conns []ConnHandle) []ConnHandle {
	for i := range conns {
		if conns[i].c != nil {
			listener.poolReturn(conns[i].c)
		}
	}
	clear(conns)
	return conns[:0]
}

func (listener *Listener) returnIncoming(idx int) {
	listener.poolReturn(listener.incoming[idx].c)
	listener.incoming[idx] = ConnHandle{}
}

const enableDebug = internal.HeapAllocDebugging

func debuglog(msg string) {
	if enableDebug {
		internal.LogAllocs(msg)
	}
}
