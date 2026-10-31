package xforward

import (
	"net"
	"sync"
	"time"

	"github.com/soypat/lneto"
)

var (
	_ net.Conn                        = FlowConn{}
	_ interface{ CloseWrite() error } = FlowConn{}
)

// TCPForwarder makes [TCPHandler] safe for concurrent use and hands out blocking [FlowConn]s.
type TCPForwarder struct {
	mu        sync.Mutex
	h         TCPHandler
	wake      func()
	backoff   lneto.BackoffStrategy
	deadlines []struct{ rd, wd time.Time } // per slot, reset on Accept.
}

// TCPForwarderConfig configures a [TCPForwarder].
type TCPForwarderConfig struct {
	TCPHandlerConfig
	// Wake is called after a flow may have a segment to send. Must not block.
	// nil means caller polls Encapsulate.
	Wake func()
	// RWBackoff is how [FlowConn] waits on empty reads and full writes. Required.
	RWBackoff lneto.BackoffStrategy
}

// Configure sizes the forwarder for cfg and resets it.
func (tf *TCPForwarder) Configure(cfg TCPForwarderConfig) error {
	if cfg.RWBackoff == nil {
		return lneto.ErrMissingHALConfig
	}
	return lneto.ErrUnsupported
}

// Demux is [TCPHandler.Demux] under lock, then wakes the pump.
func (tf *TCPForwarder) Demux(pkt Packet) (flow TCPFlow, isNew bool, err error) {
	return TCPFlow{}, false, lneto.ErrUnsupported
}

// Accept is [TCPHandler.Accept] returning a blocking [FlowConn] for the flow.
func (tf *TCPForwarder) Accept(flow TCPFlow, rxbuf, txbuf []byte) (FlowConn, error) {
	return FlowConn{}, lneto.ErrUnsupported
}

// Reject is [TCPHandler.Reject] under lock.
func (tf *TCPForwarder) Reject(flow TCPFlow) error {
	return lneto.ErrUnsupported
}

// Encapsulate is [TCPHandler.Encapsulate] under lock.
func (tf *TCPForwarder) Encapsulate(carrierData []byte, offsetToIP int) (int, error) {
	return 0, lneto.ErrUnsupported
}

// NextDeadline is [TCPHandler.NextDeadline] under lock.
func (tf *TCPForwarder) NextDeadline() int64 {
	return 0
}

// Abort reaps every flow. Blocked [FlowConn] calls return [net.ErrClosed].
func (tf *TCPForwarder) Abort() {}

// FlowConn is a blocking [net.Conn] over one forwarded flow. Close releases the flow.
type FlowConn struct {
	tf   *TCPForwarder
	flow TCPFlow
}

// Read blocks until data is received, the peer closes (io.EOF) or the read deadline passes.
func (c FlowConn) Read(b []byte) (int, error) {
	return 0, lneto.ErrUnsupported
}

// Write blocks until all of b is buffered for sending or the write deadline passes.
func (c FlowConn) Write(b []byte) (int, error) {
	return 0, lneto.ErrUnsupported
}

// CloseWrite sends a FIN once buffered data is sent. Reads keep working.
func (c FlowConn) CloseWrite() error {
	return lneto.ErrUnsupported
}

// Close releases the flow. Pending calls return [net.ErrClosed].
func (c FlowConn) Close() error {
	return lneto.ErrUnsupported
}

// LocalAddr returns the original destination the flow answers as.
func (c FlowConn) LocalAddr() net.Addr { return net.TCPAddrFromAddrPort(c.flow.ID.Local) }

// RemoteAddr returns the peer's address.
func (c FlowConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.flow.ID.Remote) }

// SetDeadline sets read and write deadlines.
func (c FlowConn) SetDeadline(t time.Time) error {
	return lneto.ErrUnsupported
}

// SetReadDeadline sets the deadline for current and future Read calls. Zero t disables it.
func (c FlowConn) SetReadDeadline(t time.Time) error {
	return lneto.ErrUnsupported
}

// SetWriteDeadline sets the deadline for current and future Write calls. Zero t disables it.
func (c FlowConn) SetWriteDeadline(t time.Time) error {
	return lneto.ErrUnsupported
}

// ID returns the flow's addresses.
func (c FlowConn) ID() FlowID { return c.flow.ID }

// Stats returns the number of segments received and sent on the flow.
// Call before Close: a released flow may be reaped at any time.
func (c FlowConn) Stats() (rxPkts, txPkts uint32, err error) {
	return 0, 0, lneto.ErrUnsupported
}
