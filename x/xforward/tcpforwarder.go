package xforward

import (
	"net"
	"os"
	"sync"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

var (
	_ net.Conn                        = FlowConn{}
	_ interface{ CloseWrite() error } = FlowConn{}
)

// TCPForwarder makes [TCPHandler] safe for concurrent use and hands out blocking [FlowConn]s.
// FlowConn Read and Write take only their flow's lock, never mu, so relays on
// different flows do not contend with each other nor with Demux and Encapsulate.
type TCPForwarder struct {
	// mu serializes every TCPHandler call except Read and Write. Taken before any flow lock.
	mu      sync.Mutex
	h       TCPHandler
	wake    func() // Called with no lock held.
	backoff lneto.BackoffStrategy
	// conns holds per-slot FlowConn state, reset on Accept.
	conns []struct {
		// wmu serializes Write and CloseWrite so concurrent writes do not interleave
		// and a FIN does not cut in-flight data. Taken before mu.
		wmu    sync.Mutex
		rd, wd time.Time // Deadlines, guarded by the slot's flow lock.
	}
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
	tf.mu.Lock()
	defer tf.mu.Unlock()
	err := tf.h.Configure(cfg.TCPHandlerConfig)
	if err != nil {
		return err
	}
	tf.wake = cfg.Wake
	tf.backoff = cfg.RWBackoff
	n := int(cfg.MaxFlows)
	internal.SliceReuse(&tf.conns, n)
	tf.conns = tf.conns[:n]
	for i := range tf.conns {
		tf.conns[i].rd = time.Time{}
		tf.conns[i].wd = time.Time{}
	}
	return nil
}

// Demux is [TCPHandler.Demux] under lock, then wakes the pump if a segment is due.
func (tf *TCPForwarder) Demux(pkt Packet) (flow TCPFlow, isNew bool, err error) {
	var wake bool
	tf.mu.Lock()
	flow, isNew, wake, err = tf.h.demux(pkt)
	tf.mu.Unlock()
	if wake {
		tf.doWake()
	}
	return flow, isNew, err
}

// Accept is [TCPHandler.Accept] returning a blocking [FlowConn] for the flow.
func (tf *TCPForwarder) Accept(flow TCPFlow, rxbuf, txbuf []byte) (FlowConn, error) {
	tf.mu.Lock()
	err := tf.h.Accept(flow, rxbuf, txbuf)
	if err == nil {
		f := &tf.h.flows[flow.slot]
		f.mu.Lock()
		tf.conns[flow.slot].rd = time.Time{}
		tf.conns[flow.slot].wd = time.Time{}
		f.mu.Unlock()
	}
	tf.mu.Unlock()
	tf.doWake() // SYN-ACK, or RST on failure, is due.
	if err != nil {
		return FlowConn{}, err
	}
	return FlowConn{tf: tf, flow: flow}, nil
}

// Reject is [TCPHandler.Reject] under lock.
func (tf *TCPForwarder) Reject(flow TCPFlow) error {
	tf.mu.Lock()
	err := tf.h.Reject(flow)
	tf.mu.Unlock()
	tf.doWake()
	return err
}

// Encapsulate is [TCPHandler.Encapsulate] under lock.
func (tf *TCPForwarder) Encapsulate(carrierData []byte, offsetToIP int) (int, error) {
	tf.mu.Lock()
	defer tf.mu.Unlock()
	return tf.h.Encapsulate(carrierData, offsetToIP)
}

// NextDeadline is [TCPHandler.NextDeadline] under lock.
func (tf *TCPForwarder) NextDeadline() int64 {
	tf.mu.Lock()
	defer tf.mu.Unlock()
	return tf.h.NextDeadline()
}

// Abort reaps every flow. Blocked [FlowConn] calls return [net.ErrClosed].
func (tf *TCPForwarder) Abort() {
	tf.mu.Lock()
	tf.h.Abort()
	tf.mu.Unlock()
}

func (tf *TCPForwarder) doWake() {
	if tf.wake != nil {
		tf.wake()
	}
}

// FlowConn is a blocking [net.Conn] over one forwarded flow. Close releases the flow.
type FlowConn struct {
	tf   *TCPForwarder
	flow TCPFlow
}

// Read blocks until data is received, the peer closes (io.EOF) or the read deadline passes.
// Takes only the flow's lock; wakes the pump if reading queued a window update.
func (c FlowConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	var backoffs uint
	for {
		n, wake, err := c.tf.h.read(c.flow, b)
		if wake {
			c.tf.doWake()
		}
		if n > 0 || err != nil {
			return n, err
		} else if err = c.expired(false); err != nil {
			return 0, err
		}
		c.tf.backoff.Do(backoffs)
		backoffs++
	}
}

// Write blocks until all of b is buffered for sending or the write deadline passes.
// Takes only the flow's lock; wakes the pump once the flow turns dirty, before any wait.
func (c FlowConn) Write(b []byte) (n int, err error) {
	s := &c.tf.conns[c.flow.slot]
	s.wmu.Lock()
	defer s.wmu.Unlock()
	var backoffs uint
	for n < len(b) {
		ngot, wake, err := c.tf.h.write(c.flow, b[n:])
		if wake {
			c.tf.doWake()
		}
		n += ngot
		if err != nil {
			return n, err
		} else if ngot > 0 {
			backoffs = 0
			continue
		} else if err = c.expired(true); err != nil {
			return n, err
		}
		c.tf.backoff.Do(backoffs)
		backoffs++
	}
	return n, nil
}

// CloseWrite sends a FIN once buffered data is sent. Reads keep working.
// It waits for a Write in progress so its data is not cut off.
func (c FlowConn) CloseWrite() error {
	s := &c.tf.conns[c.flow.slot]
	s.wmu.Lock()
	defer s.wmu.Unlock()
	c.tf.mu.Lock()
	err := c.tf.h.CloseWrite(c.flow)
	c.tf.mu.Unlock()
	c.tf.doWake()
	return err
}

// Close releases the flow. Blocked Write calls fail and Read returns io.EOF;
// once the flow is reaped calls return [net.ErrClosed].
func (c FlowConn) Close() error {
	c.tf.mu.Lock()
	err := c.tf.h.Release(c.flow)
	c.tf.mu.Unlock()
	c.tf.doWake()
	return err
}

// LocalAddr returns the original destination the flow answers as.
func (c FlowConn) LocalAddr() net.Addr { return net.TCPAddrFromAddrPort(c.flow.ID.Local) }

// RemoteAddr returns the peer's address.
func (c FlowConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.flow.ID.Remote) }

// SetDeadline sets read and write deadlines.
func (c FlowConn) SetDeadline(t time.Time) error { return c.setDeadline(t, true, true) }

// SetReadDeadline sets the deadline for current and future Read calls. Zero t disables it.
func (c FlowConn) SetReadDeadline(t time.Time) error { return c.setDeadline(t, true, false) }

// SetWriteDeadline sets the deadline for current and future Write calls. Zero t disables it.
func (c FlowConn) SetWriteDeadline(t time.Time) error { return c.setDeadline(t, false, true) }

func (c FlowConn) setDeadline(t time.Time, read, write bool) error {
	f, err := c.tf.h.lockFlow(c.flow)
	if err != nil {
		return err
	}
	s := &c.tf.conns[c.flow.slot]
	if read {
		s.rd = t
	}
	if write {
		s.wd = t
	}
	f.mu.Unlock()
	return nil
}

// expired returns [os.ErrDeadlineExceeded] once the read or write deadline has passed.
func (c FlowConn) expired(write bool) error {
	f, err := c.tf.h.lockFlow(c.flow)
	if err != nil {
		return err
	}
	deadline := c.tf.conns[c.flow.slot].rd
	if write {
		deadline = c.tf.conns[c.flow.slot].wd
	}
	f.mu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

// ID returns the flow's addresses.
func (c FlowConn) ID() FlowID { return c.flow.ID }

// Stats returns the number of segments received and sent on the flow.
// Call before Close: a released flow may be reaped at any time.
func (c FlowConn) Stats() (rxPkts, txPkts uint32, err error) {
	c.tf.mu.Lock()
	defer c.tf.mu.Unlock()
	return c.tf.h.Stats(c.flow)
}
