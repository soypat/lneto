package tcp

import (
	"io"
	"net"
	"time"

	"log/slog"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

// Handler is a low level TCP handling data structure. It implements logic
// related to data buffering, frame sequencing and connection state handling.
// Does NOT implement IP related logic, so no CRC calculation/validation or pseudo header logic.
//
// See [Conn] for a higher level abstraction of a TCP connection, and see [ControlBlock] for the low level state machine of a TCP connection.
type Handler struct {
	connid uint64
	scb    ControlBlock
	bufTx  ringTx
	bufRx  internal.Ring
	logger
	validator  lneto.Validator
	localPort  uint16
	remotePort uint16
	// connid is a connection counter that is incremented each time a new
	// connection is established via Open calls. This disambiguates whether
	// Read and Write calls belong to the current connection.

	optcodec OptionCodec
	// cc is the optional congestion controller. When nil the Handler is only
	// limited by the receive window advertised by the peer (no congestion
	// control). See [Handler.SetCongestionControl].
	cc CongestionControl
	// reasm is the optional out-of-order reassembly buffer. When disabled
	// (no buffer set) the Handler only accepts in-order segments, as before.
	// See [Handler.SetReassemblyBuffer].
	reasm reassembly
	// congestWnd caches the window returned by the last cc.Control call.
	// invalidCongestWnd means no window has been reported yet (no gating).
	congestWnd Size
	// clock injects the time source shared by the RFC 6298 retransmission timer
	// and (typically) the congestion controller. nil uses time.Now.
	clock      func() time.Time
	closing    bool
	shutdownRx bool
	// nRetransmit stores the number of times the oldest packet was retransmit.
	nRetransmit    uint8
	requeueControl bool
}

// invalidCongestWnd marks Handler.congestWnd as not-yet-reported by the
// congestion controller, in which case no congestion gating is applied.
const invalidCongestWnd = 0xffff_ffff

// SetCongestionControl installs cc as the connection's congestion controller,
// or removes it when cc is nil. It limits how much new (unacknowledged) data
// the Handler keeps in flight to the window returned by cc.Control, which is
// fed every segment crossing the connection. The controller is retained across
// connection re-opens. Returns [lneto.ErrBadState] if the connection is open:
// the controller cannot be changed mid-connection (see
// [ConnConfig.CongestionControl] to configure it on a [Conn]).
func (h *Handler) SetCongestionControl(cc CongestionControl) error {
	if !h.scb.State().IsClosed() {
		return lneto.ErrBadState
	}
	h.cc = cc
	h.congestWnd = invalidCongestWnd
	return nil
}

// SetReassemblyBuffer enables out-of-order segment reassembly using buf as
// storage for up to maxSegments segments that arrive ahead of the next expected
// sequence number (buf is divided into maxSegments equal slots). With
// reassembly enabled a single lost segment is recovered by retransmitting only
// the gap; the buffered tail is then delivered without go-back-N. Passing a nil
// buffer or zero maxSegments disables reassembly (the default: in-order only).
// Returns [lneto.ErrBadState] if the connection is open.
//
// buf should be sized at least as large as the receive buffer so that any
// in-window segment arriving during a gap can be held: the receiver subtracts
// out-of-order bytes from its advertised window, but the slab must be able to
// absorb a full window's worth of out-of-order data. Each slot holds one
// segment, so maxSegments bounds how many distinct out-of-order segments may be
// outstanding; len(buf)/maxSegments must be at least one segment (MSS) of bytes.
func (h *Handler) SetReassemblyBuffer(buf []byte, maxSegments int) error {
	if !h.scb.State().IsClosed() {
		return lneto.ErrBadState
	}
	h.reasm.reset(buf, maxSegments)
	return nil
}

// SetLoggers sets the [slog.Logger] for the Handler and internal [ControlBlock].
func (h *Handler) SetLoggers(handler, scb *slog.Logger) {
	h.logger.log = handler
	h.scb.logger.log = scb
}

// SetClock injects the time source used by the RFC 6298 retransmission timer
// (and shared with a congestion controller for deterministic testing). It must
// be set before the connection is opened; a nil clock falls back to time.Now.
func (h *Handler) SetClock(clock func() time.Time) {
	h.clock = clock
	h.scb.SetClock(clock)
}

func (h *Handler) now() time.Time {
	if h.clock != nil {
		return h.clock()
	}
	return time.Now()
}

// CheckRetransmitTimeout drives the RFC 6298 retransmission timer and should be
// called periodically (e.g. once per stack poll). When the timer has expired it
// rewinds the send sequence and transmit buffer so the next Send retransmits
// unacknowledged data from snd.UNA (go-back-N), and returns true. The next call
// to Send emits the retransmission. Congestion-controller notification of the
// timeout is wired separately.
// RetransmitDeadline returns the time at which the retransmission timer will
// next fire and whether it is currently running. A poller uses it to schedule
// the next CheckRetransmitTimeout call.
func (h *Handler) RetransmitDeadline() (time.Time, bool) {
	return h.scb.rto.deadline, h.scb.rto.running
}

func (h *Handler) CheckRetransmitTimeout() bool {
	if !h.scb.CheckRetransmitTimeout(h.now()) {
		return false
	}
	h.bufTx.RetransmitFromUNA()
	if h.cc != nil {
		// Notify the controller of the timeout so it collapses its window
		// (RFC 6298 §5 / RFC 5681 §3.1) before retransmission resumes.
		h.congestWnd = h.cc.Control(h.scb.CongestionRTOEvent())
	}
	return true
}

// ConnectionID returns the connection identifier which is incremented every time the connection is closed or open.
func (h *Handler) ConnectionID() *uint64 {
	return &h.connid
}

// State returns the state of the TCP state machine as per RFC9293. See [State].
func (h *Handler) State() State { return h.scb.State() }

// SetBuffers sets the internal buffers used to receive and transmit bytes asynchronously via [Handler.Write] and [Handler.Read] calls.
// If the argument buffer is nil then the respective currently set buffer will be reused.
func (h *Handler) SetBuffers(txbuf, rxbuf []byte, packets int) error {
	if h.bufRx.Buf == nil && (len(rxbuf) < minBufferSize || len(txbuf) < minBufferSize) {
		return lneto.ErrShortBuffer
	}
	if !h.scb.State().IsClosed() {
		return lneto.ErrInvalidConfig
	}
	if rxbuf != nil {
		h.bufRx.Buf = rxbuf
	}
	h.scb.SetRecvWindow(Size(h.bufRx.Size()))
	h.bufRx.Reset()
	return h.bufTx.ResetOrReuse(txbuf, packets, 0)
}

// LocalPort returns the local port of the connection. Returns 0 if the connection is closed and uninitialized.
func (h *Handler) LocalPort() uint16 {
	return h.localPort
}

// RemotePort returns the remote port of the connection if it is set.
// If the connection is passive and has not yet been established it will return 0.
func (h *Handler) RemotePort() uint16 {
	return h.remotePort
}

// OpenActive opens an "active" TCP connection to a known remote port. The caller holds knowledge of the IP address.
// OpenActive is used by TCP Clients to initiate a connection.
func (h *Handler) OpenActive(localPort, remotePort uint16, iss Value) error {
	if remotePort == 0 {
		return lneto.ErrZeroDestination
	} else if h.bufRx.Size() < minBufferSize || h.bufTx.Size() < minBufferSize {
		return errBufferTooSmall
	} else if h.scb.State() != StateClosed && h.scb.State() != StateTimeWait {
		return errNeedClosedTCBToOpen
	}
	// reset/Abort prepares a SCB for active connection by resetting state to closed.
	h.scb.reset()
	h.reset(localPort, remotePort, iss)
	h.scb.SetRecvWindow(Size(h.bufRx.Size()))
	return nil
}

// OpenListen prepares a passive TCP connection where the Handler acts as a server.
// OpenListen is used by TCP Servers to begin listening for remote connections.
func (h *Handler) OpenListen(localPort uint16, iss Value) error {
	if localPort == 0 {
		return lneto.ErrZeroSource
	} else if h.bufRx.Size() < minBufferSize || h.bufTx.Size() < minBufferSize {
		return errBufferTooSmall
	}
	// Open will fail unless SCB in closed state.
	err := h.scb.Open(iss, Size(h.bufRx.Size()))
	if err != nil {
		return err
	}
	h.reset(localPort, 0, iss)
	return nil
}

// Abort forcibly terminates all state associated to current connection.
// After a call to abort no more data can be sent nor received over the connection.
func (h *Handler) Abort() {
	h.info("tcp.Handler.Abort")
	h.scb.Abort()
	h.reset(0, 0, 0)
}

// reset clears all state except [ControlBlock] state. So [Handler.State] will remain unchanged.
func (h *Handler) reset(localPort, remotePort uint16, iss Value) {
	*h = Handler{
		connid:     h.connid + 1,
		scb:        h.scb,
		bufTx:      h.bufTx,
		bufRx:      h.bufRx,
		localPort:  localPort,
		remotePort: remotePort,
		validator:  h.validator,
		logger:     h.logger,
		cc:         h.cc,
		reasm:      h.reasm,
		congestWnd: invalidCongestWnd,
		clock:      h.clock,
		closing:    false,
		shutdownRx: false,
	}
	h.reasm.clear() // preserve the slab/config across reopen, drop held segments.
	h.bufTx.ResetOrReuse(nil, 0, iss)
	h.bufRx.Reset()
	if h.cc != nil {
		// Notify the controller a connection is (re)opening or tearing down so it
		// starts from a clean per-connection state while keeping its configuration.
		h.cc.Reset()
	}
}

// Recv receives an incoming TCP packet frame with the first byte being the first octet of the TCP frame.
// The [Handler]'s internal state is updated if the packet is admitted successfully.
func (h *Handler) Recv(incomingPacket []byte) error {
	if h.IsTxOver() {
		return net.ErrClosed
	}
	tfrm, err := NewFrame(incomingPacket)
	if err != nil {
		return err
	}
	tfrm.ValidateExceptCRC(&h.validator)
	err = h.validator.ErrPop()
	if err != nil {
		return err
	}

	remotePort := tfrm.SourcePort()
	if h.remotePort != 0 && remotePort != h.remotePort {
		return lneto.ErrMismatch
	}
	dstPort := tfrm.DestinationPort()
	if h.localPort != dstPort {
		return lneto.ErrMismatch
	}
	payload := tfrm.Payload()
	segIncoming := tfrm.Segment(len(payload))
	if h.scb.IncomingIsKeepalive(segIncoming) {
		h.info("tcp.Handler:rx-keepalive", slog.Uint64("port", uint64(h.localPort)))
		return nil
	}

	// Out-of-order reassembly: buffer in-window data that arrived ahead of the
	// next expected sequence number before the ControlBlock (sequential-only)
	// would reject it. Buffered segments go to the reassembly slab, not bufRx.
	if h.reasm.enabled() && h.handleOutOfOrder(segIncoming, payload) {
		return nil
	}
	if !h.shutdownRx && len(payload) > h.bufRx.Free() {
		return lneto.ErrBufferFull
	}

	prevState := h.scb.State()
	prevUNA := h.scb.snd.UNA // Capture before Recv updates snd.UNA (RFC 6298 §5.3).
	err = h.scb.Recv(segIncoming)
	if err != nil {
		if h.scb.State() == StateClosed {
			err = net.ErrClosed // Connection closed by RST; signal caller to tear down.
		}
		return err
	}
	if h.scb.State() == StateClosed {
		// TCB aborted, likely because it received an ACK in LastAck state.
		// Clean up connection now unless read pending.
		return net.ErrClosed
	}
	if prevState != h.scb.State() {
		h.info("tcp.Handler:rx-statechange", slog.Uint64("port", uint64(h.localPort)), slog.String("old", prevState.String()), slog.String("new", h.scb.State().String()), slog.String("rxflags", segIncoming.Flags.String()))
	}
	if segIncoming.DATALEN != 0 && h.shutdownRx && (h.scb.State() == StateFinWait1 || h.scb.State() == StateFinWait2) {
		// soypat/lneto#50: the application is done in both directions — read side
		// shut down (CloseRead) and our FIN sent (Close) — so inbound data has no
		// consumer. Reply RST instead of the silent ACK-and-drop that leaves the
		// peer waiting; the connection is torn down once the RST is sent.
		h.info("tcp.Handler:rst-data-after-fullclose", slog.Uint64("lport", uint64(h.localPort)), slog.Uint64("rport", uint64(h.remotePort)), slog.Uint64("datalen", uint64(segIncoming.DATALEN)))
		h.scb.QueueRST(segIncoming.ACK)
		return nil
	}
	if segIncoming.DATALEN != 0 && !h.shutdownRx {
		_, err = h.bufRx.Write(payload)
		if err != nil {
			return err
		}
	}
	if segIncoming.DATALEN != 0 && h.reasm.buffered() > 0 {
		// The just-accepted in-order segment may have filled a gap; deliver any
		// now-contiguous buffered segments.
		h.flushReassembly()
	}
	if segIncoming.Flags.HasAny(FlagACK) {
		if segIncoming.ACK == prevUNA {
			// scb keeping track of duplicate acks.
			h.info("tcp.Handler:dupack", slog.Uint64("ndupack", uint64(h.scb.dupack)), slog.Uint64("ack", uint64(segIncoming.ACK)), slog.Uint64("lport", uint64(h.localPort)), slog.Uint64("rport", uint64(h.remotePort)))
		} else {
			// Update TX ring buffer to free up acked data.
			h.bufTx.RecvACK(segIncoming.ACK)
		}
	}
	if segIncoming.Flags.HasAny(FlagSYN) {
		// Parse remote MSS from TCP options.
		h.optcodec.ForEachOption(tfrm.Options(), func(kind OptionKind, data []byte) error {
			if kind == OptMaxSegmentSize && len(data) == 2 {
				mss := uint16(data[0])<<8 | uint16(data[1])
				if mss > 0 {
					h.scb.snd.MSS = Size(mss)
				}
			}
			return nil
		})
		if h.remotePort == 0 {
			// Remote reached out and has given us their port, set it on our side.
			h.debug("tcp.Handler:rx-remoteport-set", slog.Uint64("port", uint64(h.localPort)), slog.Uint64("remoteport", uint64(remotePort)))
			h.remotePort = remotePort
		}
	}
	if h.cc != nil {
		// Feed the received segment (ACKs, duplicate ACKs/loss, RTT samples) into
		// the congestion controller after the TCB has updated snd.UNA/dupack.
		h.congestWnd = h.cc.Control(h.scb.CongestionEvent(segIncoming, false))
	}
	if h.logenabled(internal.LevelTrace) {
		h.trace("tcp.Handler:rx-done",
			slog.Uint64("lport", uint64(h.localPort)),
			slog.Uint64("rport", uint64(remotePort)),
			slog.Uint64("seg.seq", uint64(segIncoming.SEQ)),
			slog.Uint64("seg.ack", uint64(segIncoming.ACK)),
			slog.Uint64("seg.datalen", uint64(segIncoming.DATALEN)),
		)
	}
	return nil
}

// handleOutOfOrder buffers an in-window data segment that arrived ahead of the
// next expected sequence number and queues a duplicate ACK so the sender fast-
// retransmits the gap. It returns true when it has consumed the segment; false
// leaves the segment to the ControlBlock (in-order data, control segments, old
// or out-of-window segments, or when the reassembly buffer cannot hold it).
func (h *Handler) handleOutOfOrder(seg Segment, payload []byte) bool {
	if seg.DATALEN == 0 || seg.Flags.HasAny(flagctl) {
		return false // only pure data segments are buffered out of order.
	}
	rcvNxt := h.scb.RecvNext()
	if seg.SEQ == rcvNxt {
		return false // in order: the ControlBlock handles it normally.
	}
	rcvWnd := h.scb.RecvWindow()
	if !seg.SEQ.InWindow(rcvNxt, rcvWnd) || !seg.Last().InWindow(rcvNxt, rcvWnd) {
		return false // old or out of window: let the ControlBlock decide.
	}
	if !h.reasm.store(seg.SEQ, payload) {
		return false // no room: fall back to ControlBlock (challenge ACK).
	}
	h.scb.pending[0] |= FlagACK // duplicate ACK advertises the gap at rcv.NXT.
	h.trace("tcp.Handler:rx-ooo", slog.Uint64("seg.seq", uint64(seg.SEQ)), slog.Uint64("rcv.nxt", uint64(rcvNxt)))
	return true
}

// flushReassembly delivers buffered out-of-order segments that have become
// contiguous with rcv.NXT, advancing the receive sequence number and queuing an
// ACK for the newly delivered data. It stops when a gap remains or the receive
// buffer lacks room (the remainder is delivered on a later Recv or Read).
func (h *Handler) flushReassembly() {
	for h.reasm.buffered() > 0 {
		nxt := h.scb.RecvNext()
		h.reasm.prune(nxt)
		if !h.shutdownRx && h.bufRx.Free() < h.reasm.segSize {
			break // no room to deliver yet; keep the segments buffered.
		}
		data, ok := h.reasm.popContiguous(nxt)
		if !ok {
			break // a gap remains before the next buffered segment.
		}
		if !h.shutdownRx {
			if _, err := h.bufRx.Write(data); err != nil {
				break
			}
		}
		h.scb.rcv.NXT.UpdateForward(Size(len(data)))
		h.scb.pending[0] |= FlagACK
	}
}

// ShutdownRead activates local discard mode: incoming payload bytes are dropped
// (ACK/SEQ still advance normally) and Read returns [io.EOF] immediately.
// Not reversible within the lifetime of a connection.
// If [Handler.Close] and this method are both called then connection will be terminated.
func (h *Handler) ShutdownRead() {
	h.shutdownRx = true
}

// Close will initiate the TCP close sequence.
// After Close is called [Handler.Write] will fail with [net.ErrClosed].
// The connection may still receive data to read after Close called.
func (h *Handler) Close() error {
	h.trace("tcp.Handler.Close")
	if h.closing {
		return errConnectionClosing
	} else if h.State().IsClosed() {
		return net.ErrClosed
	}
	h.closing = true
	return nil
}

// Send writes TCP frame to be sent over the network to the remote peer to `b`.
// It does no IP interfacing or CRC calculation of packet, which is left to the caller to perform.
// The returned integer is the length written to the argument buffer.
func (h *Handler) Send(b []byte) (int, error) {
	if h.IsTxOver() {
		return 0, net.ErrClosed
	}
	awaitingSyn := h.AwaitingSynSend()
	requeueControl := h.requeueControl
	buffered := h.bufTx.BufferedUnsent()
	if h.scb.State() == StateCloseWait && !h.closing && buffered == 0 && !h.scb.HasPending() {
		// Remote closed with no application data left to send: initiate our own close.
		// Checked here (not in Recv) so the application can still write in CLOSE-WAIT
		// before Send is called, implementing the half-close per RFC 9293 §3.5.
		h.closing = true
	}
	if !awaitingSyn && !requeueControl && buffered == 0 && !h.closing && !h.scb.HasPending() {
		// Early nop short circuit.
		return 0, nil
	}
	tfrm, err := NewFrame(b)
	if err != nil {
		return 0, err
	}
	if buffered == 0 && h.closing && (h.scb.State() != StateCloseWait || !h.scb.HasPending()) {
		// If Close called and no more data to be sent, terminate connection.
		// In CLOSE-WAIT: wait until the pending ACK is sent first, since scb.Close()
		// overwrites pending with [FIN|ACK] (unlike ESTABLISHED which merges via bitmask).
		h.closing = false
		err = h.scb.Close()
		if err != nil {
			h.logerr("tcp.Handler.Close", slog.String("err", errstr(err)), slog.String("state", h.State().String()))
			h.Abort()
			return 0, io.EOF
		}
	}
	offset := uint8(5)
	mss := uint16(len(b) - sizeHeaderTCP)
	var segment Segment
	if awaitingSyn || requeueControl && h.scb.State() == StateSynSent {
		// Handling init syn segment.
		segment = ClientSynSegment(h.bufTx.iss, Size(h.bufRx.Size()))
		h.optcodec.PutOption16(b[sizeHeaderTCP:], OptMaxSegmentSize, mss)
		offset++
		if requeueControl {
			h.info("tcp.Handler:requeue-syn", slog.Uint64("port", uint64(h.localPort)), slog.Uint64("rport", uint64(h.remotePort)))
		}
	} else if requeueControl && h.scb.State() == StateSynRcvd {
		segment = Segment{
			SEQ:   h.scb.snd.UNA,
			ACK:   h.scb.rcv.NXT,
			WND:   Size(h.bufRx.Free()),
			Flags: synack,
		}
		h.optcodec.PutOption16(b[sizeHeaderTCP:], OptMaxSegmentSize, mss)
		offset++
		h.info("tcp.Handler:requeue-synack", slog.Uint64("port", uint64(h.localPort)), slog.Uint64("rport", uint64(h.remotePort)))
	} else if requeueControl {
		h.requeueControl = false
		return 0, nil
	} else {
		var ok bool
		maxPayload := len(b) - sizeHeaderTCP
		if h.cc != nil && h.congestWnd != invalidCongestWnd && !h.scb.HasPendingRetransmit() {
			// Limit new data to the congestion window reported by the last
			// cc.Control call. Retransmissions and pure control segments are
			// exempt: PendingSegment still emits them when the available window is
			// zero (it only suppresses new data).
			// Compared as uint64 so a large window cannot wrap on 32-bit int.
			inflight := h.scb.snd.inFlight()
			var avail Size
			if h.congestWnd > inflight {
				avail = h.congestWnd - inflight
			}
			if maxPayload > 0 && uint64(avail) < uint64(maxPayload) {
				maxPayload = int(avail)
			}
		}
		segment, ok = h.scb.PendingSegment(maxPayload)
		segment.WND = h.recvWindow()
		if !ok {
			// No pending control segment or data to send. Yield.
			return 0, nil
		} else if segment.Flags == synack {
			h.optcodec.PutOption16(b[sizeHeaderTCP:], OptMaxSegmentSize, mss)
			offset++
		} else if segment.DATALEN > 0 {
			n, err := h.bufTx.MakePacket(b[sizeHeaderTCP:sizeHeaderTCP+segment.DATALEN], segment.SEQ)
			if err != nil {
				return 0, err
			}
			segment.DATALEN = Size(n)
			if n > 0 {
				segment.Flags |= FlagPSH
			}
		}
	}
	prevState := h.scb.State()
	if h.cc != nil {
		// Observe the outgoing segment before scb.Send advances snd.NXT so the
		// controller can tell new data from a retransmission and time RTTs.
		h.congestWnd = h.cc.Control(h.scb.CongestionEvent(segment, true))
	}
	err = h.scb.Send(segment)
	if err != nil {
		return 0, err
	} else if prevState != h.scb.State() && h.logenabled(slog.LevelInfo) {
		h.info("tcp.Handler:tx-statechange", slog.Uint64("port", uint64(h.localPort)), slog.String("oldState", prevState.String()), slog.String("newState", h.scb.State().String()), slog.String("txflags", segment.Flags.String()))
	}
	h.requeueControl = false
	tfrm.SetSourcePort(h.localPort)
	tfrm.SetDestinationPort(h.remotePort)
	tfrm.SetSegment(segment, offset)
	tfrm.SetUrgentPtr(0)
	datalen := int(offset)*4 + int(segment.DATALEN)
	closedSuccess := prevState == StateTimeWait && segment.Flags.HasAny(FlagACK)
	if closedSuccess {
		h.reset(0, 0, 0)
	} else if segment.Flags.HasAny(FlagRST) {
		// A sent RST aborts the connection: tear down local state now that the
		// reset has been written to the wire (frame already in b).
		h.Abort()
	}
	return datalen, nil
}

// Write implements [io.Writer] by copying b to a internal buffer to be sent over the network on the next
// [Handler.Send] call that can send data to remote peer. Use [Handler.Free] to know the maximum length the argument slice can be before erroring.
func (h *Handler) Write(b []byte) (int, error) {
	state := h.State()
	if h.closing {
		return 0, errConnectionClosing
	} else if !state.TxDataOpen() { // Reject write call if data cannot be sent.
		return 0, net.ErrClosed
	}
	return h.bufTx.Write(b)
}

// Read implements [io.Reader] by reading received data from remote peer in internal buffer.
func (h *Handler) Read(b []byte) (n int, err error) {
	if h.shutdownRx {
		return 0, io.EOF
	}
	if h.bufRx.Buffered() > 0 {
		n, err = h.bufRx.Read(b)
	}
	if n > 0 {
		if h.reasm.buffered() > 0 {
			// Reading freed receive-buffer space; deliver any contiguous
			// out-of-order data that was waiting for room.
			h.flushReassembly()
		}
		h.maybeQueueWindowUpdate()
	}
	if n == 0 && err == nil {
		state := h.State()
		if state.IsClosed() {
			err = net.ErrClosed
		} else if !state.RxDataOpen() {
			err = io.EOF
		}
	}
	return n, err
}

// maybeQueueWindowUpdate queues a window update ACK if the receive window has
// opened significantly since it was last advertised. This prevents zero-window
// deadlocks where the remote peer cannot send data because it thinks our window
// is still 0 after we've Read() data from the buffer.
//
// Per RFC 9293 §3.8.6.2.2 (SWS avoidance), the window is updated when freed
// space >= min(bufferSize/2, MSS). This applies uniformly including zero-window
// recovery — the remote uses zero-window probes until enough space opens.
func (h *Handler) maybeQueueWindowUpdate() {
	currentFree := h.recvWindow()
	lastAdvertised := h.scb.RecvWindow()
	if currentFree <= lastAdvertised {
		return // Window hasn't grown.
	}
	thresh := Size(h.bufRx.Size()) / 2
	if mss := h.scb.snd.MSS; mss > 0 && mss < thresh {
		thresh = mss
	}
	if currentFree-lastAdvertised >= thresh {
		h.scb.pending[0] |= FlagACK
	}
}

// SizeOutput returns the total size of the transmit ring buffer.
func (h *Handler) SizeOutput() int {
	return h.bufTx.Size()
}

// SizeInput returns the total size of the receive ring buffer.
func (h *Handler) SizeInput() int {
	return h.bufRx.Size()
}

// BufferedInput returns the number of unread bytes in the receive buffer.
func (h *Handler) BufferedInput() int {
	return h.bufRx.Buffered()
}

// BufferedUnsent returns the number of written but unsent bytes in the transmit buffer.
func (h *Handler) BufferedUnsent() int {
	return h.bufTx.BufferedUnsent()
}

// FreeOutput returns the number of free bytes in the transmit buffer.
func (h *Handler) FreeOutput() int {
	return h.bufTx.Free()
}

// FreeInput returns the number of free bytes in the receive buffer.
func (h *Handler) FreeInput() int {
	return h.bufRx.Free()
}

// recvWindow returns the receive window to advertise: free receive-buffer space
// minus the bytes already held out of order, which will consume that space once
// the gap fills. Subtracting them prevents the sender from overrunning the
// receiver while a gap is open. For this to be sufficient the reassembly slab
// should be sized at least as large as the receive buffer (see
// [Handler.SetReassemblyBuffer]).
func (h *Handler) recvWindow() Size {
	free := Size(h.bufRx.Free())
	if !h.reasm.enabled() {
		return free
	}
	if ooo := Size(h.reasm.bufferedBytes()); ooo < free {
		return free - ooo
	}
	return 0
}

// AwaitingSynResponse returns true if the Handler is an active client opened with [Handler.OpenActive] and has already sent out the first SYN packet to the remote client.
func (h *Handler) AwaitingSynResponse() bool {
	return h.remotePort != 0 && h.scb.State() == StateSynSent
}

// IsAwaitingControl reports whether the connection is waiting for a response to
// a control segment that can be retransmitted to advance connection state.
func (h *Handler) IsAwaitingControl() bool {
	return h.AwaitingSynResponse() || h.scb.State() == StateSynRcvd
}

// RequeueControl asks the next Send call to retransmit the outstanding control
// segment, if the connection is waiting for one.
func (h *Handler) RequeueControl() {
	if h.IsAwaitingControl() {
		h.requeueControl = true
	}
}

// AwaitingSynAck returns true if the Handler is a passive server opened with [Handler.OpenListen] and not yet received a valid SYN remote packet.
func (h *Handler) AwaitingSynAck() bool {
	return h.remotePort == 0 && h.scb.State() == StateListen
}

// AwaitingSynSend returns true if the Handler is an active client opened with [Handler.OpenActive] and not yet sent out the first SYN packet to the remote client.
func (h *Handler) AwaitingSynSend() bool {
	return h.remotePort != 0 && h.scb.State() == StateClosed
}

// IsTxOver returns true if there is no more frames to encapsulate over the network.
// The connection is pretty much over in this case if packets made it succesfully to remote.
func (h *Handler) IsTxOver() bool {
	state := h.State()
	return state == StateClosed && !h.AwaitingSynSend() ||
		state == StateTimeWait && !h.scb.HasPending()
}

func errstr(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
