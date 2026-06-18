package tcp

import (
	"io"
	"net"

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
	// reasm tracks out-of-order segments staged in bufRx's free region. Always
	// enabled once buffers are set (see [Handler.SetBuffers]).
	reasm reassembly
	// tsPermit enables offering/accepting the RFC 7323 Timestamps option during
	// the handshake. Off by default. See [Handler.EnableTimestamps].
	tsPermit bool
	// sackPermit enables offering/accepting Selective Acknowledgment (RFC 2018)
	// during the handshake. Off by default. See [Handler.EnableSACK].
	sackPermit bool
	// sackRTO marks that a retransmission timeout opened a fresh SACK recovery
	// round; cleared once every outstanding hole has been retransmitted.
	sackRTO bool
	// congestWnd caches the window returned by the last cc.Control call.
	// invalidCongestWnd means no window has been reported yet (no gating).
	congestWnd Size
	closing    bool
	shutdownRx bool
	// nRetransmit stores the number of times the oldest packet was retransmit.
	nRetransmit    uint8
	requeueControl bool

	// loss is the optional packet-loss recovery algorithm (RTO, congestion
	// control, ...) driven from the rx/tx hooks. nil disables loss recovery, in
	// which case the connection behaves as if no timing existed. nanotime is the
	// monotonic time source (nanoseconds) passed to those hooks; it is non-nil
	// whenever loss is non-nil (enforced by [Conn.Configure]). See [LossRecovery].
	loss     LossRecovery
	nanotime func() int64
}

// SetLossRecovery installs the packet-loss recovery algorithm and the monotonic
// time source (nanoseconds, the func() int64 convention used across lneto) that
// drives it. The tcp package keeps no clock of its own; nanotime is read only to
// stamp the rx/tx hooks (see [LossRecovery]) and the RFC 7323 Timestamps option.
// Passing loss == nil disables loss recovery. It should be set before the
// connection is opened.
func (h *Handler) SetLossRecovery(loss LossRecovery, nanotime func() int64) {
	h.loss = loss
	h.nanotime = nanotime
}

// NextDeadline returns the monotonic-nanosecond instant at which the connection
// must next be serviced by a transmit attempt (e.g. an RTO expiry), or 0 when
// there is no deadline or no loss recovery is configured. See [LossRecovery].
func (h *Handler) NextDeadline() int64 {
	if h.loss == nil {
		return 0
	}
	return h.loss.NextDeadline()
}

// EnableTimestamps enables the RFC 7323 TCP Timestamps option, which is then
// offered on the SYN and, if the peer also supports it, used to measure the
// round-trip time on every acknowledgment (RTTM). It is disabled by default and
// must be set before the connection is opened. Returns [lneto.ErrBadState] if
// the connection is open.
func (h *Handler) EnableTimestamps(enable bool) error {
	if !h.scb.State().IsClosed() {
		return lneto.ErrBadState
	}
	h.tsPermit = enable
	return nil
}

// EnableSACK enables Selective Acknowledgment (RFC 2018). When enabled it is
// offered on the SYN and, if the peer also supports it, the receiver advertises
// the byte ranges it holds out of order (built from the reassembly buffer) so
// the sender can retransmit only the gaps. It has effect only together with
// [Handler.SetBuffers]. Disabled by default; must be set before the connection
// is opened. Returns [lneto.ErrBadState] if the connection is open.
func (h *Handler) EnableSACK(enable bool) error {
	if !h.scb.State().IsClosed() {
		return lneto.ErrBadState
	}
	h.sackPermit = enable
	return nil
}

// nanosPerMilli converts the monotonic nanosecond time source to the
// millisecond-resolution TCP timestamp clock (RFC 7323 §4.1).
const nanosPerMilli = 1_000_000

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

// clockReady reports whether a monotonic time source has been configured (via
// [ConnConfig.Nanotime]), enabling the Handler's time-based features such as the
// RFC 7323 Timestamps option. The tcp package keeps no clock of its own;
// nanotime is only read to stamp segments.
func (h *Handler) clockReady() bool { return h.nanotime != nil }

// tsValue returns the local timestamp-clock value for the TSval field: a
// millisecond-resolution monotonic counter (RFC 7323 §4.1) derived from the
// configured nanotime source. Returns 0 when no time source is set.
func (h *Handler) tsValue() uint32 {
	if h.nanotime == nil {
		return 0
	}
	return uint32(h.nanotime() / nanosPerMilli)
}

// TimestampsEnabled reports whether the RFC 7323 Timestamps option was
// negotiated for the current connection.
func (h *Handler) TimestampsEnabled() bool { return h.scb.tsEnabled }

// SACKEnabled reports whether Selective Acknowledgment (RFC 2018) was
// negotiated for the current connection.
func (h *Handler) SACKEnabled() bool { return h.scb.sackEnabled }

// SetLoggers sets the [slog.Logger] for the Handler and internal [ControlBlock].
func (h *Handler) SetLoggers(handler, scb *slog.Logger) {
	h.logger.log = handler
	h.scb.logger.log = scb
}

// sackRetransmitPending reports whether SACK recovery has an outstanding hole to
// retransmit this round.
func (h *Handler) sackRetransmitPending() bool {
	return h.scb.SACKEnabled() && (h.scb.InFastRecovery() || h.sackRTO) && h.bufTx.HasSACKRetransmit()
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
	h.reasm.reset(maxReasmSegments)
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
		tsPermit:   h.tsPermit,
		sackPermit: h.sackPermit,
		congestWnd: invalidCongestWnd,
		closing:    false,
		shutdownRx: false,
		loss:       h.loss,     // configuration persists across reopen.
		nanotime:   h.nanotime, // configuration persists across reopen.
	}
	if h.loss != nil {
		h.loss.Reset() // start loss recovery afresh for the new connection.
	}
	h.reasm.clear() // preserve metadata capacity across reopen, drop held segments.
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

	// Notify loss recovery of the received segment (RTT sampling, timer
	// management) and let it drop the segment before processing if it asks to.
	if h.loss != nil && !h.loss.PreRx(segIncoming, h.nanotime()).Keep {
		return nil
	}

	// Out-of-order reassembly: buffer in-window data that arrived ahead of the
	// next expected sequence number before the ControlBlock (sequential-only)
	// would reject it. Buffered segments live in bufRx's free region.
	if h.reasm.enabled() && h.handleOutOfOrder(segIncoming, payload) {
		return nil
	}
	if !h.shutdownRx && len(payload) > h.bufRx.Free() {
		return lneto.ErrBufferFull
	}

	prevState := h.scb.State()
	prevUNA := h.scb.snd.UNA       // Capture before Recv updates snd.UNA (RFC 6298 §5.3).
	prevRcvNxt := h.scb.RecvNext() // Capture before Recv to detect in-order delivery.
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
	if segIncoming.DATALEN != 0 {
		// The just-accepted in-order segment may have filled a gap; deliver any
		// now-contiguous buffered segments.
		h.deliverReassembled()
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
	h.processOptions(tfrm.Options(), segIncoming, prevRcvNxt, prevUNA)
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
	if h.shutdownRx {
		// Discard mode drops payloads, which would break the ring/rcv.NXT
		// lockstep reassemble relies on; do not buffer.
		return false
	}
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
	if !h.reasm.store(&h.bufRx, rcvNxt, seg.SEQ, payload) {
		return false // no room: fall back to ControlBlock (challenge ACK).
	}
	h.scb.pending[0] |= FlagACK // duplicate ACK advertises the gap at rcv.NXT.
	h.trace("tcp.Handler:rx-ooo", slog.Uint64("seg.seq", uint64(seg.SEQ)), slog.Uint64("rcv.nxt", uint64(rcvNxt)))
	return true
}

// deliverReassembled hands any now-contiguous out-of-order segments to the
// receive stream, advancing rcv.NXT and queuing an ACK for what was delivered.
func (h *Handler) deliverReassembled() {
	if h.reasm.buffered() == 0 {
		return
	}
	if h.shutdownRx {
		// Discard mode skips the gap-filling write, so staged bytes can no
		// longer be committed coherently; drop them (the peer retransmits).
		h.reasm.clear()
		return
	}
	if delivered := h.reasm.reassemble(&h.bufRx, h.scb.RecvNext()); delivered > 0 {
		h.scb.rcv.NXT.UpdateForward(delivered)
		h.scb.pending[0] |= FlagACK
	}
}

// reservedOptionsLen returns the number of option bytes to reserve ahead of the
// payload on an established-state segment (a multiple of 4). Data segments carry
// only the Timestamps option when negotiated.
func (h *Handler) reservedOptionsLen() int {
	if h.scb.tsEnabled {
		return 12 // NOP, NOP, Timestamps(10).
	}
	return 0
}

// appendSegmentOptions writes the TCP options for an outgoing segment into dst
// (which begins right after the 20-byte fixed header) and returns the number of
// bytes written, always a multiple of 4 (NOP-padded). mss is advertised on SYN
// segments.
func (h *Handler) appendSegmentOptions(dst []byte, seg Segment, mss uint16) int {
	n := 0
	isSyn := seg.Flags.HasAny(FlagSYN)
	if isSyn {
		m, _ := h.optcodec.PutOption16(dst[n:], OptMaxSegmentSize, mss)
		n += m
	}
	// TODO(RFC 7323 Window Scale): offer the Window Scale option (OptWindowScale)
	// on the SYN and, once negotiated, scale the advertised receive window here
	// and the peer's advertised window on receive. Without it both windows are
	// capped at 65535 bytes, which throttles throughput on high bandwidth-delay
	// paths and limits the congestion controllers. Implemented in a later part of
	// the patch train.
	// SACK-permitted (RFC 2018 §2): offer on a bare SYN when locally permitted;
	// echo on the SYN-ACK only once negotiated.
	sackPerm := h.scb.sackEnabled
	if seg.Flags == FlagSYN {
		sackPerm = h.sackPermit
	}
	if isSyn && sackPerm {
		m, _ := h.optcodec.PutOption(dst[n:], OptSACKPermitted)
		n += m
	}
	// Timestamps (RFC 7323): offer on a bare SYN when locally permitted;
	// otherwise include only once negotiated (SYN-ACK and established segments).
	// The option carries a clock reading, so it is only ever emitted when a
	// clock has been injected (time integration is opt-in; see SetClock).
	includeTS := h.scb.tsEnabled
	if seg.Flags == FlagSYN {
		includeTS = h.tsPermit && h.clockReady()
	}
	if includeTS {
		dst[n] = byte(OptNop)
		dst[n+1] = byte(OptNop)
		n += 2
		var ts [8]byte
		putUint32BE(ts[0:], h.tsValue())
		putUint32BE(ts[4:], h.scb.tsRecent)
		m, _ := h.optcodec.PutOption(dst[n:], OptTimestamps, ts[:]...)
		n += m
	}
	// SACK blocks (RFC 2018 §3): advertised on a pure ACK when we hold
	// out-of-order data, so the sender can retransmit only the gaps.
	if !isSyn && h.scb.sackEnabled && seg.DATALEN == 0 && !seg.Flags.HasAny(FlagFIN|FlagRST) && h.reasm.buffered() > 0 {
		var blocks [3]sackBlock
		if nb := h.reasm.sackBlocks(blocks[:]); nb > 0 {
			var data [3 * 8]byte
			for i := range nb {
				putUint32BE(data[i*8:], uint32(blocks[i].start))
				putUint32BE(data[i*8+4:], uint32(blocks[i].end))
			}
			m, _ := h.optcodec.PutOption(dst[n:], OptSACK, data[:nb*8]...)
			n += m
		}
	}
	for n%4 != 0 { // pad to a 32-bit boundary.
		dst[n] = byte(OptNop)
		n++
	}
	return n
}

// timestampFromOptions extracts the TCP Timestamps option (RFC 7323) from opts.
func (h *Handler) timestampFromOptions(opts []byte) (tsval, tsecr uint32, present bool) {
	h.optcodec.ForEachOption(opts, func(kind OptionKind, data []byte) error {
		if kind == OptTimestamps && len(data) == 8 {
			tsval = uint32BE(data[0:])
			tsecr = uint32BE(data[4:])
			present = true
		}
		return nil
	})
	return tsval, tsecr, present
}

// processOptions negotiates and applies the negotiated TCP options for an
// accepted incoming segment: SACK-permitted (RFC 2018) and Timestamps
// (RFC 7323). For Timestamps it refreshes the echoed TS.Recent value for
// in-order segments (§4.3) and measures the RTT from the echoed TSecr when the
// segment acknowledges new data (RTTM, §4.2).
func (h *Handler) processOptions(opts []byte, seg Segment, prevRcvNxt, prevUNA Value) {
	tsval, tsecr, present := h.timestampFromOptions(opts)
	if seg.Flags.HasAny(FlagSYN) {
		// Only negotiate when a time source is available: the option is
		// meaningless without one and tsValue would have nothing to read.
		if present && h.tsPermit && h.clockReady() {
			h.scb.tsEnabled = true
			h.scb.tsRecent = tsval
		}
		if h.sackPermit && h.optionPresent(opts, OptSACKPermitted) {
			h.scb.sackEnabled = true
		}
		return
	}
	// RFC 7323 Timestamps: refresh the echoed TS.Recent and measure RTT. Gated
	// on the option being negotiated and present on this segment.
	if h.scb.tsEnabled && present {
		if seg.SEQ == prevRcvNxt {
			h.scb.tsRecent = tsval // update echo only for in-order segments (§4.3).
		}
		if tsecr != 0 && h.scb.snd.UNA != prevUNA {
			// This ACK advanced our send sequence; the echoed TSecr yields an RTT
			// measurement. Feed it to loss recovery if it accepts out-of-band RTT
			// samples (RFC 7323 §4.2). The tcp package holds no estimator itself.
			if rttMS := int32(h.tsValue() - tsecr); rttMS >= 0 {
				if o, ok := h.loss.(RTTObserver); ok {
					o.ObserveRTT(int64(rttMS) * nanosPerMilli)
				}
			}
		}
	}
	// RFC 2018 SACK: record selectively acknowledged ranges so recovery skips
	// them. Independent of Timestamps — gated only on SACK being negotiated, so
	// a SACK-only connection (no Timestamps) still marks its scoreboard.
	if h.scb.sackEnabled && seg.Flags.HasAny(FlagACK) {
		h.optcodec.ForEachOption(opts, func(kind OptionKind, data []byte) error {
			if kind == OptSACK {
				for off := 0; off+8 <= len(data); off += 8 {
					start := Value(uint32BE(data[off:]))
					end := Value(uint32BE(data[off+4:]))
					h.bufTx.MarkSACKed(start, end)
				}
			}
			return nil
		})
	}
}

// optionPresent reports whether an option of the given kind appears in opts.
func (h *Handler) optionPresent(opts []byte, want OptionKind) (found bool) {
	h.optcodec.ForEachOption(opts, func(kind OptionKind, _ []byte) error {
		if kind == want {
			found = true
		}
		return nil
	})
	return found
}

func putUint32BE(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func uint32BE(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
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
	var now int64
	if h.loss != nil {
		now = h.nanotime()
		if h.loss.PreTx(now).Retransmit {
			// Loss recovery signalled a retransmission timeout. Done before the
			// early short-circuit below so an expired RTO retransmits even with
			// no new data queued.
			if h.scb.SACKEnabled() {
				// SACK recovery (RFC 2018) resends holes selectively rather than
				// doing go-back-N: open a fresh recovery round.
				h.bufTx.ClearRetransmitMarks()
				h.sackRTO = true
			} else {
				// Go-back-N: rewind the send sequence and transmit buffer so
				// unacknowledged data is resent from snd.UNA.
				h.scb.Retransmit()
				h.bufTx.RetransmitFromUNA()
			}
			if h.cc != nil {
				// Notify the controller of the timeout so it collapses its window
				// (RFC 6298 §5 / RFC 5681 §3.1) before retransmission resumes.
				h.congestWnd = h.cc.Control(h.scb.CongestionRTOEvent())
			}
		}
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
	if !awaitingSyn && !requeueControl && buffered == 0 && !h.closing && !h.scb.HasPending() && !h.sackRetransmitPending() {
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
		optLen := h.appendSegmentOptions(b[sizeHeaderTCP:], segment, mss)
		offset += uint8(optLen / 4)
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
		optLen := h.appendSegmentOptions(b[sizeHeaderTCP:], segment, mss)
		offset += uint8(optLen / 4)
		h.info("tcp.Handler:requeue-synack", slog.Uint64("port", uint64(h.localPort)), slog.Uint64("rport", uint64(h.remotePort)))
	} else if requeueControl {
		h.requeueControl = false
		return 0, nil
	} else if h.sackRetransmitPending() {
		// SACK recovery (RFC 2018): retransmit the next outstanding hole,
		// skipping selectively-acknowledged and already-retransmitted segments,
		// instead of go-back-N.
		optLen := h.reservedOptionsLen()
		maxPayload := len(b) - sizeHeaderTCP - optLen
		holeSeq, _ := h.bufTx.NextSACKRetransmit()
		segment = h.scb.RetransmitSegment(holeSeq)
		segment.WND = h.recvWindow()
		dataStart := sizeHeaderTCP + optLen
		n, err := h.bufTx.MakePacket(b[dataStart:dataStart+maxPayload], holeSeq)
		if err != nil {
			return 0, err
		}
		segment.DATALEN = Size(n)
		if n > 0 {
			segment.Flags |= FlagPSH
		}
		optLen = h.appendSegmentOptions(b[sizeHeaderTCP:], segment, mss)
		offset += uint8(optLen / 4)
		if !h.bufTx.HasSACKRetransmit() {
			h.sackRTO = false // all holes retransmitted this round.
		}
	} else {
		var ok bool
		// Reserve room for this segment's TCP options ahead of the payload.
		optLen := h.reservedOptionsLen()
		maxPayload := len(b) - sizeHeaderTCP - optLen
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
		}
		optLen = h.appendSegmentOptions(b[sizeHeaderTCP:], segment, mss)
		offset += uint8(optLen / 4)
		if segment.DATALEN > 0 {
			dataStart := sizeHeaderTCP + optLen
			n, err := h.bufTx.MakePacket(b[dataStart:dataStart+int(segment.DATALEN)], segment.SEQ)
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
	if h.loss != nil {
		// Record the emitted segment for RTT sampling and (re)arming the
		// retransmission timer (see [LossRecovery.PostTx]).
		h.loss.PostTx(segment, now)
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
		// Reading freed receive-buffer space; deliver any contiguous
		// out-of-order data that was waiting for room.
		h.deliverReassembled()
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
	return int(h.recvWindow())
}

// recvWindow returns the receive window to advertise: free receive-buffer space
// minus the bytes already held out of order. Subtracting them prevents the
// sender from overrunning the receiver while a gap is open.
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
