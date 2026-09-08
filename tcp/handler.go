package tcp

import (
	"io"
	"math"
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
	// reasm tracks out-of-order segments staged in bufRx's free region. Always
	// enabled once buffers are set (see [Handler.SetBuffers]).
	reasm reassembly
	// policy is the optional transmit policy (RTO, congestion control, TCP
	// extensions, ...) driven from the rx/tx hooks. nil disables it, in which case
	// the connection behaves as if no timing existed. nanotime is the monotonic
	// time source (nanoseconds) passed to those hooks; it is non-nil whenever
	// policy is non-nil (enforced by [Conn.Configure]). See [Policy].
	policy   Policy
	nanotime func() int64

	closing    bool
	shutdownRx bool
	// nRetransmit stores the number of times the oldest packet was retransmit.
	nRetransmit    uint8
	requeueControl bool
}

// SetLoggers sets the [slog.Logger] for the Handler and internal [ControlBlock].
func (h *Handler) SetLoggers(handler, scb *slog.Logger) {
	h.logger.log = handler
	h.scb.logger.log = scb
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

// SetPolicy installs the transmit policy and the monotonic time source
// (nanoseconds, the func() int64 convention used across lneto) that drives it.
// The tcp package keeps no clock of its own; nanotime is read only to stamp the
// rx/tx hooks (see [Policy]). Passing policy == nil leaves the connection with no
// policy at all. It should be set before the connection is opened.
func (h *Handler) SetPolicy(policy Policy, nanotime func() int64) {
	h.policy = policy
	h.nanotime = nanotime
}

func (h *Handler) hasPolicy() bool { return h.policy != nil }

// txIntent snapshots the send state handed to [Policy.PreTx]. It is only
// called when loss recovery is installed. buffered is passed in because the
// transmit path already has it.
func (h *Handler) txIntent(now int64, buffered int) TxIntent {
	snd := &h.scb.snd
	return TxIntent{
		Now:            now,
		State:          h.scb.State(),
		UNA:            snd.UNA,
		NXT:            snd.NXT,
		InFlight:       snd.inFlight(),
		SendWindow:     snd.WND,
		MSS:            snd.MSS,
		BufferedUnsent: Size(buffered),
	}
}

// NextDeadline returns the monotonic-nanosecond instant at which the connection
// must next be serviced by a transmit attempt (e.g. an RTO expiry), or 0 when
// there is no deadline or no loss recovery is configured. See [Policy].
//
// TODO(connection timers): only the installed policy feeds this deadline. The
// 2MSL TIME-WAIT timer and the keepalive interval are also time-driven, but this
// package holds no clock, so they remain the caller's responsibility. They
// should be folded in here as the earliest of all pending deadlines once the
// Conn.SetDeadline family is reconciled with ConnConfig.Nanotime.
//
// Zero-window probing is deliberately not one of them: it is throttled by
// counting stalled transmit attempts rather than time, precisely so that it
// works on a connection with no clock at all. See [ControlBlock.ZeroWindowProbe].
func (h *Handler) NextDeadline() int64 {
	if h.policy == nil {
		return 0
	}
	return h.policy.NextDeadline()
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
		localPort:  localPort,
		remotePort: remotePort,
		closing:    false,
		shutdownRx: false,
		// Persist configuration across reopen:
		validator: h.validator,
		policy:    h.policy,
		nanotime:  h.nanotime,
		logger:    h.logger,
		// persist memory across repoen:
		bufTx: h.bufTx,
		bufRx: h.bufRx,
		reasm: h.reasm,
	}
	if h.hasPolicy() {
		h.policy.Reset()
	}
	h.reasm.clear() // preserve metadata capacity across reopen, drop held segments.
	h.bufTx.ResetOrReuse(nil, 0, iss)
	h.bufRx.Reset()
}

// Recv receives an incoming TCP packet frame with the first byte being the first octet of the TCP frame.
// The [Handler]'s internal state is updated if the packet is admitted successfully.
//
// It reports no congestion mark. Use [Handler.RecvWithECN] where the IP header is in
// hand, since the mark lives there.
func (h *Handler) Recv(incomingPacket []byte) error {
	return h.RecvWithECN(incomingPacket, ECNNotECT)
}

// RecvWithECN receives a TCP frame together with the ECN codepoint of the IP header
// that carried it, which is where congestion is signalled (RFC 3168 §5). A codepoint
// of [ECNCE] on a connection that negotiated ECN starts echoing the congestion back
// to the peer.
//
// The codepoint is a separate argument rather than read from the frame because the
// handler is given only the TCP frame; the caller that has the IP header passes what
// it found there.
func (h *Handler) RecvWithECN(incomingPacket []byte, ecn uint8) error {
	h.scb.observeECN(ecn)
	return h.recv(incomingPacket)
}

// ECNCodepoint returns the ECN codepoint the IP layer should mark outgoing packets
// with. See [ControlBlock.ECNCodepoint].
func (h *Handler) ECNCodepoint() uint8 { return h.scb.ECNCodepoint() }

// EnableECN configures whether this connection offers ECN on its next handshake. It
// must be set before the connection is opened. See [ControlBlock.EnableECN].
func (h *Handler) EnableECN(enable bool) { h.scb.EnableECN(enable) }

// ECNEnabled reports whether ECN was negotiated with the peer.
func (h *Handler) ECNEnabled() bool { return h.scb.ECNEnabled() }

func (h *Handler) recv(incomingPacket []byte) error {
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

	// Notify loss recovery of the received segment and let it drop the segment
	// before processing if it asks to. Anything the policy records about a segment
	// that counted belongs in PostRx below, since nothing here knows yet whether
	// the state machine will accept it.
	var event RxEvent
	if h.hasPolicy() {
		now := h.nanotime()
		if !h.policy.PreRx(RxMeta{
			Now:     now,
			Segment: segIncoming,
			Options: tfrm.Options(),
			State:   h.scb.State(),
			SndUNA:  h.scb.snd.UNA,
			SndNXT:  h.scb.snd.NXT,
			RcvNXT:  h.scb.rcv.NXT,
		}).Keep {
			return nil
		}
		event = RxEvent{
			Now:         now,
			Segment:     segIncoming,
			Options:     tfrm.Options(),
			StateBefore: h.scb.State(),
		}
		una := h.scb.snd.UNA
		// Reported on every path out of here, so a policy sees a refusal as well as
		// an acceptance and never has to infer one from silence.
		defer func() {
			event.StateAfter = h.scb.State()
			event.RcvNXT = h.scb.rcv.NXT
			if event.Accepted {
				event.BytesAcked = Sizeof(una, h.scb.snd.UNA)
				event.DupACK = event.BytesAcked == 0 &&
					segIncoming.Flags.HasAny(FlagACK) && segIncoming.ACK == una
			}
			h.policy.PostRx(event)
		}()
	}

	// Out-of-order reassembly: buffer in-window data that arrived ahead of the
	// next expected sequence number before the ControlBlock (sequential-only)
	// would reject it. Buffered segments live in bufRx's free region.
	if h.reasm.enabled() && h.handleOutOfOrder(segIncoming, payload) {
		return nil
	}
	if !h.shutdownRx && len(payload) > h.bufRx.Free() {
		// The segment is in window but there is nowhere to put it. Acknowledge it
		// anyway so the peer learns our window rather than being left to guess
		// whether its segment was lost; this is what answers a zero-window probe.
		h.scb.TriggerWindowUpdate()
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
		var nw int
		nw, err = h.bufRx.Write(payload)
		if err != nil {
			return err
		}
		event.DataDelivered = Size(nw)
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
	event.Accepted = true
	if segIncoming.Flags.HasAny(FlagSYN) {
		// Parse the options only a SYN carries: the peer's maximum segment size and
		// its window scale. The window of this very SYN was recorded unscaled just
		// above, which is correct, since scaling starts with the next segment.
		h.optcodec.ForEachOption(tfrm.Options(), func(kind OptionKind, data []byte) error {
			switch {
			case kind == OptMaxSegmentSize && len(data) == 2:
				mss := uint16(data[0])<<8 | uint16(data[1])
				if mss > 0 {
					h.scb.snd.MSS = Size(mss)
				}
			case kind == OptWindowScale && len(data) == 1:
				h.scb.recvWindowScale(data[0])
			}
			return nil
		})
		if h.remotePort == 0 {
			// Remote reached out and has given us their port, set it on our side.
			h.debug("tcp.Handler:rx-remoteport-set", slog.Uint64("port", uint64(h.localPort)), slog.Uint64("remoteport", uint64(remotePort)))
			h.remotePort = remotePort
		}
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
	var holdNew bool
	buffered := h.bufTx.BufferedUnsent()
	if h.hasPolicy() {
		now = h.nanotime()
		dir := h.policy.PreTx(h.txIntent(now, buffered))
		holdNew = dir.HoldNew
		if dir.Retransmit {
			// Retransmission directed by the policy: point the send sequence's
			// retransmission pointer at the requested octet so the next segments
			// resend from there. Done before the early short-circuit below so an
			// expired RTO retransmits even with no new data queued.
			//
			// The pointer leaves the transmit queue's sent/unsent split alone, so
			// data after the resent range stays sent and the connection does not
			// forget how far it has got.
			//
			// The queue decides the effective sequence, since it resends whole
			// packets and so can only resume at a packet boundary, and it rejects
			// sequences it holds no data for. Only then is the pointer set, so a
			// directive the queue cannot honour leaves the two consistent instead of
			// pointing the connection at data it can no longer produce — which
			// matters because a selective acknowledgement names ranges the peer
			// chose, not ranges this side sent. Retransmission of a control segment
			// is not reachable from here; see [Handler.RequeueControl].
			if at, ok := h.bufTx.retransmitBoundary(dir.RetransmitFrom); ok {
				h.scb.RetransmitAt(at)
			}
		}
	}
	awaitingSyn := h.AwaitingSynSend()
	requeueControl := h.requeueControl
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
	// TODO(RFC 896 Nagle / RFC 1122 delayed ACK): whatever is available is sent
	// immediately and every segment is acknowledged. Nagle would coalesce small
	// writes until outstanding data is acknowledged, and a delayed-ACK timer would
	// piggyback ACKs. Both reduce overhead and smooth the ACK clock that
	// congestion control depends on. Deliberately omitted for now.
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
	state := h.scb.State()
	isSyn := awaitingSyn || requeueControl && state == StateSynSent
	isSynAck := state == StateSynRcvd
	if requeueControl && !isSyn && !isSynAck {
		// Nothing to requeue in this state. Checked before options are written
		// so no policy is asked to describe a segment that is never built.
		h.requeueControl = false
		return 0, nil
	}
	// Determine the option layout before the payload is sized: the option
	// length is what is left over for data. The core reserves the leading
	// option area for the MSS option it writes itself on SYN and SYN-ACK.
	kind := TxKindSegment
	coreOptLen := 0
	if isSyn {
		kind, coreOptLen = TxKindSYN, sizeOptionMSS+sizeOptionWindowScale
	} else if isSynAck {
		kind, coreOptLen = TxKindSYNACK, sizeOptionMSS+sizeOptionWindowScale
	}
	optLen := coreOptLen
	if h.hasPolicy() {
		optEnd := min(sizeHeaderTCP+maxTCPOptionBytes, len(b))
		optStart := sizeHeaderTCP + coreOptLen
		if optStart < optEnd {
			n := h.policy.WriteOptions(TxPlan{
				Now:        now,
				State:      state,
				Kind:       kind,
				Reassembly: ReassemblyView{r: &h.reasm},
			}, b[optStart:optEnd])
			if int(n) > optEnd-optStart {
				// The policy overran the buffer it was lent. Refuse to build a
				// segment from a header of unknown layout.
				return 0, errOptionOverflow
			}
			optLen += int(n)
		}
	}
	// The data offset counts four-octet words, so the option area is padded to that
	// boundary with End Of Option List. The core's own options need this too: MSS
	// and Window Scale together are seven octets, and a short offset would leave
	// the tail of the last option outside the header where no peer would parse it.
	paddedOptLen := (optLen + 3) &^ 3
	if paddedOptLen > 0 {
		// Checked before the padding is written, not after: the padded length is
		// larger than what was offered to the policy, so a buffer that had room for
		// the options need not have room for the boundary they are padded to.
		if sizeHeaderTCP+paddedOptLen > len(b) {
			return 0, lneto.ErrShortBuffer
		}
		for i := sizeHeaderTCP + optLen; i < sizeHeaderTCP+paddedOptLen; i++ {
			b[i] = 0
		}
	}
	payloadAt := sizeHeaderTCP + paddedOptLen
	offset := uint8(5 + paddedOptLen/4)
	// The advertised MSS states how much payload this side can receive, derived
	// from the buffer and the fixed headers. It is deliberately not reduced by
	// the options carried in this particular segment, which say nothing about
	// the capacity of the receive path.
	mss := uint16(len(b) - sizeHeaderTCP)
	// Window scale offered on this segment, recorded only once it is sent.
	var synShift uint8
	var sentSynOpts bool
	var segment Segment
	if isSyn {
		// Handling init syn segment.
		segment = ClientSynSegment(h.bufTx.iss, h.synWindow())
		synShift, sentSynOpts = h.putSynOptions(b[sizeHeaderTCP:], mss)
		if requeueControl {
			h.info("tcp.Handler:requeue-syn", slog.Uint64("port", uint64(h.localPort)), slog.Uint64("rport", uint64(h.remotePort)))
		}
	} else if requeueControl && isSynAck {
		segment = Segment{
			SEQ:   h.scb.snd.UNA,
			ACK:   h.scb.rcv.NXT,
			WND:   h.synWindow(),
			Flags: synack,
		}
		synShift, sentSynOpts = h.putSynOptions(b[sizeHeaderTCP:], mss)
		h.info("tcp.Handler:requeue-synack", slog.Uint64("port", uint64(h.localPort)), slog.Uint64("rport", uint64(h.remotePort)))
	} else {
		var ok bool
		maxPayload := len(b) - payloadAt
		_, retransmitting := h.scb.RetransmitPointer()
		if holdNew && !retransmitting {
			// The policy is holding new data (e.g. congestion window full): emit only
			// a pending control segment/ACK, no fresh payload.
			//
			// A retransmission is exempt, and must be: the octets it carries are
			// already counted as in flight, which is what filled the window, so
			// withholding it deadlocks the connection. The window cannot open until
			// the missing range is acknowledged, and the range cannot be resent while
			// the window is closed. RFC 5681 §3.2 sends the retransmission
			// regardless for the same reason.
			maxPayload = 0
		}
		segment, ok = h.scb.PendingSegment(maxPayload)
		if !ok && buffered > 0 && !holdNew && h.hasPolicy() {
			// Data is queued but nothing can be sent. If the peer's window is
			// closed this is the persist-timer case and a probe must go out, else a
			// lost window update stalls the connection forever.
			//
			// Loss recovery is required, not incidental: the peer cannot accept the
			// probe octet, so it must be retransmitted until it can. With no
			// retransmission timer the probe would leave a hole nothing ever fills,
			// which is a worse failure than the stall it set out to cure.
			segment, ok = h.scb.ZeroWindowProbe()
		}
		// Advertise the space free right now, scaled for the wire, rather than
		// whatever the control block last recorded.
		segment.WND = h.scb.advertisedWindow(h.recvWindow())
		if !ok {
			// No pending control segment or data to send. Yield.
			return 0, nil
		} else if segment.Flags&^flagECN == synack {
			// A SYN-ACK's window is never scaled (RFC 7323 §2.2).
			segment.WND = h.synWindow()
			synShift, sentSynOpts = h.putSynOptions(b[sizeHeaderTCP:], mss)
		} else if segment.DATALEN > 0 {
			if coreOptLen > 0 {
				// Space was reserved for an MSS option that this segment does
				// not carry. Fill it with No-Operation so the header stays a
				// valid option stream.
				for i := sizeHeaderTCP; i < sizeHeaderTCP+coreOptLen; i++ {
					b[i] = byte(OptNop)
				}
			}
			n, err := h.bufTx.MakePacket(b[payloadAt:payloadAt+int(segment.DATALEN)], segment.SEQ)
			if err != nil {
				return 0, err
			}
			segment.DATALEN = Size(n)
			if n > 0 {
				segment.Flags |= FlagPSH
			}
		}
	}
	// The congestion flags are added last, once the segment is otherwise decided,
	// because whether CWR belongs on it depends on whether it ended up carrying data.
	segment.Flags |= h.scb.ecnSendFlags(segment)
	prevState := h.scb.State()
	err = h.scb.Send(segment)
	if err != nil {
		return 0, err
	} else if prevState != h.scb.State() && h.logenabled(slog.LevelInfo) {
		h.info("tcp.Handler:tx-statechange", slog.Uint64("port", uint64(h.localPort)), slog.String("oldState", prevState.String()), slog.String("newState", h.scb.State().String()), slog.String("txflags", segment.Flags.String()))
	}
	if sentSynOpts {
		// Recorded here, not where the option was written: accepting a first SYN
		// resets the control block, which would discard the offer.
		h.scb.sentWindowScale(synShift)
	}
	if h.hasPolicy() {
		h.policy.PostTx(segment, now)
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

// synWindow returns the receive window to advertise in a SYN or SYN-ACK. Those
// segments carry the window unscaled (RFC 7323 §2.2), so it is clamped to what the
// 16-bit field holds; the scaled window takes effect from the next segment on.
func (h *Handler) synWindow() Size {
	wnd := min(Size(h.bufRx.Size()), math.MaxUint16)
	return wnd
}

// putSynOptions writes the options the core owns on a SYN or SYN-ACK: the maximum
// segment size, and the window scale shift this side needs to advertise its whole
// receive buffer. Offering the scale is what allows the peer to scale too; it takes
// effect only if the peer offers one back. See RFC 7323 §2.
//
// The offer is returned rather than recorded here, because a first SYN resets the
// control block as it is accepted and would wipe it. The caller records it once
// the segment has actually been sent.
func (h *Handler) putSynOptions(opts []byte, mss uint16) (shift uint8, ok bool) {
	n, err := h.optcodec.PutOption16(opts, OptMaxSegmentSize, mss)
	if err != nil {
		return 0, false
	}
	shift = windowScaleFor(Size(h.bufRx.Size()))
	if _, err = h.optcodec.PutOption(opts[n:], OptWindowScale, shift); err != nil {
		return 0, false
	}
	return shift, true
}
