package tcp

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"

	"github.com/soypat/lneto/internal"
)

const (
	// signals to create a retransmit packet after receiving this number of duplicate acks, not including the ack that set UNA.
	retransmitAfterDupacks = 3
	// retransmitMaxQueued sets maximum amount of retransmits to queue while receiving dupacks.
	retransmitMaxQueued = 2
	// maxChallengeRejects is the number of consecutive challenge ACKs sent without
	// a successful Recv before aborting. Prevents infinite ACK ping-pong when both
	// sides have diverged state (e.g. after packet mutation).
	maxChallengeRejects = 8
)

// ControlBlock is a partial Transmission Control Block (TCB) implementation as
// per RFC 9293 in section 3.3.1. In contrast with the description in RFC9293,
// this implementation is limited to receiving only sequential segments.
// This means buffer management is left up entirely to the user of the ControlBlock.
// Use ControlBlock as the building block that solves Sequence Number calculation
// and validation in a full TCP implementation.
//
// A ControlBlock's internal state is modified by the available "System Calls" as defined in
// RFC9293, such as Close, Listen/Open, Send, and Receive.
// Sent and received data is represented with the [Segment] struct type.
//
// Note that [ControlBlock] is the lowest level implementation of TCP and as such is missing most useful functionality.
// See [Handler], which uses ControlBlock, for a higher level implementation. [Conn] is an even higher level implementation
// which makes use of a [Handler].
type ControlBlock struct {
	// # Send Sequence Space
	//
	// 'Send' sequence numbers correspond to local data being sent.
	//
	//	     1         2          3          4
	//	----------|----------|----------|----------
	//		   SND.UNA    SND.NXT    SND.UNA
	//								+SND.WND
	//	1. old sequence numbers which have been acknowledged
	//	2. sequence numbers of unacknowledged data
	//	3. sequence numbers allowed for new data transmission
	//	4. future sequence numbers which are not yet allowed
	snd sendSpace
	// # Receive Sequence Space
	//
	// 'Receive' sequence numbers correspond to remote data being received.
	//
	//		1          2          3
	//	----------|----------|----------
	//		   RCV.NXT    RCV.NXT
	//					 +RCV.WND
	//	1 - old sequence numbers which have been acknowledged
	//	2 - sequence numbers allowed for new reception
	//	3 - future sequence numbers which are not yet allowed
	rcv recvSpace
	// When FlagRST is set in pending flags rstPtr will contain the sequence number of the RST segment to make it "believable" (See RFC9293)
	rstPtr Value
	logger

	// pending is the queue of pending flags to be sent in the next 2 segments.
	// On a call to Send the queue is advanced and flags set in the segment are unset.
	// The second position of the queue is used for FIN segments.
	pending [2]Flags
	_state  State // leading underscore so field not suggested on top of exported State method when developing.

	// challengeAcks counts consecutive challenge acks queued on receiving out of window segment.
	// challengeAcks signedness indicates whether the challengeAck is pending being sent.
	// A negative value of challengeAcks means a challenge ack is pending being sent.
	challengeAcks int8

	// dupack counts received ACK==snd.UNA && ACK<snd.NXT received. Does not count ack that set UNA.
	dupack uint8
	// nRetransmit counts number of retransmits sent since last UNA update.
	nRetransmit uint8
}

// State returns the current state of the TCP connection. See [State].
func (tcb *ControlBlock) State() State { return tcb._state }

// RecvNext returns the next sequence number expected to be received from remote.
// This implementation will reject segments that are not the next expected sequence.
// RecvNext returns 0 before StateSynRcvd.
func (tcb *ControlBlock) RecvNext() Value { return tcb.rcv.NXT }

// RecvWindow returns the receive window size. If connection is closed will return 0.
func (tcb *ControlBlock) RecvWindow() Size { return tcb.rcv.WND }

// ISS returns the initial sequence number of the connection that was defined on a call to Open by user.
func (tcb *ControlBlock) ISS() Value { return tcb.snd.ISS }

// SendUNA returns snd.UNA, the oldest sequence number not yet acked by the remote.
func (tcb *ControlBlock) SendUNA() Value { return tcb.snd.UNA }

// SendNext returns snd.NXT, one past the highest sequence number sent.
func (tcb *ControlBlock) SendNext() Value { return tcb.snd.NXT }

// MaxInFlightData returns the maximum size of a segment that can be sent by taking into account
// the send window size and the unacked data. Returns 0 before StateSynRcvd.
func (tcb *ControlBlock) MaxInFlightData() Size {
	if !tcb._state.hasIRS() {
		return 0 // SYN not yet received.
	}
	unacked := Sizeof(tcb.snd.UNA, tcb.snd.NXT)
	if unacked >= tcb.snd.WND {
		return 0
	}
	return tcb.snd.WND - unacked
}

// SetWindow sets the local receive window size. This represents the maximum amount of data
// that is permitted to be in flight.
func (tcb *ControlBlock) SetRecvWindow(wnd Size) {
	tcb.rcv.WND = wnd
}

// SetLogger sets the logger to be used by the ControlBlock.
func (tcb *ControlBlock) SetLogger(log *slog.Logger) {
	tcb.logger = logger{log: log}
}

// IncomingIsKeepalive checks if an incoming segment is a keepalive segment.
// Segments which are keepalives should not be passed into Recv or Send methods.
func (tcb *ControlBlock) IncomingIsKeepalive(incomingSegment Segment) bool {
	return incomingSegment.SEQ == tcb.rcv.NXT-1 &&
		incomingSegment.Flags == FlagACK &&
		incomingSegment.ACK == tcb.snd.NXT && incomingSegment.DATALEN == 0
}

// IncomingIsDupACK returns true if the ACK value is a duplicate acknowledgement:
// the ACK equals the oldest unacknowledged sequence number (snd.UNA) meaning no
// new data is acknowledged, while snd.UNA < snd.NXT meaning data is in flight.
func (tcb *ControlBlock) IncomingIsDupACK(ack Value) bool {
	return ack == tcb.snd.UNA && ack.LessThan(tcb.snd.NXT)
}

// MakeKeepalive creates a TCP keepalive segment. This segment
// should not be passed into Recv or Send methods.
func (tcb *ControlBlock) MakeKeepalive() Segment {
	return Segment{
		SEQ:     tcb.snd.NXT - 1,
		ACK:     tcb.rcv.NXT,
		Flags:   FlagACK,
		WND:     tcb.rcv.WND,
		DATALEN: 0,
	}
}

// QueueRST queues a RST segment to be emitted on the next send, overriding any
// other pending flags. seq is the sequence number the RST will carry (per RFC
// 9293 reset generation, the acknowledged value SEG.ACK of the offending
// segment). The connection should be torn down once the RST is sent.
func (tcb *ControlBlock) QueueRST(seq Value) {
	tcb.pending = [2]Flags{0: FlagRST}
	tcb.rstPtr = seq
}

// MakeDupACK returns a duplicate ACK segment suitable for fast-retransmit
// recovery signaling, without advancing the sender ACK boundary. Useful for:
//   - constructing an explicit duplicate ACK from local state (e.g. test harness),
//   - expressing retransmit-request condition (`ACK == snd.UNA`, `SEQ == snd.UNA`)
//   - advertising receive window via current `rcv.WND`.
func (tcb *ControlBlock) MakeDupACK() Segment {
	return Segment{
		SEQ:     tcb.snd.UNA,
		ACK:     tcb.rcv.NXT,
		Flags:   FlagACK,
		WND:     tcb.rcv.WND,
		DATALEN: 0,
	}
}

// MakeChallengeAck returns a challenge ACK segment for the current ControlBlock state
// used to respond to unexpected or ambiguous segments that require the remote peer to confirm
// its connection state. A challenge ACK does not acknowledge new data,
// consume sequence space, or carry a payload.
func (tcb *ControlBlock) MakeChallengeACK() Segment {
	return Segment{
		SEQ:     tcb.snd.NXT, // Current sequence number (no data)
		ACK:     tcb.rcv.NXT, // Acknowledging expected next byte
		Flags:   FlagACK,     // Pure ACK, no SYN/FIN/RST
		WND:     tcb.rcv.WND, // Current receive window size
		DATALEN: 0,           // No payload
	}
}

// recvSpace contains Receive Sequence Space data. Its sequence numbers correspond to remote data.
type recvSpace struct {
	IRS Value // initial receive sequence number, defined by remote in SYN segment received.
	NXT Value // receive next. seqs before this have been acked. this seq and up to NXT+WND-1 are allowed to be sent. Corresponds to remote data.
	WND Size  // receive window defined by local. Permitted number of remote unacked octets in flight.
}

// sendSpace contains Send Sequence Space data. Its sequence numbers correspond to local data.
type sendSpace struct {
	ISS Value // initial send sequence number, defined locally on connection start
	UNA Value // send unacknowledged. Seqs equal to UNA and above have NOT been acked by remote. Corresponds to local data.
	NXT Value // send next. This seq and up to UNA+WND-1 are allowed to be sent. Corresponds to local data.
	WND Size  // send window defined by remote. Permitted number of local unacked octets in flight.
	MSS Size  // maximum segment size advertised by remote peer. 0 means not set.
	WL1 Value // segment SEQ number of the last send-window update (RFC 9293 §3.10.7.4)
	WL2 Value // segment ACK number of the last send-window update (RFC 9293 §3.10.7.4)
}

// inFlight returns amount of unacked bytes sent out.
func (snd *sendSpace) inFlight() Size {
	return Sizeof(snd.UNA, snd.NXT)
}

// maxSend returns maximum segment datalength receivable by remote peer.
func (snd *sendSpace) maxSend() Size {
	if inf := snd.inFlight(); inf >= snd.WND {
		// Guard uint32 underflow when window shrinks below inflight.
		return 0
	} else {
		return snd.WND - inf
	}
}

// Open implements a passive opening of a connection (wait for incoming packets from an unknown remote port).
// Upon success [ControlBlock] enters LISTEN state, such as that of a server.
// To open an active connection use [ControlBlock.Send] with a segment generated with [ClientSynSegment].
func (tcb *ControlBlock) Open(iss Value, wnd Size) (err error) {
	switch {
	case tcb._state != StateClosed && tcb._state != StateTimeWait:
		err = errNeedClosedTCBToOpen
	case wnd > maxWindow:
		err = errWindowTooLarge
	}
	if err != nil {
		tcb.logerr("tcb:open", slog.String("err", err.Error()))
		return err
	}

	tcb.prepareToHandshake(iss, wnd, StateListen)
	tcb.trace("tcb:open-server")
	return nil
}

// prepareToHandshake initializes the TCB send/receive spaces with initial send sequence number and local window.
func (tcb *ControlBlock) prepareToHandshake(iss Value, wnd Size, newState State) {
	tcb.reset()
	tcb.resetRcv(wnd, 0)
	tcb.resetSnd(iss, 1)
	tcb._state = newState
}

// HasPending returns true if there is a pending control segment to send. Calls to Send will advance the pending queue.
func (tcb *ControlBlock) HasPending() bool {
	return tcb.pending[0] != 0 || tcb.pendingChallengeAck() || tcb.HasPendingRetransmit()
}

// HasPending returns true if the control block is pending a retransmit according to simple optmist
// retransmit strategy.
func (tcb *ControlBlock) HasPendingRetransmit() bool {
	// Force retransmit after 3 consecutive acks of UNA.
	return tcb._state.txQueuedDataOpen() && tcb.dupack >= retransmitAfterDupacks && tcb.nRetransmit <= tcb.dupack-retransmitAfterDupacks
}

// ZeroWindowProbe returns a segment carrying the next octet of new data, to send
// when the peer's window is zero and nothing is outstanding (RFC 9293 §3.8.6.1).
// The peer must acknowledge the octet, reporting its current window, so a lost
// window update can no longer stall the connection. Once sent the octet is
// outstanding and further probes are its retransmissions, which the caller must
// drive with a retransmission timer. It reports false when no probe is due and
// does not modify the ControlBlock.
func (tcb *ControlBlock) ZeroWindowProbe() (_ Segment, ok bool) {
	if tcb.snd.WND != 0 || tcb.snd.UNA != tcb.snd.NXT || !tcb._state.TxDataOpen() {
		return Segment{}, false
	}
	return Segment{SEQ: tcb.snd.NXT, DATALEN: 1, ACK: tcb.rcv.NXT, WND: tcb.rcv.WND, Flags: FlagACK}, true
}

// PendingRetransmit returns a segment resending already-sent data at seq, with
// at most payloadLen octets bounded by snd.NXT and snd.MSS. Sending it through
// [ControlBlock.Send] leaves snd.NXT unchanged. It reports false when seq is
// outside [snd.UNA, snd.NXT), the state cannot send data, or a control segment
// or challenge ACK is due, which keeps priority. It does not modify the
// ControlBlock. Implements RFC 9293 §3.10.8 (RETRANSMISSION TIMEOUT).
func (tcb *ControlBlock) PendingRetransmit(seq Value, payloadLen int) (_ Segment, ok bool) {
	if tcb.pending[0].HasAny(flagctl) || tcb.pendingChallengeAck() || !tcb._state.txQueuedDataOpen() {
		return Segment{}, false
	} else if seq.LessThan(tcb.snd.UNA) || !seq.LessThan(tcb.snd.NXT) {
		return Segment{}, false
	}
	payloadLen = min(payloadLen, int(Sizeof(seq, tcb.snd.NXT)))
	if tcb.snd.MSS > 0 {
		payloadLen = min(payloadLen, int(tcb.snd.MSS))
	}
	if payloadLen <= 0 {
		return Segment{}, false
	}
	return Segment{SEQ: seq, DATALEN: Size(payloadLen), ACK: tcb.rcv.NXT, WND: tcb.rcv.WND, Flags: FlagACK}, true
}

// PendingSegment calculates a suitable next segment to send from a payload length.
// It does not modify the ControlBlock state or pending segment queue.
func (tcb *ControlBlock) PendingSegment(payloadLen int) (_ Segment, ok bool) {
	pending := tcb.pending[0]
	if tcb.pendingChallengeAck() {
		// Do not clear challengeAck here: PendingSegment is documented as read-only.
		// The flag is consumed in Send when the ACK segment is actually transmitted.
		return tcb.MakeChallengeACK(), true
	} else if !pending.HasAny(flagctl) && tcb.HasPendingRetransmit() {
		// Optimist Strategy: retransmit oldest data once.
		return Segment{SEQ: tcb.snd.UNA, DATALEN: Size(payloadLen), ACK: tcb.rcv.NXT, WND: tcb.rcv.WND, Flags: FlagACK}, true
	}
	canSendData := tcb._state.txQueuedDataOpen()
	if !canSendData {
		payloadLen = 0 // No send-buffer data may go out in this state.
	}
	if pending == 0 && payloadLen == 0 {
		return Segment{}, false // No pending segment.
	}

	// Limit payload to what send window allows.
	inFlight := tcb.snd.inFlight()
	_ = inFlight
	maxPayload := tcb.snd.maxSend()
	if payloadLen > int(maxPayload) {
		if maxPayload == 0 && pending == 0 {
			return Segment{}, false
		} else if maxPayload > tcb.snd.WND {
			panic("seqs: bad calculation")
		}
		payloadLen = int(maxPayload)
	}
	// Cap by remote MSS.
	if tcb.snd.MSS > 0 && payloadLen > int(tcb.snd.MSS) {
		payloadLen = int(tcb.snd.MSS)
	}

	if canSendData {
		pending |= FlagACK // ACK is always set in established state. Not in RFC9293 but somehow expected?
	} else {
		payloadLen = 0 // Can't send data if not established.
	}

	var ack Value
	if pending.HasAny(FlagACK) {
		ack = tcb.rcv.NXT
	}

	var seq Value = tcb.snd.NXT
	if pending.HasAny(FlagRST) {
		seq = tcb.rstPtr
	}

	seg := Segment{
		SEQ:     seq,
		ACK:     ack,
		WND:     tcb.rcv.WND,
		Flags:   pending,
		DATALEN: Size(payloadLen),
	}
	tcb.traceSeg("tcb:pending-out", seg)
	return seg, true
}

// Recv processes a segment that is being received from the network. It updates the TCB
// if there is no error. The ControlBlock can only receive segments that are the next
// expected sequence number which means the caller must handle the out-of-order case
// and buffering that comes with it.
func (tcb *ControlBlock) Recv(seg Segment) (err error) {
	err = tcb.validateIncomingSegment(seg)
	if err != nil {
		tcb.traceRcv("tcb:rcv.reject")
		tcb.traceSeg("tcb:rcv.reject", seg)
		tcb.logerr("tcb:rcv.reject", slog.String("err", err.Error()))
		return err
	}

	// RFC 9293 §3.10.7.4: SYN on synchronized connection → challenge ACK.
	if seg.Flags.HasAny(FlagSYN) && !tcb._state.IsPreestablished() {
		tcb.triggerChallengeAckEmit()
		tcb.pending[0] |= FlagACK
		return errDropSegment
	}

	prevNxt := tcb.snd.NXT
	var pending Flags
	switch tcb._state {
	case StateListen:
		pending, err = tcb.rcvListen(seg)
	case StateSynSent:
		pending, err = tcb.rcvSynSent(seg)
	case StateSynRcvd:
		pending, err = tcb.rcvSynRcvd(seg)
	case StateEstablished:
		pending, err = tcb.rcvEstablished(seg)
	case StateFinWait1:
		pending, err = tcb.rcvFinWait1(seg)
	case StateFinWait2:
		pending, err = tcb.rcvFinWait2(seg)
	case StateCloseWait:
	case StateLastAck:
		// RFC 9293 §3.10.7.4: close only once our FIN is acknowledged
		// (seg.ACK == snd.NXT). An ACK covering earlier data but not the FIN
		// must leave the connection in LAST-ACK.
		if seg.Flags.HasAny(FlagACK) && seg.ACK == tcb.snd.NXT {
			tcb.Abort()
		}
	case StateClosing:
		// Thanks to @knieriem for finding and reporting this bug.
		// RFC 9293 §3.10.7.4: enter TIME-WAIT only once our FIN is acknowledged
		// (seg.ACK == snd.NXT), not on any ACK.
		if seg.Flags.HasAny(FlagACK) && seg.ACK == tcb.snd.NXT {
			tcb._state = StateTimeWait
		}
	case StateTimeWait:
		// RFC 9293 §3.10.7.4: an acceptable segment here is dropped without
		// advancing the connection. A pure ACK must not be echoed (an ACK loop);
		// a retransmitted FIN is out of window and already drew a challenge ACK
		// during validation.
		return errDropSegment
	default:
		panic("unexpected recv state:" + tcb._state.String())
	}
	if err != nil {
		return err
	}
	tcb.triggerChallengeAckSatisfied() // Successful Recv — reset challenge counter.

	tcb.pending[0] |= pending
	if prevNxt != 0 && tcb.snd.NXT != prevNxt && tcb.logenabled(slog.LevelDebug) {
		tcb.debug("tcb:snd.nxt-change", slog.String("state", tcb._state.String()),
			slog.Uint64("seg.ack", uint64(seg.ACK)), slog.Uint64("snd.nxt", uint64(tcb.snd.NXT)),
			slog.Uint64("prevnxt", uint64(prevNxt)), slog.Uint64("seg.seq", uint64(seg.SEQ)))
	}

	// We accept the segment and update TCB state.
	// RFC 9293 §3.10.7.4 step 5: update send window only when WL1/WL2 conditions allow it.
	// WL1==WL2==0 is the uninitialized sentinel; the first update is always allowed so that
	// connections with a remote ISS in the upper half of the uint32 space still work
	// (modular LessThan would otherwise return false for 0.LessThan(largeISS)).
	// Within that, duplicate ACKs (non-advancing) may only open the window, never shrink it.
	wlUnset := tcb.snd.WL1 == 0 && tcb.snd.WL2 == 0
	prevWND := tcb.snd.WND
	if wlUnset || tcb.snd.WL1.LessThan(seg.SEQ) || (tcb.snd.WL1 == seg.SEQ && tcb.snd.WL2.LessThanEq(seg.ACK)) {
		if tcb.snd.UNA.LessThan(seg.ACK) || seg.WND > tcb.snd.WND {
			tcb.snd.WND = seg.WND
		}
		tcb.snd.WL1 = seg.SEQ
		tcb.snd.WL2 = seg.ACK
	}

	if seg.Flags.HasAny(FlagACK) && seg.ACK.LessThanEq(tcb.snd.NXT) {
		// RFC 5681 §2: a duplicate ACK carries no data and leaves the window unchanged.
		isDupACK := tcb.IncomingIsDupACK(seg.ACK) && seg.DATALEN == 0 && seg.WND == prevWND
		if isDupACK && tcb.State().txQueuedDataOpen() && !seg.Flags.HasAny(flagctl) && tcb.dupack < tcb.nRetransmit+retransmitMaxQueued+retransmitMaxQueued {
			// Duplicate ack. Don't advance dupack counter past scb.nRetransmit+retransmitAfterDupacks
			tcb.dupack++
		} else if tcb.snd.UNA.LessThan(seg.ACK) {
			// Only update ACK if it advances UNA and is not in the future.
			tcb.snd.UNA = seg.ACK
			tcb.dupack = 0
			tcb.nRetransmit = 0
		}
	}

	seglen := seg.LEN()
	tcb.rcv.NXT.UpdateForward(seglen)

	if tcb.logenabled(internal.LevelTrace) {
		tcb.traceRcv("tcb:rcv")
		tcb.traceSeg("recv:seg", seg)
	}
	return err
}

// Send processes a segment that is being sent to the network. It updates the TCB
// if there is no error.
func (tcb *ControlBlock) Send(seg Segment) error {
	err := tcb.validateOutgoingSegment(seg)
	if err != nil {
		tcb.traceSnd("tcb:snd.reject")
		tcb.traceSeg("tcb:snd.reject", seg)
		tcb.logerr("tcb:snd.reject", slog.String("err", err.Error()))
		return err
	}

	hasFIN := seg.Flags.HasAny(FlagFIN)
	var newPending Flags
	switch tcb._state {
	case StateClosed:
		if seg.Flags == FlagSYN {
			tcb.prepareToHandshake(seg.SEQ, seg.WND, StateSynSent)
			tcb.trace("tcb:open-client")
		}
	case StateSynRcvd, StateEstablished:
		if hasFIN {
			tcb._state = StateFinWait1 // RFC 9293: 3.10.4 CLOSE call.
		}
	case StateClosing:
		// RFC 9293 §3.10.7.4: CLOSING leaves to TIME-WAIT only on receiving the
		// ACK of our FIN (handled in Recv). Sending the ACK owed for the peer's
		// FIN must not advance the state, or we would enter TIME-WAIT before our
		// own FIN is acknowledged.
	case StateCloseWait:
		if hasFIN {
			tcb._state = StateLastAck
		}
		// No auto-queue of FIN on ACK: user must call Close() to initiate local FIN.
	}

	// Advance pending flags queue.
	tcb.pending[0] &^= seg.Flags
	if tcb.pending[0] == 0 {
		// Ensure we don't queue a FINACK if we have already sent a FIN.
		tcb.pending = [2]Flags{tcb.pending[1] &^ (seg.Flags & (FlagFIN)), 0}
	}
	tcb.pending[0] |= newPending

	// Sending an ACK satisfies any outstanding challenge-ACK obligation.
	if tcb.pendingChallengeAck() && seg.Flags.HasAny(FlagACK) {
		tcb.triggerChallengeAckSent()
	}

	// The segment is valid, we can update TCB state.
	seglen := seg.LEN()
	retransmit := seg.SEQ.LessThan(tcb.snd.NXT)
	if retransmit {
		if tcb.nRetransmit < 255-retransmitMaxQueued-retransmitAfterDupacks {
			tcb.nRetransmit++
		}
	} else {
		tcb.snd.NXT.UpdateForward(seglen)
	}

	tcb.rcv.WND = seg.WND
	if tcb.logenabled(internal.LevelTrace) {
		tcb.traceSnd("tcb:snd")
		tcb.traceSeg("tcb:snd", seg)
	}

	return nil
}

func (tcb *ControlBlock) validateOutgoingSegment(seg Segment) (err error) {
	hasAck := seg.Flags.HasAny(FlagACK)
	isFirst := tcb._state == StateClosed && seg.isFirstSYN()
	checkSeq := !isFirst && !seg.Flags.HasAny(FlagRST)
	seglast := seg.Last()
	// A zero send window still admits control segments and a one-octet probe.
	zeroWindowOK := tcb.snd.WND == 0 && seg.DATALEN <= 1 && seg.SEQ == tcb.snd.NXT
	outOfWindow := checkSeq && !seg.SEQ.InWindow(tcb.snd.NXT, tcb.snd.WND) &&
		!zeroWindowOK
	// A retransmission resends only sent data: one reaching past snd.NXT would
	// send new data without advancing snd.NXT.
	isRetransmit := checkSeq && seg.SEQ.InRange(tcb.snd.UNA, tcb.snd.NXT) &&
		Add(seg.SEQ, seg.LEN()).LessThanEq(tcb.snd.NXT)
	switch {
	case tcb._state == StateClosed && !isFirst:
		err = io.ErrClosedPipe
	case seg.WND > maxWindow:
		err = errWindowTooLarge
	case hasAck && seg.ACK != tcb.rcv.NXT:
		err = errAckNotNext

	case outOfWindow && !isRetransmit:
		if tcb.snd.WND == 0 {
			err = errZeroWindow
		} else {
			err = errSeqNotInWindow
		}

	case seg.DATALEN > 0 && tcb._state == StateFinWait2:
		// FIN-WAIT-2 means our FIN was acknowledged, so no data below it can be
		// unacknowledged and data here is a caller error. FIN-WAIT-1 is excluded:
		// its FIN sits above data the peer may still be missing, which must go out
		// for either side to make progress (RFC 9293 §3.10.8).
		err = errConnectionClosing

	case checkSeq && tcb.snd.WND == 0 && seg.DATALEN > 1 && seg.SEQ == tcb.snd.NXT:
		err = errZeroWindow

	case checkSeq && !seglast.InWindow(tcb.snd.NXT, tcb.snd.WND) && !zeroWindowOK && !isRetransmit:
		err = errLastNotInWindow
	}
	return err
}

func (tcb *ControlBlock) validateIncomingSegment(seg Segment) (err error) {
	flags := seg.Flags
	hasAck := flags.HasAll(FlagACK)
	// Short circuit SEQ checks if SYN present in pre-established states only.
	// In synchronized states SYN must pass normal SEQ validation (RFC 9293 §3.10.7.4).
	preestablished := tcb._state.IsPreestablished()
	// LISTEN has no receive window context; RFC 9293 §3.10.7.1 step 1: "no checking in LISTEN state."
	checkSEQ := (!flags.HasAny(FlagSYN) || !preestablished) && tcb._state != StateListen
	established := tcb._state == StateEstablished
	acksOld := hasAck && !tcb.snd.UNA.LessThan(seg.ACK)
	acksUnsentData := hasAck && !seg.ACK.LessThanEq(tcb.snd.NXT)
	ctlOrDataSegment := established && (seg.DATALEN > 0 || flags.HasAny(FlagFIN|FlagRST))
	zeroWindowOK := tcb.rcv.WND == 0 && seg.DATALEN == 0 && seg.SEQ == tcb.rcv.NXT
	// See section 3.4 of RFC 9293 for more on these checks.
	switch {
	case seg.WND > maxWindow:
		err = errWindowOverflow
	case tcb._state == StateClosed:
		err = io.ErrClosedPipe

	case checkSEQ && tcb.rcv.WND == 0 && seg.DATALEN > 0 && seg.SEQ == tcb.rcv.NXT:
		err = errZeroWindow

	case checkSEQ && !seg.SEQ.InWindow(tcb.rcv.NXT, tcb.rcv.WND) && !zeroWindowOK:
		err = errSeqNotInWindow

	case checkSEQ && !seg.Last().InWindow(tcb.rcv.NXT, tcb.rcv.WND) && !zeroWindowOK:
		err = errLastNotInWindow

	case checkSEQ && !flags.HasAny(FlagRST) && seg.SEQ != tcb.rcv.NXT:
		// This part diverts from TCB as described in RFC 9293. We want to support
		// only sequential segments to keep implementation simple and maintainable. See SHLD-31.
		err = errRequireSequential
	}
	if err != nil {
		// RFC 9293 §3.4: If segment not acceptable, send ACK (unless RST).
		switch err {
		case errZeroWindow:
			if !flags.HasAny(FlagRST) {
				tcb.pending[0] |= FlagACK
			}
		case errSeqNotInWindow, errLastNotInWindow, errRequireSequential:
			if !flags.HasAny(FlagRST) {
				if tcb.tooManyChallengeAcks() {
					tcb.Abort()
					return net.ErrClosed
				}
				tcb.triggerChallengeAckEmit()
			}
		}
		return err
	}
	if flags.HasAny(FlagRST) {
		return tcb.handleRST(seg.SEQ)
	}

	isDebug := tcb.logenabled(slog.LevelDebug)
	// Drop-segment checks.
	switch {
	// Special treatment of duplicate ACKs on established connection and of ACKs of unsent data.
	// https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.4-2.5.2.2.2.3.2.1
	case established && acksOld && !ctlOrDataSegment:
		// We don't drop packet.
		if isDebug {
			tcb.debug("rcv:ACK-old", slog.String("state", tcb._state.String()),
				slog.Uint64("seg.ack", uint64(seg.ACK)), slog.Uint64("snd.una", uint64(tcb.snd.UNA)))
		}

	case established && acksUnsentData:
		// ACK for data we haven't sent. Drop and send challenge ACK.
		err = errDropSegment
		tcb.pending[0] |= FlagACK // Send ACK for unsent data; |= preserves any pending FIN.
		if isDebug {
			tcb.debug("rcv:ACK-unsent", slog.String("state", tcb._state.String()),
				slog.Uint64("seg.ack", uint64(seg.ACK)), slog.Uint64("snd.nxt", uint64(tcb.snd.NXT)))
		}

	case preestablished && (acksOld || acksUnsentData):
		err = errDropSegment
		tcb.pending[0] = FlagRST
		tcb.rstPtr = seg.ACK
		tcb.resetSnd(tcb.snd.ISS, seg.WND)
		if isDebug {
			tcb.debug("rcv:RST-old", slog.String("state", tcb._state.String()), slog.Uint64("ack", uint64(seg.ACK)))
		}
	}
	return err
}

func (tcb *ControlBlock) resetSnd(localISS Value, remoteWND Size) {
	tcb.snd = sendSpace{
		ISS: localISS,
		UNA: localISS,
		NXT: localISS,
		WND: remoteWND,
		// UP, WL1, WL2 defaults to zero values.
	}
}

func (tcb *ControlBlock) resetRcv(localWND Size, remoteISS Value) {
	tcb.rcv = recvSpace{
		IRS: remoteISS,
		NXT: remoteISS,
		WND: localWND,
	}
}

func (tcb *ControlBlock) handleRST(seq Value) error {
	tcb.debug("rcv:RST", slog.String("state", tcb._state.String()))
	switch tcb._state {
	case StateSynSent:
		// RFC 9293 §3.10.7.2: RST in SYN-SENT aborts the active open.
		tcb.Abort()
		return net.ErrClosed
	case StateListen:
		// RFC 9293 §3.5.3: RST in LISTEN state is ignored.
		return errDropSegment
	case StateSynRcvd:
		// RFC 9293 §3.5.3: SYN-RCVD (passive open) returns to LISTEN on RST.
		tcb.pending[0] = 0
		tcb._state = StateListen
		tcb.resetSnd(tcb.snd.ISS+tcb.rstJump(), tcb.snd.WND)
		tcb.resetRcv(tcb.rcv.WND, 3_14159_2653^tcb.rcv.IRS)
		return errDropSegment
	}
	// Synchronized states: exact SEQ match required; challenge ACK for in-window non-exact.
	if seq != tcb.rcv.NXT {
		tcb.triggerChallengeAckEmit()
		tcb.pending[0] |= FlagACK
		return errDropSegment
	}
	tcb.Abort()
	return net.ErrClosed
}

func (tcb *ControlBlock) rstJump() Value {
	return 100
}

// Abort sets ControlBlock state to Closed and resets all sequence numbers and pending flag.
// No more data can be sent nor received after the connection is aborted until opened again.
// An abort call prepares the connection for opening an active connection via a
// SYN packet during Send call in state=StateClosed.
func (tcb *ControlBlock) Abort() {
	tcb.reset()
	tcb.debug("tcb:abort")
}

func (tcb *ControlBlock) reset() {
	*tcb = ControlBlock{
		logger: tcb.logger,
	}
}

// Close implements a passive/active closing of a connection. It does not immediately
// delete the TCB but initiates the process so that pending outgoing segments initiate
// the closing process. After a call to Close users should not send more data.
// Close returns an error if the connection is already closed or closing.
func (tcb *ControlBlock) Close() (err error) {
	// See RFC 9293: 3.10.4 CLOSE call.
	switch tcb._state {
	case StateClosed:
		err = errConnNotExist
	case StateCloseWait:
		tcb._state = StateLastAck
		tcb.pending = [2]Flags{FlagFIN | FlagACK, 0}
	case StateListen, StateSynSent:
		// In Listen State there is no established connection.
		// In SynSent the remote endpoint is not yet synchronized and upon receiving an RST will abort connection.
		tcb.Abort()
	case StateSynRcvd, StateEstablished:
		// We suppose user has no more pending data to send, so we flag FIN to be sent.
		// Users of this API should call Close only when they have no more data to send.
		// When FIN is sent SCB will transition to FinWait1.
		tcb.pending[0] = (tcb.pending[0] & FlagACK) | FlagFIN
	case StateFinWait2, StateTimeWait:
		err = errConnectionClosing
	default:
		err = errInvalidState
	}
	if err == nil {
		tcb.trace("tcb:close", slog.String("state", tcb._state.String()))
	} else {
		tcb.logerr("tcb:close", slog.String("err", err.Error()))
	}
	return err
}

func (tcb *ControlBlock) triggerChallengeAckSatisfied() {
	tcb.challengeAcks = 0
}
func (tcb *ControlBlock) triggerChallengeAckEmit() {
	if tcb.challengeAcks >= 0 {
		// Only increment challenge ack counter if last challenge ack already sent.
		tcb.challengeAcks = -tcb.challengeAcks - 1
	}
}
func (tcb *ControlBlock) triggerChallengeAckSent() {
	if tcb.challengeAcks < 0 {
		tcb.challengeAcks = -tcb.challengeAcks // Make positive.
	}
}
func (tcb *ControlBlock) pendingChallengeAck() bool {
	return tcb.challengeAcks < 0
}
func (tcb *ControlBlock) tooManyChallengeAcks() bool {
	if tcb.challengeAcks >= 0 {
		return tcb.challengeAcks > maxChallengeRejects
	} else {
		return tcb.challengeAcks < -maxChallengeRejects
	}
}

// ISN generates an Initial Sequence Number(ISN) per RFC 6528:
//
//	ISN = M + F(localip, localport, remoteip, remoteport, secretkey)
//
// where M is nanotime, F is SipHash-2-4 keyed with generator's secret so the ISN
// of one connection does not predict the ISN of another. addr buffers to ISN are only required to be of less than length 16.
func ISN(key *[16]byte, nanotime int64, localAddr, remoteAddr []byte, localPort, remotePort uint16) Value {
	// | localPort16 | remotePort16 | localAddr... | remoteAddr... |
	var buf [4 + 16 + 16]byte
	binary.BigEndian.PutUint16(buf[0:], localPort)
	binary.BigEndian.PutUint16(buf[2:], remotePort)
	n := 4 + copy(buf[4:20], localAddr)
	n += copy(buf[n:], remoteAddr)
	f := internal.SipHash24(key, buf[:n])
	m := uint64(nanotime) >> 12 // 4.096µs ticks.
	return Value(uint32(m) + uint32(f))
}
