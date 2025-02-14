package tcp

import (
	"io"
	"log/slog"
	"math"
	"net"

	"github.com/soypat/lneto/internal"
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
	// pending is the queue of pending flags to be sent in the next 2 segments.
	// On a call to Send the queue is advanced and flags set in the segment are unset.
	// The second position of the queue is used for FIN segments.
	pending      [2]Flags
	_state       State // leading underscore so field not suggested on top of exported State method when developing.
	challengeAck bool
	logger
}

// State returns the current state of the TCP connection.
func (tcb *ControlBlock) State() State { return tcb._state }

// RecvNext returns the next sequence number expected to be received from remote.
// This implementation will reject segments that are not the next expected sequence.
// RecvNext returns 0 before StateSynRcvd.
func (tcb *ControlBlock) RecvNext() Value { return tcb.rcv.NXT }

// RecvWindow returns the receive window size. If connection is closed will return 0.
func (tcb *ControlBlock) RecvWindow() Size { return tcb.rcv.WND }

// ISS returns the initial sequence number of the connection that was defined on a call to Open by user.
func (tcb *ControlBlock) ISS() Value { return tcb.snd.ISS }

// MaxInFlightData returns the maximum size of a segment that can be sent by taking into account
// the send window size and the unacked data. Returns 0 before StateSynRcvd.
func (tcb *ControlBlock) MaxInFlightData() Size {
	if !tcb._state.hasIRS() {
		return 0 // SYN not yet received.
	}
	unacked := Sizeof(tcb.snd.UNA, tcb.snd.NXT)
	return tcb.snd.WND - unacked - 1 // TODO: is this -1 supposed to be here?
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

// sendSpace contains Send Sequence Space data. Its sequence numbers correspond to local data.
type sendSpace struct {
	ISS Value // initial send sequence number, defined locally on connection start
	UNA Value // send unacknowledged. Seqs equal to UNA and above have NOT been acked by remote. Corresponds to local data.
	NXT Value // send next. This seq and up to UNA+WND-1 are allowed to be sent. Corresponds to local data.
	WND Size  // send window defined by remote. Permitted number of local unacked octets in flight.
	// WL1 Value // segment sequence number used for last window update
	// WL2 Value // segment acknowledgment number used for last window update
}

// inFlight returns amount of unacked bytes sent out.
func (snd *sendSpace) inFlight() Size {
	return Sizeof(snd.UNA, snd.NXT)
}

// maxSend returns maximum segment datalength receivable by remote peer.
func (snd *sendSpace) maxSend() Size {
	return snd.WND - snd.inFlight()
}

// recvSpace contains Receive Sequence Space data. Its sequence numbers correspond to remote data.
type recvSpace struct {
	IRS Value // initial receive sequence number, defined by remote in SYN segment received.
	NXT Value // receive next. seqs before this have been acked. this seq and up to NXT+WND-1 are allowed to be sent. Corresponds to remote data.
	WND Size  // receive window defined by local. Permitted number of remote unacked octets in flight.
}

// Open implements a passive opening of a connection (wait for incoming packets).
// Upon success [ControlBlock] enters LISTEN state, such as that of a server.
// To open an active connection use [ControlBlock.Send] with a segment generated with [ClientSynSegment].
func (tcb *ControlBlock) Open(iss Value, wnd Size) (err error) {
	switch {
	case tcb._state != StateClosed && tcb._state != StateListen:
		err = errTCBNotClosed
	case wnd > math.MaxUint16:
		err = errWindowTooLarge
	}
	if err != nil {
		tcb.logerr("tcb:open", slog.String("err", err.Error()))
		return err
	}
	tcb._state = StateListen
	tcb.prepareToHandshake(iss, wnd)
	tcb.trace("tcb:open-server")
	return nil
}

// prepareToHandshake initializes the TCB send/receive spaces with initial send sequence number and local window.
func (tcb *ControlBlock) prepareToHandshake(iss Value, wnd Size) {
	tcb.resetRcv(wnd, 0)
	tcb.resetSnd(iss, 1)
	tcb.pending = [2]Flags{}
}

// HasPending returns true if there is a pending control segment to send. Calls to Send will advance the pending queue.
func (tcb *ControlBlock) HasPending() bool { return tcb.pending[0] != 0 }

// PendingSegment calculates a suitable next segment to send from a payload length.
// It does not modify the ControlBlock state or pending segment queue.
func (tcb *ControlBlock) PendingSegment(payloadLen int) (_ Segment, ok bool) {
	if tcb.challengeAck {
		tcb.challengeAck = false
		return Segment{SEQ: tcb.snd.NXT, ACK: tcb.rcv.NXT, Flags: FlagACK, WND: tcb.rcv.WND}, true
	}
	pending := tcb.pending[0]
	established := tcb._state == StateEstablished
	if !established && tcb._state != StateCloseWait {
		payloadLen = 0 // Can't send data if not established.
	}
	if pending == 0 && payloadLen == 0 {
		return Segment{}, false // No pending segment.
	}

	// Limit payload to what send window allows.
	inFlight := tcb.snd.inFlight()
	_ = inFlight
	maxPayload := tcb.snd.maxSend()
	if payloadLen > int(maxPayload) {
		if maxPayload == 0 && !tcb.pending[0].HasAny(FlagFIN|FlagRST|FlagSYN) {
			return Segment{}, false
		} else if maxPayload > tcb.snd.WND {
			panic("seqs: bad calculation")
		}
		payloadLen = int(maxPayload)
	}

	if established {
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
		if seg.Flags.HasAny(FlagACK) {
			tcb.close()
		}
	case StateClosing:
		// Thanks to @knieriem for finding and reporting this bug.
		if seg.Flags.HasAny(FlagACK) {
			tcb._state = StateTimeWait
		}
	default:
		panic("unexpected recv state:" + tcb._state.String())
	}
	if err != nil {
		return err
	}

	tcb.pending[0] |= pending
	if prevNxt != 0 && tcb.snd.NXT != prevNxt && tcb.logenabled(slog.LevelDebug) {
		tcb.debug("tcb:snd.nxt-change", slog.String("state", tcb._state.String()),
			slog.Uint64("seg.ack", uint64(seg.ACK)), slog.Uint64("snd.nxt", uint64(tcb.snd.NXT)),
			slog.Uint64("prevnxt", uint64(prevNxt)), slog.Uint64("seg.seq", uint64(seg.SEQ)))
	}

	// We accept the segment and update TCB state.
	tcb.snd.WND = seg.WND
	if seg.Flags.HasAny(FlagACK) {
		tcb.snd.UNA = seg.ACK
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
	hasACK := seg.Flags.HasAny(FlagACK)
	var newPending Flags
	switch tcb._state {
	case StateClosed:
		if seg.Flags == FlagSYN {
			tcb._state = StateSynSent
			tcb.prepareToHandshake(seg.SEQ, seg.WND)
			tcb.trace("tcb:open-client")
		}
	case StateSynRcvd:
		if hasFIN {
			tcb._state = StateFinWait1 // RFC 9293: 3.10.4 CLOSE call.
		}
	case StateClosing:
		if hasACK {
			tcb._state = StateTimeWait
		}
	case StateEstablished:
		if hasFIN {
			tcb._state = StateFinWait1
		}
	case StateCloseWait:
		if hasFIN {
			tcb._state = StateLastAck
		} else if hasACK {
			newPending = finack // Queue finack.
		}
	}

	// Advance pending flags queue.
	tcb.pending[0] &^= seg.Flags
	if tcb.pending[0] == 0 {
		// Ensure we don't queue a FINACK if we have already sent a FIN.
		tcb.pending = [2]Flags{tcb.pending[1] &^ (seg.Flags & (FlagFIN)), 0}
	}
	tcb.pending[0] |= newPending

	// The segment is valid, we can update TCB state.
	seglen := seg.LEN()
	tcb.snd.NXT.UpdateForward(seglen)
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
	// Extra check for when send Window is zero and no data is being sent.
	zeroWindowOK := tcb.snd.WND == 0 && seg.DATALEN == 0 && seg.SEQ == tcb.snd.NXT
	outOfWindow := checkSeq && !seg.SEQ.InWindow(tcb.snd.NXT, tcb.snd.WND) &&
		!zeroWindowOK
	switch {
	case tcb._state == StateClosed && !isFirst:
		err = io.ErrClosedPipe
	case seg.WND > math.MaxUint16:
		err = errWindowTooLarge
	case hasAck && seg.ACK != tcb.rcv.NXT:
		err = errAckNotNext

	case outOfWindow:
		if tcb.snd.WND == 0 {
			err = errZeroWindow
		} else {
			err = errSeqNotInWindow
		}

	case seg.DATALEN > 0 && (tcb._state == StateFinWait1 || tcb._state == StateFinWait2):
		err = errConnectionClosing // Case 1: No further SENDs from the user will be accepted by the TCP implementation.

	case checkSeq && tcb.snd.WND == 0 && seg.DATALEN > 0 && seg.SEQ == tcb.snd.NXT:
		err = errZeroWindow

	case checkSeq && !seglast.InWindow(tcb.snd.NXT, tcb.snd.WND) && !zeroWindowOK:
		err = errLastNotInWindow
	}
	return err
}

func (tcb *ControlBlock) validateIncomingSegment(seg Segment) (err error) {
	flags := seg.Flags
	hasAck := flags.HasAll(FlagACK)
	// Short circuit SEQ checks if SYN present since the incoming segment initialize1s connection.
	checkSEQ := !flags.HasAny(FlagSYN)
	established := tcb._state == StateEstablished
	preestablished := tcb._state.IsPreestablished()
	acksOld := hasAck && !tcb.snd.UNA.LessThan(seg.ACK)
	acksUnsentData := hasAck && !seg.ACK.LessThanEq(tcb.snd.NXT)
	ctlOrDataSegment := established && (seg.DATALEN > 0 || flags.HasAny(FlagFIN|FlagRST))
	zeroWindowOK := tcb.rcv.WND == 0 && seg.DATALEN == 0 && seg.SEQ == tcb.rcv.NXT
	// See section 3.4 of RFC 9293 for more on these checks.
	switch {
	case seg.WND > math.MaxUint16:
		err = errWindowOverflow
	case tcb._state == StateClosed:
		err = io.ErrClosedPipe

	case checkSEQ && tcb.rcv.WND == 0 && seg.DATALEN > 0 && seg.SEQ == tcb.rcv.NXT:
		err = errZeroWindow

	case checkSEQ && !seg.SEQ.InWindow(tcb.rcv.NXT, tcb.rcv.WND) && !zeroWindowOK:
		err = errSeqNotInWindow

	case checkSEQ && !seg.Last().InWindow(tcb.rcv.NXT, tcb.rcv.WND) && !zeroWindowOK:
		err = errLastNotInWindow

	case checkSEQ && seg.SEQ != tcb.rcv.NXT:
		// This part diverts from TCB as described in RFC 9293. We want to support
		// only sequential segments to keep implementation simple and maintainable. See SHLD-31.
		err = errRequireSequential
	}
	if err != nil {
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
		err = errDropSegment
		tcb.pending[0] &= FlagFIN // Completely ignore duplicate ACKs but do not erase fin bit.
		if isDebug {
			tcb.debug("rcv:ACK-dup", slog.String("state", tcb._state.String()),
				slog.Uint64("seg.ack", uint64(seg.ACK)), slog.Uint64("snd.una", uint64(tcb.snd.UNA)))
		}

	case established && acksUnsentData:
		err = errDropSegment
		tcb.pending[0] = FlagACK // Send ACK for unsent data.
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
	if seq != tcb.rcv.NXT {
		// See RFC9293: If the RST bit is set and the sequence number does not exactly match the next expected sequence value, yet is within the current receive window, TCP endpoints MUST send an acknowledgment (challenge ACK).
		tcb.challengeAck = true
		tcb.pending[0] |= FlagACK
		return errDropSegment
	}
	if tcb._state.IsPreestablished() {
		tcb.pending[0] = 0
		tcb._state = StateListen
		tcb.resetSnd(tcb.snd.ISS+tcb.rstJump(), tcb.snd.WND)
		tcb.resetRcv(tcb.rcv.WND, 3_14159_2653^tcb.rcv.IRS)
	} else {
		tcb.close() // Enter closed state and return.
		return net.ErrClosed
	}
	return errDropSegment
}

func (tcb *ControlBlock) rstJump() Value {
	return 100
}

// close sets ControlBlock state to closed and resets all sequence numbers and pending flag.
func (tcb *ControlBlock) close() {
	tcb._state = StateClosed
	tcb.pending = [2]Flags{}
	tcb.resetRcv(0, 0)
	tcb.resetSnd(0, 0)
	tcb.debug("tcb:close")
}

// Close implements a passive/active closing of a connection. It does not immediately
// delete the TCB but initiates the process so that pending outgoing segments initiate
// the closing process. After a call to Close users should not send more data.
// Close returns an error if the connection is already closed or closing.
func (tcb *ControlBlock) Close() (err error) {
	// See RFC 9293: 3.10.4 CLOSE call.
	switch tcb._state {
	case StateClosed:
		err = errConnNotexist
	case StateCloseWait:
		tcb._state = StateLastAck
		tcb.pending = [2]Flags{FlagFIN, FlagACK}
	case StateListen, StateSynSent:
		tcb.close()
	case StateSynRcvd, StateEstablished:
		// We suppose user has no more pending data to send, so we flag FIN to be sent.
		// Users of this API should call Close only when they have no more data to send.
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
