package tcp

func (tcb *ControlBlock) rcvListen(seg Segment) (pending Flags, err error) {
	switch {
	case !seg.Flags.HasAll(FlagSYN):
		err = errExpectedSYN
	}
	if err != nil {
		return 0, err
	}
	// Initialize all connection state:
	tcb.resetSnd(tcb.snd.ISS, seg.WND)
	tcb.resetRcv(tcb.rcv.WND, seg.SEQ)

	// We must respond with SYN|ACK frame after receiving SYN in listen state (three way handshake).
	tcb.pending[0] = synack
	tcb._state = StateSynRcvd
	return synack, nil
}

func (tcb *ControlBlock) rcvSynSent(seg Segment) (pending Flags, err error) {
	hasSyn := seg.Flags.HasAny(FlagSYN)
	hasAck := seg.Flags.HasAny(FlagACK)
	switch {
	case !hasSyn:
		err = errExpectedSYN

	case hasAck && seg.ACK != tcb.snd.UNA+1:
		err = errBadSegack
	}
	if err != nil {
		return 0, err
	}

	if hasAck {
		tcb._state = StateEstablished
		pending = FlagACK
		tcb.resetRcv(tcb.rcv.WND, seg.SEQ)
	} else {
		// Simultaneous connection sync edge case.
		pending = synack
		tcb._state = StateSynRcvd
		tcb.resetSnd(tcb.snd.ISS, seg.WND)
		tcb.resetRcv(tcb.rcv.WND, seg.SEQ)
	}
	return pending, nil
}

func (tcb *ControlBlock) rcvSynRcvd(seg Segment) (pending Flags, err error) {
	switch {
	case !seg.Flags.HasAll(FlagACK):
		// RFC 9293 §3.10.7.4 step 5: "If the ACK bit is off, drop the segment and return."
		err = errBadSegack
	case seg.ACK != tcb.snd.UNA+1:
		err = errBadSegack
	}
	if err != nil {
		return 0, err
	}
	tcb._state = StateEstablished
	return 0, nil
}

func (tcb *ControlBlock) rcvEstablished(seg Segment) (pending Flags, err error) {
	flags := seg.Flags
	dataToAck := seg.DATALEN > 0
	hasFin := flags.HasAny(FlagFIN)
	if dataToAck || hasFin {
		pending = FlagACK
		if hasFin {
			// See Figure 5: TCP Connection State Diagram of RFC 9293.
			tcb._state = StateCloseWait
			// RFC 9293 §3.5: CLOSE-WAIT allows local side to continue sending.
			// Do NOT auto-queue FIN here; user must call Close() explicitly.
		}
	}

	return pending, nil
}

func (tcb *ControlBlock) rcvFinWait1(seg Segment) (pending Flags, err error) {
	flags := seg.Flags
	hasFin := flags&FlagFIN != 0
	hasAck := flags&FlagACK != 0
	switch {
	case hasFin && hasAck && seg.ACK == tcb.snd.NXT:
		// Special case: Server sent a FINACK response to our FIN so we enter TimeWait directly.
		// We have to check ACK against send NXT to avoid simultaneous close sequence edge case.
		tcb._state = StateTimeWait
	case hasFin:
		tcb._state = StateClosing
	case hasAck && seg.ACK == tcb.snd.NXT:
		// RFC 9293 §3.10.7.4 step 5: enter FIN-WAIT-2 only if the FIN is now acknowledged.
		tcb._state = StateFinWait2
	case hasAck:
		// Partial ACK: acknowledges data but not the FIN. Stay in FIN-WAIT-1.
	default:
		return 0, errFinwaitExpectedACK
	}
	// Only queue ACK when there is data or FIN to acknowledge.
	// Bare ACKs must not elicit an ACK response; doing so creates an
	// infinite ACK ping-pong when the peer sends challenge ACKs.
	if seg.DATALEN > 0 || hasFin {
		pending = FlagACK
	}
	return pending, nil
}

func (tcb *ControlBlock) rcvFinWait2(seg Segment) (pending Flags, err error) {
	if seg.Flags.HasAny(FlagFIN) {
		tcb._state = StateTimeWait
		return FlagACK, nil
	}
	// Bare ACKs and data are valid in FIN-WAIT-2 per RFC 9293 §3.10.7.4.
	// The remote side hasn't closed yet; it may still send data.
	if seg.DATALEN > 0 {
		return FlagACK, nil
	}
	return 0, nil
}
