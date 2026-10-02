package tcp

// Policies drives several [Policy] implementations as one, so independent
// concerns such as a retransmission timer and selective acknowledgement can be
// combined without one embedding the other. Install it with
// [Handler.SetPolicy], for example tcp.Policies{&timer, &sack}. Members must not
// be nil.
//
// Every hook is offered to every member in order. Results are merged as follows:
//
//   - PreRx keeps the segment only if every member keeps it. Every member is
//     still asked.
//   - PreTx returns the smallest new-data limit, and requests a retransmission
//     if any member does, from the lowest sequence requested, so the resend
//     covers what every requester wanted.
//
// Members writing options in PreTx must append after the options already
// present, which end at the frame's data offset, and raise the offset to cover
// their own.
//
// Members should own separate state: two members each running a retransmission
// timer both drive retransmission, and no merge rule recovers one correct timer.
type Policies []Policy

var _ Policy = Policies(nil)

// Reset resets every member. It implements [Policy].
func (ps Policies) Reset() {
	for _, p := range ps {
		p.Reset()
	}
}

// PreTx merges the members' transmit requests. It implements [Policy].
func (ps Policies) PreTx(h *Handler, outgoingOpts Frame) (newTransmitLimit Size, retransmitFrom Value, retransmit bool) {
	newTransmitLimit = TransmitUnlimited
	for _, p := range ps {
		limit, from, rtx := p.PreTx(h, outgoingOpts)
		newTransmitLimit = min(newTransmitLimit, limit)
		if rtx && (!retransmit || from.LessThan(retransmitFrom)) {
			retransmitFrom, retransmit = from, true
		}
	}
	return newTransmitLimit, retransmitFrom, retransmit
}

// PostTx reports the emitted frame to every member. It implements [Policy].
func (ps Policies) PostTx(h *Handler, outgoing Frame) {
	for _, p := range ps {
		p.PostTx(h, outgoing)
	}
}

// PreRx keeps the segment only if every member keeps it. It implements [Policy].
func (ps Policies) PreRx(h *Handler, incoming Frame) (keep bool) {
	keep = true
	for _, p := range ps {
		keep = p.PreRx(h, incoming) && keep
	}
	return keep
}

// PostRx reports the accepted frame to every member. It implements [Policy].
func (ps Policies) PostRx(h *Handler, prevState State, accepted Frame) {
	for _, p := range ps {
		p.PostRx(h, prevState, accepted)
	}
}

// NextDeadline returns the earliest non-zero deadline among members that have a
// NextDeadline method, such as rto.Timer, or 0 if none has one.
func (ps Policies) NextDeadline() (earliest int64) {
	for _, p := range ps {
		dp, ok := p.(interface{ NextDeadline() int64 })
		if !ok {
			continue
		}
		if d := dp.NextDeadline(); d != 0 && (earliest == 0 || d < earliest) {
			earliest = d
		}
	}
	return earliest
}
