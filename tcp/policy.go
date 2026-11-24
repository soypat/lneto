package tcp

// TransmitUnlimited size returned by [Policy.PreTx] to signal no new data transmit limit (no congestion control).
const TransmitUnlimited = ^Size(0)

// Policy observes segment traffic and steers transmit behaviour: RTO,
// congestion control and the like (discussion #157). The tcp package holds no
// clock, so a Policy needing time carries its own (issue #140).
type Policy interface {
	// Reset returns the Policy to its pre-connection state. Should be called on every
	// Open/Listen on connection creation. Configuration like clock setting and fine tuning
	// should persist throughout the Policy lifetime after Reset calls.
	Reset()

	// PreTx is called before writing to a frame.
	// The outgoing frame options can be set by the Policy and will be respected if Frame offset >5.
	// Keep in mind Handler will add options PreTx already added, these options are best overwritten in PostTx.
	// retransmitFrom is ignored unless within [snd.UNA, snd.NXT) and returned retransmit==true.
	// It resends one segment starting at the queued packet containing retransmitFrom.
	// The request applies only to this call: if it cannot be emitted (a control segment
	// takes priority or there is no payload room) the Policy must return it again later.
	// newTransmitLimit sets the maximum number of new bytes to send over the wire (congestion control).
	// If not implementing congestion control then newTransmitLimit=[TransmitUnlimited].
	PreTx(h *Handler, outgoingOpts Frame) (newTransmitLimit Size, retransmitFrom Value, retransmit bool)
	// PostTx called on leaving the transmit path with the fully written frame.
	// PostTx can strategically overwrite options normally set by Handler like MSS, Window scaling which
	// ends up being more ergonomic than adding them in PreTx and then de-duplicating them in PostTx.
	PostTx(h *Handler, outgoing Frame)

	// PreRx is called by [Handler] on every incoming segment.
	// PreRx can choose to drop segment if it returns keep=false.
	PreRx(h *Handler, incoming Frame) (keep bool)
	// PostRx is called by [Handler] after accepting an incoming segment.
	// To access [ControlBlock.SendUNA] before incoming frame was processed save UNA in PreRx.
	PostRx(h *Handler, prevState State, accepted Frame)
}

// ECNPolicy is a [Policy] doing Explicit Congestion Notification (RFC 3168),
// whose codepoints are in the IP header the Handler does not see. The
// [Handler] hands it, alone or as a member of [Policies], each segment's frame
// together with the codepoint of the packet carrying it: [Handler.RecvECN]
// takes the codepoint of a received packet and [Handler.SendECN] returns the
// one for a sent packet, which a [Conn] reads from and writes to the IP header.
// Policies needing no IP header leave it unimplemented.
type ECNPolicy interface {
	Policy
	// PreRxECN is called by [Handler] before [Policy.PreRx] with the incoming
	// frame and the ECN codepoint of the packet carrying it, Not-ECT if the
	// frame came through [Handler.Recv].
	PreRxECN(h *Handler, incoming Frame, ecn uint8)
	// PostTxECN is called by [Handler] after [Policy.PostTx] with the same frame,
	// whose flags it may still set, and returns the ECN codepoint of the packet
	// to carry it.
	PostTxECN(h *Handler, outgoing Frame) (ecn uint8)
}

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
//   - The Handler offers PreRxECN and PostTxECN to every member that is an
//     [ECNPolicy], also in nested Policies, and sends the codepoint of the
//     first. Policies itself is no ECNPolicy, whatever its members.
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

// preRxECN calls PreRxECN of p if it is an [ECNPolicy], or of every such member
// if it is [Policies].
func preRxECN(p Policy, h *Handler, incoming Frame, ecn uint8) {
	switch p := p.(type) {
	case ECNPolicy:
		p.PreRxECN(h, incoming, ecn)
	case Policies:
		for _, member := range p {
			preRxECN(member, h, incoming, ecn)
		}
	}
}

// postTxECN calls PostTxECN of p if it is an [ECNPolicy], or of every such
// member if it is [Policies], and returns the codepoint of the first. ok is
// false without one.
func postTxECN(p Policy, h *Handler, outgoing Frame) (ecn uint8, ok bool) {
	switch p := p.(type) {
	case ECNPolicy:
		return p.PostTxECN(h, outgoing), true
	case Policies:
		for _, member := range p {
			if cp, isECN := postTxECN(member, h, outgoing); isECN && !ok {
				ecn, ok = cp, true
			}
		}
	}
	return ecn, ok
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
