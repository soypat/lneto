package tcp

// TransmitUnlimited size returned by [Policy.PreTx] to signal no new data transmit limit (no congestion control).
const TransmitUnlimited = ^Size(0)

// Policy observes segment traffic and steers transmit behaviour: RTO,
// congestion control and the like (discussion #157). The tcp package holds no
// clock, so a Policy needing time carries its own (issue #140).
// Introspection stays off the interface; put it on the concrete type.
type Policy interface {
	// Reset returns the Policy to its pre-connection state. Called on every
	// (re)open and Abort. Must preserve configuration such as a clock.
	Reset()

	// PreTx is called before writing to a frame.
	// The outgoing frame options can be set by the Policy and will be respected if Frame offset >5.
	// rtxFrom is ignored unless within [snd.UNA, snd.NXT] and returned retransmit==true.
	// newTransmitLimit sets the maximum number of new bytes to send over the wire (congestion control).
	// If not implementing congestion control then newTransmitLimit=[TransmitUnlimited].
	PreTx(h *Handler, outgoingOpts Frame) (newTransmitLimit Size, rtxFrom Value, retransmit bool)
	// PostTx called on leaving the transmit path with the fully written frame.
	PostTx(h *Handler, outgoing Frame)

	// PreRx is called by [Handler] on every incoming segment.
	// PreRx can choose to drop segment if it returns keep=false.
	PreRx(h *Handler, incoming Frame) (keep bool)
	// PostRx is called by [Handler] after accepting an incoming segment.
	// TODO: congestion control will also want the pre-Recv snd.UNA here.
	PostRx(h *Handler, prevState State, accepted Frame)
}
