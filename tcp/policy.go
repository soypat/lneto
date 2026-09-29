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
	// retransmitFrom is ignored unless within [snd.UNA, snd.NXT] and returned retransmit==true.
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
