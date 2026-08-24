package tcp

type Policy interface {
	Reset()
	// PreTx is called before writing to a frame.
	// The outgoing frame options can be set by the Policy and will be respected if Frame offset >5.
	PreTx(h *Handler, outgoingOpts Frame) (rtxFrom Value, retransmit, holdNew bool)
	// PreRx is called by [Handler] on every incoming segment.
	// PreRx can choose to drop segment if it returns keep=false.
	PreRx(h *Handler, incoming Frame) (keep bool)
	// PostRx is called by [Handler] after accepting an incoming segment.
	PostRx(h *Handler, prevState State, accepted Frame)
	// PostTx called on leaving the transmit path.
	PostTx(h *Handler, outgoing Frame)
}
