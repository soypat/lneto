package tcp

// LossRecovery abstracts TCP packet-loss recovery: RTO, congestion control and
// any similar algorithm that observes segment traffic and steers the
// connection's transmit behaviour. As far as the tcp package is concerned these
// are all the same thing — packet-loss recovery algorithms — so they share one
// interface (see discussion #157).
//
// The tcp package stays free of any time source: the current monotonic time in
// nanoseconds (the func() int64 convention used across lneto) is passed in at
// each hook boundary. It originates from [ConnConfig.Nanotime] and satisfies the
// "WHEN was this segment rx/tx'd" requirement without a clock living inside the
// state machine, which also keeps implementations deterministic for testing
// (see issue #140).
//
// The interface is intentionally free of errors: an implementation handles or
// reports its own errors rather than propagating them into lneto internals.
//
// Introspection (smoothed RTT, current window, ...) is deliberately left off the
// interface; expose it on the concrete implementation the caller constructs and
// hands to [ConnConfig].
type LossRecovery interface {
	// Reset returns the implementation to its initial, pre-connection state. It
	// is invoked whenever the connection is (re)opened or aborted so a single
	// LossRecovery value can be reused across the lifetime of connection reuse
	// (see discussion #115).
	Reset()

	// NextDeadline returns the monotonic-nanosecond instant at which the
	// connection must next be serviced by a transmit attempt — typically the RTO
	// expiry. A return of 0 means there is no pending deadline. It replaces a
	// poll/atomic-flag scheme with a deadline the caller's event loop can
	// schedule against.
	NextDeadline() int64

	// PreRx is called for every segment received on the TCP port before the
	// state machine processes it, with the monotonic time the segment arrived. It
	// returns whether the segment should be kept (processed) or dropped.
	PreRx(incoming Segment, now int64) RxDirective

	// PreTx is called on entering the transmit path (Encapsulate), before a
	// segment is built, with the current monotonic time. Its directive tells the
	// connection whether to retransmit unacknowledged data, rewind the send
	// pointer, or hold back new data.
	PreTx(now int64) TxDirective

	// PostTx is called on leaving the transmit path with the segment that was
	// actually emitted and the monotonic time it was sent. This is where segment
	// timing (for RTT sampling and the retransmission timer) is recorded.
	PostTx(outgoing Segment, now int64)
}

// TxDirective is returned by [LossRecovery.PreTx] to steer the transmit path.
// The zero value directs the connection to proceed normally (send new data if
// available, no retransmission).
type TxDirective struct {
	// RewindNXT is the number of sequence-space octets to rewind snd.NXT by
	// before transmitting, for partial (e.g. selective) retransmission. Zero
	// means no rewind. It is independent of Retransmit, which rewinds fully to
	// snd.UNA.
	RewindNXT uint32
	// Retransmit requests go-back-N retransmission: the connection rewinds
	// snd.NXT to snd.UNA and resends unacknowledged data from the oldest
	// sequence number.
	Retransmit bool
	// HoldNew pauses transmission of new data (for example when the congestion
	// window is exhausted). Retransmissions already directed by this same
	// directive still proceed.
	HoldNew bool
}

// RxDirective is returned by [LossRecovery.PreRx].
//
// NOTE: its shape is the minimum viable contract — it mirrors the original
// PreRx "keep" boolean from discussion #157 — and is the one element of the
// interface not yet fully settled there. It is a struct (rather than a bare
// bool) so fields can be added without breaking implementations.
type RxDirective struct {
	// Keep reports whether the received segment should be handed to the state
	// machine. A false value drops the segment before it is processed.
	Keep bool
}
