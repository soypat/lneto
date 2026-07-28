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
//
// # Why a runtime interface and not a type parameter
//
// A compile-time alternative was considered, parameterizing the connection on
// the policy (Endpoint[P LossRecovery]) with a zero-sized no-op default, on the
// expectation that unused hooks would specialize away and leave the plain path
// call-free. Measurement does not support that on this project's primary
// toolchain:
//
//   - gc (and therefore TamaGo, a gc fork) compiles method calls on a type
//     parameter into indirect calls through the instantiation dictionary. A
//     zero-sized policy is not devirtualized or inlined, so the plain path pays
//     the same dispatch as an interface. The nil check used here compiles to a
//     branch and no call at all, which is strictly cheaper.
//   - TinyGo (LLVM) does fully specialize and eliminate the no-op hooks, so the
//     type parameter would win there, but only there.
//
// A type parameter would also be viral: [Conn] is threaded concretely through
// the stack APIs, and a connection registry holding differently-parameterized
// endpoints has to erase the type anyway, which reintroduces dispatch one level
// up at demultiplexing.
//
// The cost of this seam is measured by BenchmarkHandlerDatapath versus
// BenchmarkHandlerDatapathLossRecovery. Revisit the decision with those numbers
// rather than by assertion.
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
	// state machine processes it. It returns whether the segment should be kept
	// (processed) or dropped.
	PreRx(rx RxMeta) RxDirective

	// PreTx is called on entering the transmit path (Encapsulate), before a
	// segment is built, with a snapshot of the send state. Its directive tells
	// the connection whether to retransmit unacknowledged data, rewind the send
	// pointer, or hold back new data.
	//
	// It runs before the segment is planned because its directives change what
	// gets planned; consequently the outgoing segment's flags and payload are
	// not yet known here. Observe those in [LossRecovery.PostTx].
	PreTx(intent TxIntent) TxDirective

	// WriteOptions is called once the kind of the outgoing segment is known but
	// before its payload is sized, so that the option length can be subtracted
	// from the space left for data. The policy appends TCP options to opts and
	// returns how many octets it wrote; returning 0 adds no options.
	//
	// opts is a borrowed view of the remaining option area of the segment being
	// built, already positioned after any option the core writes itself. It must
	// not be retained beyond the call and must not be written past its length.
	// The core validates the resulting option stream, pads the header to a
	// four-octet boundary and sets the data offset.
	WriteOptions(plan TxPlan, opts []byte) uint8

	// PostTx is called on leaving the transmit path with the segment that was
	// actually emitted and the monotonic time it was sent. This is where segment
	// timing (for RTT sampling and the retransmission timer) is recorded.
	PostTx(outgoing Segment, now int64)
}

// TxIntent is the snapshot of send state handed to [LossRecovery.PreTx] before
// a segment is planned. It is passed by value and must not be retained.
//
// It carries what a loss-recovery or congestion-control algorithm needs to
// decide whether to retransmit and whether new data may be sent, without
// exposing the control block or the transmit buffer. Notably it never carries
// payload bytes: outgoing data may eventually live in application memory
// referenced by the retransmission queue rather than in a contiguous internal
// buffer (the zero-copy transmit direction sketched in discussion #87), so
// policy addresses data by sequence number only.
type TxIntent struct {
	// Now is the current monotonic time in nanoseconds, as read from the
	// connection's clock. It is the only time source a hook may rely on.
	Now int64
	// State is the connection state on entering the transmit path.
	State State
	// UNA is the oldest unacknowledged sequence number (snd.UNA), the point a
	// go-back-N retransmission rewinds to.
	UNA Value
	// NXT is the next sequence number to be sent (snd.NXT).
	NXT Value
	// InFlight is the number of octets sent but not yet acknowledged,
	// equivalently the distance from UNA to NXT. Congestion control compares it
	// against its window to decide whether new data may go out.
	InFlight Size
	// SendWindow is the receive window most recently advertised by the remote
	// peer (snd.WND), already unscaled. The effective limit on new data is the
	// lesser of this and any window the policy imposes itself.
	SendWindow Size
	// MSS is the maximum segment size advertised by the remote peer, or 0 if it
	// sent none. Congestion-control windows are conventionally maintained in
	// multiples of it.
	MSS Size
	// BufferedUnsent is the number of octets the application has queued that
	// have not been sent yet. Zero means holding back new data has no effect
	// because there is none to send.
	BufferedUnsent Size
}

// RxMeta describes a received segment handed to [LossRecovery.PreRx]. It is
// passed by value and must not be retained.
//
// Where [TxIntent] describes a segment not yet built, RxMeta describes one that
// has arrived and been structurally validated but not yet processed by the
// state machine, so the receive state it reports is the state before the
// segment is applied.
type RxMeta struct {
	// Now is the monotonic time in nanoseconds at which the segment arrived.
	Now int64
	// Segment is the parsed header of the received segment.
	Segment Segment
	// Options is a borrowed view of the segment's TCP option area, empty if it
	// carries none. It is valid only for the duration of the call and must not
	// be retained. The core parses the options it needs itself; a policy is free
	// to parse the same bytes for its own extensions.
	Options []byte
	// State is the connection state before the segment is processed.
	State State
	// SndUNA and SndNXT bound the outstanding send sequence space, which is what
	// classifies the segment's acknowledgment as advancing, duplicate or
	// invalid.
	SndUNA Value
	SndNXT Value
	// RcvNXT is the next sequence number expected from the peer, before this
	// segment is applied. It is what decides whether the segment is the one that
	// may update receive-side extension state.
	RcvNXT Value
}

// TxKind classifies the segment the transmit path is about to build. It is
// what a policy needs to decide which TCP options apply without owning the
// handshake state machine.
type TxKind uint8

const (
	// TxKindSegment is an ordinary post-handshake segment: data, a pure ACK, or
	// a segment carrying FIN or RST.
	TxKindSegment TxKind = iota
	// TxKindSYN is a connection-initiating SYN. Options offered here are the
	// ones being negotiated.
	TxKindSYN
	// TxKindSYNACK is a SYN-ACK responding to a peer's SYN. Options here answer
	// what the peer offered.
	TxKindSYNACK
)

// TxPlan describes the segment about to be built when [LossRecovery.WriteOptions]
// is called. It is passed by value and must not be retained.
type TxPlan struct {
	// Now is the current monotonic time in nanoseconds, the same instant
	// reported to [LossRecovery.PreTx] for this transmit.
	Now int64
	// State is the connection state.
	State State
	// Kind classifies the segment, which determines the applicable options.
	Kind TxKind
}

// TxDirective is returned by [LossRecovery.PreTx] to steer the transmit path.
// The zero value directs the connection to proceed normally (send new data if
// available, no retransmission).
type TxDirective struct {
	// RewindNXT is the number of sequence-space octets to rewind snd.NXT by
	// before transmitting, for partial (e.g. selective) retransmission. Zero
	// means no rewind. It is independent of Retransmit, which rewinds fully to
	// snd.UNA.
	// RewindNXT uint32

	// RetransmitAll requests go-back-N retransmission: the connection rewinds
	// snd.NXT to snd.UNA and resends unacknowledged data from the oldest
	// sequence number.
	RetransmitAll bool
	// HoldNew pauses transmission of new (not yet sent) data, for example when a
	// congestion controller's window is exhausted. Retransmissions directed by
	// this same directive, pending control segments and ACKs still proceed; only
	// fresh data from the send buffer is withheld until a later PreTx clears it.
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
