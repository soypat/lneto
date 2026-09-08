package tcp

// Policy abstracts the algorithms that observe a connection's segment traffic
// and steer what it transmits: the retransmission timer, congestion control, and
// the TCP extensions that negotiate an option and act on it. As far as the tcp
// package is concerned these are all the same thing — they watch segments go by
// and influence the next one — so they share one interface (see discussion #157).
//
// The name is deliberately broader than the loss recovery this began as. An
// implementation that samples round-trip times from the timestamp option, or that
// advertises selective acknowledgements, is not recovering from loss at all, yet
// it needs exactly the same hooks at exactly the same points. Naming the seam
// after one of its clients invited the assumption that the others did not belong.
//
// The core deliberately owns none of these. What stays in this package is the
// RFC 9293 state machine, the sequence space and the buffers; what a policy adds
// is timing, windows and options, none of which the state machine needs in order
// to be correct. A connection with no policy at all still completes a handshake,
// carries data and closes; it simply never retransmits.
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
// the policy (Endpoint[P Policy]) with a zero-sized no-op default, on the
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
// BenchmarkHandlerDatapathPolicy. Revisit the decision with those numbers
// rather than by assertion.
type Policy interface {
	// Reset returns the implementation to its initial, pre-connection state. It
	// is invoked whenever the connection is (re)opened or aborted so a single
	// Policy value can be reused across the lifetime of connection reuse
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
	//
	// Because it runs first, nothing is yet known about whether the segment is
	// acceptable. State that depends on the segment counting, such as
	// acknowledgement accounting or a recorded timestamp, belongs in [PostRx]
	// instead; PreRx is for deciding the segment's fate, not for recording it.
	PreRx(rx RxMeta) RxDirective

	// PostRx is called once the connection has finished with a received segment,
	// reporting what it did with it. It is the counterpart to PreRx and the place
	// for state that must only change for a segment that counted: an acknowledgement
	// that really advanced the send sequence, a timestamp from a segment that was
	// acceptable, a duplicate acknowledgement that really was one.
	//
	// It is called for rejected segments too, with Accepted false, so a policy can
	// observe a segment being refused without having to infer it.
	PostRx(event RxEvent)

	// PreTx is called on entering the transmit path (Encapsulate), before a
	// segment is built, with a snapshot of the send state. Its directive tells
	// the connection whether to retransmit unacknowledged data, rewind the send
	// pointer, or hold back new data.
	//
	// It runs before the segment is planned because its directives change what
	// gets planned; consequently the outgoing segment's flags and payload are
	// not yet known here. Observe those in [Policy.PostTx].
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
	//
	// The segment may never be sent. WriteOptions runs before the segment is
	// sized, and the transmit path can still find there is nothing to send or fail
	// to build what it planned, in which case no [Policy.PostTx] follows for it. An
	// implementation must therefore not treat having written an option as the
	// option having been exchanged: commit anything that changes how later segments
	// are interpreted in PostTx, which reports what actually went out. Getting this
	// wrong is not cosmetic — a policy that considers an extension negotiated
	// because it wrote the option, on a segment the peer never received, will
	// enforce that extension against a peer that never agreed to it.
	WriteOptions(plan TxPlan, opts []byte) uint8

	// PostTx is called on leaving the transmit path with the segment that was
	// actually emitted and the monotonic time it was sent. This is where segment
	// timing (for RTT sampling and the retransmission timer) is recorded.
	PostTx(outgoing Segment, now int64)
}

// TxIntent is the snapshot of send state handed to [Policy.PreTx] before
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

// RxMeta describes a received segment handed to [Policy.PreRx]. It is
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

// TxPlan describes the segment about to be built when [Policy.WriteOptions]
// is called. It is passed by value and must not be retained.
type TxPlan struct {
	// Now is the current monotonic time in nanoseconds, the same instant
	// reported to [Policy.PreTx] for this transmit.
	Now int64
	// State is the connection state.
	State State
	// Kind classifies the segment, which determines the applicable options.
	Kind TxKind
	// Reassembly reports the out-of-order blocks the receive path is holding, for
	// a policy that advertises them as selective acknowledgements (RFC 2018). It
	// is read here, while the outgoing segment's options are being written, rather
	// than on receive, because that is when the blocks are put on the wire.
	//
	// It borrows connection state for the duration of the call and must not be
	// retained. See [ReassemblyView].
	Reassembly ReassemblyView
}

// TxDirective is returned by [Policy.PreTx] to steer the transmit path.
// The zero value directs the connection to proceed normally (send new data if
// available, no retransmission).
type TxDirective struct {
	// Retransmit requests retransmission of unacknowledged data, resuming at
	// RetransmitFrom. The connection rewinds snd.NXT and its transmit queue to
	// that sequence number, so everything already sent from there onward is sent
	// again; there is no way to skip a range that the peer has selectively
	// acknowledged. Setting RetransmitFrom to [TxIntent.UNA] therefore requests
	// plain go-back-N.
	Retransmit bool
	// RetransmitFrom is the sequence number at which retransmission resumes. It
	// is ignored unless Retransmit is set, and is clamped into
	// [[TxIntent.UNA], [TxIntent.NXT]] so a stale or bogus value cannot corrupt
	// the connection.
	//
	// The transmit queue tracks whole segments, so a sequence inside a queued
	// segment resumes from that segment's first octet: retransmission may start
	// before the requested sequence but never after it.
	RetransmitFrom Value
	// HoldNew pauses transmission of new (not yet sent) data, for example when a
	// congestion controller's window is exhausted. Retransmissions directed by
	// this same directive, pending control segments and ACKs still proceed; only
	// fresh data from the send buffer is withheld until a later PreTx clears it.
	HoldNew bool
}

// RxEvent reports what a connection did with a received segment. It is passed by
// value to [Policy.PostRx] and must not be retained.
//
// It exists so that a policy does not have to reconstruct the state machine's
// decisions from the raw segment. Reconstructing them means duplicating the
// acceptance rules, and getting them subtly wrong means accounting for data the
// connection never accepted.
type RxEvent struct {
	// Now is the current monotonic time in nanoseconds, the same instant reported
	// to [Policy.PreRx] for this segment.
	Now int64
	// Segment is the segment as received.
	Segment Segment
	// Options is the option area of the received segment, borrowed for the duration
	// of the call exactly as [RxMeta.Options] is. A policy that records an option's
	// value only for a segment that counted reads it here rather than in PreRx.
	Options []byte
	// RcvNXT is the receive sequence the connection expects next, after this
	// segment. Some option rules are stated against it, such as the RFC 7323 §4.3
	// condition for advancing the recorded timestamp.
	RcvNXT Value
	// Accepted reports whether the connection took the segment. A false value means
	// it was refused or dropped, and nothing about it should be accounted for.
	Accepted bool
	// BytesAcked is how much previously unacknowledged data this segment
	// acknowledged, zero when it advanced nothing.
	BytesAcked Size
	// DupACK reports an acknowledgement that did not advance the send sequence,
	// which is the signal fast retransmit counts.
	DupACK bool
	// DataDelivered is the count of payload octets the receive path took, which is
	// zero for a pure acknowledgement and for data that was buffered out of order.
	DataDelivered Size
	// StateBefore and StateAfter bracket the connection state across the segment,
	// so a policy sees a transition without watching for it.
	StateBefore State
	StateAfter  State
}

// RxDirective is returned by [Policy.PreRx].
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
