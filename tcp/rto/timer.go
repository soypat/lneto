package rto

import (
	"time"

	"github.com/soypat/lneto/tcp"
)

// RFC 6298 retransmission-timeout (RTO) parameters. The algorithm keeps a
// single retransmission timer per connection (RFC 6298 §5): the timer is
// (re)started whenever new data is acknowledged while data remains in flight,
// stopped when all data is acknowledged, and on expiry the oldest unacknowledged
// segment is retransmitted and the RTO is doubled (exponential backoff, §5.5).
const (
	// rtoInitial is the RTO used before the first RTT measurement (RFC 6298 §2.1).
	rtoInitial = time.Second
	// rtoMin clamps the lower bound of the RTO. RFC 6298 §2.4 recommends a
	// minimum of 1s, but that is punishing on the low-latency links lneto
	// targets; like Linux we use a smaller floor so recovery on LAN/embedded
	// links is timely.
	rtoMin = 200 * time.Millisecond
	// rtoMax clamps the upper bound across exponential backoff (RFC 6298 §5.5
	// permits a maximum of at least 60s).
	rtoMax = 60 * time.Second

	// rttGainShift (alpha = 1/8) and rttvarGainShift (beta = 1/4) are the
	// smoothing gains of RFC 6298 §2.3, applied as integer shifts.
	rttGainShift    = 3 // alpha = 1/8
	rttvarGainShift = 2 // beta  = 1/4
	// rttvarK is the RTTVAR multiplier in RTO = SRTT + K*RTTVAR (RFC 6298 §2.3).
	rttvarK = 4
	// backoffMax caps the exponential-backoff doublings so RTO arithmetic cannot
	// overflow and a wedged connection keeps probing at rtoMax.
	backoffMax = 12
)

// Timer implements the RFC 6298 round-trip-time estimator and the single
// retransmission timer as a [tcp.Policy]. Construct it with new(Timer) and hand
// it to [tcp.ConnConfig.Policy]; the connection calls [Timer.Reset] on open, so
// the zero value is ready to use.
//
// Timer is a pure, reactive state machine: it observes the segments a connection
// sends and receives (via the tcp.Policy hooks) and the monotonic time handed
// in at each hook, and from those alone derives RTT estimates and retransmission
// decisions. It holds no clock and allocates nothing, which keeps it
// deterministic for unit testing (see issue #140).
//
// Timer tracks its own shadow of the send sequence space purely from the segments
// it observes: [Timer.PostTx] advances the highest sequence sent and [Timer.PreRx]
// advances the highest sequence acknowledged. This is what lets it manage the
// timer (RFC 6298 §5.2/§5.3) without reaching into the tcp state machine, and it
// is also how retransmissions are distinguished for Karn's algorithm — a segment
// whose sequence space is not beyond the shadow snd.NXT is a retransmission and
// is never RTT-sampled.
type Timer struct {
	srtt    time.Duration // smoothed round-trip time (SRTT).
	rttvar  time.Duration // round-trip-time variation (RTTVAR).
	rto     time.Duration // current retransmission timeout.
	haveRTT bool          // false until the first RTT sample is taken.

	// Shadow of the send sequence space, derived from observed segments.
	haveSeq bool      // false until the first data segment is observed.
	sndUNA  tcp.Value // highest acknowledged sequence number seen on the wire.
	sndNXT  tcp.Value // one past the highest sequence number sent.

	// RTT sampling state (Karn's algorithm, RFC 6298 §3): at most one segment is
	// timed at a time and retransmitted segments are never sampled.
	timing   bool
	timedSeq tcp.Value // ACK at or beyond this value completes the sample.
	timedAt  int64     // send time (monotonic ns) of the timed segment.

	// Retransmission timer state.
	running  bool
	deadline int64 // time (monotonic ns) at which the timer expires.
	backoff  uint8 // consecutive timeouts, for exponential backoff.

	// expirations counts timeouts since Reset. It exists so a policy sharing this
	// timer can notice a timeout it did not itself drive: a congestion controller
	// must collapse its window on one, and when the timer is a peer in a
	// [tcp.Composite] the controller never sees the timer's directive.
	expirations uint32
}

var _ tcp.Policy = (*Timer)(nil)

// Reset returns the estimator to its pre-connection state with the initial RTO.
// It implements [tcp.Policy] and is called when the connection opens or aborts
// so the estimator can be reused across connection reuse.
func (r *Timer) Reset() { *r = Timer{rto: rtoInitial} }

// SmoothedRTT returns the current smoothed round-trip time (SRTT), or zero
// before the first RTT measurement. It is concrete-type introspection and is
// intentionally not part of [tcp.Policy].
func (r *Timer) SmoothedRTT() time.Duration { return r.srtt }

// CurrentRTO returns the timeout currently in effect, clamped to [rtoMin, rtoMax].
func (r *Timer) CurrentRTO() time.Duration {
	rto := r.rto
	if rto < rtoMin {
		rto = rtoMin
	} else if rto > rtoMax {
		rto = rtoMax
	}
	return rto
}

// Running reports whether the retransmission timer is currently armed.
func (r *Timer) Running() bool { return r.running }

// Expirations returns how many times the retransmission timer has expired since
// [Timer.Reset]. A policy that shares this timer rather than driving it watches
// this for a change to learn that a timeout happened, since it never sees the
// timer's own directive. It is concrete-type introspection and is intentionally
// not part of [tcp.Policy].
func (r *Timer) Expirations() uint32 { return r.expirations }

// NextDeadline returns the monotonic-nanosecond instant at which the timer
// expires, or 0 when it is not armed. It implements [tcp.Policy].
func (r *Timer) NextDeadline() int64 {
	if !r.running {
		return 0
	}
	return r.deadline
}

// PreRx keeps every segment: the estimator never drops traffic and records
// nothing before the connection has decided whether the segment counts. It
// implements [tcp.Policy].
func (r *Timer) PreRx(rx tcp.RxMeta) tcp.RxDirective {
	return tcp.RxDirective{Keep: true}
}

// PostRx samples the RTT and manages the retransmission timer from a segment the
// connection accepted (RFC 6298 §5.2/§5.3). It implements [tcp.Policy].
//
// A refused segment is ignored. Acting on one would let an acknowledgement the
// state machine rejected, for data never sent, collapse the backoff and take a
// bogus RTT sample.
func (r *Timer) PostRx(event tcp.RxEvent) {
	incoming, now := event.Segment, event.Now
	if !event.Accepted || !r.haveSeq || !incoming.Flags.HasAny(tcp.FlagACK) {
		return
	}
	ack := incoming.ACK
	if r.timing && !ack.LessThan(r.timedSeq) {
		// ACK covers the timed segment: take the RTT sample (§4). A valid
		// measurement collapses the backoff (§5.7).
		r.updateRTT(time.Duration(now - r.timedAt))
		r.timing = false
		r.backoff = 0
	}
	if r.sndUNA.LessThan(ack) && !r.sndNXT.LessThan(ack) {
		// ACK advances snd.UNA and does not exceed what we have sent.
		r.sndUNA = ack
	}
	if r.sndUNA == r.sndNXT {
		r.running = false // §5.3: all outstanding data acknowledged.
	} else {
		// §5.3: new (but not all) data acknowledged — restart the timer.
		r.running = true
		r.deadline = now + int64(r.CurrentRTO())
	}
}

// WriteOptions adds no TCP options: retransmission timing needs none of its
// own. It implements [tcp.Policy].
func (r *Timer) WriteOptions(plan tcp.TxPlan, opts []byte) uint8 { return 0 }

// PreTx reports whether the retransmission timer has expired and, if so, applies
// the RFC 6298 §5.4–§5.6 timeout response — discard the outstanding RTT sample
// (Karn), back the RTO off exponentially and restart the timer — returning a
// directive that asks the connection to retransmit from snd.UNA (go-back-N). It
// implements [tcp.Policy].
func (r *Timer) PreTx(intent tcp.TxIntent) tcp.TxDirective {
	now := intent.Now
	if !r.running || now < r.deadline || r.sndUNA == r.sndNXT {
		return tcp.TxDirective{}
	}
	r.expirations++
	r.timing = false // §5.4: do not sample a retransmitted segment.
	if r.backoff < backoffMax {
		r.backoff++
		r.rto = min(r.CurrentRTO()*2, rtoMax) // §5.5: RTO = RTO * 2.
	}
	r.running = true
	r.deadline = now + int64(r.CurrentRTO())
	return tcp.TxDirective{Retransmit: true, RetransmitFrom: intent.UNA}
}

// PostTx records an emitted segment: it advances the shadow send sequence,
// begins timing newly transmitted data (RFC 6298 §3) and arms the timer (§5.1).
// Segments that do not extend the send sequence are retransmissions and are
// never RTT-sampled (Karn's algorithm). Control-only segments (no data) are
// ignored. It implements [tcp.Policy].
func (r *Timer) PostTx(outgoing tcp.Segment, now int64) {
	if outgoing.DATALEN == 0 {
		return // only data segments are timed / arm the RTO.
	}
	segStart := outgoing.SEQ
	segEnd := segStart + tcp.Value(outgoing.LEN())
	if !r.haveSeq {
		r.haveSeq = true
		r.sndUNA = segStart
		r.sndNXT = segStart
	}
	if !r.sndNXT.LessThan(segEnd) {
		// tcp.Segment does not extend the send sequence: it is a retransmission.
		// Discard any outstanding RTT sample per Karn's algorithm. The timer was
		// already (re)armed by PreTx on the timeout that triggered this resend.
		r.timing = false
		return
	}
	r.sndNXT = segEnd
	if !r.timing {
		r.timing = true
		r.timedSeq = segEnd
		r.timedAt = now
	}
	if !r.running {
		r.running = true
		r.deadline = now + int64(r.CurrentRTO())
	}
}

// ObserveRTT folds a round-trip measurement taken by other means into the
// estimator, for a policy that composes this timer and can measure the round trip
// more accurately than acknowledgement timing allows. The RFC 7323 timestamp echo
// is the case this exists for.
//
// Unlike the timer's own sampling this does not apply Karn's algorithm, because a
// sample derived from an echoed timestamp is unambiguous even when the segment
// carrying it was a retransmission (RFC 7323 §4.1). Non-positive samples are
// ignored.
func (r *Timer) ObserveRTT(rtt time.Duration) { r.updateRTT(rtt) }

// updateRTT folds a round-trip measurement into SRTT/RTTVAR/RTO using the
// integer-shift form of RFC 6298 §2.2/§2.3.
func (r *Timer) updateRTT(sample time.Duration) {
	if sample <= 0 {
		return
	}
	if !r.haveRTT {
		// First measurement (RFC 6298 §2.2).
		r.srtt = sample
		r.rttvar = sample / 2
		r.haveRTT = true
	} else {
		// Subsequent measurements (RFC 6298 §2.3):
		//   RTTVAR = (1-beta)*RTTVAR + beta*|SRTT-R|
		//   SRTT   = (1-alpha)*SRTT  + alpha*R
		diff := r.srtt - sample
		if diff < 0 {
			diff = -diff
		}
		r.rttvar += (diff - r.rttvar) >> rttvarGainShift
		r.srtt += (sample - r.srtt) >> rttGainShift
	}
	r.rto = r.srtt + rttvarK*r.rttvar
}
