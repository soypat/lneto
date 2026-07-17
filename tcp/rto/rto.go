// Package rto implements the RFC 6298 round-trip-time estimator and single
// retransmission timer as a [tcp.LossRecovery] implementation.
//
// Control is a pure, reactive state machine: it observes the segments a
// connection sends and receives (via the LossRecovery hooks) and the monotonic
// time handed in at each hook, and from those alone derives RTT estimates and
// retransmission decisions. It holds no clock and allocates nothing, which
// keeps it deterministic for unit testing (issue #140) and keeps all timing out
// of the tcp state machine — package tcp depends only on the [tcp.LossRecovery]
// interface, never on this package.
package rto

import (
	"time"

	"github.com/soypat/lneto/tcp"
)

// RFC 6298 retransmission-timeout (RTO) parameters. The algorithm keeps a
// single retransmission timer per connection (RFC 6298 §5): the timer is
// (re)started whenever new data is acknowledged while data remains in flight,
// stopped when all data is acknowledged, and on expiry the oldest
// unacknowledged segment is retransmitted and the RTO is doubled (exponential
// backoff, §5.5).
const (
	// Initial is the RTO used before the first RTT measurement (RFC 6298 §2.1).
	Initial = time.Second
	// Min clamps the lower bound of the RTO. RFC 6298 §2.4 recommends a minimum
	// of 1s, but that is punishing on the low-latency links lneto targets; like
	// Linux we use a smaller floor so recovery on LAN/embedded links is timely.
	Min = 200 * time.Millisecond
	// Max clamps the upper bound across exponential backoff (RFC 6298 §5.5
	// permits a maximum of at least 60s).
	Max = 60 * time.Second

	// rttGainShift (alpha = 1/8) and rttvarGainShift (beta = 1/4) are the
	// smoothing gains of RFC 6298 §2.3, applied as integer shifts.
	rttGainShift    = 3 // alpha = 1/8
	rttvarGainShift = 2 // beta  = 1/4
	// rttvarK is the RTTVAR multiplier in RTO = SRTT + K*RTTVAR (RFC 6298 §2.3).
	rttvarK = 4
	// backoffMax caps the exponential-backoff doublings so RTO arithmetic cannot
	// overflow and a wedged connection keeps probing at Max.
	backoffMax = 12
)

// seqLessThan reports whether sequence number a precedes b using
// wraparound-safe (modulo 2^32) comparison, mirroring tcp.Value.LessThan
// without depending on that method.
func seqLessThan(a, b uint32) bool { return int32(a-b) < 0 }

// Control implements the RFC 6298 round-trip-time estimator and the single
// retransmission timer as a [tcp.LossRecovery]. The zero value is ready to use
// after [Control.Reset] (which [tcp.Conn] calls when the connection opens); it
// holds no references and allocates nothing.
//
// Control tracks its own shadow of the send sequence space purely from the
// segments it observes: [Control.PostTx] advances the highest sequence sent and
// [Control.PreRx] advances the highest sequence acknowledged. This is what lets
// it manage the timer (RFC 6298 §5.2/§5.3) without reaching into the tcp state
// machine, and it is also how retransmissions are distinguished for Karn's
// algorithm — a segment whose sequence space is not beyond the shadow snd.NXT is
// a retransmission and is never RTT-sampled.
type Control struct {
	srtt    time.Duration // smoothed round-trip time (SRTT).
	rttvar  time.Duration // round-trip-time variation (RTTVAR).
	rto     time.Duration // current retransmission timeout.
	haveRTT bool          // false until the first RTT sample is taken.

	// Shadow of the send sequence space, derived from observed segments.
	haveSeq bool   // false until the first data segment is observed.
	sndUNA  uint32 // highest acknowledged sequence number seen on the wire.
	sndNXT  uint32 // one past the highest sequence number sent.

	// RTT sampling state (Karn's algorithm, RFC 6298 §3 / RFC 2988): at most one
	// segment is timed at a time and retransmitted segments are never sampled.
	timing   bool
	timedSeq uint32 // ACK at or beyond this value completes the sample.
	timedAt  int64  // send time (monotonic ns) of the timed segment.

	// Retransmission timer state.
	running  bool
	deadline int64 // time (monotonic ns) at which the timer expires.
	backoff  uint8 // consecutive timeouts, for exponential backoff.
}

var _ tcp.LossRecovery = (*Control)(nil)

// Reset returns the estimator to its pre-connection state with the initial RTO.
// It implements [tcp.LossRecovery] and is called when the connection opens or
// aborts so the estimator can be reused across connection reuse.
func (r *Control) Reset() { *r = Control{rto: Initial} }

// SmoothedRTT returns the current smoothed round-trip time (SRTT), or zero
// before the first RTT measurement. It is concrete-type introspection and is
// intentionally not part of [tcp.LossRecovery].
func (r *Control) SmoothedRTT() time.Duration { return r.srtt }

// CurrentRTO returns the timeout currently in effect, clamped to [Min, Max].
func (r *Control) CurrentRTO() time.Duration {
	rto := r.rto
	if rto < Min {
		rto = Min
	} else if rto > Max {
		rto = Max
	}
	return rto
}

// Running reports whether the retransmission timer is currently armed.
func (r *Control) Running() bool { return r.running }

// NextDeadline returns the monotonic-nanosecond instant at which the timer
// expires, or 0 when it is not armed. It implements [tcp.LossRecovery].
func (r *Control) NextDeadline() int64 {
	if !r.running {
		return 0
	}
	return r.deadline
}

// PreRx samples the RTT and manages the retransmission timer from a received
// segment (RFC 6298 §5.2/§5.3). It implements [tcp.LossRecovery] and always
// keeps the segment (the estimator never drops traffic).
func (r *Control) PreRx(incoming tcp.Segment, now int64) tcp.RxDirective {
	if !r.haveSeq || !incoming.Flags.HasAny(tcp.FlagACK) {
		return tcp.RxDirective{Keep: true}
	}
	ack := uint32(incoming.ACK)
	if r.timing && !seqLessThan(ack, r.timedSeq) {
		// ACK covers the timed segment: take the RTT sample (§4). A valid
		// measurement collapses the backoff (§5.7).
		r.UpdateRTT(time.Duration(now - r.timedAt))
		r.timing = false
		r.backoff = 0
	}
	if seqLessThan(r.sndUNA, ack) && !seqLessThan(r.sndNXT, ack) {
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
	return tcp.RxDirective{Keep: true}
}

// PreTx reports whether the retransmission timer has expired and, if so, applies
// the RFC 6298 §5.4–§5.6 timeout response — discard the outstanding RTT sample
// (Karn), back the RTO off exponentially and restart the timer — returning a
// directive that asks the connection to retransmit from snd.UNA (go-back-N). It
// implements [tcp.LossRecovery].
func (r *Control) PreTx(now int64) tcp.TxDirective {
	if !r.running || now < r.deadline || r.sndUNA == r.sndNXT {
		return tcp.TxDirective{}
	}
	r.timing = false // §5.4: do not sample a retransmitted segment.
	if r.backoff < backoffMax {
		r.backoff++
		r.rto = min(r.CurrentRTO()*2, Max) // §5.5: RTO = RTO * 2.
	}
	r.running = true
	r.deadline = now + int64(r.CurrentRTO())
	return tcp.TxDirective{Retransmit: true}
}

// PostTx records an emitted segment: it advances the shadow send sequence,
// begins timing newly transmitted data (RFC 6298 §3) and arms the timer (§5.1).
// Segments that do not extend the send sequence are retransmissions and are
// never RTT-sampled (Karn's algorithm). Control-only segments (no data) are
// ignored. It implements [tcp.LossRecovery].
func (r *Control) PostTx(outgoing tcp.Segment, now int64) {
	if outgoing.DATALEN == 0 {
		return // only data segments are timed / arm the RTO.
	}
	segStart := uint32(outgoing.SEQ)
	segEnd := segStart + uint32(outgoing.LEN())
	if !r.haveSeq {
		r.haveSeq = true
		r.sndUNA = segStart
		r.sndNXT = segStart
	}
	if !seqLessThan(r.sndNXT, segEnd) {
		// Segment does not extend the send sequence: it is a retransmission.
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

// UpdateRTT folds a round-trip measurement into SRTT/RTTVAR/RTO using the
// integer-shift form of RFC 6298 §2.2/§2.3. It is exposed for callers that
// obtain RTT samples out of band (e.g. RFC 7323 timestamps).
func (r *Control) UpdateRTT(sample time.Duration) {
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
