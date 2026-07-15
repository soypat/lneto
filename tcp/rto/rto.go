// Package rto implements the RFC 6298 round-trip-time estimator and single
// retransmission timer used by package tcp.
//
// It is intentionally a leaf package with no dependency on package tcp: time is
// injected as monotonic nanoseconds (the func() int64 convention used
// throughout lneto) and sequence numbers are plain uint32 compared with
// wraparound-safe arithmetic. This keeps timing out of the TCP state machine
// and lets both tcp and tcp/congestion consume the estimator without an import
// cycle, while remaining deterministic and allocation-free for unit testing.
package rto

import "time"

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
// without depending on package tcp.
func seqLessThan(a, b uint32) bool { return int32(a-b) < 0 }

// Control implements the RFC 6298 round-trip-time estimator and the single
// retransmission timer. The zero value is not ready for use; call [Control.Init]
// first. It holds no references and allocates nothing.
//
// Control owns the time source: it reads the current monotonic time from an
// injected clock (see [Control.SetClock]) rather than being handed a timestamp
// on every call. This keeps timing wholly inside this leaf package, so the tcp
// package carries no clock and no time dependency of its own. Time integration
// is opt-in: with no clock injected every timing method is inert (no RTT is
// sampled, the timer never arms and [Control.Expired] is always false), so a
// connection behaves exactly as it did before RTO support existed.
type Control struct {
	srtt    time.Duration // smoothed round-trip time (SRTT).
	rttvar  time.Duration // round-trip-time variation (RTTVAR).
	rto     time.Duration // current retransmission timeout.
	haveRTT bool          // false until the first RTT sample is taken.

	// clock is the injected monotonic time source in nanoseconds (the
	// func() int64 convention used across lneto). nil disables all timing.
	clock func() int64

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

// Init resets the estimator to its pre-connection state with the initial RTO,
// preserving the injected clock so a connection can be reused across reopens.
func (r *Control) Init() { *r = Control{rto: Initial, clock: r.clock} }

// SetClock injects the monotonic time source (nanoseconds) that drives RTT
// estimation and the retransmission timer. Passing nil disables all timing
// (time integration is opt-in). It should be set before the connection opens.
func (r *Control) SetClock(clock func() int64) { r.clock = clock }

// Clock returns the injected time source, or nil when timing is disabled.
func (r *Control) Clock() func() int64 { return r.clock }

// active reports whether a clock has been injected (timing enabled).
func (r *Control) active() bool { return r.clock != nil }

// Running reports whether the retransmission timer is currently armed.
func (r *Control) Running() bool { return r.running }

// Deadline returns the monotonic-nanosecond instant at which the timer expires.
// It is only meaningful while [Control.Running] reports true.
func (r *Control) Deadline() int64 { return r.deadline }

// SmoothedRTT returns the current smoothed round-trip time (SRTT), or zero
// before the first RTT measurement.
func (r *Control) SmoothedRTT() time.Duration { return r.srtt }

// Stop turns the retransmission timer off without touching the RTT estimate.
func (r *Control) Stop() { r.running = false }

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

// StartSample begins timing the segment ending at endSeq if no sample is
// outstanding (single-sample estimator, RFC 6298 §3). Retransmitted segments
// must not be timed; callers pass only newly transmitted sequence space. It is
// inert until a clock is injected (see [Control.SetClock]).
func (r *Control) StartSample(endSeq uint32) {
	if !r.active() || r.timing {
		return
	}
	r.timing = true
	r.timedSeq = endSeq
	r.timedAt = r.clock()
}

// ArmTimer starts the retransmission timer if it is not already running
// (RFC 6298 §5.1: when a segment is sent and the timer is not running, start it).
// It is inert until a clock is injected (see [Control.SetClock]).
func (r *Control) ArmTimer() {
	if !r.active() || r.running {
		return
	}
	r.running = true
	r.deadline = r.clock() + int64(r.CurrentRTO())
}

// OnAckSample updates the estimator from an acknowledgment. ack is the highest
// acknowledged sequence number and allAcked reports whether ack covers all
// in-flight data. It takes an RTT sample when ack advances past the timed
// segment, then manages the timer per RFC 6298 §5.2/§5.3 (restart while data
// remains, stop when fully acknowledged). It is inert until a clock is injected.
func (r *Control) OnAckSample(ack uint32, allAcked bool) {
	if !r.active() {
		return
	}
	now := r.clock()
	if r.timing && !seqLessThan(ack, r.timedSeq) {
		r.UpdateRTT(time.Duration(now - r.timedAt))
		r.timing = false
		r.backoff = 0 // a valid measurement collapses backoff (RFC 6298 §5.7).
	}
	if allAcked {
		r.running = false // §5.3: all outstanding data acknowledged, turn timer off.
		return
	}
	// §5.3: new (but not all) data acknowledged — restart the timer.
	r.running = true
	r.deadline = now + int64(r.CurrentRTO())
}

// UpdateRTT folds a round-trip measurement into SRTT/RTTVAR/RTO using the
// integer-shift form of RFC 6298 §2.2/§2.3.
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

// Expired reports whether the retransmission timer has fired by the current
// time. It is always false until a clock is injected (see [Control.SetClock]).
func (r *Control) Expired() bool {
	return r.active() && r.running && r.clock() >= r.deadline
}

// OnTimeout applies the RFC 6298 §5.4–§5.6 timeout response: discard the
// outstanding RTT sample (Karn), back the RTO off exponentially and restart the
// timer. The caller is responsible for rewinding the send state to snd.UNA. It
// is inert until a clock is injected (see [Control.SetClock]).
func (r *Control) OnTimeout() {
	if !r.active() {
		return
	}
	r.timing = false // §5.4: do not sample a retransmitted segment.
	if r.backoff < backoffMax {
		r.backoff++
		// §5.5: RTO = RTO * 2.
		r.rto = min(r.CurrentRTO()*2, Max)
	}
	r.running = true
	r.deadline = r.clock() + int64(r.CurrentRTO())
}

// OnRetransmit notifies the estimator that the timed segment was retransmitted
// for a reason other than a timer expiry (e.g. fast retransmit), so its RTT
// sample must be discarded per Karn's algorithm.
func (r *Control) OnRetransmit() { r.timing = false }
