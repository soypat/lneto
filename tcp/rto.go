package tcp

import "time"

// Retransmission-timeout (RTO) parameters following RFC 6298. The algorithm
// keeps a single retransmission timer per connection (RFC 6298 §5): the timer
// is (re)started whenever new data is acknowledged while data remains in
// flight, stopped when all data is acknowledged, and on expiry the oldest
// unacknowledged segment is retransmitted and the RTO is doubled (exponential
// backoff, §5.5).
const (
	// rtoInitial is the RTO used before the first RTT measurement (RFC 6298 §2.1).
	rtoInitial = time.Second
	// rtoMin clamps the lower bound of the RTO. RFC 6298 §2.4 recommends a
	// minimum of 1s, but that is punishing on the low-latency links lneto targets;
	// like Linux we use a smaller floor so recovery on LAN/embedded links is timely.
	rtoMin = 200 * time.Millisecond
	// rtoMax clamps the upper bound across exponential backoff (RFC 6298 §5.5
	// permits a maximum of at least 60s).
	rtoMax = 60 * time.Second
	// rttGain (alpha = 1/8) and rttvarGain (beta = 1/4) are the smoothing gains
	// of RFC 6298 §2.3, applied as integer shifts.
	rttGainShift    = 3 // alpha = 1/8
	rttvarGainShift = 2 // beta  = 1/4
	// rttvarK is the RTTVAR multiplier in RTO = SRTT + K*RTTVAR (RFC 6298 §2.3).
	rttvarK = 4
	// rtoBackoffMax caps the exponential-backoff doublings so RTO arithmetic
	// cannot overflow and a wedged connection keeps probing at rtoMax.
	rtoBackoffMax = 12
)

// rtoControl implements the RFC 6298 round-trip-time estimator and the single
// retransmission timer. It holds no references and allocates nothing; all
// methods take the current time explicitly so the logic is deterministic and
// unit-testable.
type rtoControl struct {
	srtt    time.Duration // smoothed round-trip time (SRTT).
	rttvar  time.Duration // round-trip-time variation (RTTVAR).
	rto     time.Duration // current retransmission timeout.
	haveRTT bool          // false until the first RTT sample is taken.

	// RTT sampling state (Karn's algorithm, RFC 6298 §3 / RFC 2988): at most one
	// segment is timed at a time and retransmitted segments are never sampled.
	timing   bool
	timedSeq Value     // ACK at or beyond this value completes the sample.
	timedAt  time.Time // send time of the timed segment.

	// Retransmission timer state.
	running  bool
	deadline time.Time // time at which the timer expires.
	backoff  uint8     // consecutive timeouts, for exponential backoff.
}

// init resets the estimator to its pre-connection state with the initial RTO.
func (r *rtoControl) init() {
	*r = rtoControl{rto: rtoInitial}
}

// currentRTO returns the timeout currently in effect (never below rtoMin).
func (r *rtoControl) currentRTO() time.Duration {
	rto := r.rto
	if rto < rtoMin {
		rto = rtoMin
	} else if rto > rtoMax {
		rto = rtoMax
	}
	return rto
}

// startSample begins timing the segment ending at endSeq if no sample is
// outstanding (single-sample estimator, RFC 6298 §3). Retransmitted segments
// must not be timed; callers pass only newly transmitted sequence space.
func (r *rtoControl) startSample(endSeq Value, now time.Time) {
	if r.timing {
		return
	}
	r.timing = true
	r.timedSeq = endSeq
	r.timedAt = now
}

// armTimer starts the retransmission timer if it is not already running
// (RFC 6298 §5.1: when a segment is sent and the timer is not running, start it).
func (r *rtoControl) armTimer(now time.Time) {
	if r.running {
		return
	}
	r.running = true
	r.deadline = now.Add(r.currentRTO())
}

// onAckSample updates the estimator from an acknowledgment. ack is the highest
// acknowledged sequence number, allAcked reports whether ack covers all
// in-flight data, and now is the time the ACK was processed. It takes an RTT
// sample when ack advances past the timed segment, then manages the timer per
// RFC 6298 §5.2/§5.3 (restart while data remains, stop when fully acknowledged).
func (r *rtoControl) onAckSample(ack Value, allAcked bool, now time.Time) {
	if r.timing && !ack.LessThan(r.timedSeq) {
		r.updateRTT(now.Sub(r.timedAt))
		r.timing = false
		r.backoff = 0 // a valid measurement collapses backoff (RFC 6298 §5.7).
	}
	if allAcked {
		r.running = false // §5.3: all outstanding data acknowledged, turn timer off.
		return
	}
	// §5.3: new (but not all) data acknowledged — restart the timer.
	r.running = true
	r.deadline = now.Add(r.currentRTO())
}

// updateRTT folds a round-trip measurement into SRTT/RTTVAR/RTO using the
// integer-shift form of RFC 6298 §2.2/§2.3.
func (r *rtoControl) updateRTT(sample time.Duration) {
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

// expired reports whether the retransmission timer has fired by time now.
func (r *rtoControl) expired(now time.Time) bool {
	return r.running && !now.Before(r.deadline)
}

// onTimeout applies the RFC 6298 §5.4–§5.6 timeout response: discard the
// outstanding RTT sample (Karn), back the RTO off exponentially and restart the
// timer. The caller is responsible for rewinding the send state to snd.UNA.
func (r *rtoControl) onTimeout(now time.Time) {
	r.timing = false // §5.4: do not sample a retransmitted segment.
	if r.backoff < rtoBackoffMax {
		r.backoff++
		r.rto = min(
			// §5.5: RTO = RTO * 2.
			r.currentRTO()*2, rtoMax)
	}
	r.running = true
	r.deadline = now.Add(r.currentRTO())
}

// onRetransmit notifies the estimator that the timed segment was retransmitted
// for a reason other than a timer expiry (e.g. fast retransmit), so its RTT
// sample must be discarded per Karn's algorithm.
func (r *rtoControl) onRetransmit() {
	r.timing = false
}
