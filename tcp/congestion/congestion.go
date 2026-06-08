// Package congestion provides pluggable TCP congestion-control algorithms for
// the lneto/tcp package. It ships two controllers, [CUBIC] ([RFC9438]) and
// [BBR] (BBRv3, [draft-ietf-ccwg-bbr]), both of which satisfy
// tcp.CongestionControl and can be installed on a connection via
// tcp.Handler.SetCongestionControl or tcp.ConnConfig.CongestionControl.
//
// The algorithms are decoupled from the TCP state machine: the Handler feeds
// each controller a tcp.CongestionEvent describing a segment and the relevant
// sender state, and the controller reports a congestion window in bytes. The
// numeric cores (window growth for CUBIC, bandwidth/round-trip estimation for
// BBR) are kept separate from any I/O so they can be exercised by unit tests.
//
// [RFC9438]: https://www.rfc-editor.org/rfc/rfc9438
// [draft-ietf-ccwg-bbr]: https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/
package congestion

import (
	"time"

	"github.com/soypat/lneto/tcp"
)

// defaultMSS is the segment size assumed by a congestion controller before the
// peer's MSS option has been observed. 1460 = 1500 (Ethernet MTU) - 20 (IPv4) - 20 (TCP).
const defaultMSS tcp.Size = 1460

// dupackLossThresh is the number of consecutive duplicate ACKs treated as a
// loss signal, matching TCP fast retransmit (RFC 5681 §3.2).
const dupackLossThresh = 3

// rttSampler implements a single-outstanding-sample round-trip-time estimator
// in the style of RFC 6298 / Karn's algorithm: at most one segment is timed at
// a time. A sample is started when new data leaves the sender and completed
// when an acknowledgment advances past the timed sequence number. Retransmitted
// segments are never timed (Karn's algorithm) which keeps the estimate honest.
type rttSampler struct {
	seq     tcp.Value // sequence number whose ACK completes the in-flight sample.
	start   time.Time
	pending bool
}

// startSample begins timing the segment ending at endSeq if no sample is
// currently outstanding. It is a no-op while a sample is already pending.
func (s *rttSampler) startSample(endSeq tcp.Value, now time.Time) {
	if s.pending {
		return
	}
	s.seq = endSeq
	s.start = now
	s.pending = true
}

// observeACK completes the outstanding sample if ack acknowledges the timed
// sequence number, returning the measured RTT and true. Otherwise it returns
// 0, false.
func (s *rttSampler) observeACK(ack tcp.Value, now time.Time) (time.Duration, bool) {
	if !s.pending || ack.LessThan(s.seq) {
		return 0, false
	}
	s.pending = false
	rtt := now.Sub(s.start)
	if rtt <= 0 {
		return 0, false
	}
	return rtt, true
}

// minmaxSample is one entry of the windowed [minmax] filter.
type minmaxSample struct {
	t uint32 // monotonic time stamp (round count or millisecond clock).
	v uint64 // measured value.
}

// minmax is a windowed running maximum/minimum estimator that tracks the best
// value over a sliding window in O(1) space using three staggered samples
// (best, second-best and third-best, each covering progressively more recent
// fractions of the window) instead of storing every sample. BBR uses such a
// windowed max filter for its bandwidth estimate ([draft-ietf-ccwg-bbr]
// §2.10). Use [minmax.runningMax] for a windowed maximum and
// [minmax.runningMin] for a windowed minimum.
type minmax struct {
	s    [3]minmaxSample
	seed bool // false until the first measurement has been recorded.
}

// get returns the current best (max or min) value in the window.
func (m *minmax) get() uint64 { return m.s[0].v }

func (m *minmax) reset(t uint32, meas uint64) uint64 {
	m.seed = true
	val := minmaxSample{t: t, v: meas}
	m.s[0], m.s[1], m.s[2] = val, val, val
	return m.s[0].v
}

// runningMax updates the windowed maximum with measurement meas at time t over
// a window of win, returning the current maximum.
func (m *minmax) runningMax(win, t uint32, meas uint64) uint64 {
	val := minmaxSample{t: t, v: meas}
	if !m.seed || m.s[0].v <= val.v || // first sample or found new max?
		val.t-m.s[2].t > win { // nothing left in window?
		return m.reset(t, meas)
	}
	if m.s[1].v <= val.v {
		m.s[1] = val
		m.s[2] = val
	} else if m.s[2].v <= val.v {
		m.s[2] = val
	}
	return m.subwinUpdate(win, t, val)
}

// runningMin updates the windowed minimum with measurement meas at time t over
// a window of win, returning the current minimum.
func (m *minmax) runningMin(win, t uint32, meas uint64) uint64 {
	val := minmaxSample{t: t, v: meas}
	if !m.seed || val.v <= m.s[0].v || // first sample or found new min?
		val.t-m.s[2].t > win { // nothing left in window?
		return m.reset(t, meas)
	}
	if val.v <= m.s[1].v {
		m.s[1] = val
		m.s[2] = val
	} else if val.v <= m.s[2].v {
		m.s[2] = val
	}
	return m.subwinUpdate(win, t, val)
}

// subwinUpdate ages out samples that fall outside the window and re-partitions
// the remaining estimates so the second estimate covers the most recent 3/4 of
// the window and the third the most recent 1/2.
func (m *minmax) subwinUpdate(win, t uint32, val minmaxSample) uint64 {
	dt := t - m.s[0].t
	if dt > win {
		// Best value has aged out; second/third estimates take over.
		m.s[0] = m.s[1]
		m.s[1] = m.s[2]
		m.s[2] = val
		if t-m.s[0].t > win {
			m.s[0] = m.s[1]
			m.s[1] = m.s[2]
			m.s[2] = val
		}
	} else if m.s[1].t == m.s[0].t && dt > win/4 {
		// Second estimate covers the most recent 3/4 of the window.
		m.s[2] = val
		m.s[1] = val
	} else if m.s[2].t == m.s[1].t && t-m.s[1].t > win/2 {
		// Third estimate covers the most recent 1/2 of the window.
		m.s[2] = val
	}
	return m.s[0].v
}

// nowFunc returns t() or [time.Now] when t is nil.
func nowFunc(t func() time.Time) time.Time {
	if t == nil {
		return time.Now()
	}
	return t()
}

// ccBase holds state shared by the congestion controllers in this package: the
// segment size, an injectable clock, the RTT sampler, and the ACK/loss
// bookkeeping used by observe.
type ccBase struct {
	mss   tcp.Size
	clock func() time.Time
	rtt   rttSampler
	// lastUNA is the highest acknowledged sequence number observed, used by
	// observe to derive how many new bytes an incoming ACK acknowledged.
	lastUNA tcp.Value
	// roundAcked accumulates acknowledged bytes between completed RTT samples
	// and lastSampleAt anchors the start of that accumulation interval. The
	// delivery rate over a round is roundAcked divided by the elapsed time
	// between consecutive sample completions (which is one round trip in steady
	// state), so it covers the whole round of ACKs and not just the single ACK
	// that completed the RTT sample.
	roundAcked   tcp.Size
	lastSampleAt time.Time
	lossEpoch    bool // true while a single loss event is being absorbed.
	haveLastUN   bool
}

func (b *ccBase) now() time.Time { return nowFunc(b.clock) }

func (b *ccBase) segMSS() tcp.Size {
	if b.mss == 0 {
		return defaultMSS
	}
	return b.mss
}

// sample carries the congestion-control inputs derived by [ccBase.observe]
// from a single [tcp.CongestionEvent].
type sample struct {
	// acked is the number of bytes newly acknowledged by this event.
	acked tcp.Size
	// roundAcked is the total number of bytes acknowledged between the previous
	// and this completed RTT sample, i.e. over roundElapsed. Valid only when
	// rttOK is true and roundElapsed is positive.
	roundAcked tcp.Size
	// inflight is the number of unacknowledged bytes in flight after the event.
	inflight tcp.Size
	// rtt is the completed round-trip-time sample; valid only when rttOK.
	rtt time.Duration
	// roundElapsed is the time between the previous and this completed RTT
	// sample. Zero for the first sample of a connection.
	roundElapsed time.Duration
	rttOK        bool
	// loss reports the duplicate-ACK count reaching the fast-retransmit
	// threshold.
	loss bool
}

// observe extracts congestion-control inputs from a [tcp.CongestionEvent],
// updating the shared base state (RTT sampler, ACK and round bookkeeping).
func (b *ccBase) observe(ev tcp.CongestionEvent) (s sample) {
	seg := &ev.Segment
	s.inflight = ev.InFlight
	if ev.MSS > 0 {
		b.mss = ev.MSS // adopt the peer-negotiated MSS once known.
	}
	now := b.now()
	if !b.haveLastUN {
		b.lastUNA = ev.SndUNA
		b.haveLastUN = true
	}
	if ev.Tx {
		// Time new (non-retransmitted) data for the RTT estimate. Retransmits
		// reuse a sequence below SndNXT and are skipped (Karn's algorithm).
		if seg.DATALEN > 0 && !seg.SEQ.LessThan(ev.SndNXT) {
			b.rtt.startSample(seg.Last()+1, now)
		}
		return s
	}
	if seg.Flags.HasAny(tcp.FlagACK) {
		if b.lastUNA.LessThan(ev.SndUNA) {
			s.acked = tcp.Sizeof(b.lastUNA, ev.SndUNA)
			b.lastUNA = ev.SndUNA
			b.roundAcked += s.acked
		}
		s.rtt, s.rttOK = b.rtt.observeACK(seg.ACK, now)
		if s.rttOK {
			// Credit the bytes delivered since the previous sample completion to
			// this sample; the elapsed interval is one round trip in steady state.
			if !b.lastSampleAt.IsZero() {
				s.roundAcked = b.roundAcked
				s.roundElapsed = now.Sub(b.lastSampleAt)
			}
			b.roundAcked = 0
			b.lastSampleAt = now
		}
	}
	s.loss = ev.Dupacks >= dupackLossThresh
	return s
}

// Compile-time assertions that both controllers satisfy tcp.CongestionControl.
var (
	_ tcp.CongestionControl = (*CUBIC)(nil)
	_ tcp.CongestionControl = (*BBR)(nil)
)
