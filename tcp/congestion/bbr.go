package congestion

import (
	"math"
	"time"

	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
)

// BBR tuning constants as defined by BBRv3 [draft-ietf-ccwg-bbr]. BBR
// ("Bottleneck Bandwidth and Round-trip propagation time") models the network
// path with two estimated quantities — the maximum delivery rate (BBR.max_bw)
// and the minimum round-trip time (BBR.min_rtt) — and sizes the volume of
// in-flight data from the resulting bandwidth-delay product (BDP).
//
// [draft-ietf-ccwg-bbr]: https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/
const (
	// bbrStartupPacingGain ≈ 2.77 = 4*ln(2), the pacing gain that allows the
	// sending rate to double each round during Startup
	// (BBR.StartupPacingGain, [draft-ietf-ccwg-bbr] §2.4).
	bbrStartupPacingGain = 4 * math.Ln2
	// bbrDrainPacingGain is the pacing gain used in Drain to empty the queue
	// built during Startup within one round trip: any value at or below
	// 1/BBR.DefaultCwndGain = 0.5 suffices and BBR uses 0.5
	// (BBR.DrainPacingGain, [draft-ietf-ccwg-bbr] §2.4, §5.3.2).
	bbrDrainPacingGain = 0.5
	// bbrDefaultCwndGain is the cwnd gain used in most phases (Startup, Drain,
	// ProbeBW): scaling the BDP by 2 allows the sending rate to double each
	// round and leaves headroom for delayed/aggregated ACKs
	// (BBR.DefaultCwndGain, [draft-ietf-ccwg-bbr] §2.5).
	bbrDefaultCwndGain = 2.0
	// bbrFullBwThresh is the minimum per-round delivery-rate growth ratio that
	// still counts as "the pipe is still filling" during Startup: less than 25%
	// growth counts toward Startup exit ([draft-ietf-ccwg-bbr] §5.3.1.2).
	bbrFullBwThresh = 1.25
	// bbrFullBwCount is the number of consecutive non-app-limited rounds
	// without significant bandwidth growth required to estimate the pipe is
	// full and exit Startup ([draft-ietf-ccwg-bbr] §5.3.1.2).
	bbrFullBwCount = 3
	// bbrMinPipeCwnd is the minimal congestion window BBR targets, in segments,
	// allowing pipelining with delayed-ACK peers (BBR.MinPipeCwnd = 4*SMSS,
	// [draft-ietf-ccwg-bbr] §2.7).
	bbrMinPipeCwnd = 4
	// bbrProbeRTTCwndGain scales the BDP to produce the congestion window held
	// during ProbeRTT, reducing in-flight data to 50% of the estimated BDP
	// (BBR.ProbeRTTCwndGain, [draft-ietf-ccwg-bbr] §2.13.2).
	bbrProbeRTTCwndGain = 0.5
	// bbrProbeRTTDuration is the minimum duration for which ProbeRTT holds the
	// reduced in-flight volume to drain the path and re-measure min_rtt
	// (BBR.ProbeRTTDuration, [draft-ietf-ccwg-bbr] §2.13.2).
	bbrProbeRTTDuration = 200 * time.Millisecond
	// bbrProbeRTTInterval is the minimum time interval between ProbeRTT states:
	// a min_rtt sample older than this schedules a ProbeRTT
	// (BBR.ProbeRTTInterval, [draft-ietf-ccwg-bbr] §2.13.2). This simplified
	// implementation uses it directly as the min_rtt staleness window instead
	// of keeping the separate 10-second BBR.MinRTTFilterLen of §2.13.1.
	bbrProbeRTTInterval = 5 * time.Second
	// bbrBwWindowRounds is the length, in round trips, of the max_bw max
	// filter. It approximates the BBR.MaxBwFilterLen window of 2 ProbeBW
	// cycles ([draft-ietf-ccwg-bbr] §2.10) for this implementation's
	// fixed-duration gain cycling, where a full cycle spans roughly
	// len(bbrPacingGainCycle) round trips.
	bbrBwWindowRounds uint32 = 2 * uint32(len(bbrPacingGainCycle))
)

// bbrPacingGainCycle is the pacing-gain sequence used in ProbeBW, a
// fixed-duration simplification of the ProbeBW_UP/DOWN/CRUISE/REFILL phases of
// [draft-ietf-ccwg-bbr] §5.3.3: the 1.25 phase probes for more bandwidth
// (ProbeBW_UP, §5.3.3.4), the 0.9 phase drains any queue the probe created
// (ProbeBW_DOWN, §5.3.3.1) and the unity phases cruise at the estimated
// bandwidth (ProbeBW_CRUISE/REFILL, §5.3.3.2, §5.3.3.3). Each phase lasts
// about one min_rtt rather than using the draft's adaptive phase durations.
var bbrPacingGainCycle = [8]float32{1.25, 0.9, 1, 1, 1, 1, 1, 1}

// bbrState enumerates the BBR state machine phases.
type bbrState uint8

const (
	bbrStartup  bbrState = iota // Exponentially probe for bandwidth.
	bbrDrain                    // Drain the queue created during Startup.
	bbrProbeBW                  // Steady-state: cycle pacing gain around 1.0.
	bbrProbeRTT                 // Periodically drain to re-measure min_rtt.
)

func (s bbrState) String() string {
	switch s {
	case bbrStartup:
		return "STARTUP"
	case bbrDrain:
		return "DRAIN"
	case bbrProbeBW:
		return "PROBE_BW"
	case bbrProbeRTT:
		return "PROBE_RTT"
	default:
		return "<invalid bbr state>"
	}
}

// BBRConfig configures a [BBR] controller. See [BBR.Configure].
type BBRConfig struct {
	// MSS is the maximum segment size in bytes. If zero the peer's advertised
	// value is used once observed, and a default of 1460 until then.
	MSS tcp.Size
	// InitialCwnd is the initial congestion window in segments. If zero, the
	// RFC 6928 recommended value of 10 segments is used.
	InitialCwnd tcp.Size
}

// BBR implements a simplified version of the BBRv3 congestion-control algorithm
// specified in [draft-ietf-ccwg-bbr]. Rather than reacting to loss like
// Reno/CUBIC, BBR continuously estimates the maximum delivery rate (max_bw) and
// minimum round-trip time (min_rtt) and sizes the congestion window from the
// resulting bandwidth-delay product, probing periodically for changes. It
// implements [tcp.Policy].
//
// # Why it measures its own round trips
//
// BBR needs the minimum round-trip time, being its estimate of the path's
// propagation delay, and a delivery rate. Neither is what a retransmission timer
// keeps: a smoothed round-trip time is deliberately inflated by queueing, which
// is precisely the component BBR must exclude to tell a full pipe from a full
// queue. So this controller times segments itself from the traffic it observes.
//
// That is not the duplication a shared timer exists to prevent. What must not be
// duplicated is the retransmission decision, and BBR makes none: it carries no
// timer, reports no deadline, and asks for no retransmission. Compose it with an
// [rto.Timer] for that, and pass the same timer to [BBR.SetTimer] so a timeout
// invalidates the round-trip sample in flight when it fires.
//
// The zero value is not usable; call [BBR.Configure] before installing it.
//
// Simplifications relative to the draft: round trips are approximated by elapsed
// time instead of packet-delivery accounting (§5.5.1); the ProbeBW phases use
// fixed durations of one min_rtt with the draft's gain values instead of adaptive
// phase lengths (§5.3.3); the loss-based short-term model (BBR.Beta,
// BBR.LossThresh of §2.7) and the extra_acked aggregation estimator (§5.5.9) are
// not implemented.
type BBR struct {
	// cfg retains the normalized configuration so [BBR.Reset] can restore the
	// initial per-connection state without reconfiguration.
	cfg bbrConfig

	// shared is a retransmission timer owned and driven elsewhere, read only to
	// notice a timeout. BBR drives no timer of its own.
	shared *rto.Timer
	// lastExpirations is the shared timer's timeout count as of the last
	// transmit, so a timeout is noticed without seeing the timer's directive.
	lastExpirations uint32

	state bbrState

	bwFilter    minmax // windowed max of delivery rate, bytes/sec.
	roundCount  uint32
	roundStart  int64 // monotonic nanoseconds.
	roundInited bool

	rtProp      time.Duration
	rtPropStamp int64 // monotonic nanoseconds.
	haveRTProp  bool

	pacingGain float32
	cwndGain   float32
	cwnd       tcp.Size // congestion window, bytes.

	cycleIndex int   // current phase within bbrPacingGainCycle.
	cycleStamp int64 // when the current ProbeBW phase began.

	fullBw        float32 // bandwidth at the last full-pipe check, bytes/sec.
	fullBwCount   int
	fullBwReached bool

	probeRTTDone     int64
	probeRTTDoneInit bool

	// Round-trip and delivery-rate sampling, taken from the observed segment
	// stream in the manner of Karn's algorithm: one segment timed at a time, and
	// a retransmission never timed.
	sndNXT   tcp.Value // one past the highest sequence sent.
	sndUNA   tcp.Value // highest sequence acknowledged.
	haveSeq  bool
	timing   bool
	timedSeq tcp.Value // an acknowledgement at or beyond this completes the sample.
	timedAt  int64
	// ackedInRound counts octets acknowledged since the last completed sample,
	// which with the sample's duration gives the delivery rate.
	ackedInRound tcp.Size

	// mss is the peer's advertised MSS once observed, else 0.
	mss tcp.Size
}

// bbrConfig is the normalized [BBRConfig] retained for [BBR.Reset].
type bbrConfig struct {
	mss      tcp.Size
	initCwnd tcp.Size
}

var _ tcp.Policy = (*BBR)(nil)

// Configure validates and stores cfg and resets the controller to its initial
// state. It is the static configuration step and is not part of [tcp.Policy];
// call it before installing the controller on a connection.
func (bbr *BBR) Configure(cfg BBRConfig) error {
	icwnd := cfg.InitialCwnd
	if icwnd == 0 {
		icwnd = 10
	}
	bbr.cfg = bbrConfig{
		mss:      cfg.MSS,
		initCwnd: icwnd,
	}
	bbr.Reset()
	return nil
}

// Reset clears the per-connection state, restoring the initial window from the
// configuration applied by [BBR.Configure]. It implements [tcp.Policy] and is
// called when a connection opens or is torn down. The peer-negotiated MSS is
// forgotten; the static configuration and any shared timer are preserved.
func (bbr *BBR) Reset() {
	cfg, shared := bbr.cfg, bbr.shared
	smss := cfg.mss
	if smss == 0 {
		smss = defaultBBRMSS
	}
	*bbr = BBR{
		cfg:        cfg,
		shared:     shared, // Installed configuration, not per-connection state.
		mss:        cfg.mss,
		state:      bbrStartup,
		pacingGain: bbrStartupPacingGain,
		cwndGain:   bbrDefaultCwndGain,
		cwnd:       cfg.initCwnd * smss,
	}
}

// defaultBBRMSS is the segment size assumed before the peer's MSS option has been
// observed. 1460 = 1500 (Ethernet MTU) - 20 (IPv4) - 20 (TCP).
const defaultBBRMSS tcp.Size = 1460

// SetTimer points the controller at a retransmission timer it reads but does not
// drive, so that a timeout invalidates the round-trip sample in flight. The timer
// must be driven by whoever owns it, which means adding it to the same
// [tcp.Composite] as a policy in its own right, before this controller.
//
// Unlike [CUBIC.SetTimer] this is not about sharing an estimate: BBR measures its
// own round trips because it needs the minimum rather than the smoothed value.
// Passing nil leaves the controller with no view of timeouts at all, which costs
// it only the discarded sample.
func (bbr *BBR) SetTimer(t *rto.Timer) {
	bbr.shared = t
	if t != nil {
		bbr.lastExpirations = t.Expirations()
	}
}

// State returns the current BBR state-machine phase as a human-readable string
// ("STARTUP", "DRAIN", "PROBE_BW" or "PROBE_RTT").
func (bbr *BBR) State() string { return bbr.state.String() }

// CongestionWindow returns the current congestion window in bytes: the maximum
// number of unacknowledged octets the sender should allow in flight.
func (bbr *BBR) CongestionWindow() tcp.Size { return bbr.cwnd }

// BandwidthEstimate returns the current maximum delivery rate estimate (max_bw)
// in bytes per second, or 0 before the first delivery-rate sample.
func (bbr *BBR) BandwidthEstimate() float32 { return float32(bbr.bwFilter.get()) }

// MinRTT returns the current minimum round-trip time estimate (min_rtt), or 0
// before the first RTT sample.
func (bbr *BBR) MinRTT() time.Duration { return bbr.rtProp }

// PacingRate returns the rate, in bytes per second, at which the sender should
// pace transmissions: pacing_gain * max_bw.
//
// Nothing consumes it yet: the transmit path has no pacing, so BBR's control over
// the connection is the congestion window alone. It is reported because the gain
// cycling that produces it is the part of BBR being exercised, and because a
// window derived from a rate the sender cannot pace to is the known gap between
// this implementation and the draft.
func (bbr *BBR) PacingRate() float32 { return bbr.pacingGain * bbr.BandwidthEstimate() }

// bdp returns the bandwidth-delay product in bytes: max_bw * min_rtt. It is the
// amount of in-flight data needed to keep the bottleneck fully utilized.
func (bbr *BBR) bdp() float32 {
	return bbr.BandwidthEstimate() * float32(bbr.rtProp.Seconds())
}

// NextDeadline reports no deadline: BBR schedules nothing and makes no
// retransmission decision. It implements [tcp.Policy].
func (bbr *BBR) NextDeadline() int64 { return 0 }

// PreRx keeps every segment: a congestion controller drops nothing and records
// nothing before the connection has judged the segment. It implements
// [tcp.Policy].
func (bbr *BBR) PreRx(rx tcp.RxMeta) tcp.RxDirective { return tcp.RxDirective{Keep: true} }

// WriteOptions adds no TCP options. It implements [tcp.Policy].
func (bbr *BBR) WriteOptions(plan tcp.TxPlan, opts []byte) uint8 { return 0 }

// PostRx completes a round-trip sample and feeds the model the delivery rate
// measured over it. It implements [tcp.Policy].
//
// A refused segment is ignored: an acknowledgement the state machine rejected
// would otherwise contribute octets that were never delivered to the delivery
// rate, which is the one quantity BBR sizes the window from.
func (bbr *BBR) PostRx(event tcp.RxEvent) {
	if !event.Accepted || !bbr.haveSeq || !event.Segment.Flags.HasAny(tcp.FlagACK) {
		return
	}
	ack := event.Segment.ACK
	if bbr.sndUNA.LessThan(ack) && !bbr.sndNXT.LessThan(ack) {
		bbr.ackedInRound += tcp.Sizeof(bbr.sndUNA, ack)
		bbr.sndUNA = ack
	}
	if !bbr.timing || ack.LessThan(bbr.timedSeq) {
		return // No sample completed by this acknowledgement.
	}
	rtt := time.Duration(event.Now - bbr.timedAt)
	bbr.timing = false
	if rtt <= 0 {
		bbr.ackedInRound = 0
		return
	}
	acked := bbr.ackedInRound
	bbr.ackedInRound = 0
	bbr.onACK(acked, tcp.Sizeof(bbr.sndUNA, bbr.sndNXT), rtt, event.Now)
}

// PreTx withholds new data once the octets in flight have reached the congestion
// window, and notices a timeout on a shared timer. It implements [tcp.Policy].
//
// It asks for no retransmission: BBR is not loss-based and in this implementation
// has no short-term loss model, so recovering a lost segment is left to the timer
// and to selective acknowledgement, whichever is composed alongside.
func (bbr *BBR) PreTx(intent tcp.TxIntent) tcp.TxDirective {
	if intent.MSS != 0 {
		bbr.mss = intent.MSS
	}
	if bbr.shared != nil {
		if n := bbr.shared.Expirations(); n != bbr.lastExpirations {
			bbr.lastExpirations = n
			// A timeout makes the outstanding sample ambiguous, exactly as it does
			// for the timer's own sampling (Karn). The bandwidth and round-trip
			// model is left to recover through normal probing, since BBR treats
			// loss as no signal about the path's capacity.
			bbr.timing = false
		}
	}
	var dir tcp.TxDirective
	if intent.InFlight >= bbr.CongestionWindow() {
		dir.HoldNew = true
	}
	return dir
}

// PostTx records an emitted segment, starting a round-trip sample on newly
// transmitted data. It implements [tcp.Policy].
//
// A segment that does not extend the send sequence is a retransmission and is
// never timed, per Karn's algorithm: its acknowledgement cannot be attributed to
// either transmission, so the sample would be meaningless.
func (bbr *BBR) PostTx(outgoing tcp.Segment, now int64) {
	if outgoing.DATALEN == 0 {
		return // Only data segments carry a measurable round trip.
	}
	segStart := outgoing.SEQ
	segEnd := segStart + tcp.Value(outgoing.LEN())
	if !bbr.haveSeq {
		bbr.haveSeq = true
		bbr.sndUNA, bbr.sndNXT = segStart, segStart
	}
	if !bbr.sndNXT.LessThan(segEnd) {
		bbr.timing = false // Retransmission: discard the outstanding sample.
		return
	}
	bbr.sndNXT = segEnd
	if !bbr.timing {
		bbr.timing = true
		bbr.timedSeq = segEnd
		bbr.timedAt = now
	}
}

// segMSS returns the segment size to size windows in.
func (bbr *BBR) segMSS() tcp.Size {
	if bbr.mss != 0 {
		return bbr.mss
	}
	if bbr.cfg.mss != 0 {
		return bbr.cfg.mss
	}
	return defaultBBRMSS
}

// onACK feeds an acknowledgement into the model: acked is the number of octets
// delivered over the round-trip sample rtt, and inflight is the number still in
// flight after it. It is the numeric core, kept separate from the segment stream
// so the state machine can be exercised without a connection.
func (bbr *BBR) onACK(acked, inflight tcp.Size, rtt time.Duration, now int64) {
	if acked == 0 || rtt <= 0 {
		return
	}
	bbr.update(float64(acked)/rtt.Seconds(), inflight, rtt, now)
}

// update advances the BBR model with a delivery-rate sample of rate bytes/sec
// (0 means no rate could be measured yet) and a round-trip sample rtt.
func (bbr *BBR) update(rate float64, inflight tcp.Size, rtt time.Duration, now int64) {
	if rtt <= 0 {
		return
	}
	bbr.updateRound(now, rtt)
	if rate > 0 {
		bbr.bwFilter.runningMax(bbrBwWindowRounds, bbr.roundCount, uint64(rate))
	}
	bbr.updateMinRTT(now, rtt)

	switch bbr.state {
	case bbrStartup:
		bbr.checkFullPipe()
		if bbr.fullBwReached {
			bbr.enterDrain()
		}
	case bbrDrain:
		if tcp.Size(bbr.bdp()) >= inflight {
			bbr.enterProbeBW(now)
		}
	case bbrProbeBW:
		bbr.advanceProbeBWCycle(now)
	}
	bbr.maybeProbeRTT(now, inflight)
	bbr.setPacingAndCwnd()
}

// updateRound approximates packet-timed round-trip counting by treating one
// min_rtt of elapsed time as a round. The draft counts rounds by
// packet-delivery accounting ([draft-ietf-ccwg-bbr] §5.5.1); the time-based
// approximation avoids per-packet state.
func (bbr *BBR) updateRound(now int64, rtt time.Duration) {
	if !bbr.roundInited {
		bbr.roundStart = now
		bbr.roundInited = true
		return
	}
	win := bbr.rtProp
	if win <= 0 {
		win = rtt
	}
	if now-bbr.roundStart >= int64(win) {
		bbr.roundCount++
		bbr.roundStart = now
	}
}

// updateMinRTT lowers the min_rtt estimate on any smaller sample and
// (re)stamps it ([draft-ietf-ccwg-bbr] §5.5.7). Expiry of a stale min_rtt is
// handled by maybeProbeRTT, not here, so that an inflated sample cannot
// silently raise the propagation-delay estimate.
func (bbr *BBR) updateMinRTT(now int64, rtt time.Duration) {
	if !bbr.haveRTProp || rtt <= bbr.rtProp {
		bbr.rtProp = rtt
		bbr.rtPropStamp = now
		bbr.haveRTProp = true
	}
}

// checkFullPipe estimates whether the pipe is full to decide the Startup exit:
// once the delivery rate grows by less than bbrFullBwThresh per round for
// bbrFullBwCount consecutive rounds, the per-flow available bandwidth is
// considered fully utilized ([draft-ietf-ccwg-bbr] §5.3.1.2).
func (bbr *BBR) checkFullPipe() {
	bw := bbr.BandwidthEstimate()
	if bw >= bbr.fullBw*bbrFullBwThresh {
		bbr.fullBw = bw
		bbr.fullBwCount = 0
		return
	}
	bbr.fullBwCount++
	if bbr.fullBwCount >= bbrFullBwCount {
		bbr.fullBwReached = true
	}
}

// enterDrain switches to the Drain state which pacing-drains the queue built
// during Startup while keeping the window high ([draft-ietf-ccwg-bbr] §5.3.2).
// Drain exits to ProbeBW once inflight is at or below the estimated BDP (the
// draft's additional 3-round escape hatch is omitted).
func (bbr *BBR) enterDrain() {
	bbr.state = bbrDrain
	bbr.pacingGain = bbrDrainPacingGain
	bbr.cwndGain = bbrDefaultCwndGain // keep cwnd high while pacing drains the queue.
}

// enterProbeBW switches to the steady-state ProbeBW gain cycling
// ([draft-ietf-ccwg-bbr] §5.3.3), starting with the bandwidth-probing phase.
func (bbr *BBR) enterProbeBW(now int64) {
	bbr.state = bbrProbeBW
	bbr.cwndGain = bbrDefaultCwndGain
	bbr.cycleIndex = 0 // start with the 1.25 bandwidth-probing phase.
	bbr.pacingGain = bbrPacingGainCycle[bbr.cycleIndex]
	bbr.cycleStamp = now
}

// advanceProbeBWCycle rotates through bbrPacingGainCycle, each phase lasting
// about one min_rtt (a fixed-duration simplification of the adaptive phase
// durations of [draft-ietf-ccwg-bbr] §5.3.3).
func (bbr *BBR) advanceProbeBWCycle(now int64) {
	phase := bbr.rtProp
	if phase <= 0 {
		return
	}
	if now-bbr.cycleStamp < int64(phase) {
		return
	}
	bbr.cycleIndex = (bbr.cycleIndex + 1) % len(bbrPacingGainCycle)
	bbr.pacingGain = bbrPacingGainCycle[bbr.cycleIndex]
	bbr.cycleStamp = now
}

// maybeProbeRTT enters ProbeRTT when the min_rtt estimate has gone stale
// ([draft-ietf-ccwg-bbr] §5.3.4), holding the window at the ProbeRTT target
// for bbrProbeRTTDuration so the path drains and a fresh min_rtt can be
// measured, then returns to ProbeBW (or Startup if the pipe was never filled).
func (bbr *BBR) maybeProbeRTT(now int64, inflight tcp.Size) {
	stale := bbr.haveRTProp && now-bbr.rtPropStamp > int64(bbrProbeRTTInterval)
	if bbr.state != bbrProbeRTT && stale {
		bbr.state = bbrProbeRTT
		bbr.pacingGain = 1
		bbr.cwndGain = bbrProbeRTTCwndGain
		bbr.probeRTTDoneInit = false
		return
	}
	if bbr.state != bbrProbeRTT {
		return
	}
	// In ProbeRTT: wait until inflight has drained to the ProbeRTT window, then
	// hold for at least the probe duration before resuming
	// ([draft-ietf-ccwg-bbr] §5.3.4.1).
	if !bbr.probeRTTDoneInit {
		if inflight <= bbr.probeRTTCwnd() {
			bbr.probeRTTDone = now + int64(bbrProbeRTTDuration)
			bbr.probeRTTDoneInit = true
		}
		return
	}
	if now-bbr.probeRTTDone >= 0 {
		bbr.rtPropStamp = now // min_rtt refreshed by the recent low-load samples.
		if bbr.fullBwReached {
			bbr.enterProbeBW(now)
		} else {
			bbr.state = bbrStartup
			bbr.pacingGain = bbrStartupPacingGain
			bbr.cwndGain = bbrDefaultCwndGain
		}
	}
}

// probeRTTCwnd returns the congestion window held during ProbeRTT:
// max(bbrProbeRTTCwndGain*BDP, MinPipeCwnd) ([draft-ietf-ccwg-bbr] §5.6.4.5).
func (bbr *BBR) probeRTTCwnd() tcp.Size {
	minWnd := tcp.Size(bbrMinPipeCwnd) * bbr.segMSS()
	return max(tcp.Size(bbrProbeRTTCwndGain*bbr.bdp()), minWnd)
}

func (bbr *BBR) setPacingAndCwnd() {
	minWnd := tcp.Size(bbrMinPipeCwnd) * bbr.segMSS()
	if bbr.state == bbrProbeRTT {
		bbr.cwnd = bbr.probeRTTCwnd()
		return
	}
	bdp := bbr.bdp()
	if bdp <= 0 {
		// No estimate yet: stay at the initial/minimum window.
		if bbr.cwnd < minWnd {
			bbr.cwnd = minWnd
		}
		return
	}
	bbr.cwnd = max(tcp.Size(bbr.cwndGain*bdp), minWnd)
}
