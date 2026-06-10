package congestion

import (
	"math"
	"time"

	"github.com/soypat/lneto/tcp"
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
var bbrPacingGainCycle = [8]float64{1.25, 0.9, 1, 1, 1, 1, 1, 1}

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

// BBRConfig configures a [BBR] controller. See [BBR.Reset].
type BBRConfig struct {
	// MSS is the maximum segment size in bytes. If zero, a default of 1460 is used.
	MSS tcp.Size
	// InitialCwnd is the initial congestion window in segments. If zero, the
	// [RFC6928] recommended value of 10 segments is used.
	InitialCwnd tcp.Size
	// Now injects a clock for deterministic testing. If nil, [time.Now] is used.
	Now func() time.Time
}

// BBR implements a simplified version of the BBRv3 congestion-control
// algorithm specified in [draft-ietf-ccwg-bbr]. Rather than reacting to loss
// like Reno/CUBIC, BBR continuously estimates the maximum delivery rate
// (max_bw) and minimum round-trip time (min_rtt) and sizes the congestion
// window from the resulting bandwidth-delay product, probing periodically for
// changes. It implements tcp.CongestionControl.
//
// Simplifications relative to the draft: round trips are approximated by
// elapsed time instead of packet-delivery accounting (§5.5.1); the ProbeBW
// phases use fixed durations of one min_rtt with the draft's gain values
// instead of adaptive phase lengths (§5.3.3); the loss-based short-term model
// (BBR.Beta, BBR.LossThresh of §2.7) and the extra_acked aggregation estimator
// (§5.5.9) are not implemented.
type BBR struct {
	base ccBase

	state bbrState

	bwFilter    minmax // windowed max of delivery rate, bytes/sec.
	roundCount  uint32
	roundStart  time.Time
	roundInited bool

	rtProp      time.Duration
	rtPropStamp time.Time

	pacingGain float64
	cwndGain   float64
	cwnd       tcp.Size // congestion window, bytes.

	cycleIndex int       // current phase within bbrPacingGainCycle.
	cycleStamp time.Time // when the current ProbeBW phase began.

	fullBw        float64 // bandwidth at the last full-pipe check, bytes/sec.
	fullBwCount   int
	fullBwReached bool

	probeRTTDone     time.Time
	probeRTTDoneInit bool
}

// Reset (re)initializes the controller with cfg, returning an error if the
// configuration is invalid. It follows the package Reset/Configure convention.
func (bbr *BBR) Reset(cfg BBRConfig) error {
	mss := cfg.MSS
	if mss == 0 {
		mss = defaultMSS
	}
	icwnd := cfg.InitialCwnd
	if icwnd == 0 {
		icwnd = 10
	}
	*bbr = BBR{
		base: ccBase{
			mss:   cfg.MSS,
			clock: cfg.Now,
		},
		state:      bbrStartup,
		pacingGain: bbrStartupPacingGain,
		cwndGain:   bbrDefaultCwndGain,
		cwnd:       icwnd * mss,
	}
	return nil
}

// State returns the current BBR state-machine phase as a human-readable string
// ("STARTUP", "DRAIN", "PROBE_BW" or "PROBE_RTT").
func (bbr *BBR) State() string { return bbr.state.String() }

// CongestionWindow returns the current congestion window in bytes.
func (bbr *BBR) CongestionWindow() tcp.Size { return bbr.cwnd }

// BandwidthEstimate returns the current maximum delivery rate estimate (max_bw)
// in bytes per second, or 0 before the first delivery-rate sample.
func (bbr *BBR) BandwidthEstimate() float64 { return float64(bbr.bwFilter.get()) }

// MinRTT returns the current minimum round-trip time estimate (min_rtt), or 0
// before the first RTT sample.
func (bbr *BBR) MinRTT() time.Duration { return bbr.rtProp }

// PacingRate returns the rate, in bytes per second, at which the sender should
// pace transmissions: pacing_gain * max_bw.
func (bbr *BBR) PacingRate() float64 { return bbr.pacingGain * bbr.BandwidthEstimate() }

// BDP returns the bandwidth-delay product in bytes: max_bw * min_rtt. It is the
// amount of in-flight data needed to keep the bottleneck fully utilized.
func (bbr *BBR) BDP() float64 {
	return bbr.BandwidthEstimate() * bbr.rtProp.Seconds()
}

// Control implements tcp.CongestionControl. On every completed RTT sample it
// feeds the delivery rate measured over the round (bytes acknowledged between
// sample completions divided by the elapsed time) and the RTT into the BBR
// model, updates the congestion window and returns it in bytes.
func (bbr *BBR) Control(ev tcp.CongestionEvent) tcp.Size {
	s := bbr.base.observe(ev)
	if s.rttOK {
		var rate float64
		if s.roundElapsed > 0 {
			rate = float64(s.roundAcked) / s.roundElapsed.Seconds()
		}
		bbr.update(rate, s.inflight, s.rtt)
	}
	return bbr.CongestionWindow()
}

// OnACK feeds an acknowledgment into the model: acked is the number of bytes
// delivered over the round-trip sample rtt, and inflight is the number of bytes
// still in flight after the ACK. The controller updates its bandwidth/RTT
// estimates, advances its state machine, and recomputes the pacing rate and
// congestion window.
func (bbr *BBR) OnACK(acked, inflight tcp.Size, rtt time.Duration) {
	if acked == 0 || rtt <= 0 {
		return
	}
	bbr.update(float64(acked)/rtt.Seconds(), inflight, rtt)
}

// update advances the BBR model with a delivery-rate sample of rate bytes/sec
// (0 means no rate could be measured yet) and a round-trip sample rtt.
func (bbr *BBR) update(rate float64, inflight tcp.Size, rtt time.Duration) {
	if rtt <= 0 {
		return
	}
	now := bbr.base.now()
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
		if tcp.Size(bbr.BDP()) >= inflight {
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
func (bbr *BBR) updateRound(now time.Time, rtt time.Duration) {
	if !bbr.roundInited {
		bbr.roundStart = now
		bbr.roundInited = true
		return
	}
	win := bbr.rtProp
	if win <= 0 {
		win = rtt
	}
	if now.Sub(bbr.roundStart) >= win {
		bbr.roundCount++
		bbr.roundStart = now
	}
}

// updateMinRTT lowers the min_rtt estimate on any smaller sample and
// (re)stamps it ([draft-ietf-ccwg-bbr] §5.5.7). Expiry of a stale min_rtt is
// handled by maybeProbeRTT, not here, so that an inflated sample cannot
// silently raise the propagation-delay estimate.
func (bbr *BBR) updateMinRTT(now time.Time, rtt time.Duration) {
	if bbr.rtPropStamp.IsZero() || rtt <= bbr.rtProp {
		bbr.rtProp = rtt
		bbr.rtPropStamp = now
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
func (bbr *BBR) enterProbeBW(now time.Time) {
	bbr.state = bbrProbeBW
	bbr.cwndGain = bbrDefaultCwndGain
	bbr.cycleIndex = 0 // start with the 1.25 bandwidth-probing phase.
	bbr.pacingGain = bbrPacingGainCycle[bbr.cycleIndex]
	bbr.cycleStamp = now
}

// advanceProbeBWCycle rotates through bbrPacingGainCycle, each phase lasting
// about one min_rtt (a fixed-duration simplification of the adaptive phase
// durations of [draft-ietf-ccwg-bbr] §5.3.3).
func (bbr *BBR) advanceProbeBWCycle(now time.Time) {
	phase := bbr.rtProp
	if phase <= 0 {
		return
	}
	if now.Sub(bbr.cycleStamp) < phase {
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
func (bbr *BBR) maybeProbeRTT(now time.Time, inflight tcp.Size) {
	stale := !bbr.rtPropStamp.IsZero() && now.Sub(bbr.rtPropStamp) > bbrProbeRTTInterval
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
			bbr.probeRTTDone = now.Add(bbrProbeRTTDuration)
			bbr.probeRTTDoneInit = true
		}
		return
	}
	if now.Sub(bbr.probeRTTDone) >= 0 {
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
	minWnd := tcp.Size(bbrMinPipeCwnd) * bbr.base.segMSS()
	return max(tcp.Size(bbrProbeRTTCwndGain*bbr.BDP()), minWnd)
}

func (bbr *BBR) setPacingAndCwnd() {
	minWnd := tcp.Size(bbrMinPipeCwnd) * bbr.base.segMSS()
	if bbr.state == bbrProbeRTT {
		bbr.cwnd = bbr.probeRTTCwnd()
		return
	}
	bdp := bbr.BDP()
	if bdp <= 0 {
		// No estimate yet: stay at the initial/minimum window.
		if bbr.cwnd < minWnd {
			bbr.cwnd = minWnd
		}
		return
	}
	target := max(tcp.Size(bbr.cwndGain*bdp), minWnd)
	bbr.cwnd = target
}

// OnLoss is provided for symmetry with [CUBIC]. BBR is not loss-based: it does
// not collapse its window on packet loss the way Reno/CUBIC do, so this is
// intentionally a no-op. The draft's loss-driven short-term model
// (BBR.Beta = 0.7 and BBR.LossThresh = 2%, [draft-ietf-ccwg-bbr] §2.7,
// §5.5.10) is not implemented; bandwidth and RTT estimation alone drive the
// window via OnACK.
func (bbr *BBR) OnLoss() {}
