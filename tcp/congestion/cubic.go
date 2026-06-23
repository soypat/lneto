package congestion

import (
	"math"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
)

// CUBIC tuning constants as defined by [RFC9438]. All windows below are
// expressed in units of MSS-sized segments.
const (
	// cubicC is the constant that determines the aggressiveness of CUBIC in
	// competing with other congestion control algorithms in high-BDP networks.
	// SHOULD be set to 0.4 ([RFC9438] §5.1). Unit: segments/second³.
	cubicC = 0.4
	// cubicBeta is the multiplicative window-decrease factor applied on a
	// congestion event. SHOULD be set to 0.7 ([RFC9438] §4.6), a gentler cut
	// than Reno's 0.5.
	cubicBeta = 0.7
	// cubicAlpha is the additive increase factor of the Reno-friendly region,
	// chosen so AIMD(alpha, beta) achieves the same average window as Reno's
	// AIMD(1, 0.5): alpha = 3*(1-beta)/(1+beta) ([RFC9438] §4.3).
	cubicAlpha = 3 * (1 - cubicBeta) / (1 + cubicBeta)
	// cubicMinCwnd is the floor, in segments, for both the congestion window
	// and the slow-start threshold on a loss-induced reduction
	// ([RFC9438] §4.6, Figure 5: cwnd = max(ssthresh, 2) on loss and
	// ssthresh = max(ssthresh, 2)).
	cubicMinCwnd = 2.0
	// cubicMaxTargetRatio bounds the target window to 1.5*cwnd so the window
	// increase rate stays below the increase rate of slow start
	// ([RFC9438] §4.2).
	cubicMaxTargetRatio = 1.5
)

// CUBICConfig configures a [CUBIC] controller. See [CUBIC.Configure].
type CUBICConfig struct {
	// MSS is the maximum segment size in bytes. If zero, a default of 1460 is used.
	MSS tcp.Size
	// InitialCwnd is the initial congestion window in segments. If zero, the
	// [RFC6928] recommended value of 10 segments is used.
	InitialCwnd tcp.Size
	// SlowStartThresh is the initial slow-start threshold in segments. If zero,
	// the controller starts in unbounded slow start (threshold = +Inf).
	SlowStartThresh float64
	// FastConvergence enables CUBIC's fast-convergence heuristic which yields
	// bandwidth more readily to newly arriving flows. SHOULD be implemented
	// when multiple flows share a bottleneck ([RFC9438] §4.7).
	FastConvergence bool
	// Now injects a clock for deterministic testing. If nil, [time.Now] is used.
	Now func() time.Time
}

// CUBIC implements the CUBIC congestion-control algorithm ([RFC9438]), the
// default congestion controller of the major operating system stacks. CUBIC
// grows its congestion window as a cubic function of the time elapsed since
// the last congestion event, producing a concave approach toward the window
// size that last caused loss (W_max) followed by a convex probe for additional
// bandwidth. It implements tcp.CongestionControl.
//
// The window is tracked internally in units of MSS-sized segments;
// [CUBIC.CongestionWindow] reports it in bytes. Slow start uses the Reno
// algorithm, which [RFC9438] §4.10 permits (HyStart++ is recommended but not
// required).
//
// [RFC9438]: https://www.rfc-editor.org/rfc/rfc9438
type CUBIC struct {
	base ccBase
	// cfg retains the normalized configuration so [CUBIC.Reset] can restore the
	// initial per-connection state without reconfiguration.
	cfg cubicConfig

	cwnd     float64 // congestion window, segments.
	ssthresh float64 // slow-start threshold, segments.
	// wMax is the window size just before the last reduction, possibly further
	// reduced by fast convergence ([RFC9438] §4.1.2 W_max, §4.7).
	wMax float64
	// cwndPrior is cwnd at the time of the most recent reduction
	// ([RFC9438] §4.1.2 cwnd_prior).
	cwndPrior float64

	// Cubic epoch state. epoch is the zero time until the first
	// congestion-avoidance ACK of an epoch establishes the origin
	// ([RFC9438] §4.2: t_epoch, cwnd_epoch).
	epoch       time.Time
	originPoint float64 // window the cubic curve converges to, segments.
	k           float64 // time (seconds) for the curve to reach originPoint.

	// wEst estimates the congestion window of a Reno flow for the
	// Reno-friendly region so CUBIC achieves at least Reno's throughput on
	// short-RTT or small-BDP paths ([RFC9438] §4.3 W_est).
	wEst float64

	fastConvergence bool
}

// cubicConfig is the normalized [CUBICConfig] retained for [CUBIC.Reset].
type cubicConfig struct {
	clock           func() time.Time
	mss             tcp.Size
	initCwnd        float64
	ssthresh        float64
	fastConvergence bool
}

// Configure validates and stores cfg, returning an error if the configuration
// is invalid, and resets the controller to its initial state. Configure is the
// static configuration step and is not part of tcp.CongestionControl; call it
// before installing the controller on a Handler. See [CUBIC.Reset].
func (cubic *CUBIC) Configure(cfg CUBICConfig) error {
	if cfg.SlowStartThresh < 0 {
		return lneto.ErrInvalidConfig
	}
	icwnd := cfg.InitialCwnd
	if icwnd == 0 {
		icwnd = 10 // RFC 6928 initial window.
	}
	ssthresh := cfg.SlowStartThresh
	if ssthresh == 0 {
		ssthresh = math.Inf(1)
	}
	cubic.cfg = cubicConfig{
		clock:           cfg.Now,
		mss:             cfg.MSS,
		initCwnd:        float64(icwnd),
		ssthresh:        ssthresh,
		fastConvergence: cfg.FastConvergence,
	}
	cubic.Reset()
	return nil
}

// Reset clears the per-connection state, restoring the initial window from the
// configuration applied by [CUBIC.Configure]. It implements
// tcp.CongestionControl and is called by the Handler when a connection opens or
// is torn down. The peer-negotiated MSS is forgotten; the static configuration
// is preserved.
func (cubic *CUBIC) Reset() {
	cfg := cubic.cfg
	*cubic = CUBIC{
		base: ccBase{
			mss:   cfg.mss,
			clock: cfg.clock,
		},
		cfg:             cfg,
		cwnd:            cfg.initCwnd,
		ssthresh:        cfg.ssthresh,
		wEst:            cfg.initCwnd,
		fastConvergence: cfg.fastConvergence,
	}
}

// CongestionWindow returns the current congestion window in bytes: the maximum
// number of unacknowledged bytes the sender should allow in flight.
func (cubic *CUBIC) CongestionWindow() tcp.Size {
	w := cubic.cwnd * float64(cubic.base.segMSS())
	if w < 1 {
		w = 1
	}
	return tcp.Size(w)
}

// WindowSegments returns the current congestion window in MSS-sized segments.
func (cubic *CUBIC) WindowSegments() float64 { return cubic.cwnd }

// SlowStartThresh returns the current slow-start threshold in segments.
func (cubic *CUBIC) SlowStartThresh() float64 { return cubic.ssthresh }

// InSlowStart reports whether the controller is in the exponential slow-start
// phase (congestion window below the slow-start threshold).
func (cubic *CUBIC) InSlowStart() bool { return cubic.cwnd < cubic.ssthresh }

// Control implements tcp.CongestionControl. It detects new acknowledgments and
// loss events from the event crossing the Handler boundary, updates the CUBIC
// window accordingly and returns it in bytes.
func (cubic *CUBIC) Control(ev tcp.CongestionEvent) tcp.Size {
	if ev.RTO {
		// Retransmission timeout (RFC 6298): collapse to the loss window and
		// re-enter slow start (RFC 9438 §4.8). Discard any timed RTT sample
		// since the segment is being retransmitted (Karn).
		cubic.base.rtt.pending = false
		cubic.onRTO()
		return cubic.CongestionWindow()
	}
	s := cubic.base.observe(ev)
	if s.loss {
		cubic.onLoss()
	}
	if s.acked > 0 {
		cubic.onACK(s.acked, s.rtt)
	}
	return cubic.CongestionWindow()
}

// onACK informs the controller that acked bytes of new data were
// acknowledged with the given round-trip estimate. In slow start the window
// grows by one segment per acknowledged segment (exponential per RTT,
// [RFC9438] §4.10); in congestion avoidance it follows the cubic window
// increase function ([RFC9438] §4.2).
func (cubic *CUBIC) onACK(acked tcp.Size, rtt time.Duration) {
	if acked == 0 {
		return
	}
	cubic.base.lossEpoch = false // a fresh ACK ends any in-progress loss epoch.
	ackSeg := float64(acked) / float64(cubic.base.segMSS())
	if cubic.cwnd < cubic.ssthresh {
		// Slow start: exponential growth, capped at the threshold.
		cubic.cwnd += ackSeg
		if cubic.cwnd > cubic.ssthresh {
			cubic.cwnd = cubic.ssthresh
		}
		return
	}
	cubic.congestionAvoidance(ackSeg, rtt)
}

func (cubic *CUBIC) congestionAvoidance(ackSeg float64, rtt time.Duration) {
	now := cubic.base.now()
	if cubic.epoch.IsZero() {
		// Establish the epoch origin ([RFC9438] §4.2): K is the time for the
		// curve to grow from cwnd_epoch back to W_max. If cwnd is already at or
		// above W_max (convex region from the start, or after a timeout per
		// §4.8) then K=0 and the curve grows from the current window.
		cubic.epoch = now
		if cubic.cwnd < cubic.wMax {
			cubic.k = math.Cbrt((cubic.wMax - cubic.cwnd) / cubicC)
			cubic.originPoint = cubic.wMax
		} else {
			cubic.k = 0
			cubic.originPoint = cubic.cwnd
		}
		cubic.wEst = cubic.cwnd // W_est starts at cwnd_epoch (§4.3).
	}

	// target = W_cubic(t+RTT) clamped to [cwnd, 1.5*cwnd] so the increase rate
	// is non-decreasing yet below slow start's ([RFC9438] §4.2).
	t := now.Sub(cubic.epoch).Seconds() + rtt.Seconds()
	target := cubic.cubicTarget(t)
	if target < cubic.cwnd {
		target = cubic.cwnd
	} else if target > cubicMaxTargetRatio*cubic.cwnd {
		target = cubicMaxTargetRatio * cubic.cwnd
	}
	// Concave/convex region growth: cwnd += (target-cwnd)/cwnd per acked
	// segment ([RFC9438] §4.4, §4.5).
	cubic.cwnd += (target - cubic.cwnd) / cubic.cwnd * ackSeg

	// Reno-friendly region ([RFC9438] §4.3): estimate the window Reno would
	// have and never fall below it. alpha is cubicAlpha until W_est reaches
	// cwnd_prior, then 1 to match Reno's AIMD(1, 0.5) increase rate.
	alpha := cubicAlpha
	if cubic.wEst >= cubic.cwndPrior {
		alpha = 1
	}
	cubic.wEst += alpha * ackSeg / cubic.cwnd
	if cubic.wEst > cubic.cwnd {
		cubic.cwnd = cubic.wEst
	}
}

// cubicTarget evaluates the cubic window increase function
// W_cubic(t) = C*(t-K)^3 + W_max at t seconds into the current epoch
// ([RFC9438] §4.2, Figure 1). The result is in segments.
func (cubic *CUBIC) cubicTarget(t float64) float64 {
	d := t - cubic.k
	return cubic.originPoint + cubicC*d*d*d
}

// OnLoss applies the multiplicative decrease of [RFC9438] §4.6 in response to
// a congestion event (e.g. three duplicate ACKs): ssthresh = cwnd*beta and
// cwnd = ssthresh, both floored at 2 segments. The window is computed from
// cwnd rather than flight size, the variant §4.6 permits for senders that do
// not grow cwnd while under-utilized. Repeated calls within the same loss
// epoch are coalesced into a single reduction.
func (cubic *CUBIC) onLoss() {
	if cubic.base.lossEpoch {
		return // already reduced for this congestion event.
	}
	cubic.base.lossEpoch = true
	cubic.epoch = time.Time{} // restart the cubic epoch on the next ACK.

	// Fast convergence ([RFC9438] §4.7): when this W_max is lower than the
	// previous one the available bandwidth has likely dropped, so lower the
	// inflection point further to release bandwidth to other flows. Applied
	// before the window reduction below.
	if cubic.fastConvergence && cubic.cwnd < cubic.wMax {
		cubic.wMax = cubic.cwnd * (1 + cubicBeta) / 2
	} else {
		cubic.wMax = cubic.cwnd
	}
	cubic.cwndPrior = cubic.cwnd

	cubic.ssthresh = cubic.cwnd * cubicBeta
	if cubic.ssthresh < cubicMinCwnd {
		cubic.ssthresh = cubicMinCwnd
	}
	cubic.cwnd = cubic.ssthresh
	cubic.wEst = cubic.cwnd
}

// OnRTO applies the response to a retransmission timeout ([RFC9438] §4.8):
// ssthresh is set using beta as in the multiplicative decrease while cwnd
// collapses to 1 segment and the connection re-enters slow start, following
// Reno ([RFC5681] §3.1). W_max is cleared so the first congestion avoidance
// stage after the timeout starts a fresh cubic epoch with K=0 and W_max set
// to the window at the beginning of that stage.
func (cubic *CUBIC) onRTO() {
	cubic.ssthresh = cubic.cwnd * cubicBeta
	if cubic.ssthresh < cubicMinCwnd {
		cubic.ssthresh = cubicMinCwnd
	}
	cubic.cwndPrior = cubic.cwnd
	cubic.wMax = 0
	cubic.cwnd = 1
	cubic.wEst = cubic.cwnd
	cubic.epoch = time.Time{}
	cubic.base.lossEpoch = false
}
