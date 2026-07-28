// Package congestion implements TCP congestion-control algorithms as
// [tcp.Policy] policies living outside the core tcp package.
//
// A controller here observes the segment stream through the loss-recovery
// hooks and throttles the connection by withholding new data once the octets
// in flight reach its congestion window. It composes [rto.Timer] rather than
// reimplementing retransmission timing, so a single installed policy provides
// both the RFC 6298 timer and the congestion window, which is what the single
// composite-policy design calls for.
//
// The package deliberately uses only exported tcp API: it is the working proof
// that congestion control does not need to live inside the state machine.
package congestion

import (
	"math"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
)

// CUBIC tuning constants as defined by [RFC9438]. Windows are expressed in
// units of MSS-sized segments.
//
// [RFC9438]: https://www.rfc-editor.org/rfc/rfc9438
const (
	// cubicC determines how aggressively CUBIC competes for bandwidth in
	// high-BDP networks. SHOULD be 0.4 (§5.1). Unit: segments/second³.
	cubicC = 0.4
	// cubicBeta is the multiplicative window-decrease factor on a congestion
	// event. SHOULD be 0.7 (§4.6), a gentler cut than Reno's 0.5.
	cubicBeta = 0.7
	// cubicAlpha is the additive increase of the Reno-friendly region, chosen
	// so AIMD(alpha, beta) matches Reno's average window: 3*(1-beta)/(1+beta)
	// (§4.3).
	cubicAlpha = 3 * (1 - cubicBeta) / (1 + cubicBeta)
	// cubicMinCwnd floors the window and threshold on a loss reduction at 2
	// segments (§4.6, Figure 5).
	cubicMinCwnd = 2.0
	// cubicMaxTargetRatio bounds the target to 1.5*cwnd so the increase rate
	// stays below that of slow start (§4.2).
	cubicMaxTargetRatio = 1.5
	// defaultMSS is assumed until the peer's MSS is observed.
	defaultMSS = 1460
	// dupACKThreshold is the number of duplicate ACKs taken as a loss signal
	// (RFC 5681 §3.2).
	dupACKThreshold = 3
	nanosPerSecond  = 1e9
)

// CUBICConfig configures a [CUBIC] controller.
type CUBICConfig struct {
	// MSS is the maximum segment size in bytes assumed before the peer
	// advertises one. If zero, 1460 is used.
	MSS tcp.Size
	// InitialCwnd is the initial congestion window in segments. If zero, the
	// RFC 6928 value of 10 segments is used.
	InitialCwnd tcp.Size
	// SlowStartThresh is the initial slow-start threshold in segments. If zero
	// the controller starts in unbounded slow start.
	SlowStartThresh float64
	// FastConvergence enables CUBIC's fast-convergence heuristic, which yields
	// bandwidth more readily to newly arriving flows (§4.7).
	FastConvergence bool
}

// CUBIC implements the CUBIC congestion-control algorithm ([RFC9438]) as a
// [tcp.Policy]. It grows its congestion window as a cubic function of the
// time since the last congestion event, giving a concave approach toward the
// window that last caused loss followed by a convex probe for more bandwidth.
//
// The window is tracked in MSS-sized segments; [CUBIC.CongestionWindow] reports
// it in bytes. Slow start uses the Reno algorithm, which §4.10 permits.
//
// CUBIC embeds an [rto.Timer] and forwards the policy hooks to it, so installing a
// CUBIC alone also installs RFC 6298 retransmission timing. Loss is detected from
// that timer and from duplicate ACKs.
//
// To run alongside another policy that needs the same timing, point it at a shared
// timer with [CUBIC.SetTimer] instead; see that method for why two timers on one
// connection cannot be reconciled.
//
// The zero value is not usable; call [CUBIC.Configure] before installing it.
//
// [RFC9438]: https://www.rfc-editor.org/rfc/rfc9438
type CUBIC struct {
	// timer provides retransmission timing and the smoothed RTT the cubic curve
	// is evaluated against. It is used only when no shared timer is set.
	timer rto.Timer
	// shared is a timer owned and driven by someone else, set by
	// [CUBIC.SetTimer]. When it is set this controller reads the timer but does
	// not drive it, because a timer driven twice would observe every segment twice.
	shared *rto.Timer
	// lastExpirations is the timer's timeout count as of the last transmit, so a
	// timeout is noticed whether or not this controller drove the timer.
	lastExpirations uint32
	cfg             cubicConfig

	cwnd     float64 // congestion window, segments.
	ssthresh float64 // slow-start threshold, segments.
	// wMax is the window just before the last reduction, possibly lowered
	// further by fast convergence (§4.1.2, §4.7).
	wMax float64
	// cwndPrior is cwnd at the most recent reduction (§4.1.2).
	cwndPrior float64
	// wEst estimates the window a Reno flow would have, so CUBIC never
	// underperforms Reno on short-RTT paths (§4.3).
	wEst float64

	// Cubic epoch state (§4.2). epochSet is false until the first
	// congestion-avoidance ACK of an epoch establishes the origin.
	epoch       int64 // monotonic nanoseconds.
	epochSet    bool
	originPoint float64 // window the curve converges to, segments.
	k           float64 // seconds for the curve to reach originPoint.

	// lossEpoch coalesces repeated loss signals for one congestion event.
	lossEpoch bool

	// mss is the peer's advertised MSS once observed, else 0.
	mss tcp.Size

	// ACK tracking, used to derive newly acknowledged data and duplicate ACKs
	// from the segment stream.
	lastACK tcp.Value
	haveACK bool
	dupACKs int
	// fastRetransmit requests a retransmission on the next transmit after the
	// duplicate-ACK threshold is reached.
	fastRetransmit bool

	// ecnReactedAt is when the window was last reduced for a congestion mark.
	// RFC 3168 §6.1.2 allows reacting at most once per window of data, or more
	// loosely once per round trip, and the difference matters: several marked packets
	// in one window are one congestion event reported many times, and halving the
	// window for each would collapse it far below what the path can carry.
	//
	// The loss epoch cannot serve here as it does for duplicate acknowledgements,
	// because it ends at the next acknowledgement that advances — which for a marked
	// window is the very next segment.
	ecnReactedAt    int64
	haveECNReaction bool
}

// cubicConfig is the normalized [CUBICConfig] retained across [CUBIC.Reset].
type cubicConfig struct {
	mss             tcp.Size
	initCwnd        float64
	ssthresh        float64
	fastConvergence bool
}

var _ tcp.Policy = (*CUBIC)(nil)

// Configure validates and stores cfg and resets the controller. It is the
// static configuration step and is not part of [tcp.Policy]; call it
// before installing the controller on a connection.
func (c *CUBIC) Configure(cfg CUBICConfig) error {
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
	c.cfg = cubicConfig{
		mss:             cfg.MSS,
		initCwnd:        float64(icwnd),
		ssthresh:        ssthresh,
		fastConvergence: cfg.FastConvergence,
	}
	c.Reset()
	return nil
}

// Reset returns the controller and its retransmission timer to the initial
// per-connection state, retaining the configuration. It implements
// [tcp.Policy].
func (c *CUBIC) Reset() {
	cfg, shared := c.cfg, c.shared
	*c = CUBIC{
		cfg:      cfg,
		shared:   shared, // Installed configuration, not per-connection state.
		cwnd:     cfg.initCwnd,
		ssthresh: cfg.ssthresh,
		wEst:     cfg.initCwnd,
		mss:      cfg.mss,
	}
	if shared == nil {
		c.timer.Reset() // A shared timer is reset by whoever drives it.
	}
}

// SetTimer makes this controller read timing from t instead of from a timer of its
// own, without driving it. It is how CUBIC is combined with another policy that
// needs the same retransmission timer, such as the RFC 7323 timestamp extension:
// two policies each driving their own timer would retransmit on whichever estimate
// is more pessimistic and both take credit for the result.
//
// The shared timer must itself be driven, which means adding it to the same
// [tcp.Composite] as a policy in its own right. Add it before this controller, so a
// timeout is seen on the transmit it happens on rather than the next one.
//
// Passing nil returns the controller to using its own timer. Call before the
// connection is opened.
func (c *CUBIC) SetTimer(t *rto.Timer) {
	c.shared = t
	c.lastExpirations = c.tmr().Expirations()
}

// tmr returns the timer in effect, shared or own.
func (c *CUBIC) tmr() *rto.Timer {
	if c.shared != nil {
		return c.shared
	}
	return &c.timer
}

// NextDeadline returns the retransmission deadline of the timer this controller
// drives, or 0 when the timer is shared and reports its own. It implements
// [tcp.Policy].
func (c *CUBIC) NextDeadline() int64 {
	if c.shared != nil {
		return 0
	}
	return c.timer.NextDeadline()
}

// PreRx keeps every segment: a congestion controller drops nothing and records
// nothing before the connection has judged the segment. It implements
// [tcp.Policy].
func (c *CUBIC) PreRx(rx tcp.RxMeta) tcp.RxDirective {
	if c.shared == nil {
		return c.timer.PreRx(rx)
	}
	return tcp.RxDirective{Keep: true}
}

// PostRx forwards an accepted segment to the retransmission timer and updates the
// congestion window from the acknowledgement it carries. It implements
// [tcp.Policy].
//
// A refused segment is ignored, which is the difference between counting real
// feedback and counting whatever arrives: an acknowledgement the state machine
// rejected would otherwise grow the window for data that was never delivered, and
// a rejected duplicate would count toward fast retransmit.
func (c *CUBIC) PostRx(event tcp.RxEvent) {
	if c.shared == nil {
		c.timer.PostRx(event)
	}
	if !event.Accepted || !event.Segment.Flags.HasAny(tcp.FlagACK) {
		return
	}
	if event.Segment.Flags.HasAny(tcp.FlagECE) && c.ecnMayReact(event.Now) {
		// The peer is reporting that the path marked our data as congested (RFC 3168
		// §6.1.2). Treat it as the loss it stands in for, which is what makes the mark
		// worth asking for: a signal acted on identically to a drop, but arriving a
		// round trip earlier and costing no retransmission.
		//
		// The core answers it with CWR; nothing is needed here for that.
		c.onLoss()
		c.ecnReactedAt, c.haveECNReaction = event.Now, true
	}
	c.observeACK(event.Segment, event.Now)
}

// PreTx applies the retransmission timer's directive, adds a duplicate-ACK
// triggered retransmission if one is pending, and withholds new data when the
// octets in flight have reached the congestion window. It implements
// [tcp.Policy].
func (c *CUBIC) PreTx(intent tcp.TxIntent) tcp.TxDirective {
	if intent.MSS != 0 {
		c.mss = intent.MSS
	}
	var dir tcp.TxDirective
	if c.shared == nil {
		dir = c.timer.PreTx(intent)
	}
	// A timeout is detected from the timer's own count rather than from the
	// directive, so it is noticed whether this controller drove the timer or merely
	// reads one driven beside it.
	if n := c.tmr().Expirations(); n != c.lastExpirations {
		c.lastExpirations = n
		// The retransmission timer expired: collapse the window (§4.8).
		c.onRTO()
	} else if c.fastRetransmit {
		c.fastRetransmit = false
		// Resume from the oldest unacknowledged octet: without SACK there is no
		// information about which later octets arrived, so go-back-N is the only
		// correct choice.
		dir.Retransmit = true
		dir.RetransmitFrom = intent.UNA
	}
	if intent.InFlight >= c.CongestionWindow() {
		dir.HoldNew = true
	}
	return dir
}

// WriteOptions adds no TCP options. Congestion control needs none; a policy
// composing timestamps or SACK would write them here. It implements
// [tcp.Policy].
func (c *CUBIC) WriteOptions(plan tcp.TxPlan, opts []byte) uint8 { return 0 }

// PostTx forwards the emitted segment to the retransmission timer. It
// implements [tcp.Policy].
func (c *CUBIC) PostTx(outgoing tcp.Segment, now int64) {
	if c.shared == nil {
		c.timer.PostTx(outgoing, now)
	}
}

// CongestionWindow returns the congestion window in bytes: the maximum number
// of unacknowledged octets the sender should allow in flight. It never reports
// less than one segment, so a connection cannot deadlock.
func (c *CUBIC) CongestionWindow() tcp.Size {
	mss := float64(c.segMSS())
	w := c.cwnd * mss
	if w < mss {
		w = mss
	}
	return tcp.Size(w)
}

// WindowSegments returns the congestion window in MSS-sized segments.
func (c *CUBIC) WindowSegments() float64 { return c.cwnd }

// SlowStartThresh returns the slow-start threshold in segments.
func (c *CUBIC) SlowStartThresh() float64 { return c.ssthresh }

// InSlowStart reports whether the controller is in exponential slow start.
func (c *CUBIC) InSlowStart() bool { return c.cwnd < c.ssthresh }

// SmoothedRTT returns the smoothed round-trip time of the embedded timer.
func (c *CUBIC) SmoothedRTT() int64 { return int64(c.tmr().SmoothedRTT()) }

// ecnMayReact reports whether enough time has passed since the last reduction for a
// congestion mark to count as a new event rather than another report of the last one.
//
// A round trip is the interval RFC 3168 §6.1.2 permits, measured by the timer in
// effect. Before any round-trip estimate exists there is nothing to measure against,
// so a first mark is acted on and a second waits for an estimate to appear.
func (c *CUBIC) ecnMayReact(now int64) bool {
	if !c.haveECNReaction {
		return true
	}
	srtt := int64(c.tmr().SmoothedRTT())
	if srtt <= 0 {
		return false
	}
	return now-c.ecnReactedAt >= srtt
}

func (c *CUBIC) segMSS() tcp.Size {
	if c.mss == 0 {
		return defaultMSS
	}
	return c.mss
}

// observeACK derives newly acknowledged data and duplicate ACKs from the
// segment stream. The controller tracks the acknowledgment number itself
// because the hooks report segments, not send-state transitions.
func (c *CUBIC) observeACK(seg tcp.Segment, now int64) {
	ack := seg.ACK
	if !c.haveACK {
		c.haveACK = true
		c.lastACK = ack
		return
	}
	if c.lastACK.LessThan(ack) {
		acked := tcp.Sizeof(c.lastACK, ack)
		c.lastACK = ack
		c.dupACKs = 0
		c.onACK(acked, now)
		return
	}
	if ack != c.lastACK || seg.DATALEN != 0 {
		return // Stale or data-bearing: not a duplicate ACK.
	}
	// RFC 5681 §2: a pure ACK carrying no data that does not advance the
	// acknowledgment number signals a segment arriving out of order.
	c.dupACKs++
	if c.dupACKs == dupACKThreshold {
		c.onLoss()
		c.fastRetransmit = true
	}
}

// onACK grows the window for acked octets of newly acknowledged data. Slow
// start grows by one segment per acknowledged segment (§4.10); congestion
// avoidance follows the cubic increase function (§4.2).
func (c *CUBIC) onACK(acked tcp.Size, now int64) {
	if acked == 0 {
		return
	}
	c.lossEpoch = false // A fresh ACK ends any in-progress loss epoch.
	ackSeg := float64(acked) / float64(c.segMSS())
	if c.cwnd < c.ssthresh {
		c.cwnd += ackSeg
		if c.cwnd > c.ssthresh {
			c.cwnd = c.ssthresh
		}
		return
	}
	c.congestionAvoidance(ackSeg, now)
}

func (c *CUBIC) congestionAvoidance(ackSeg float64, now int64) {
	if !c.epochSet {
		// Establish the epoch origin (§4.2): K is the time for the curve to
		// grow from cwnd_epoch back to W_max. If cwnd already reaches W_max
		// the curve starts convex from the current window with K=0.
		c.epochSet = true
		c.epoch = now
		if c.cwnd < c.wMax {
			c.k = math.Cbrt((c.wMax - c.cwnd) / cubicC)
			c.originPoint = c.wMax
		} else {
			c.k = 0
			c.originPoint = c.cwnd
		}
		c.wEst = c.cwnd // W_est starts at cwnd_epoch (§4.3).
	}

	// target = W_cubic(t+RTT) clamped to [cwnd, 1.5*cwnd] so the increase rate
	// is non-decreasing yet below slow start's (§4.2).
	rtt := float64(c.tmr().SmoothedRTT()) / nanosPerSecond
	t := float64(now-c.epoch)/nanosPerSecond + rtt
	target := c.cubicTarget(t)
	if target < c.cwnd {
		target = c.cwnd
	} else if target > cubicMaxTargetRatio*c.cwnd {
		target = cubicMaxTargetRatio * c.cwnd
	}
	// Concave/convex growth: cwnd += (target-cwnd)/cwnd per acked segment
	// (§4.4, §4.5).
	c.cwnd += (target - c.cwnd) / c.cwnd * ackSeg

	// Reno-friendly region (§4.3): never fall below the window Reno would
	// have. alpha is cubicAlpha until W_est reaches cwnd_prior, then 1.
	alpha := float64(cubicAlpha)
	if c.wEst >= c.cwndPrior {
		alpha = 1
	}
	c.wEst += alpha * ackSeg / c.cwnd
	if c.wEst > c.cwnd {
		c.cwnd = c.wEst
	}
}

// cubicTarget evaluates W_cubic(t) = C*(t-K)³ + W_max, in segments (§4.2).
func (c *CUBIC) cubicTarget(t float64) float64 {
	d := t - c.k
	return c.originPoint + cubicC*d*d*d
}

// onLoss applies the multiplicative decrease of §4.6 for a congestion event:
// ssthresh = cwnd*beta and cwnd = ssthresh, both floored at 2 segments.
// Repeated signals within one loss epoch are coalesced.
func (c *CUBIC) onLoss() {
	if c.lossEpoch {
		return
	}
	c.lossEpoch = true
	c.epochSet = false // Restart the cubic epoch on the next ACK.

	// Fast convergence (§4.7): a W_max below the previous one suggests the
	// available bandwidth dropped, so lower the inflection point further.
	if c.cfg.fastConvergence && c.cwnd < c.wMax {
		c.wMax = c.cwnd * (1 + cubicBeta) / 2
	} else {
		c.wMax = c.cwnd
	}
	c.cwndPrior = c.cwnd

	c.ssthresh = c.cwnd * cubicBeta
	if c.ssthresh < cubicMinCwnd {
		c.ssthresh = cubicMinCwnd
	}
	c.cwnd = c.ssthresh
	c.wEst = c.cwnd
}

// onRTO applies the timeout response of §4.8: ssthresh is reduced by beta
// while cwnd collapses to one segment and the connection re-enters slow start
// (RFC 5681 §3.1). W_max is cleared so the next congestion-avoidance stage
// starts a fresh epoch.
func (c *CUBIC) onRTO() {
	c.ssthresh = c.cwnd * cubicBeta
	if c.ssthresh < cubicMinCwnd {
		c.ssthresh = cubicMinCwnd
	}
	c.cwndPrior = c.cwnd
	c.wMax = 0
	c.cwnd = 1
	c.wEst = c.cwnd
	c.epochSet = false
	c.lossEpoch = false
}
