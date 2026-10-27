// Package congestion implements TCP congestion control as [tcp.Policy]
// implementations. A controller limits new data to its congestion window and
// runs its own [rto.Timer] for timeouts and the smoothed RTT.
package congestion

import (
	"math"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
)

// CUBIC constants of [RFC9438], with windows in segments.
//
// [RFC9438]: https://www.rfc-editor.org/rfc/rfc9438
const (
	cubicC              = 0.4                                   // §5.1, segments/second³.
	cubicBeta           = 0.7                                   // Multiplicative decrease (§4.6).
	cubicAlpha          = 3 * (1 - cubicBeta) / (1 + cubicBeta) // Reno-friendly increase (§4.3).
	cubicMinCwnd        = 2.0                                   // Floor after a loss (§4.6).
	cubicMaxTargetRatio = 1.5                                   // Target bound (§4.2).
	// defaultMSS is assumed if the remote advertised no MSS (RFC 9293 §3.7.1).
	defaultMSS     = 536
	nanosPerSecond = 1e9
)

// CUBICConfig configures a [CUBIC] controller.
type CUBICConfig struct {
	// Nanotime returns monotonic time in nanoseconds, also for the timer.
	// Required.
	Nanotime func() int64
	// InitialCwnd is the initial window in segments. Zero means 10, RFC
	// 6928's window for an SMSS up to 1460.
	InitialCwnd tcp.Size
	// SlowStartThresh is the initial slow-start threshold in segments. Zero
	// means unbounded.
	SlowStartThresh float64
	// FastConvergence lowers W_max on repeated losses to yield bandwidth to
	// new flows (§4.7).
	FastConvergence bool
}

// CUBIC implements CUBIC congestion control ([RFC9438]) with Reno slow start
// (§4.10). The window grows only while the connection fills it, and the cubic
// function skips the time it does not. Its segments exclude the options of
// the Policies before it in [tcp.Policies].
//
// It runs its own retransmission timer, which [CUBIC.Timer] returns. Install
// no other [rto.Timer] beside it.
//
// A timeout, a resend of data and a fast retransmit the ControlBlock owes,
// which the controller requests itself, are losses, except for the zero-window
// probe octet the peer refused and copies of SND.UNA (below). A loss starts
// recovery until the data sent before it is acknowledged; further losses
// meanwhile belong to the same event, and partial ACKs resend the next hole
// not resent yet, one per round trip also after a timeout. Duplicate ACKs for
// that data are no new loss until SND.UNA passes it (RFC 6582 §3.2). The first
// two duplicate ACKs each allow one more segment (RFC 3042).
//
// The ControlBlock resends SND.UNA on every duplicate ACK from the third. Each
// copy the peer already holds draws a duplicate ACK at a later SND.UNA, so as
// many duplicate ACKs as copies were sent do not count, and the resends they
// cause are copies again, until SND.UNA passes the data sent before the last
// copy.
//
// Unlike RFC 5681, recovery does not inflate the window (§3.2), so new data
// waits until the reduced window opens, and the window is not reduced after
// an idle period (§4.1). Resends other Policies request, such as those of
// tcp/sack, are not limited by the window.
//
// Call [CUBIC.Configure] before use.
//
// [RFC9438]: https://www.rfc-editor.org/rfc/rfc9438
type CUBIC struct {
	cfg             cubicConfig
	nanotime        func() int64
	timer           rto.Timer
	lastExpirations uint32 // Timer timeouts already handled.

	cwnd      float64 // Segments.
	ssthresh  float64 // Segments.
	wMax      float64 // Window before the last reduction (§4.1.2, §4.7).
	cwndPrior float64 // cwnd at the last reduction (§4.1.2).
	wEst      float64 // Reno-friendly window estimate (§4.3).

	// Epoch of the cubic function (§4.2), set by the first ACK in congestion
	// avoidance.
	epoch       int64
	epochSet    bool
	originPoint float64 // W_max of the curve, segments.
	k           float64 // Seconds until the curve reaches originPoint.

	inRecovery bool
	afterRTO   bool      // Recovery started or extended by a timeout: the window still grows.
	recover    tcp.Value // Recovery ends when SND.UNA reaches it.
	// haveRecover holds until SND.UNA passes recover. Until then duplicate
	// ACKs and resends are no new loss (RFC 6582 §3.2 step 1).
	haveRecover bool
	highRxt     tcp.Value // End of the data resent since the loss (RFC 6675).
	dupACKs     uint8     // Duplicate ACKs not answering copies, up to 3 (RFC 3042, 5681).

	// Copies of SND.UNA and the duplicate ACKs answering them.
	copyOwed  bool      // Resends the ControlBlock owes for this SND.UNA are no loss.
	copies    uint8     // Copies of SND.UNA sent.
	answers   uint8     // Duplicate ACKs expected for copies of earlier SND.UNAs.
	copiesNxt tcp.Value // SND.NXT at the latest copy. Once SND.UNA passes it, all were answered.

	cwndLimited  bool // The last transmit had data to fill the window.
	appLimited   bool // The window has not been full since appLimitedAt.
	appLimitedAt int64

	// probe is the zero-window probe octet, refused while the peer's window
	// was closed. Its repair is not a loss.
	probe     tcp.Value
	haveProbe bool

	smss tcp.Size // Smaller of the peer's MSS and ours.

	// State before the segment being received, saved in PreRx.
	una      tcp.Value
	sendRoom tcp.Size // MaxInFlightData, which grows when the peer's window does.

	// State before the segment being sent, saved in PreTx.
	nxt     tcp.Value
	probing bool // A zero-window probe is outstanding, or the refused probe octet is SND.UNA.

	fastRetransmit bool // Resend SND.UNA until a segment covering it is sent.
}

// cubicConfig is the part of [CUBICConfig] kept across [CUBIC.Reset].
type cubicConfig struct {
	initCwnd        float64
	ssthresh        float64
	fastConvergence bool
}

var _ tcp.Policy = (*CUBIC)(nil)

// Configure applies cfg and resets the controller.
func (c *CUBIC) Configure(cfg CUBICConfig) error {
	if cfg.SlowStartThresh < 0 {
		return lneto.ErrInvalidConfig
	} else if err := c.timer.Configure(cfg.Nanotime); err != nil {
		return err
	}
	icwnd := cfg.InitialCwnd
	if icwnd == 0 {
		icwnd = 10
	}
	ssthresh := cfg.SlowStartThresh
	if ssthresh == 0 {
		ssthresh = math.Inf(1)
	}
	c.cfg = cubicConfig{
		initCwnd:        float64(icwnd),
		ssthresh:        ssthresh,
		fastConvergence: cfg.FastConvergence,
	}
	c.nanotime = cfg.Nanotime
	c.Reset()
	return nil
}

// Reset clears the per-connection state, keeping the configuration. It
// implements [tcp.Policy].
func (c *CUBIC) Reset() {
	*c = CUBIC{
		cfg:      c.cfg,
		nanotime: c.nanotime,
		timer:    c.timer,
		cwnd:     c.cfg.initCwnd,
		ssthresh: c.cfg.ssthresh,
		smss:     defaultMSS,
	}
	c.timer.Reset()
}

// Timer returns the retransmission timer the controller runs, for example to
// receive the samples of timestamps.Config.Timer.
func (c *CUBIC) Timer() *rto.Timer { return &c.timer }

// NextDeadline returns the timer's next deadline. See [rto.Timer.NextDeadline].
func (c *CUBIC) NextDeadline() int64 { return c.timer.NextDeadline() }

// PreRx records the send state before the segment is processed. It
// implements [tcp.Policy].
func (c *CUBIC) PreRx(h *tcp.Handler, incoming tcp.Frame) bool {
	cb := h.ControlBlock()
	c.una, c.sendRoom = cb.SendUNA(), cb.MaxInFlightData()
	return c.timer.PreRx(h, incoming)
}

// PostRx grows the window on an ACK of new data and reduces it when the
// ControlBlock owes a fast retransmit after three duplicate ACKs not answering
// copies. It implements [tcp.Policy].
func (c *CUBIC) PostRx(h *tcp.Handler, prevState tcp.State, accepted tcp.Frame) {
	c.timer.PostRx(h, prevState, accepted)
	cb := h.ControlBlock()
	seg := accepted.Segment(len(accepted.Payload()))
	if !prevState.IsSynchronized() || !seg.Flags.HasAny(tcp.FlagACK) {
		return
	}
	una, nxt := cb.SendUNA(), cb.SendNext()
	// RFC 5681 §2, with the peer's window not grown.
	dupACK := seg.ACK == c.una && una == c.una && una.LessThan(nxt) && seg.DATALEN == 0 &&
		!seg.Flags.HasAny(tcp.FlagSYN|tcp.FlagFIN) && cb.MaxInFlightData() <= c.sendRoom
	c.postRx(una, nxt, cb.HasPendingRetransmit(), dupACK, c.nanotime())
}

func (c *CUBIC) postRx(una, nxt tcp.Value, owed, dupACK bool, now int64) {
	if c.una.LessThan(una) {
		c.fastRetransmit, c.haveProbe, c.copyOwed = false, false, false
		c.dupACKs = 0
		c.haveRecover = c.haveRecover && !c.recover.LessThan(una)
		c.answers, c.copies = c.answers+min(c.copies, 255-c.answers), 0
		if c.copiesNxt.LessThan(una) {
			c.answers = 0
		}
		c.onACK(tcp.Sizeof(c.una, una), una, now)
	} else {
		if dupACK && c.answers > 0 {
			c.answers--
		} else if dupACK && !c.inRecovery {
			c.dupACKs = min(c.dupACKs+1, 3)
		}
		if owed {
			if c.dupACKs == 3 && !c.onProbe(una) && !c.haveRecover {
				c.onLoss(nxt)
			} else {
				c.copyOwed = true
			}
			c.fastRetransmit = true
		}
	}
	c.una = una
	if una == nxt && !c.appLimited {
		c.appLimited, c.appLimitedAt = true, now // Nothing in flight.
	}
}

// PreTx runs the timer, handles a timeout, requests a pending resend of SND.UNA
// and limits new data to the window left after the octets in flight. It
// implements [tcp.Policy].
func (c *CUBIC) PreTx(h *tcp.Handler, outgoingOpts tcp.Frame) (newTransmitLimit tcp.Size, rtxFrom tcp.Value, retransmit bool) {
	_, _, timeout := c.timer.PreTx(h, outgoingOpts)
	cb := h.ControlBlock()
	offset, _ := outgoingOpts.OffsetAndFlags()
	c.setSMSS(cb.SendMSS(), tcp.Size(len(outgoingOpts.RawData())-int(offset)*4))
	una, nxt := cb.SendUNA(), cb.SendNext()
	queued := min(tcp.Size(h.BufferedUnsent()), cb.MaxInFlightData())
	probing := cb.MaxInFlightData() == 0 && tcp.Sizeof(una, nxt) <= 1
	newTransmitLimit, _, retransmit = c.preTx(una, nxt, queued, c.timer.Expirations(), probing, c.nanotime())
	return newTransmitLimit, una, retransmit || timeout // Both resend SND.UNA.
}

// preTx handles a transmit with queued octets of new data the peer's window
// allows.
func (c *CUBIC) preTx(una, nxt tcp.Value, queued tcp.Size, expirations uint32, probing bool, now int64) (newTransmitLimit tcp.Size, rtxFrom tcp.Value, retransmit bool) {
	probing = probing || c.onProbe(una)
	c.nxt, c.probing = nxt, probing
	if expirations != c.lastExpirations {
		c.lastExpirations = expirations
		if !probing { // A zero-window probe timing out is not congestion.
			c.onRTO(nxt)
		}
	}
	if c.fastRetransmit {
		rtxFrom, retransmit = una, true // A resend is not limited by the window.
	}
	flight, cwnd := tcp.Sizeof(una, nxt), c.CongestionWindow()
	c.cwndLimited = flight+queued+c.smss >= cwnd
	if !c.cwndLimited && !c.appLimited {
		c.appLimited, c.appLimitedAt = true, now
	} else if c.cwndLimited && c.appLimited {
		c.appLimited = false
		c.epoch += now - c.appLimitedAt // The epoch skips the pause (§5.8).
	}
	cwnd += tcp.Size(min(c.dupACKs, 2)) * c.smss
	if flight >= cwnd {
		return 0, rtxFrom, retransmit
	}
	return cwnd - flight, rtxFrom, retransmit
}

// PostTx takes a resend of data other than a copy as a loss, as when another
// Policy found one, records copies, how far data was resent and a zero-window
// probe, and clears the resend request once a segment covering SND.UNA is
// sent. It implements [tcp.Policy].
func (c *CUBIC) PostTx(h *tcp.Handler, outgoing tcp.Frame) {
	c.timer.PostTx(h, outgoing)
	c.postTx(outgoing.Segment(len(outgoing.Payload())), h.ControlBlock().SendUNA())
}

func (c *CUBIC) postTx(seg tcp.Segment, una tcp.Value) {
	if seg.DATALEN > 0 && seg.SEQ.LessThan(c.nxt) && !c.probing {
		isCopy := seg.SEQ == una && c.copyOwed
		if isCopy {
			c.copies, c.copiesNxt = min(c.copies, 254)+1, c.nxt
		} else if !c.haveRecover {
			c.onLoss(c.nxt)
		}
		if end := tcp.Add(seg.SEQ, seg.DATALEN); c.highRxt.LessThan(end) {
			c.highRxt = end
		}
	} else if c.probing && seg.SEQ == c.nxt && seg.DATALEN == 1 {
		c.probe, c.haveProbe = seg.SEQ, true
	}
	if c.fastRetransmit && seg.SEQ.LessThanEq(una) && una.LessThan(tcp.Add(seg.SEQ, seg.LEN())) {
		c.fastRetransmit = false
	}
}

// CongestionWindow returns the congestion window in bytes, in whole segments
// and at least one.
func (c *CUBIC) CongestionWindow() tcp.Size {
	return tcp.Size(max(c.cwnd, 1)) * c.smss
}

// WindowSegments returns the congestion window in segments.
func (c *CUBIC) WindowSegments() float64 { return c.cwnd }

// SlowStartThresh returns the slow-start threshold in segments.
func (c *CUBIC) SlowStartThresh() float64 { return c.ssthresh }

// onProbe reports whether the zero-window probe octet is the oldest
// unacknowledged.
func (c *CUBIC) onProbe(una tcp.Value) bool { return c.haveProbe && una == c.probe }

func (c *CUBIC) setSMSS(peer, local tcp.Size) {
	if peer == 0 {
		peer = defaultMSS
	}
	c.smss = min(peer, max(local, 1))
}

// onACK handles an ACK of acked new octets.
func (c *CUBIC) onACK(acked tcp.Size, una tcp.Value, now int64) {
	if c.inRecovery {
		if !una.LessThan(c.recover) {
			c.inRecovery, c.afterRTO = false, false
			return // Full ACK: no growth (RFC 6582 §3.2 step 3).
		}
		// Partial ACK (RFC 6582 §3.2 step 3): resend SND.UNA unless it was.
		c.fastRetransmit = !una.LessThan(c.highRxt)
		if !c.afterRTO {
			return
		}
	}
	// Grow only while limited by the window, which basing ssthresh on cwnd
	// requires (§4.6).
	if !c.cwndLimited {
		return
	}
	ackSeg := float64(acked) / float64(c.smss)
	if c.cwnd < c.ssthresh {
		c.cwnd = min(c.cwnd+min(ackSeg, 1), c.ssthresh) // RFC 5681 §3.1.
		return
	}
	c.congestionAvoidance(ackSeg, now)
}

func (c *CUBIC) congestionAvoidance(ackSeg float64, now int64) {
	if !c.epochSet {
		c.epochSet = true
		c.epoch = now
		if c.cwnd < c.wMax {
			c.k = math.Cbrt((c.wMax - c.cwnd) / cubicC) // §4.2, Figure 2.
			c.originPoint = c.wMax
		} else {
			c.k = 0
			c.originPoint = c.cwnd
		}
		c.wEst = c.cwnd
	}
	rtt := float64(c.timer.SmoothedRTT()) / nanosPerSecond
	t := float64(now-c.epoch)/nanosPerSecond + rtt
	target := min(max(c.cubicTarget(t), c.cwnd), cubicMaxTargetRatio*c.cwnd)
	c.cwnd += (target - c.cwnd) / c.cwnd * ackSeg // §4.4, §4.5.

	alpha := float64(cubicAlpha)
	if c.wEst >= c.cwndPrior {
		alpha = 1
	}
	c.wEst += alpha * ackSeg / c.cwnd // §4.3, Figure 4.
	c.cwnd = max(c.cwnd, c.wEst)
}

// cubicTarget returns W_cubic(t) = C*(t-K)³ + W_max (§4.2, Figure 1).
func (c *CUBIC) cubicTarget(t float64) float64 {
	d := t - c.k
	return c.originPoint + cubicC*d*d*d
}

// onLoss applies the multiplicative decrease (§4.6) and starts recovery up to
// nxt, unless already recovering.
func (c *CUBIC) onLoss(nxt tcp.Value) {
	if c.inRecovery {
		return
	}
	c.inRecovery, c.recover, c.haveRecover, c.highRxt = true, nxt, true, c.una
	c.dupACKs = 0
	c.epochSet = false
	if c.cfg.fastConvergence && c.cwnd < c.wMax {
		c.wMax = c.cwnd * (1 + cubicBeta) / 2
	} else {
		c.wMax = c.cwnd
	}
	c.cwndPrior = c.cwnd
	c.ssthresh = max(c.cwnd*cubicBeta, cubicMinCwnd)
	c.cwnd = c.ssthresh
}

// onRTO collapses the window to one segment (§4.8, RFC 5681 §3.1) and sets
// recover to nxt (RFC 6582 §3.2 step 4). Recovery continues up to it, so
// partial ACKs resend the next hole. ssthresh is reduced only on the first
// loss of a recovery. The timer resends SND.UNA.
func (c *CUBIC) onRTO(nxt tcp.Value) {
	if !c.inRecovery {
		c.ssthresh = max(c.cwnd*cubicBeta, cubicMinCwnd)
		c.cwndPrior = c.cwnd
	}
	c.wMax = 0
	c.cwnd = 1
	c.epochSet = false
	c.inRecovery, c.afterRTO, c.recover, c.haveRecover, c.highRxt = true, true, nxt, true, c.una
	c.dupACKs = 0
}
