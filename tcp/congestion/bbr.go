package congestion

import (
	"math"
	"time"

	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
)

// BBR constants of [draft-ietf-ccwg-bbr], with windows in segments.
//
// [draft-ietf-ccwg-bbr]: https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/
const (
	bbrStartupPacingGain = 4 * math.Ln2           // Doubles the rate per round (§2.4).
	bbrDrainPacingGain   = 0.5                    // §2.4.
	bbrCwndGain          = 2.0                    // BBR.DefaultCwndGain (§2.5).
	bbrProbeRTTCwndGain  = 0.5                    // §2.13.2.
	bbrFullBwThresh      = 1.25                   // Growth per round of a pipe still filling (§5.3.1.2).
	bbrFullBwCount       = 3                      // Rounds below it until the pipe is full.
	bbrMinPipeCwnd       = 4                      // §2.7.
	bbrProbeRTTDuration  = 200 * time.Millisecond // §2.13.2.
	// bbrProbeRTTInterval is also the age at which min_rtt is stale, instead
	// of the 10s BBR.MinRTTFilterLen (§2.13.1).
	bbrProbeRTTInterval = 5 * time.Second
)

// bbrProbeBWGains are the pacing gains of ProbeBW, each held for one min_rtt:
// UP probes for bandwidth, DOWN drains the queue it built, then the flow
// cruises (§5.3.3).
var bbrProbeBWGains = [8]float32{1.25, 0.9, 1, 1, 1, 1, 1, 1}

// bbrBwWindow is the max_bw filter length in rounds, two ProbeBW cycles
// (BBR.MaxBwFilterLen, §2.10).
const bbrBwWindow = 2 * uint32(len(bbrProbeBWGains))

type bbrState uint8

const (
	bbrStartup  bbrState = iota // Probe for bandwidth, doubling per round.
	bbrDrain                    // Drain the queue Startup built.
	bbrProbeBW                  // Cycle the pacing gain around 1.
	bbrProbeRTT                 // Reduce the flight to measure min_rtt again.
)

func (s bbrState) String() string {
	switch s {
	case bbrStartup:
		return "Startup"
	case bbrDrain:
		return "Drain"
	case bbrProbeBW:
		return "ProbeBW"
	case bbrProbeRTT:
		return "ProbeRTT"
	}
	return "invalid"
}

// BBRConfig configures a [BBR] controller.
type BBRConfig struct {
	// Nanotime returns monotonic time in nanoseconds, also for the timer.
	// Required.
	Nanotime func() int64
	// InitialCwnd is the window in segments until the first round trip is
	// measured. Zero means 10, RFC 6928's window for an SMSS up to 1460.
	InitialCwnd tcp.Size
}

// BBR implements a simplified BBR congestion control ([draft-ietf-ccwg-bbr]).
// Instead of reacting to loss it estimates the path's bandwidth (max_bw) and
// propagation round trip (min_rtt), and limits new data to twice their product.
// Its segments exclude the options of the Policies before it in [tcp.Policies].
//
// It runs its own retransmission timer, which [BBR.Timer] returns. Install no
// other [rto.Timer] beside it. It measures round trips itself, one segment of
// new data at a time and never a resend (Karn), since the timer's smoothed RTT
// includes the queueing BBR must exclude.
//
// Losses and ECE leave the window alone. A fast retransmit the ControlBlock
// owes after three duplicate ACKs not answering copies of SND.UNA, counted as
// CUBIC does, and a timeout other than of a zero-window probe start recovery
// until the data sent before is acknowledged. Recovery sends no new data, so a
// receiver holding few segments out of order (8 for tcp.Handler) is not sent
// more, and each partial ACK resends SND.UNA unless it was resent, as by
// tcp/sack (RFC 6582 §3.2), whose resends the window does not limit. Without a
// loss model the flight of twice the BDP can overflow a shallow queue or such
// a receiver, which costs more than with CUBIC.
//
// Simplifications: the transmit path cannot pace, so [BBR.PacingRate] is only
// reported, Drain holds the flight at the BDP instead and the gains of ProbeBW
// have no effect; rounds are one min_rtt of time (§5.5.1); ProbeBW phases last
// one min_rtt each (§5.3.3); the loss model (§2.7), the extra_acked estimate
// (§5.5.9), application-limited samples (§4.5.2) and the window reduction
// after a timeout (§5.6.4.4) are not implemented.
//
// Call [BBR.Configure] before use.
type BBR struct {
	initCwnd        tcp.Size
	nanotime        func() int64
	timer           rto.Timer
	lastExpirations uint32 // Timer timeouts already handled.

	state      bbrState
	pacingGain float32
	cwndGain   float32
	cwnd       tcp.Size // Bytes; zero until the first round trip.
	priorCwnd  tcp.Size // cwnd on entering ProbeRTT.

	maxBw      maxFilter // Bytes per second, over rounds.
	round      uint32
	roundStart int64

	minRTT      time.Duration
	minRTTStamp int64

	cycle      int // Index into bbrProbeBWGains.
	cycleStart int64

	fullBw        uint64 // max_bw at the last round that grew it enough.
	fullBwCount   uint8
	fullBwReached bool

	probeRTTDone    int64 // When ProbeRTT ends, once the flight is down.
	probeRTTDoneSet bool

	inRecovery bool
	recover    tcp.Value // Recovery ends when SND.UNA reaches it.
	highRxt    tcp.Value // End of the data resent since recovery started.
	resendUNA  bool      // Resend SND.UNA until a segment covering it is sent.
	dup        dupACKs

	// The round trip being measured, ending at the ACK of timedEnd, and the
	// octets delivered meanwhile (§4.5).
	timing         bool
	timedEnd       tcp.Value
	timedAt        int64
	timedDelivered tcp.Size // delivered when the timed segment was sent.
	timedIdle      bool     // Nothing was in flight when the timed segment was sent.
	delivered      tcp.Size // Octets acknowledged, wrapping.

	smss tcp.Size // Smaller of the peer's MSS and ours.

	// State before the segment being received, saved in PreRx.
	una      tcp.Value
	sendRoom tcp.Size // MaxInFlightData, which grows when the peer's window does.

	// State before the segment being sent, saved in PreTx.
	nxt     tcp.Value
	probing bool // A zero-window probe is outstanding.
	idle    bool // Nothing is in flight.
}

var _ tcp.Policy = (*BBR)(nil)

// Configure applies cfg and resets the controller.
func (b *BBR) Configure(cfg BBRConfig) error {
	if err := b.timer.Configure(cfg.Nanotime); err != nil {
		return err
	}
	b.initCwnd = cfg.InitialCwnd
	if b.initCwnd == 0 {
		b.initCwnd = 10
	}
	b.nanotime = cfg.Nanotime
	b.Reset()
	return nil
}

// Reset clears the per-connection state, keeping the configuration. It
// implements [tcp.Policy].
func (b *BBR) Reset() {
	*b = BBR{
		initCwnd:   b.initCwnd,
		nanotime:   b.nanotime,
		timer:      b.timer,
		pacingGain: bbrStartupPacingGain,
		cwndGain:   bbrCwndGain,
		smss:       defaultMSS,
	}
	b.timer.Reset()
}

// Timer returns the retransmission timer the controller runs, for example to
// receive the samples of timestamps.Config.Timer.
func (b *BBR) Timer() *rto.Timer { return &b.timer }

// NextDeadline returns the timer's next deadline. See [rto.Timer.NextDeadline].
func (b *BBR) NextDeadline() int64 { return b.timer.NextDeadline() }

// State returns the name of the phase: Startup, Drain, ProbeBW or ProbeRTT.
func (b *BBR) State() string { return b.state.String() }

// CongestionWindow returns the congestion window in bytes.
func (b *BBR) CongestionWindow() tcp.Size {
	if b.cwnd == 0 {
		return b.initCwnd * b.smss
	}
	return b.cwnd
}

// MaxBandwidth returns max_bw in bytes per second, zero before a round trip
// was measured.
func (b *BBR) MaxBandwidth() uint64 { return b.maxBw.get() }

// MinRTT returns min_rtt, zero before a round trip was measured.
func (b *BBR) MinRTT() time.Duration { return b.minRTT }

// PacingRate returns the rate in bytes per second BBR would pace at. Nothing
// paces to it.
func (b *BBR) PacingRate() float32 { return b.pacingGain * float32(b.maxBw.get()) }

// PreRx records SND.UNA before the segment is processed. It implements
// [tcp.Policy].
func (b *BBR) PreRx(h *tcp.Handler, incoming tcp.Frame) bool {
	cb := h.ControlBlock()
	b.una, b.sendRoom = cb.SendUNA(), cb.MaxInFlightData()
	return b.timer.PreRx(h, incoming)
}

// PostRx grows the window on an ACK of new data and updates the model once
// the timed segment is acknowledged. It implements [tcp.Policy].
func (b *BBR) PostRx(h *tcp.Handler, prevState tcp.State, accepted tcp.Frame) {
	b.timer.PostRx(h, prevState, accepted)
	cb := h.ControlBlock()
	una, nxt := cb.SendUNA(), cb.SendNext()
	dupACK := isDupACK(accepted.Segment(len(accepted.Payload())), b.una, una, nxt, b.sendRoom, cb.MaxInFlightData())
	b.postRx(una, nxt, cb.HasPendingRetransmit(), dupACK, b.nanotime())
}

func (b *BBR) postRx(una, nxt tcp.Value, owed, dupACK bool, now int64) {
	if !b.una.LessThan(una) {
		if dupACK {
			b.dup.dup(!b.inRecovery)
		}
		if owed && b.dup.owed(!b.inRecovery) {
			b.inRecovery, b.recover, b.highRxt = true, nxt, una
		}
		return
	}
	b.dup.acked(una)
	acked := tcp.Sizeof(b.una, una)
	b.una = una
	b.delivered += acked
	if b.timing && !una.LessThan(b.timedEnd) {
		b.timing = false
		if rtt := time.Duration(now - b.timedAt); rtt > 0 {
			b.onRoundTrip(b.delivered-b.timedDelivered, tcp.Sizeof(una, nxt), rtt, b.timedIdle, now)
		}
	}
	if b.cwnd != 0 {
		b.growCwnd(acked)
	}
	if b.state == bbrDrain && tcp.Sizeof(una, nxt) <= b.drainCwnd() {
		b.enterProbeBW(now)
	}
	if b.inRecovery {
		b.inRecovery = una.LessThan(b.recover)
		b.resendUNA = b.inRecovery && !una.LessThan(b.highRxt) // Partial ACK.
	}
}

// PreTx runs the timer, starts recovery on a timeout, discarding the round trip
// it made ambiguous, requests a pending resend of SND.UNA and limits new data
// to the whole segments the window leaves after the octets in flight. It
// implements [tcp.Policy].
func (b *BBR) PreTx(h *tcp.Handler, outgoingOpts tcp.Frame) (newTransmitLimit tcp.Size, rtxFrom tcp.Value, retransmit bool) {
	_, _, timeout := b.timer.PreTx(h, outgoingOpts)
	cb := h.ControlBlock()
	offset, _ := outgoingOpts.OffsetAndFlags()
	b.smss = segmentSize(cb.SendMSS(), tcp.Size(len(outgoingOpts.RawData())-int(offset)*4))
	una, nxt := cb.SendUNA(), cb.SendNext()
	probing := cb.MaxInFlightData() == 0 && tcp.Sizeof(una, nxt) <= 1
	return b.preTx(una, nxt, b.timer.Expirations(), timeout, probing, b.nanotime())
}

// preTx handles a transmit after expirations timeouts, the latest now if
// timeout, and with a zero-window probe outstanding if probing.
func (b *BBR) preTx(una, nxt tcp.Value, expirations uint32, timeout, probing bool, now int64) (newTransmitLimit tcp.Size, rtxFrom tcp.Value, retransmit bool) {
	b.nxt, b.probing, b.idle = nxt, probing, una == nxt
	if expirations != b.lastExpirations {
		b.lastExpirations = expirations
		b.timing = false
		if !probing { // A zero-window probe timing out is no loss.
			b.inRecovery, b.recover, b.highRxt = true, nxt, una // RFC 6582 §3.2 step 4.
		}
	}
	if b.idle && b.state == bbrProbeRTT && b.probeRTTDoneSet && now >= b.probeRTTDone {
		b.endProbeRTT(now) // Restart from idle (§5.4.3).
	}
	retransmit = timeout || b.resendUNA // Both resend SND.UNA.
	flight, cwnd := tcp.Sizeof(una, nxt), b.CongestionWindow()
	if b.state == bbrDrain {
		cwnd = min(cwnd, b.drainCwnd())
	}
	if flight >= cwnd || b.inRecovery {
		return 0, una, retransmit
	}
	return (cwnd - flight) / b.smss * b.smss, una, retransmit // Whole segments.
}

// PostTx times a segment of new data unless one is timed, discards the
// measurement on a resend, whose ACK is ambiguous, records how far data was
// resent and clears the resend request once a segment covering SND.UNA is
// sent. It implements [tcp.Policy].
func (b *BBR) PostTx(h *tcp.Handler, outgoing tcp.Frame) {
	b.timer.PostTx(h, outgoing)
	b.postTx(outgoing.Segment(len(outgoing.Payload())), h.ControlBlock().SendUNA(), b.nanotime())
}

func (b *BBR) postTx(seg tcp.Segment, una tcp.Value, now int64) {
	if seg.DATALEN == 0 {
		return
	}
	end := tcp.Add(seg.SEQ, seg.DATALEN)
	if seg.SEQ.LessThan(b.nxt) {
		b.timing = false
		b.dup.resent(seg.SEQ, una, b.nxt)
		if b.highRxt.LessThan(end) {
			b.highRxt = end
		}
	} else if !b.timing && !b.probing {
		b.timing, b.timedEnd, b.timedAt, b.timedDelivered = true, end, now, b.delivered
		b.timedIdle = b.idle
	}
	if b.resendUNA && seg.SEQ.LessThanEq(una) && una.LessThan(end) {
		b.resendUNA = false
	}
}

// onRoundTrip updates the model with a round trip of rtt that delivered
// octets, with inflight octets left in flight, of a segment sent after idle if
// idle.
func (b *BBR) onRoundTrip(delivered, inflight tcp.Size, rtt time.Duration, idle bool, now int64) {
	if b.minRTT == 0 || now-b.roundStart >= int64(b.minRTT) {
		b.round++
		b.roundStart = now
	}
	b.maxBw.update(bbrBwWindow, b.round, uint64(delivered)*uint64(time.Second)/uint64(rtt))
	// A min_rtt not measured for bbrProbeRTTInterval takes the next sample,
	// also a larger one (§5.5.7), and starts ProbeRTT unless the sample was
	// taken after idle, without a queue to drain.
	expired := b.minRTT != 0 && now-b.minRTTStamp > int64(bbrProbeRTTInterval)
	if b.minRTT == 0 || rtt <= b.minRTT || expired {
		b.minRTT, b.minRTTStamp = rtt, now
	}
	switch b.state {
	case bbrStartup:
		b.checkFullPipe()
	case bbrProbeBW:
		if now-b.cycleStart >= int64(b.minRTT) {
			b.cycle = (b.cycle + 1) % len(bbrProbeBWGains)
			b.pacingGain, b.cycleStart = bbrProbeBWGains[b.cycle], now
		}
	}
	b.checkProbeRTT(inflight, now, expired && !idle)
	if b.cwnd == 0 {
		b.cwnd = b.CongestionWindow()
	}
}

// checkFullPipe leaves Startup once max_bw grew by less than a quarter for
// three rounds (§5.3.1.2).
func (b *BBR) checkFullPipe() {
	if bw := b.maxBw.get(); float32(bw) >= float32(b.fullBw)*bbrFullBwThresh {
		b.fullBw, b.fullBwCount = bw, 0
		return
	}
	b.fullBwCount++
	if b.fullBwCount >= bbrFullBwCount {
		b.fullBwReached = true
		b.state, b.pacingGain = bbrDrain, bbrDrainPacingGain
	}
}

func (b *BBR) enterProbeBW(now int64) {
	b.state, b.cycle, b.cycleStart = bbrProbeBW, 0, now
	b.pacingGain, b.cwndGain = bbrProbeBWGains[0], bbrCwndGain
}

// checkProbeRTT enters ProbeRTT once min_rtt expired, and leaves it when the
// flight was down to the ProbeRTT window for bbrProbeRTTDuration (§5.3.4).
func (b *BBR) checkProbeRTT(inflight tcp.Size, now int64, expired bool) {
	if b.state != bbrProbeRTT {
		if expired {
			b.state, b.pacingGain, b.cwndGain = bbrProbeRTT, 1, bbrProbeRTTCwndGain
			b.probeRTTDoneSet, b.priorCwnd = false, b.cwnd
		}
		return
	}
	if !b.probeRTTDoneSet {
		if inflight <= b.probeRTTCwnd() {
			b.probeRTTDone, b.probeRTTDoneSet = now+int64(bbrProbeRTTDuration), true
		}
		return
	}
	if now >= b.probeRTTDone {
		b.endProbeRTT(now)
	}
}

func (b *BBR) endProbeRTT(now int64) {
	b.cwnd = max(b.cwnd, b.priorCwnd)
	if b.fullBwReached {
		b.enterProbeBW(now)
	} else {
		b.state, b.pacingGain, b.cwndGain = bbrStartup, bbrStartupPacingGain, bbrCwndGain
	}
}

// growCwnd adds acked octets to the window up to cwnd_gain times the BDP,
// before the pipe is full only while it is below that (§5.6.4.6).
func (b *BBR) growCwnd(acked tcp.Size) {
	target := max(tcp.Size(b.cwndGain*float32(b.bdp())), bbrMinPipeCwnd*b.smss)
	switch {
	case b.state == bbrProbeRTT:
		b.cwnd = min(b.cwnd, b.probeRTTCwnd())
	case b.fullBwReached:
		b.cwnd = min(b.cwnd+acked, target)
	case b.cwnd < target:
		b.cwnd += acked
	}
	b.cwnd = max(b.cwnd, bbrMinPipeCwnd*b.smss)
}

// drainCwnd returns the window Drain, which cannot pace, holds the flight to
// and ends at.
func (b *BBR) drainCwnd() tcp.Size { return max(b.bdp(), bbrMinPipeCwnd*b.smss) }

// probeRTTCwnd returns the ProbeRTT window (§5.6.4.5).
func (b *BBR) probeRTTCwnd() tcp.Size {
	return max(tcp.Size(bbrProbeRTTCwndGain*float32(b.bdp())), bbrMinPipeCwnd*b.smss)
}

// bdp returns max_bw times min_rtt in bytes.
func (b *BBR) bdp() tcp.Size {
	return tcp.Size(float32(b.maxBw.get()) * float32(b.minRTT.Seconds()))
}
