package congestion

import (
	"math"
	"testing"

	"github.com/soypat/lneto/tcp"
)

const testMSS = 100

// newCUBIC returns a controller with a small MSS so window arithmetic in the
// tests is easy to read.
func newCUBIC(t *testing.T, cfg CUBICConfig) *CUBIC {
	t.Helper()
	if cfg.MSS == 0 {
		cfg.MSS = testMSS
	}
	c := new(CUBIC)
	if err := c.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	return c
}

// ackSeg builds a pure ACK segment acknowledging up to ack.
func ackSeg(ack tcp.Value) tcp.Segment {
	return tcp.Segment{ACK: ack, Flags: tcp.FlagACK, WND: 1 << 15}
}

// dataSeg builds an outgoing data segment, as PostTx would observe it.
func dataSeg(seq tcp.Value, n tcp.Size) tcp.Segment {
	return tcp.Segment{SEQ: seq, DATALEN: n, Flags: tcp.FlagACK}
}

func TestCUBIC_ConfigureDefaults(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{})
	if got := c.WindowSegments(); got != 10 {
		t.Errorf("initial cwnd=%v segments, want the RFC 6928 value of 10", got)
	}
	if !math.IsInf(c.SlowStartThresh(), 1) {
		t.Errorf("ssthresh=%v, want +Inf (unbounded slow start)", c.SlowStartThresh())
	}
	if !c.InSlowStart() {
		t.Error("controller should start in slow start")
	}
	if err := (&CUBIC{}).Configure(CUBICConfig{SlowStartThresh: -1}); err == nil {
		t.Error("negative slow-start threshold must be rejected")
	}
}

// TestCUBIC_SlowStartGrowth verifies the window grows by one segment per
// acknowledged segment while below the threshold (RFC 9438 §4.10).
func TestCUBIC_SlowStartGrowth(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 4})
	c.PostRx(tcp.RxEvent{Segment: ackSeg(1000), Now: 0, Accepted: true}) // Establishes the acknowledgment baseline.
	if got := c.WindowSegments(); got != 4 {
		t.Fatalf("cwnd=%v after baseline ACK, want 4", got)
	}
	for i := 1; i <= 3; i++ {
		c.PostRx(tcp.RxEvent{Segment: ackSeg(tcp.Value(1000 + i*testMSS)), Now: int64(i), Accepted: true})
		want := float64(4 + i)
		if got := c.WindowSegments(); got != want {
			t.Fatalf("after %d acked segments cwnd=%v, want %v", i, got, want)
		}
	}
	if !c.InSlowStart() {
		t.Error("still below threshold, should remain in slow start")
	}
	if got, want := c.CongestionWindow(), tcp.Size(7*testMSS); got != want {
		t.Errorf("CongestionWindow=%d bytes, want %d", got, want)
	}
}

// TestCUBIC_SlowStartCapsAtThreshold verifies slow start stops at ssthresh and
// hands over to congestion avoidance.
func TestCUBIC_SlowStartCapsAtThreshold(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 4, SlowStartThresh: 6})
	c.PostRx(tcp.RxEvent{Segment: ackSeg(1000), Now: 0, Accepted: true})
	c.PostRx(tcp.RxEvent{Segment: ackSeg(1000 + 10*testMSS), Now: 1, Accepted: true}) // Acknowledge far more than the gap.
	if got := c.WindowSegments(); got != 6 {
		t.Fatalf("cwnd=%v, want it capped at ssthresh 6", got)
	}
	if c.InSlowStart() {
		t.Error("cwnd reached ssthresh, should have left slow start")
	}
}

// TestCUBIC_DuplicateACKsReduceWindow verifies three duplicate ACKs are taken
// as a congestion event: the window is cut by beta and a retransmission is
// requested on the next transmit (RFC 5681 §3.2, RFC 9438 §4.6).
func TestCUBIC_DuplicateACKsReduceWindow(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 10})
	c.PostRx(tcp.RxEvent{Segment: ackSeg(1000), Now: 0, Accepted: true})
	before := c.WindowSegments()

	for i := range dupACKThreshold - 1 {
		c.PostRx(tcp.RxEvent{Segment: ackSeg(1000), Now: int64(i + 1), Accepted: true})
		if c.WindowSegments() != before {
			t.Fatalf("window changed after %d duplicate ACKs, want a reduction only at %d", i+1, dupACKThreshold)
		}
	}
	c.PostRx(tcp.RxEvent{Segment: ackSeg(1000), Now: 10, Accepted: true}) // Third duplicate: congestion event.

	want := before * cubicBeta
	if got := c.WindowSegments(); math.Abs(got-want) > 1e-9 {
		t.Errorf("cwnd=%v after loss, want %v (cwnd*beta)", got, want)
	}
	if got := c.SlowStartThresh(); math.Abs(got-want) > 1e-9 {
		t.Errorf("ssthresh=%v after loss, want %v", got, want)
	}
	dir := c.PreTx(tcp.TxIntent{Now: 11, UNA: 1000})
	if !dir.Retransmit {
		t.Error("a retransmission must be requested after the duplicate-ACK threshold")
	}
	if dir.RetransmitFrom != 1000 {
		t.Errorf("retransmit from %d, want snd.UNA=1000 (go-back-N without SACK)", dir.RetransmitFrom)
	}
	if dir2 := c.PreTx(tcp.TxIntent{Now: 12, UNA: 1000}); dir2.Retransmit {
		t.Error("the fast retransmission must be requested only once")
	}
}

// TestCUBIC_LossEpochCoalesces verifies further duplicate ACKs within the same
// congestion event do not reduce the window again (RFC 9438 §4.6).
func TestCUBIC_LossEpochCoalesces(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 10})
	c.PostRx(tcp.RxEvent{Segment: ackSeg(1000), Now: 0, Accepted: true})
	for i := range dupACKThreshold {
		c.PostRx(tcp.RxEvent{Segment: ackSeg(1000), Now: int64(i + 1), Accepted: true})
	}
	reduced := c.WindowSegments()
	for i := range 5 {
		c.PostRx(tcp.RxEvent{Segment: ackSeg(1000), Now: int64(10 + i), Accepted: true})
	}
	if got := c.WindowSegments(); got != reduced {
		t.Errorf("cwnd=%v after further duplicates, want it unchanged at %v", got, reduced)
	}
}

// TestCUBIC_RTOCollapsesWindow verifies a retransmission timeout collapses the
// window to one segment and re-enters slow start (RFC 9438 §4.8).
func TestCUBIC_RTOCollapsesWindow(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 10})
	// Arm the retransmission timer with an outstanding data segment.
	c.PostTx(dataSeg(1000, testMSS), 0)
	before := c.WindowSegments()

	const wellPastRTO = 10 * int64(nanosPerSecond)
	dir := c.PreTx(tcp.TxIntent{Now: wellPastRTO, UNA: 1000, NXT: 1000 + testMSS})
	if !dir.Retransmit {
		t.Fatal("expected the retransmission timer to fire")
	}
	if got := c.WindowSegments(); got != 1 {
		t.Errorf("cwnd=%v after timeout, want 1 segment", got)
	}
	if got, want := c.SlowStartThresh(), before*cubicBeta; math.Abs(got-want) > 1e-9 {
		t.Errorf("ssthresh=%v after timeout, want %v", got, want)
	}
	if !c.InSlowStart() {
		t.Error("a timeout must re-enter slow start")
	}
}

// TestCUBIC_CongestionAvoidanceGrowsOverTime verifies that once past the
// threshold the window follows the cubic curve, recovering toward the window
// that last caused loss as time since the epoch increases.
func TestCUBIC_CongestionAvoidanceGrowsOverTime(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 20})
	c.PostRx(tcp.RxEvent{Segment: ackSeg(1000), Now: 0, Accepted: true})
	// Force a congestion event so W_max is set and the controller leaves slow
	// start.
	for i := range dupACKThreshold {
		c.PostRx(tcp.RxEvent{Segment: ackSeg(1000), Now: int64(i + 1), Accepted: true})
	}
	afterLoss := c.WindowSegments()
	if c.InSlowStart() {
		t.Fatal("expected congestion avoidance after the reduction")
	}

	// Acknowledge new data over an increasing time span; the cubic curve must
	// grow the window back toward W_max without exceeding it immediately.
	seq := tcp.Value(1000)
	const second = int64(nanosPerSecond)
	for i := 1; i <= 20; i++ {
		seq += testMSS
		c.PostRx(tcp.RxEvent{Segment: ackSeg(seq), Now: int64(i) * second / 4, Accepted: true})
	}
	grown := c.WindowSegments()
	if grown <= afterLoss {
		t.Errorf("cwnd=%v did not grow from %v during congestion avoidance", grown, afterLoss)
	}
	if grown > 20 {
		t.Errorf("cwnd=%v exceeded the pre-loss window of 20 too eagerly", grown)
	}
}

// TestCUBIC_HoldsNewDataAtWindow verifies the controller withholds new data
// exactly when the octets in flight reach the congestion window, which is the
// mechanism by which congestion control throttles the connection.
func TestCUBIC_HoldsNewDataAtWindow(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 3})
	cwnd := c.CongestionWindow()
	if cwnd != 3*testMSS {
		t.Fatalf("CongestionWindow=%d, want %d", cwnd, 3*testMSS)
	}
	if dir := c.PreTx(tcp.TxIntent{Now: 1, InFlight: cwnd - 1}); dir.HoldNew {
		t.Error("must not hold new data below the congestion window")
	}
	if dir := c.PreTx(tcp.TxIntent{Now: 2, InFlight: cwnd}); !dir.HoldNew {
		t.Error("must hold new data once in flight reaches the congestion window")
	}
	if dir := c.PreTx(tcp.TxIntent{Now: 3, InFlight: cwnd + 1}); !dir.HoldNew {
		t.Error("must hold new data above the congestion window")
	}
}

// TestCUBIC_AdoptsPeerMSS verifies the window is denominated in the peer's
// advertised MSS once it is known.
func TestCUBIC_AdoptsPeerMSS(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 4})
	if got, want := c.CongestionWindow(), tcp.Size(4*testMSS); got != want {
		t.Fatalf("CongestionWindow=%d before the peer MSS is known, want %d", got, want)
	}
	c.PreTx(tcp.TxIntent{Now: 1, MSS: 500})
	if got, want := c.CongestionWindow(), tcp.Size(4*500); got != want {
		t.Errorf("CongestionWindow=%d after learning MSS=500, want %d", got, want)
	}
}

// TestCUBIC_ResetRestoresConfiguration verifies Reset returns the controller to
// its configured initial state so one value can be reused across connections.
func TestCUBIC_ResetRestoresConfiguration(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 8})
	c.PostRx(tcp.RxEvent{Segment: ackSeg(1000), Now: 0, Accepted: true})
	for i := range dupACKThreshold {
		c.PostRx(tcp.RxEvent{Segment: ackSeg(1000), Now: int64(i + 1), Accepted: true})
	}
	if c.WindowSegments() == 8 {
		t.Fatal("test needs a modified window before Reset")
	}
	c.Reset()
	if got := c.WindowSegments(); got != 8 {
		t.Errorf("cwnd=%v after Reset, want the configured 8", got)
	}
	if !c.InSlowStart() {
		t.Error("Reset must restore slow start")
	}
	if c.NextDeadline() != 0 {
		t.Error("Reset must clear the retransmission deadline")
	}
}

// TestCUBIC_ReactsToECN verifies a congestion mark echoed by the peer reduces the
// window as a loss would.
//
// This is the whole point of asking the path to mark instead of drop: the signal is
// acted on identically, but it arrives a round trip earlier and costs no
// retransmission. A controller that negotiated ECN and ignored ECE would have
// congestion reported to it and respond to none of it, which is worse than never
// asking — the router marked the packet instead of dropping it, so the drop that would
// have forced a reaction never happened.
func TestCUBIC_ReactsToECN(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{})
	// Grow the window so a reduction is visible.
	c.PostRx(tcp.RxEvent{Segment: ackSeg(1000), Now: 0, Accepted: true})
	for i := 1; i <= 8; i++ {
		c.PostRx(tcp.RxEvent{Segment: ackSeg(tcp.Value(1000 + i*testMSS)), Now: int64(i), Accepted: true})
	}
	before := c.WindowSegments()
	if before <= cubicMinCwnd {
		t.Fatalf("window is %v segments, too small for a reduction to be visible", before)
	}

	// An acknowledgement echoing congestion.
	ece := ackSeg(tcp.Value(1000 + 9*testMSS))
	ece.Flags |= tcp.FlagECE
	c.PostRx(tcp.RxEvent{Segment: ece, Now: 9, Accepted: true})
	after := c.WindowSegments()
	if after >= before {
		t.Errorf("window is %v segments after a congestion mark, was %v: the mark was ignored", after, before)
	}
	if !c.InSlowStart() && c.SlowStartThresh() >= before {
		t.Errorf("slow-start threshold %v was not lowered below the previous window %v", c.SlowStartThresh(), before)
	}

	// Coalesced per event, like a burst of duplicate acknowledgements: a second mark
	// in the same epoch must not collapse the window again.
	reduced := c.WindowSegments()
	ece2 := ackSeg(tcp.Value(1000 + 10*testMSS))
	ece2.Flags |= tcp.FlagECE
	c.PostRx(tcp.RxEvent{Segment: ece2, Now: 10, Accepted: true})
	if got := c.WindowSegments(); got < reduced {
		t.Errorf("window fell again to %v on a second mark in the same event, was %v", got, reduced)
	}
}

// TestCUBIC_IgnoresECNOnRefusedSegment verifies a congestion mark on a segment the
// connection refused does not reduce the window, so a forged or stale segment cannot
// throttle the connection.
func TestCUBIC_IgnoresECNOnRefusedSegment(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{})
	c.PostRx(tcp.RxEvent{Segment: ackSeg(1000), Now: 0, Accepted: true})
	for i := 1; i <= 6; i++ {
		c.PostRx(tcp.RxEvent{Segment: ackSeg(tcp.Value(1000 + i*testMSS)), Now: int64(i), Accepted: true})
	}
	before := c.WindowSegments()
	ece := ackSeg(tcp.Value(1000 + 7*testMSS))
	ece.Flags |= tcp.FlagECE
	c.PostRx(tcp.RxEvent{Segment: ece, Now: 7, Accepted: false})
	if got := c.WindowSegments(); got != before {
		t.Errorf("window moved to %v on a refused segment's congestion mark, was %v", got, before)
	}
}

// TestCUBIC_ECNReactionRateLimited verifies several congestion marks within one round
// trip reduce the window once, and that a mark a round trip later reduces it again.
//
// A marked window produces a mark on every acknowledgement in it, all reporting the
// same congestion event. Reacting to each would halve the window repeatedly and drive
// it far below what the path carries — worse than the drop the mark replaced. RFC 3168
// §6.1.2 permits one reaction per window, or more loosely per round trip.
func TestCUBIC_ECNReactionRateLimited(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{})
	// Establish a round-trip estimate and a window worth reducing.
	const rtt = int64(50 * 1e6) // 50ms in nanoseconds.
	c.PostTx(dataSeg(1000, testMSS), 0)
	c.PostRx(tcp.RxEvent{Segment: ackSeg(1000 + testMSS), Now: rtt, Accepted: true})
	for i := 2; i <= 9; i++ {
		c.PostRx(tcp.RxEvent{Segment: ackSeg(tcp.Value(1000 + i*testMSS)), Now: rtt, Accepted: true})
	}
	if c.SmoothedRTT() <= 0 {
		t.Fatal("no round-trip estimate to rate-limit against")
	}
	before := c.WindowSegments()

	// Three marks arriving inside one round trip: one congestion event.
	mark := func(seq int, now int64) {
		seg := ackSeg(tcp.Value(1000 + seq*testMSS))
		seg.Flags |= tcp.FlagECE
		c.PostRx(tcp.RxEvent{Segment: seg, Now: now, Accepted: true})
	}
	mark(10, rtt)
	afterFirst := c.WindowSegments()
	if afterFirst >= before {
		t.Fatalf("window %v not reduced by a congestion mark, was %v", afterFirst, before)
	}
	mark(11, rtt+c.SmoothedRTT()/4)
	mark(12, rtt+c.SmoothedRTT()/2)
	if got := c.WindowSegments(); got < afterFirst {
		t.Errorf("window fell to %v on further marks in the same round trip, want no lower than %v", got, afterFirst)
	}

	// A mark a full round trip later is a new event and is acted on.
	settled := c.WindowSegments()
	mark(13, rtt+2*c.SmoothedRTT())
	if got := c.WindowSegments(); got >= settled {
		t.Errorf("window %v not reduced by a mark a round trip later, was %v", got, settled)
	}
}
