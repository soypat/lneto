package congestion

import (
	"math"
	"testing"
	"time"

	"github.com/soypat/lneto/tcp"
)

func newTestCUBIC(t *testing.T, clock *time.Time) *CUBIC {
	t.Helper()
	var c CUBIC
	err := c.Configure(CUBICConfig{
		MSS:             1000,
		InitialCwnd:     10,
		FastConvergence: true,
		Now:             func() time.Time { return *clock },
	})
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	return &c
}

func TestCUBICSlowStart(t *testing.T) {
	clock := time.Unix(0, 0)
	c := newTestCUBIC(t, &clock)
	c.ssthresh = 100 // bound slow start so we observe exponential growth.

	start := c.WindowSegments()
	segBytes := tcp.Size(1000)
	for range int(start) {
		c.onACK(segBytes, 50*time.Millisecond)
	}
	if got := c.WindowSegments(); got < 2*start-0.001 {
		t.Errorf("after one RTT of slow start cwnd=%.2f, want ~%.2f (doubled)", got, 2*start)
	}
	if !c.InSlowStart() {
		t.Error("expected still in slow start")
	}
}

func TestCUBICMultiplicativeDecrease(t *testing.T) {
	clock := time.Unix(0, 0)
	c := newTestCUBIC(t, &clock)
	c.cwnd = 100
	c.onLoss()
	if math.Abs(c.cwnd-70) > 1e-9 {
		t.Errorf("cwnd after loss=%.4f, want 70 (0.7*100)", c.cwnd)
	}
	if math.Abs(c.ssthresh-70) > 1e-9 {
		t.Errorf("ssthresh after loss=%.4f, want 70", c.ssthresh)
	}
	if math.Abs(c.wMax-100) > 1e-9 {
		t.Errorf("wMax after loss=%.4f, want 100", c.wMax)
	}
}

func TestCUBICLossEpochCoalesces(t *testing.T) {
	clock := time.Unix(0, 0)
	c := newTestCUBIC(t, &clock)
	c.cwnd = 100
	c.onLoss()
	first := c.cwnd
	c.onLoss() // same congestion event, must not cut twice.
	if c.cwnd != first {
		t.Errorf("second OnLoss in same epoch cut window again: %.4f -> %.4f", first, c.cwnd)
	}
}

// TestCUBICCurveShape verifies the defining property of CUBIC: the window
// follows W(t) = C*(t-K)^3 + W_max, reaching exactly W_max at t=K, staying
// below it (concave) before K, and exceeding it (convex) after K.
func TestCUBICCurveShape(t *testing.T) {
	clock := time.Unix(0, 0)
	c := newTestCUBIC(t, &clock)
	c.cwnd = 100
	c.onLoss() // wMax=100, cwnd=70, ssthresh=70.

	c.onACK(1000, 50*time.Millisecond) // establish epoch origin.
	if c.epoch.IsZero() {
		t.Fatal("epoch not established after congestion-avoidance ACK")
	}
	wantK := math.Cbrt((100 - 70) / cubicC)
	if math.Abs(c.k-wantK) > 1e-9 {
		t.Errorf("K=%.6f, want %.6f", c.k, wantK)
	}
	if math.Abs(c.originPoint-100) > 1e-9 {
		t.Errorf("originPoint=%.6f, want 100 (wMax)", c.originPoint)
	}
	if got := c.cubicTarget(c.k); math.Abs(got-100) > 1e-9 {
		t.Errorf("W(K)=%.6f, want 100 (=W_max)", got)
	}
	if got := c.cubicTarget(c.k * 0.5); got >= 100 {
		t.Errorf("W(K/2)=%.6f, want < 100 (concave region)", got)
	}
	if got := c.cubicTarget(c.k * 2); got <= 100 {
		t.Errorf("W(2K)=%.6f, want > 100 (convex region)", got)
	}
}

func TestCUBICRecoversTowardWmax(t *testing.T) {
	clock := time.Unix(0, 0)
	c := newTestCUBIC(t, &clock)
	c.cwnd = 100
	c.onLoss()
	const rtt = 20 * time.Millisecond
	prev := c.WindowSegments()
	for round := range 30 {
		clock = clock.Add(rtt)
		w := int(c.WindowSegments())
		for range w {
			c.onACK(1000, rtt)
		}
		cur := c.WindowSegments()
		if cur < prev-1e-6 {
			t.Fatalf("round %d: window shrank without loss: %.3f -> %.3f", round, prev, cur)
		}
		prev = cur
	}
	if prev <= 70 {
		t.Errorf("window did not recover from post-loss 70: got %.3f", prev)
	}
}

// TestCUBICTargetClamp verifies the RFC 9438 §4.2 bound: even when the cubic
// curve is far above the current window (steep concave region), the per-RTT
// growth must stay below slow start's, i.e. target is capped at 1.5*cwnd so
// one window's worth of ACKs grows cwnd by at most 50%.
func TestCUBICTargetClamp(t *testing.T) {
	clock := time.Unix(0, 0)
	c := newTestCUBIC(t, &clock)
	c.ssthresh = 10 // force congestion avoidance.
	c.cwnd = 10
	c.wMax = 10000 // cubic curve target far above cwnd.

	start := c.WindowSegments()
	// One round trip of ACKs at a large RTT (cubic curve well past K).
	const rtt = 10 * time.Second
	for range int(start) {
		c.onACK(1000, rtt)
	}
	// Reno-friendly region adds at most ~1 extra segment per RTT on top of the
	// clamped cubic growth of 0.5*cwnd.
	if got := c.WindowSegments(); got > 1.5*start+1 {
		t.Errorf("cwnd grew %.2f -> %.2f in one RTT, exceeds 1.5x slow-start bound", start, got)
	}
}

func TestCUBICOnRTO(t *testing.T) {
	clock := time.Unix(0, 0)
	c := newTestCUBIC(t, &clock)
	c.cwnd = 100
	c.ssthresh = 100
	c.onRTO()
	if c.cwnd != 1 {
		t.Errorf("cwnd after RTO=%.3f, want 1 (RFC 9438 §4.8 / RFC 5681 loss window)", c.cwnd)
	}
	if got := c.SlowStartThresh(); got != 70 {
		t.Errorf("ssthresh after RTO=%.3f, want 70 (0.7*100)", got)
	}
	if c.wMax != 0 {
		t.Errorf("wMax after RTO=%.3f, want 0 (fresh epoch with K=0, RFC 9438 §4.8)", c.wMax)
	}
	if !c.InSlowStart() {
		t.Error("RTO should re-enter slow start (cwnd < ssthresh)")
	}
}

func TestCUBICResetValidation(t *testing.T) {
	var c CUBIC
	if err := c.Configure(CUBICConfig{SlowStartThresh: -1}); err == nil {
		t.Error("expected error for negative SlowStartThresh")
	}
	if err := c.Configure(CUBICConfig{}); err != nil {
		t.Errorf("default Reset failed: %v", err)
	}
	if !c.InSlowStart() {
		t.Error("default config should start in slow start (infinite ssthresh)")
	}
	if c.CongestionWindow() != 10*defaultMSS {
		t.Errorf("default cwnd=%d bytes, want %d", c.CongestionWindow(), 10*defaultMSS)
	}
}

// TestCUBICControlEvents drives the controller through tcp.CongestionEvent
// values, exercising the event-decoding glue (acked-byte derivation, RTT
// sampling, loss signalling) without a live Handler.
func TestCUBICControlEvents(t *testing.T) {
	clock := time.Unix(0, 0)
	c := newTestCUBIC(t, &clock)
	c.ssthresh = 100

	startCwnd := c.WindowSegments()

	// Transmit 1000 bytes of new data (SEQ==SndNXT) → starts an RTT sample.
	c.Control(tcp.CongestionEvent{
		Segment: tcp.Segment{SEQ: 1000, ACK: 5000, DATALEN: 1000, Flags: tcp.FlagPSH | tcp.FlagACK},
		SndUNA:  1000, SndNXT: 1000, Tx: true,
	})
	// Peer ACKs the 1000 bytes 50ms later (SndUNA advanced to 2000).
	clock = clock.Add(50 * time.Millisecond)
	cwnd := c.Control(tcp.CongestionEvent{
		Segment: tcp.Segment{SEQ: 5000, ACK: 2000, Flags: tcp.FlagACK},
		SndUNA:  2000, SndNXT: 2000,
	})
	if c.WindowSegments() <= startCwnd {
		t.Errorf("cwnd did not grow on ACK: %.3f -> %.3f", startCwnd, c.WindowSegments())
	}
	if cwnd != c.CongestionWindow() {
		t.Errorf("Control returned %d, want CongestionWindow %d", cwnd, c.CongestionWindow())
	}
}

func TestCUBICControlRTO(t *testing.T) {
	clock := time.Unix(0, 0)
	c := newTestCUBIC(t, &clock)
	c.cwnd = 100
	c.ssthresh = 100
	// A retransmission-timeout event must collapse the window to the loss window
	// and re-enter slow start (RFC 9438 §4.8).
	c.Control(tcp.CongestionEvent{RTO: true})
	if c.cwnd != 1 {
		t.Errorf("cwnd after RTO=%.3f, want 1", c.cwnd)
	}
	if !c.InSlowStart() {
		t.Error("RTO should re-enter slow start (cwnd < ssthresh)")
	}
}

func TestCUBICControlLoss(t *testing.T) {
	clock := time.Unix(0, 0)
	c := newTestCUBIC(t, &clock)
	c.cwnd = 100
	c.ssthresh = 100
	// A received event at the duplicate-ACK threshold must cut the window.
	c.Control(tcp.CongestionEvent{
		Segment: tcp.Segment{SEQ: 5000, ACK: 1000, Flags: tcp.FlagACK},
		SndUNA:  1000, SndNXT: 9000, Dupacks: dupackLossThresh,
	})
	if c.cwnd >= 100 {
		t.Errorf("cwnd not reduced on loss event: %.3f", c.cwnd)
	}
}
