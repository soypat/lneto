package congestion

import (
	"errors"
	"math"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/sack"
	"github.com/soypat/lneto/tcp/timestamps"
)

const (
	testMSS = 100
	// connMTU makes both sides advertise an MSS of testMSS.
	connMTU      = tcpHeaderLen + testMSS
	connBuf      = 8000
	tcpHeaderLen = 20
)

// newCUBIC returns a controller with an SMSS of testMSS at SND.UNA 1000.
func newCUBIC(t *testing.T, cfg CUBICConfig) *CUBIC {
	t.Helper()
	if cfg.Nanotime == nil {
		cfg.Nanotime = func() int64 { return 0 }
	}
	c := new(CUBIC)
	if err := c.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	c.smss, c.una = testMSS, 1000
	return c
}

// transmit runs the transmit hook with flight octets outstanding and queued
// octets of new data.
func transmit(c *CUBIC, flight, queued tcp.Size, now int64) {
	c.preTx(c.una, c.una+tcp.Value(flight), queued, c.lastExpirations, false, now)
}

// ack acknowledges acked octets of new data after a transmit that found the
// window full.
func ack(c *CUBIC, acked tcp.Size, now int64) {
	nxt := c.una + tcp.Value(max(c.CongestionWindow(), acked))
	transmit(c, tcp.Sizeof(c.una, nxt), 0, now)
	c.postRx(c.una+tcp.Value(acked), nxt, false, false, now)
}

// loss reports three duplicate ACKs, the third owing a fast retransmit, with
// the window full.
func loss(c *CUBIC, now int64) {
	nxt := c.una + tcp.Value(c.CongestionWindow())
	for i := range 3 {
		c.postRx(c.una, nxt, i == 2, true, now)
	}
}

func TestCUBIC_Configure(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{})
	if c.WindowSegments() != 10 || !math.IsInf(float64(c.SlowStartThresh()), 1) {
		t.Errorf("cwnd=%v ssthresh=%v, want 10 and +Inf", c.WindowSegments(), c.SlowStartThresh())
	}
	nanotime := func() int64 { return 0 }
	for _, tc := range []struct {
		cfg  CUBICConfig
		want error
	}{
		{cfg: CUBICConfig{}, want: lneto.ErrMissingHALConfig},
		{cfg: CUBICConfig{Nanotime: nanotime, SlowStartThresh: -1}, want: lneto.ErrInvalidConfig},
	} {
		if err := new(CUBIC).Configure(tc.cfg); !errors.Is(err, tc.want) {
			t.Errorf("Configure(%+v) = %v, want %v", tc.cfg, err, tc.want)
		}
	}
}

// TestCUBIC_RefusedProbe verifies a fast retransmit owed for the zero-window
// probe octet the peer refused is no loss.
func TestCUBIC_RefusedProbe(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 10})
	una := c.una
	c.preTx(una, una, 0, 0, true, 0)
	c.postTx(tcp.Segment{SEQ: una, DATALEN: 1, Flags: tcp.FlagACK}, una) // The probe.
	for i := range 3 {
		c.postRx(una, una+1+3*testMSS, i == 2, true, 1)
	}
	if got := c.WindowSegments(); got != 10 {
		t.Errorf("cwnd=%v after the refused probe was owed, want 10", got)
	}
}

// TestCUBIC_SlowStart verifies slow start grows by at most one segment per
// ACK (RFC 5681 §3.1), up to ssthresh, and only if the last transmit had data
// in flight or queued to fill the window, also for ACKs handled one after
// another.
func TestCUBIC_SlowStart(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ssthresh float32
		acks     int
		flight   tcp.Size // At the transmit before the ACKs.
		queued   tcp.Size
		want     float32
	}{
		{name: "one-segment-per-ack", acks: 2, flight: 4 * testMSS, want: 6},
		{name: "capped-at-ssthresh", ssthresh: 4.5, acks: 1, flight: 4 * testMSS, want: 4.5},
		{name: "queued", acks: 1, flight: 2 * testMSS, queued: 2 * testMSS, want: 5},
		{name: "application-limited", acks: 1, flight: 2 * testMSS, queued: testMSS / 2, want: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCUBIC(t, CUBICConfig{InitialCwnd: 4, SlowStartThresh: tc.ssthresh})
			nxt := c.una + tcp.Value(tc.flight)
			transmit(c, tc.flight, tc.queued, 1)
			for range tc.acks {
				c.postRx(c.una+2*testMSS, nxt, false, false, 1) // Two segments.
			}
			if got := c.WindowSegments(); got != tc.want {
				t.Errorf("cwnd=%v, want %v", got, tc.want)
			}
		})
	}
}

// TestCUBIC_Loss verifies a fast retransmit cuts the window by beta, at
// least to 2 segments, sets W_max with or without fast convergence (§4.6,
// §4.7) and requests a resend of SND.UNA, not limited by the window, until one
// is sent.
func TestCUBIC_Loss(t *testing.T) {
	for _, tc := range []struct {
		name            string
		cwnd, wMax      float32
		fastConvergence bool
		wantCwnd        float32
		wantWMax        float32
	}{
		{name: "cut-by-beta", cwnd: 10, wantCwnd: 7, wantWMax: 10},
		{name: "below-w-max", cwnd: 8, wMax: 10, wantCwnd: 5.6, wantWMax: 8},
		{name: "fast-convergence", cwnd: 8, wMax: 10, fastConvergence: true, wantCwnd: 5.6, wantWMax: 6.8},
		{name: "minimum-window", cwnd: 2, wantCwnd: 2, wantWMax: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCUBIC(t, CUBICConfig{FastConvergence: tc.fastConvergence})
			c.cwnd, c.wMax = tc.cwnd, tc.wMax
			una, nxt := c.una, c.una+tcp.Value(c.CongestionWindow())
			loss(c, 1)
			if math.Abs(float64(c.cwnd-tc.wantCwnd)) > 1e-6 || c.ssthresh != c.cwnd || math.Abs(float64(c.wMax-tc.wantWMax)) > 1e-6 {
				t.Errorf("cwnd=%v ssthresh=%v W_max=%v, want %v, %v, %v", c.cwnd, c.ssthresh, c.wMax, tc.wantCwnd, tc.wantCwnd, tc.wantWMax)
			}
			for range 2 {
				if _, from, rtx := c.preTx(una, nxt, 0, 0, false, 0); !rtx || from != una {
					t.Fatalf("preTx = rtx %v from %d; want a resend from %d", rtx, from, una)
				}
			}
			c.postTx(tcp.Segment{SEQ: nxt, DATALEN: testMSS, Flags: tcp.FlagACK}, una)
			if _, _, rtx := c.preTx(una, nxt+testMSS, 0, 0, false, 0); !rtx {
				t.Fatal("new data cleared the resend request")
			}
			c.postTx(tcp.Segment{SEQ: una, DATALEN: testMSS, Flags: tcp.FlagACK}, una)
			if _, _, rtx := c.preTx(una, nxt+testMSS, 0, 0, false, 0); rtx {
				t.Error("resend requested again after it was sent")
			}
		})
	}
}

// TestCUBIC_ResendIsLoss verifies a resend of data outside recovery, as by
// another Policy, cuts the window, and a zero-window probe resent does not.
func TestCUBIC_ResendIsLoss(t *testing.T) {
	for _, tc := range []struct {
		name    string
		probing bool
		want    float32
	}{
		{name: "resend", want: 7},
		{name: "zero-window-probe", probing: true, want: 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCUBIC(t, CUBICConfig{InitialCwnd: 10})
			c.preTx(c.una, c.una+10*testMSS, 0, 0, tc.probing, 0)
			c.postTx(tcp.Segment{SEQ: c.una, DATALEN: testMSS, Flags: tcp.FlagACK}, c.una)
			if got := c.WindowSegments(); got != tc.want {
				t.Errorf("cwnd=%v, want %v", got, tc.want)
			}
		})
	}
}

// TestCUBIC_Recovery verifies losses during recovery do not cut the window
// again, partial ACKs resend SND.UNA without growing it, the full ACK ends
// recovery without growing it, and duplicate ACKs cut it again only once
// SND.UNA passed the data sent before the loss (RFC 6582 §3.2).
func TestCUBIC_Recovery(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 10})
	recover := c.una + tcp.Value(c.CongestionWindow())
	loss(c, 1)
	reduced := c.WindowSegments()
	c.preTx(c.una, recover, 0, 0, false, 1)
	c.postTx(tcp.Segment{SEQ: c.una, DATALEN: testMSS, Flags: tcp.FlagACK}, c.una) // The resend.
	ack(c, testMSS, 2)                                                             // Partial ACK.
	if _, from, rtx := c.preTx(c.una, recover, 0, 0, false, 0); !rtx || from != c.una {
		t.Fatalf("no resend of SND.UNA %d after a partial ACK", c.una)
	}
	loss(c, 3)
	if got := c.WindowSegments(); got != reduced {
		t.Fatalf("cwnd=%v during recovery, want %v", got, reduced)
	}
	ack(c, tcp.Sizeof(c.una, recover), 4) // Full ACK.
	if _, _, rtx := c.preTx(c.una, c.una, 0, 0, false, 0); rtx || c.WindowSegments() != reduced {
		t.Fatalf("resend %v, cwnd=%v after the full ACK; want none and %v", rtx, c.WindowSegments(), reduced)
	}
	c.preTx(c.una, recover+testMSS, 0, 0, false, 5)
	c.postTx(tcp.Segment{SEQ: c.una, DATALEN: testMSS, Flags: tcp.FlagACK}, c.una) // As by tcp/sack.
	loss(c, 5)                                                                     // At the data sent before the loss.
	if got := c.WindowSegments(); got != reduced {
		t.Fatalf("cwnd=%v after duplicate ACKs and a resend at %d, want %v", got, recover, reduced)
	}
	ack(c, testMSS, 6)
	loss(c, 7)
	if got := c.WindowSegments(); got >= reduced {
		t.Errorf("cwnd=%v after a loss beyond the resend, want below %v", got, reduced)
	}
}

// TestCUBIC_PartialACKAfterResends verifies a partial ACK resends SND.UNA
// only if it was not resent since the loss, as by tcp/sack (RFC 6675 HighRxt).
func TestCUBIC_PartialACKAfterResends(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 10})
	recover := c.una + tcp.Value(c.CongestionWindow())
	loss(c, 1)
	c.preTx(c.una, recover, 0, 0, false, 1)
	for i := range 3 { // SND.UNA and the two holes above it.
		c.postTx(tcp.Segment{SEQ: c.una + tcp.Value(i*testMSS), DATALEN: testMSS, Flags: tcp.FlagACK}, c.una)
	}
	ack(c, testMSS, 2)
	if _, _, rtx := c.preTx(c.una, recover, 0, 0, false, 2); rtx {
		t.Errorf("resend of SND.UNA %d, already resent", c.una)
	}
	ack(c, 2*testMSS, 3)
	if _, from, rtx := c.preTx(c.una, recover, 0, 0, false, 3); !rtx || from != c.una {
		t.Errorf("no resend of SND.UNA %d, not resent yet", c.una)
	}
}

// TestCUBIC_AnsweredCopies verifies duplicate ACKs answering copies of a
// resend do not count toward a fast retransmit, whose resend is a copy too,
// while a resend of other data is still a loss.
func TestCUBIC_AnsweredCopies(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 10})
	recover := c.una + tcp.Value(c.CongestionWindow())
	loss(c, 1)
	reduced := c.WindowSegments()
	c.preTx(c.una, recover+2*testMSS, 0, 0, false, 1)
	resend := tcp.Segment{SEQ: c.una, DATALEN: testMSS, Flags: tcp.FlagACK}
	c.postTx(resend, c.una)
	for range 2 {
		c.postRx(c.una, recover, true, true, 1)
		c.postTx(resend, c.una)
	}
	nxt := recover + 4*testMSS
	c.postRx(recover+testMSS, nxt, false, false, 2) // Before the copies.
	for i := range 3 {
		c.postRx(c.una, nxt, i == 2, true, 3)
	}
	c.preTx(c.una, nxt, 0, 0, false, 3)
	c.postTx(tcp.Segment{SEQ: c.una, DATALEN: testMSS, Flags: tcp.FlagACK}, c.una)
	if got := c.WindowSegments(); got != reduced {
		t.Fatalf("cwnd=%v after duplicate ACKs answering copies, want %v", got, reduced)
	}
	c.postTx(tcp.Segment{SEQ: c.una + testMSS, DATALEN: testMSS, Flags: tcp.FlagACK}, c.una)
	if got := c.WindowSegments(); got >= reduced {
		t.Errorf("cwnd=%v after a resend of other data, want below %v", got, reduced)
	}
}

// TestCUBIC_UnansweredCopies verifies that once SND.UNA passes the copies
// of resends, duplicate ACKs no longer count as their answers.
func TestCUBIC_UnansweredCopies(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 10})
	recover := c.una + tcp.Value(c.CongestionWindow())
	loss(c, 1)
	reduced := c.WindowSegments()
	c.preTx(c.una, recover, 0, 0, false, 1)
	resend := tcp.Segment{SEQ: c.una, DATALEN: testMSS, Flags: tcp.FlagACK}
	c.postTx(resend, c.una)
	for range 2 { // Lost copies.
		c.postRx(c.una, recover, true, true, 1)
		c.postTx(resend, c.una)
	}
	ack(c, tcp.Sizeof(c.una, recover)+testMSS, 2)
	loss(c, 3)
	if got := c.WindowSegments(); got >= reduced {
		t.Errorf("cwnd=%v after a loss beyond the copies, want below %v", got, reduced)
	}
}

// TestCUBIC_RecoverWraps verifies a loss after SND.UNA passed the data sent
// before the last one cuts the window also 3GB later, when sequence numbers
// have wrapped past it.
func TestCUBIC_RecoverWraps(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 10})
	recover := c.una + tcp.Value(c.CongestionWindow())
	loss(c, 1)
	ack(c, tcp.Sizeof(c.una, recover)+testMSS, 2)
	reduced := c.WindowSegments()
	c.una += 3e9
	loss(c, 3)
	if got := c.WindowSegments(); got >= reduced {
		t.Errorf("cwnd=%v after a loss 3GB later, want below %v", got, reduced)
	}
}

// TestCUBIC_Timeout verifies a timeout collapses the window to one segment,
// clears W_max (§4.8) and reduces ssthresh only on the first loss of a
// recovery, and that a zero-window probe timing out changes nothing.
func TestCUBIC_Timeout(t *testing.T) {
	for _, tc := range []struct {
		name         string
		loss         bool // Fast retransmit before the timeouts.
		timeouts     int
		probing      bool
		wantCwnd     float32
		wantSsthresh float32
		wantWMax     float32 // From 12 before.
	}{
		{name: "first", timeouts: 1, wantCwnd: 1, wantSsthresh: 7},
		{name: "repeated", timeouts: 2, wantCwnd: 1, wantSsthresh: 7},
		{name: "in-recovery", loss: true, timeouts: 1, wantCwnd: 1, wantSsthresh: 7},
		{name: "zero-window-probe", timeouts: 2, probing: true, wantCwnd: 10, wantSsthresh: float32(math.Inf(1)), wantWMax: 12},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCUBIC(t, CUBICConfig{InitialCwnd: 10})
			c.wMax = 12
			nxt := c.una + tcp.Value(c.CongestionWindow())
			if tc.loss {
				loss(c, 0)
				c.wMax = 12
			}
			for i := range tc.timeouts {
				c.preTx(c.una, nxt, 0, uint32(i+1), tc.probing, 0)
			}
			if c.WindowSegments() != tc.wantCwnd || math.Abs(float64(c.SlowStartThresh()-tc.wantSsthresh)) > 1e-6 || c.wMax != tc.wantWMax {
				t.Errorf("cwnd=%v ssthresh=%v W_max=%v, want %v, %v, %v", c.WindowSegments(), c.SlowStartThresh(), c.wMax, tc.wantCwnd, tc.wantSsthresh, tc.wantWMax)
			}
		})
	}
}

// TestCUBIC_CongestionAvoidance verifies one ACK of a segment in congestion
// avoidance against the formulas of §4.2-§4.5, at the start of an epoch with
// t = RTT: the concave and convex regions, the 1.5*cwnd target bound and the
// Reno-friendly region with alpha switching to 1 at cwnd_prior.
func TestCUBIC_CongestionAvoidance(t *testing.T) {
	const s = time.Second
	for _, tc := range []struct {
		name                  string
		cwnd, wMax, cwndPrior float64
		rtt                   time.Duration
	}{
		{name: "concave", cwnd: 7, wMax: 10, cwndPrior: 10, rtt: s},
		{name: "convex", cwnd: 10, wMax: 10, cwndPrior: 12, rtt: 2 * s},
		{name: "target-bound", cwnd: 10, wMax: 10, cwndPrior: 12, rtt: 5 * s},
		{name: "reno-friendly", cwnd: 7, wMax: 10, cwndPrior: 10},
		{name: "reno-friendly-alpha-1", cwnd: 7, wMax: 10, cwndPrior: 7},
		{name: "after-loss-convergence", cwnd: 5, wMax: 7, cwndPrior: 7, rtt: s / 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCUBIC(t, CUBICConfig{})
			c.Timer().ObserveRTT(tc.rtt)
			c.cwnd, c.ssthresh, c.wMax, c.cwndPrior = float32(tc.cwnd), float32(tc.cwnd), float32(tc.wMax), float32(tc.cwndPrior)
			ack(c, testMSS, 0)

			k, origin := 0.0, tc.cwnd
			if tc.cwnd < tc.wMax {
				k, origin = math.Cbrt((tc.wMax-tc.cwnd)/0.4), tc.wMax
			}
			wCubic := origin + 0.4*math.Pow(tc.rtt.Seconds()-k, 3)
			target := min(max(wCubic, tc.cwnd), 1.5*tc.cwnd)
			cwnd := tc.cwnd + (target-tc.cwnd)/tc.cwnd
			alpha := 3 * (1 - 0.7) / (1 + 0.7)
			if tc.cwnd >= tc.cwndPrior {
				alpha = 1
			}
			want := max(cwnd, tc.cwnd+alpha/cwnd)
			if got := c.WindowSegments(); math.Abs(float64(got)-want) > 1e-5 {
				t.Errorf("cwnd=%v, want %v", got, want)
			}
		})
	}
}

// TestCUBIC_ApplicationLimitedTime verifies time the window is not full, or
// nothing is in flight, does not advance the cubic function (§4.2, §5.8): a
// controller pausing 10s grows as one that does not.
func TestCUBIC_ApplicationLimitedTime(t *testing.T) {
	const second = int64(nanosPerSecond)
	for _, tc := range []struct {
		name  string
		pause func(c *CUBIC) // At 1s.
	}{
		{name: "window-not-full", pause: func(c *CUBIC) {
			transmit(c, 2*testMSS, 0, second)
			c.postRx(c.una+testMSS, c.una+2*testMSS, false, false, second)
		}},
		{name: "nothing-in-flight", pause: func(c *CUBIC) {
			cwnd := c.CongestionWindow()
			transmit(c, cwnd, 0, second)
			c.postRx(c.una+tcp.Value(cwnd), c.una+tcp.Value(cwnd), false, false, second)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			busy, idle := newCUBIC(t, CUBICConfig{InitialCwnd: 20}), newCUBIC(t, CUBICConfig{InitialCwnd: 20})
			for _, c := range []*CUBIC{busy, idle} {
				loss(c, 0)
				ack(c, 20*testMSS, 0) // Full ACK.
				ack(c, testMSS, 0)    // Starts the epoch.
				tc.pause(c)
			}
			for i := int64(1); i <= 4; i++ {
				ack(busy, testMSS, second+i*second)
				ack(idle, testMSS, 11*second+i*second)
			}
			if busy.WindowSegments() != idle.WindowSegments() {
				t.Errorf("cwnd=%v after a 10s pause, want %v as without", idle.WindowSegments(), busy.WindowSegments())
			}
		})
	}
}

// TestCUBIC_EpochAfterLoss verifies a loss ends the cubic epoch: the next
// stage starts from the reduced window as a fresh controller in the same
// state does (§4.2).
func TestCUBIC_EpochAfterLoss(t *testing.T) {
	const second = int64(nanosPerSecond)
	fresh := newCUBIC(t, CUBICConfig{})
	fresh.cwnd, fresh.ssthresh, fresh.wMax, fresh.cwndPrior = 7, 7, 10, 10
	lossy := newCUBIC(t, CUBICConfig{})
	lossy.ssthresh = 10
	ack(lossy, testMSS, 0) // Starts an epoch.
	lossy.cwnd = 10
	loss(lossy, 50*second)
	ack(lossy, 10*testMSS, 50*second) // Full ACK.
	ack(fresh, testMSS, 100*second)
	ack(lossy, testMSS, 100*second)
	if fresh.WindowSegments() != lossy.WindowSegments() {
		t.Errorf("cwnd=%v after a loss, want %v as a fresh controller", lossy.WindowSegments(), fresh.WindowSegments())
	}
}

// TestCUBIC_LimitedTransmit verifies the first two duplicate ACKs each allow
// one more segment until an ACK of new data or a loss, and none count during
// recovery (RFC 3042).
func TestCUBIC_LimitedTransmit(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 3})
	nxt := c.una + 3*testMSS
	for i, want := range []tcp.Size{testMSS, 2 * testMSS, 2 * testMSS} {
		c.postRx(c.una, nxt, false, true, 1)
		if limit, _, _ := c.preTx(c.una, nxt, 0, 0, false, 0); limit != want {
			t.Errorf("limit=%d after %d duplicate ACKs, want %d", limit, i+1, want)
		}
	}
	c.postRx(c.una+testMSS, nxt, false, false, 2)
	if limit, _, _ := c.preTx(c.una, nxt, 0, 0, false, 0); limit != c.CongestionWindow()-tcp.Sizeof(c.una, nxt) {
		t.Errorf("limit=%d after an ACK of new data, want the window's", limit)
	}
	c.postRx(c.una, nxt, false, true, 3)
	loss(c, 4)
	c.postRx(c.una, nxt, false, true, 5)
	if c.dup.n != 0 {
		t.Errorf("%d duplicate ACKs counted in recovery, want 0", c.dup.n)
	}
}

// TestCUBIC_LimitsNewData verifies the new-data limit is what the window, in
// whole segments, leaves after the octets in flight.
func TestCUBIC_LimitsNewData(t *testing.T) {
	c := newCUBIC(t, CUBICConfig{InitialCwnd: 3})
	c.cwnd = 3.8
	cwnd := c.CongestionWindow()
	if cwnd != 3*testMSS {
		t.Fatalf("CongestionWindow=%d for 3.8 segments, want %d", cwnd, 3*testMSS)
	}
	for _, tc := range []struct{ flight, want tcp.Size }{
		{flight: 0, want: cwnd},
		{flight: cwnd - 1, want: 1},
		{flight: cwnd, want: 0},
		{flight: cwnd + 1, want: 0},
	} {
		if limit, _, _ := c.preTx(c.una, c.una+tcp.Value(tc.flight), 0, 0, false, 0); limit != tc.want {
			t.Errorf("limit=%d with %d in flight, want %d", limit, tc.flight, tc.want)
		}
	}
}

// pairConfig configures connPair.
type pairConfig struct {
	cwnd      tcp.Size // Initial window of the client.
	sack      bool     // SACK on both sides.
	ts        bool     // Timestamps on both sides.
	serverMTU int      // Server's MTU in the handshake, connMTU if zero.
}

// connPair returns two established handlers with a CUBIC controller and its
// timer on the client, a packet buffer and the clock, which advances 1ms per
// read.
func connPair(t *testing.T, cfg pairConfig) (client, server *tcp.Handler, cubic *CUBIC, packet []byte, clock *int64) {
	t.Helper()
	clock = new(int64)
	nanotime := func() int64 {
		*clock += int64(nanosPerSecond) / 1000
		return *clock
	}
	cubic = new(CUBIC)
	if err := cubic.Configure(CUBICConfig{Nanotime: nanotime, InitialCwnd: cfg.cwnd}); err != nil {
		t.Fatal(err)
	}
	client, server = new(tcp.Handler), new(tcp.Handler)
	// The server holds up to 8 segments out of order; the client queues as
	// many as its buffer holds.
	for h, packets := range map[*tcp.Handler]int{client: connBuf / testMSS, server: 8} {
		if err := h.SetBuffers(make([]byte, connBuf), make([]byte, connBuf), packets); err != nil {
			t.Fatal(err)
		}
	}
	client.SetPolicy(cubic)
	switch {
	case cfg.sack:
		client.SetPolicy(tcp.Policies{new(sack.Policy), cubic})
		server.SetPolicy(new(sack.Policy))
	case cfg.ts:
		var cts, sts timestamps.Policy
		if err := cts.Configure(timestamps.Config{Nanotime: nanotime, Timer: cubic.Timer()}); err != nil {
			t.Fatal(err)
		}
		if err := sts.Configure(timestamps.Config{Nanotime: nanotime}); err != nil {
			t.Fatal(err)
		}
		client.SetPolicy(tcp.Policies{&cts, cubic})
		server.SetPolicy(&sts)
	}
	if err := server.OpenListen(80, 0); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenActive(1234, 80, 0); err != nil {
		t.Fatal(err)
	}
	packet = make([]byte, connMTU)
	relay(t, client, server, packet)                                    // SYN
	relay(t, server, client, make([]byte, max(cfg.serverMTU, connMTU))) // SYN-ACK
	relay(t, client, server, packet)                                    // ACK
	if client.State() != tcp.StateEstablished || server.State() != tcp.StateEstablished {
		t.Fatalf("handshake failed: client=%s server=%s", client.State(), server.State())
	}
	return client, server, cubic, packet, clock
}

// relay moves one segment from one handler to the other, returning its length.
func relay(t *testing.T, from, to *tcp.Handler, packet []byte) int {
	t.Helper()
	n := sendOnly(t, from, packet)
	if n == 0 {
		return 0
	}
	if err := to.Recv(packet[:n]); err != nil {
		t.Fatal("recv:", err)
	}
	return n
}

// sendOnly transmits without delivering.
func sendOnly(t *testing.T, h *tcp.Handler, packet []byte) int {
	t.Helper()
	clear(packet)
	n, err := h.Send(packet)
	if err != nil {
		t.Fatal("send:", err)
	}
	return n
}

// TestCUBIC_SMSS verifies the window counts segments of the smaller of the
// peer's MSS and ours, without the options of the Policies before it (RFC
// 5681 §2).
func TestCUBIC_SMSS(t *testing.T) {
	var c CUBIC
	if c.setSMSS(0, 1000); c.smss != defaultMSS {
		t.Errorf("SMSS=%d without the peer's MSS, want %d", c.smss, defaultMSS)
	}
	for _, tc := range []struct {
		name string
		cfg  pairConfig
		want tcp.Size
	}{
		{name: "peer-larger", cfg: pairConfig{serverMTU: 1500}, want: testMSS},
		{name: "timestamps", cfg: pairConfig{ts: true}, want: testMSS - 12},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _, cubic, packet, _ := connPair(t, tc.cfg)
			if _, err := client.Write(make([]byte, testMSS)); err != nil {
				t.Fatal("write:", err)
			}
			sendOnly(t, client, packet)
			if got := cubic.CongestionWindow(); got != 10*tc.want {
				t.Errorf("CongestionWindow=%d, want 10 segments of %d", got, tc.want)
			}
		})
	}
}

// TestCUBIC_LimitsConnection verifies a connection sends no more than the
// window and resumes once data is acknowledged.
func TestCUBIC_LimitsConnection(t *testing.T) {
	client, server, cubic, packet, _ := connPair(t, pairConfig{cwnd: 2})
	if _, err := client.Write(make([]byte, connBuf/2)); err != nil {
		t.Fatal("write:", err)
	}
	var sent int
	for n := sendOnly(t, client, packet); n != 0; n = sendOnly(t, client, packet) {
		sent += n - tcpHeaderLen
		if err := server.Recv(packet[:n]); err != nil {
			t.Fatal(err)
		}
	}
	if sent != 2*testMSS {
		t.Fatalf("sent %d octets with a window of %d", sent, 2*testMSS)
	}
	held := client.BufferedUnsent()
	relay(t, server, client, packet)
	if cubic.WindowSegments() <= 2 || sendOnly(t, client, packet) == 0 || client.BufferedUnsent() >= held {
		t.Error("window did not grow and let held data out after the ACK")
	}
}

// TestCUBIC_LossRecovery drops new-data segments and ACKs on a connection and
// checks the data is repaired without a timeout, with ssthresh cut once: by
// fast retransmit, with Limited Transmit for a small window (RFC 3042), with
// partial ACKs for consecutive losses (RFC 6582 §3.2), by a SACK resend
// before the third duplicate ACK, and with more data in flight, whose
// duplicate ACKs answering copies of resends are no loss.
func TestCUBIC_LossRecovery(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cwnd     tcp.Size
		segments int
		lost     []int // Indices of the new-data segments dropped.
		lostACKs []int // Indices of the ACKs dropped.
		sack     bool
		cuts     int // Reductions of ssthresh, 1 if zero.
	}{
		{name: "fast-retransmit", cwnd: 4, segments: 6, lost: []int{0}},
		{name: "limited-transmit", cwnd: 3, segments: 5, lost: []int{0}},
		{name: "partial-ack", cwnd: 6, segments: 8, lost: []int{0, 1}},
		{name: "sack", cwnd: 8, segments: 5, lost: []int{0}, lostACKs: []int{0}, sack: true},
		{name: "more-data-queued", cwnd: 8, segments: 70, lost: []int{0}},
		{name: "every-12th-lost", cwnd: 8, segments: 70, lost: []int{0, 12, 24, 36, 48, 60}, cuts: 6},
		{name: "sack-consecutive", cwnd: 8, segments: 20, lost: []int{0, 1, 2, 3}, sack: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server, cubic, packet, _ := connPair(t, pairConfig{cwnd: tc.cwnd, sack: tc.sack})
			if _, err := client.Write(make([]byte, tc.segments*testMSS)); err != nil {
				t.Fatal("write:", err)
			}
			cb := client.ControlBlock()
			next, sent, acks, cuts := cb.SendNext(), 0, 0, 0
			ssthresh := cubic.SlowStartThresh()
			// send returns what the client sends, without the lost segments.
			send := func() (out [][]byte) {
				defer func() {
					if s := cubic.SlowStartThresh(); s < ssthresh {
						cuts++
					}
					ssthresh = cubic.SlowStartThresh()
				}()
				for n := sendOnly(t, client, packet); n != 0; n = sendOnly(t, client, packet) {
					frm, _ := tcp.NewFrame(packet[:n])
					if seg := frm.Segment(len(frm.Payload())); seg.SEQ == next {
						next += tcp.Value(seg.DATALEN)
						sent++
						if slices.Contains(tc.lost, sent-1) {
							continue
						}
					}
					out = append(out, append([]byte(nil), packet[:n]...))
				}
				return out
			}
			// Each round the server answers every segment, then the client
			// takes each answer and sends what it can after it.
			for toServer := send(); len(toServer) > 0; {
				var answers [][]byte
				for _, pkt := range toServer {
					server.Recv(pkt) // Rejects copies of segments it has.
					for m := sendOnly(t, server, packet); m != 0; m = sendOnly(t, server, packet) {
						acks++
						if !slices.Contains(tc.lostACKs, acks-1) {
							answers = append(answers, append([]byte(nil), packet[:m]...))
						}
					}
				}
				toServer = nil
				for _, answer := range answers {
					client.Recv(answer)
					toServer = append(toServer, send()...)
				}
			}
			wantCuts := max(tc.cuts, 1)
			if cb.SendUNA() != cb.SendNext() || client.BufferedUnsent() != 0 || cubic.timer.Expirations() != 0 || cuts != wantCuts {
				t.Errorf("unacknowledged %d, unsent %d, timeouts %d, cuts %d; want 0, 0, 0, %d",
					tcp.Sizeof(cb.SendUNA(), cb.SendNext()), client.BufferedUnsent(), cubic.timer.Expirations(), cuts, wantCuts)
			}
		})
	}
}

// TestCUBIC_OwedResends verifies each resend the ControlBlock owes for a burst
// of duplicate ACKs handled before the next transmit carries the lost data.
func TestCUBIC_OwedResends(t *testing.T) {
	client, server, _, packet, _ := connPair(t, pairConfig{cwnd: 8})
	if _, err := client.Write(make([]byte, 8*testMSS)); err != nil {
		t.Fatal("write:", err)
	}
	una := client.ControlBlock().SendUNA()
	sendOnly(t, client, packet) // Lost.
	var dupACKs [][]byte
	for relay(t, client, server, packet) != 0 {
		n := sendOnly(t, server, packet)
		dupACKs = append(dupACKs, append([]byte(nil), packet[:n]...))
	}
	for _, ack := range dupACKs {
		if err := client.Recv(ack); err != nil {
			t.Fatal(err)
		}
	}
	for n := sendOnly(t, client, packet); n != 0; n = sendOnly(t, client, packet) {
		frm, _ := tcp.NewFrame(packet[:n])
		if seg := frm.Segment(len(frm.Payload())); seg.SEQ == una && seg.DATALEN != testMSS {
			t.Fatalf("resend %v, want the %d lost octets", seg, testMSS)
		}
	}
}

// TestCUBIC_RecoveryAfterTimeout verifies that after a timeout partial ACKs
// resend the rest of a lost window while the window grows (RFC 6582 §3.2).
func TestCUBIC_RecoveryAfterTimeout(t *testing.T) {
	client, server, cubic, packet, clock := connPair(t, pairConfig{cwnd: 6})
	if _, err := client.Write(make([]byte, 6*testMSS)); err != nil {
		t.Fatal("write:", err)
	}
	for sendOnly(t, client, packet) != 0 { // The whole window is lost.
	}
	*clock += int64(2 * nanosPerSecond)
	for range 12 {
		relay(t, client, server, packet)
		relay(t, server, client, packet)
	}
	cb := client.ControlBlock()
	if cb.SendUNA() != cb.SendNext() || cubic.timer.Expirations() != 1 || cubic.WindowSegments() <= 1 {
		t.Fatalf("unacknowledged %d, timeouts %d, cwnd %v; want 0, 1 and growth from 1",
			tcp.Sizeof(cb.SendUNA(), cb.SendNext()), cubic.timer.Expirations(), cubic.WindowSegments())
	}
}

// TestCUBIC_Timer verifies the controller runs its timer: data in flight
// arms it, with the deadline reported through tcp.Policies, and the ACK
// stops it with an RTT sample.
func TestCUBIC_Timer(t *testing.T) {
	client, server, cubic, packet, _ := connPair(t, pairConfig{})
	if _, err := client.Write(make([]byte, testMSS)); err != nil {
		t.Fatal("write:", err)
	}
	relay(t, client, server, packet)
	if d := (tcp.Policies{cubic}).NextDeadline(); d == 0 || d != cubic.Timer().NextDeadline() {
		t.Fatalf("deadline %d with data in flight, want the timer's %d", d, cubic.Timer().NextDeadline())
	}
	relay(t, server, client, packet)
	if cubic.Timer().Running() || cubic.Timer().SmoothedRTT() == 0 {
		t.Errorf("timer running %v, SRTT %v after the ACK; want stopped and sampled", cubic.Timer().Running(), cubic.Timer().SmoothedRTT())
	}
}

// TestCUBIC_Reset verifies a controller reset after a timeout, which also
// resets its timer, starts the next connection afresh.
func TestCUBIC_Reset(t *testing.T) {
	client, _, cubic, packet, clock := connPair(t, pairConfig{cwnd: 6})
	if _, err := client.Write(make([]byte, testMSS)); err != nil {
		t.Fatal("write:", err)
	}
	sendOnly(t, client, packet) // Lost.
	*clock += int64(2 * nanosPerSecond)
	sendOnly(t, client, packet) // Resent on the timeout.
	if cubic.timer.Expirations() != 1 || cubic.WindowSegments() != 1 {
		t.Fatalf("timeouts %d, cwnd %v; test needs one timeout", cubic.timer.Expirations(), cubic.WindowSegments())
	}
	cubic.Reset()
	cb := client.ControlBlock()
	limit, _, rtx := cubic.preTx(cb.SendUNA(), cb.SendUNA(), 0, cubic.timer.Expirations(), false, 0)
	if cubic.WindowSegments() != 6 || !math.IsInf(float64(cubic.SlowStartThresh()), 1) || rtx || limit != 6*cubic.smss || cubic.timer.Expirations() != 0 {
		t.Errorf("cwnd %v, ssthresh %v, resend %v, limit %d, timeouts %d after Reset; want 6, +Inf, none, %d, 0",
			cubic.WindowSegments(), cubic.SlowStartThresh(), rtx, limit, cubic.timer.Expirations(), 6*cubic.smss)
	}
}

// TestCUBIC_WindowUpdateNotDuplicate verifies an ACK opening the peer's
// window is not a duplicate ACK (RFC 5681 §2).
func TestCUBIC_WindowUpdateNotDuplicate(t *testing.T) {
	client, server, cubic, packet, _ := connPair(t, pairConfig{cwnd: 2})
	if _, err := client.Write(make([]byte, 8*testMSS)); err != nil {
		t.Fatal("write:", err)
	}
	relay(t, client, server, packet)
	n := sendOnly(t, server, packet) // ACK with the window reduced by the segment.
	ack := append([]byte(nil), packet[:n]...)
	sendOnly(t, client, packet)
	sendOnly(t, client, packet)
	if err := client.Recv(ack); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Read(make([]byte, testMSS)); err != nil {
		t.Fatal(err)
	}
	if relay(t, server, client, packet) == 0 {
		t.Fatal("test needs the server's window update")
	}
	if cubic.dup.n != 0 {
		t.Errorf("window update counted as %d duplicate ACKs, want 0", cubic.dup.n)
	}
}

// TestCUBIC_ZeroWindowProbe verifies zero-window probes timing out, and the
// repair of the probe octet the peer refused once its window reopens, leave
// the window alone.
func TestCUBIC_ZeroWindowProbe(t *testing.T) {
	for _, tc := range []struct {
		name    string
		queued  int  // Data written after the peer's window closed.
		timeout bool // The last probe times out before the window reopens.
	}{
		{name: "last-probe-timed-out", queued: testMSS, timeout: true},
		{name: "window-reopens-first", queued: 6 * testMSS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server, cubic, packet, clock := connPair(t, pairConfig{cwnd: 100})
			if _, err := client.Write(make([]byte, connBuf)); err != nil {
				t.Fatal("write:", err)
			}
			for relay(t, client, server, packet) != 0 {
				relay(t, server, client, packet)
			}
			if _, err := client.Write(make([]byte, tc.queued)); err != nil {
				t.Fatal("write:", err)
			}
			cwnd := cubic.WindowSegments()
			for i := range 3 {
				if n := sendOnly(t, client, packet); n != tcpHeaderLen+1 {
					t.Fatalf("sent %d octets, want a zero-window probe", n)
				}
				if i < 2 || tc.timeout {
					*clock += int64(100 * nanosPerSecond)
				}
			}
			if _, err := server.Read(make([]byte, connBuf)); err != nil {
				t.Fatal(err)
			}
			for range 50 {
				for relay(t, server, client, packet) != 0 {
				}
				if relay(t, client, server, packet) == 0 {
					*clock += int64(10 * nanosPerSecond)
				}
			}
			cb := client.ControlBlock()
			if cb.SendUNA() != cb.SendNext() || client.BufferedUnsent() != 0 {
				t.Fatalf("%d octets unacknowledged, %d unsent", tcp.Sizeof(cb.SendUNA(), cb.SendNext()), client.BufferedUnsent())
			}
			if cubic.WindowSegments() < cwnd || !math.IsInf(float64(cubic.SlowStartThresh()), 1) {
				t.Errorf("cwnd=%v ssthresh=%v, want at least %v and +Inf", cubic.WindowSegments(), cubic.SlowStartThresh(), cwnd)
			}
		})
	}
}

func TestCUBIC_ZeroAlloc(t *testing.T) {
	if runtime.Compiler == "tinygo" {
		t.Skip("TinyGo's testing.AllocsPerRun does not count allocations")
	}
	client, server, _, packet, _ := connPair(t, pairConfig{})
	data := make([]byte, testMSS)
	allocs := testing.AllocsPerRun(100, func() {
		if _, err := client.Write(data); err != nil {
			t.Fatal("write:", err)
		}
		if relay(t, client, server, packet) == 0 {
			t.Fatal("no data segment produced")
		}
		if _, err := server.Read(data); err != nil {
			t.Fatal("read:", err)
		}
		relay(t, server, client, packet)
	})
	if allocs != 0 {
		t.Errorf("allocated %v times per exchange, want 0", allocs)
	}
}
