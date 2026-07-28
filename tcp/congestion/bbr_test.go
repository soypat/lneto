package congestion

import (
	"testing"
	"time"

	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
)

// These tests are ported from the pre-rework branch, where BBR was driven by a
// tcp.CongestionEvent and read a time.Time clock. The numeric core is unchanged and
// the assertions with it; what changed is that time arrives as monotonic nanoseconds
// at the hook boundary, and that the segment stream reaches the controller through
// tcp.Policy rather than through a single Control call.

const bbrTestMSS = 1000

func newTestBBR(t *testing.T) *BBR {
	t.Helper()
	var b BBR
	err := b.Configure(BBRConfig{MSS: bbrTestMSS, InitialCwnd: 10})
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	return &b
}

func TestBBRInitialState(t *testing.T) {
	b := newTestBBR(t)
	if b.State() != "STARTUP" {
		t.Errorf("initial state=%q, want STARTUP", b.State())
	}
	if b.CongestionWindow() != 10*bbrTestMSS {
		t.Errorf("initial cwnd=%d, want %d", b.CongestionWindow(), 10*bbrTestMSS)
	}
	if b.BandwidthEstimate() != 0 {
		t.Errorf("initial bw=%v, want 0", b.BandwidthEstimate())
	}
	if d := b.NextDeadline(); d != 0 {
		t.Errorf("NextDeadline=%d, want 0: BBR schedules nothing", d)
	}
}

func TestBBRBandwidthEstimate(t *testing.T) {
	b := newTestBBR(t)
	const rtt = 100 * time.Millisecond
	var now int64
	for range 5 {
		now += int64(rtt)
		b.onACK(10000, 10000, rtt, now) // 100_000 bytes/sec.
	}
	bw := b.BandwidthEstimate()
	if bw < 99000 || bw > 101000 {
		t.Errorf("bw=%v, want ~100000 bytes/sec", bw)
	}
	if b.MinRTT() != rtt {
		t.Errorf("minRTT=%v, want %v", b.MinRTT(), rtt)
	}
	if bdp := b.bdp(); bdp < 9500 || bdp > 10500 {
		t.Errorf("BDP=%v, want ~10000 bytes", bdp)
	}
	// Pacing rate is pacing_gain * bw; across all phases the gain lies between
	// the drain gain (0.5) and the startup gain (~2.77).
	if pr := b.PacingRate(); pr < bw*bbrDrainPacingGain*0.99 || pr > bw*bbrStartupPacingGain*1.01 {
		t.Errorf("PacingRate=%v out of range [%v, %v]", pr, bw*bbrDrainPacingGain, bw*bbrStartupPacingGain)
	}
}

func TestBBRBandwidthMaxFilter(t *testing.T) {
	b := newTestBBR(t)
	const rtt = 100 * time.Millisecond
	var now int64
	now += int64(rtt)
	b.onACK(20000, 20000, rtt, now) // 200_000 bytes/sec peak.
	for range 3 {
		now += int64(rtt)
		b.onACK(5000, 5000, rtt, now) // 50_000 bytes/sec.
	}
	if bw := b.BandwidthEstimate(); bw < 199000 {
		t.Errorf("bw=%v, peak should be retained by max filter (~200000)", bw)
	}
}

func TestBBRStartupToDrain(t *testing.T) {
	b := newTestBBR(t)
	const rtt = 50 * time.Millisecond
	var now int64

	acked := tcp.Size(4000)
	for range 6 {
		now += int64(rtt)
		b.onACK(acked, acked, rtt, now)
		acked = tcp.Size(float64(acked) * 1.5) // >25% growth each round.
	}
	if b.State() != "STARTUP" {
		t.Fatalf("state=%q while bandwidth still growing, want STARTUP", b.State())
	}

	for range bbrFullBwCount + 2 {
		now += int64(rtt)
		b.onACK(acked, acked, rtt, now) // constant => no growth.
	}
	if b.State() == "STARTUP" {
		t.Errorf("state still STARTUP after bandwidth plateau, want DRAIN/PROBE_BW")
	}
	if !b.fullBwReached {
		t.Error("fullBwReached should be set after plateau")
	}
}

func TestBBRReachesProbeBW(t *testing.T) {
	b := newTestBBR(t)
	const rtt = 50 * time.Millisecond
	const rate = 100000.0
	ackPerRound := tcp.Size(rate * rtt.Seconds())
	var now int64

	acked := tcp.Size(4000)
	for range 8 {
		now += int64(rtt)
		b.onACK(acked, acked, rtt, now)
		if acked < ackPerRound {
			acked *= 2
		} else {
			acked = ackPerRound
		}
	}
	for range 20 {
		now += int64(rtt)
		b.onACK(ackPerRound, ackPerRound/2, rtt, now)
	}
	if b.State() != "PROBE_BW" {
		t.Fatalf("state=%q, want PROBE_BW in steady state", b.State())
	}
	bdp := b.bdp()
	if bdp < 4500 || bdp > 5500 {
		t.Errorf("BDP=%v, want ~5000 bytes", bdp)
	}
	if cwnd := b.CongestionWindow(); tcp.Size(bdp) > cwnd {
		t.Errorf("cwnd=%d should cover at least the BDP %v", cwnd, bdp)
	}
}

func TestBBRProbeRTT(t *testing.T) {
	b := newTestBBR(t)
	const rtt = 50 * time.Millisecond
	const rate = 100000.0
	ackPerRound := tcp.Size(rate * rtt.Seconds())
	var now int64

	acked := tcp.Size(4000)
	for range 8 {
		now += int64(rtt)
		b.onACK(acked, acked, rtt, now)
		if acked < ackPerRound {
			acked *= 2
		} else {
			acked = ackPerRound
		}
	}
	for range 10 {
		now += int64(rtt)
		b.onACK(ackPerRound, ackPerRound/2, rtt, now)
	}

	// Advance past the min-RTT window with samples *higher* than the 50ms
	// minimum (the path is now queuing), so min_rtt goes stale and ProbeRTT fires.
	const highRTT = 80 * time.Millisecond
	now += int64(bbrProbeRTTInterval + time.Second)
	b.onACK(ackPerRound, ackPerRound/2, highRTT, now)
	if b.State() != "PROBE_RTT" {
		t.Fatalf("state=%q after stale min_rtt, want PROBE_RTT", b.State())
	}
	now += int64(rtt)
	b.onACK(ackPerRound, bbrMinPipeCwnd*bbrTestMSS, highRTT, now)
	if got, want := b.CongestionWindow(), tcp.Size(bbrMinPipeCwnd)*bbrTestMSS; got != want {
		t.Errorf("ProbeRTT cwnd=%d, want %d (min pipe)", got, want)
	}
}

// bbrRound transmits a window of nseg segments from seq and acknowledges them
// individually one round trip later, through the policy hooks.
func bbrRound(b *BBR, seq tcp.Value, nseg, segBytes int, now, rtt int64) (nextSeq tcp.Value, nextNow int64) {
	for i := range tcp.Value(nseg) {
		start := seq + i*tcp.Value(segBytes)
		b.PostTx(tcp.Segment{
			SEQ: start, ACK: 5000, DATALEN: tcp.Size(segBytes),
			Flags: tcp.FlagPSH | tcp.FlagACK,
		}, now)
	}
	now += rtt
	for i := range tcp.Value(nseg) {
		ack := seq + (i+1)*tcp.Value(segBytes)
		b.PostRx(tcp.RxEvent{
			Segment:  tcp.Segment{SEQ: 5000, ACK: ack, Flags: tcp.FlagACK},
			Now:      now,
			Accepted: true,
		})
	}
	return seq + tcp.Value(nseg*segBytes), now
}

// TestBBRRoundAccumulation verifies the delivery-rate sample covers all octets
// acknowledged during a round trip, not just the single acknowledgement that
// completes the round-trip sample. Ten 1000-octet segments per 50ms round,
// acknowledged individually, must produce a ~200 kB/s estimate rather than ~20 kB/s.
func TestBBRRoundAccumulation(t *testing.T) {
	b := newTestBBR(t)
	const nseg, segBytes = 10, 1000
	const rtt = int64(50 * time.Millisecond)

	seq := tcp.Value(1000)
	var now int64
	// The first round only anchors the interval; later rounds measure it.
	for range 3 {
		seq, now = bbrRound(b, seq, nseg, segBytes, now, rtt)
	}
	// True delivery rate: 10_000 octets / 50ms = 200_000 octets/sec.
	bw := b.BandwidthEstimate()
	if bw < 150000 || bw > 250000 {
		t.Errorf("bw=%v, want ~200000 bytes/sec (whole round credited, not a single ACK)", bw)
	}
}

// TestBBRMeasuresThroughTheHooks verifies the seam glue yields round-trip and
// bandwidth estimates from the segment stream alone, with no clock of its own and no
// retransmission timer to read.
func TestBBRMeasuresThroughTheHooks(t *testing.T) {
	b := newTestBBR(t)
	const rtt = int64(50 * time.Millisecond)
	seq := tcp.Value(1000)
	var now int64
	for range 2 {
		seq, now = bbrRound(b, seq, 1, 4000, now, rtt)
	}
	if b.BandwidthEstimate() <= 0 {
		t.Error("BBR did not estimate bandwidth after two completed rounds")
	}
	if b.MinRTT() != time.Duration(rtt) {
		t.Errorf("minRTT=%v, want %v", b.MinRTT(), time.Duration(rtt))
	}
}

// TestBBRIgnoresRefusedSegment verifies an acknowledgement the connection refused
// contributes nothing. It would otherwise credit octets that were never delivered to
// the delivery rate, which is the one quantity BBR sizes its window from, so a peer
// or an attacker could inflate the window with acknowledgements for data never sent.
func TestBBRIgnoresRefusedSegment(t *testing.T) {
	b := newTestBBR(t)
	const rtt = int64(50 * time.Millisecond)
	seq := tcp.Value(1000)
	var now int64
	seq, now = bbrRound(b, seq, 4, 1000, now, rtt)
	bwBefore, rttBefore := b.BandwidthEstimate(), b.MinRTT()

	// A refused acknowledgement, for far more than was ever sent.
	b.PostTx(tcp.Segment{SEQ: seq, ACK: 5000, DATALEN: 1000, Flags: tcp.FlagPSH | tcp.FlagACK}, now)
	b.PostRx(tcp.RxEvent{
		Segment:  tcp.Segment{SEQ: 5000, ACK: seq + 1_000_000, Flags: tcp.FlagACK},
		Now:      now + rtt,
		Accepted: false,
	})
	if got := b.BandwidthEstimate(); got != bwBefore {
		t.Errorf("bandwidth estimate moved to %v on a refused segment, was %v", got, bwBefore)
	}
	if got := b.MinRTT(); got != rttBefore {
		t.Errorf("minRTT moved to %v on a refused segment, was %v", got, rttBefore)
	}
}

// TestBBRNeverTimesARetransmission verifies Karn's algorithm: a segment that does
// not extend the send sequence is a retransmission, and its acknowledgement cannot
// be attributed to either transmission, so it must not be timed. Timing it inflates
// or deflates min_rtt with a number that measures nothing.
func TestBBRNeverTimesARetransmission(t *testing.T) {
	b := newTestBBR(t)
	const rtt = int64(50 * time.Millisecond)
	seq := tcp.Value(1000)
	var now int64
	seq, now = bbrRound(b, seq, 4, 1000, now, rtt)
	want := b.MinRTT()

	// Resend an earlier segment, then acknowledge well after it: a timed sample
	// would record the long delay as the path's propagation time.
	b.PostTx(tcp.Segment{SEQ: seq - 1000, ACK: 5000, DATALEN: 1000, Flags: tcp.FlagPSH | tcp.FlagACK}, now)
	if b.timing {
		t.Error("a retransmission started a round-trip sample")
	}
	b.PostRx(tcp.RxEvent{
		Segment:  tcp.Segment{SEQ: 5000, ACK: seq, Flags: tcp.FlagACK},
		Now:      now + 10*rtt,
		Accepted: true,
	})
	if got := b.MinRTT(); got != want {
		t.Errorf("minRTT=%v after acknowledging a retransmission, want %v unchanged", got, want)
	}
}

// TestBBRHoldsAtTheCongestionWindow verifies the controller withholds new data once
// the octets in flight reach its window, which is the only control it exerts over
// the connection, and that it asks for no retransmission.
func TestBBRHoldsAtTheCongestionWindow(t *testing.T) {
	b := newTestBBR(t)
	cwnd := b.CongestionWindow()
	dir := b.PreTx(tcp.TxIntent{InFlight: cwnd - 1, MSS: bbrTestMSS, SendWindow: 65535})
	if dir.HoldNew {
		t.Error("held new data below the congestion window")
	}
	dir = b.PreTx(tcp.TxIntent{InFlight: cwnd, MSS: bbrTestMSS, SendWindow: 65535})
	if !dir.HoldNew {
		t.Error("did not hold new data at the congestion window")
	}
	if dir.Retransmit {
		t.Error("BBR asked for a retransmission; it has no loss model to ask on behalf of")
	}
}

// TestBBRTimeoutDiscardsSample verifies a timeout on a shared timer invalidates the
// round-trip sample in flight. The acknowledgement that eventually arrives cannot be
// attributed to a particular transmission, so timing it would feed the propagation
// delay estimate a number that measures a timeout instead.
func TestBBRTimeoutDiscardsSample(t *testing.T) {
	b := newTestBBR(t)
	timer := new(rto.Timer)
	timer.Reset()
	b.SetTimer(timer)

	// Put a segment in flight through both, so both are timing it.
	seg := tcp.Segment{SEQ: 1000, ACK: 5000, DATALEN: 1000, Flags: tcp.FlagPSH | tcp.FlagACK}
	b.PostTx(seg, 0)
	timer.PostTx(seg, 0)
	if !b.timing {
		t.Fatal("no sample started for new data")
	}
	// Expire the timer, then transmit: the controller must notice.
	deadline := timer.NextDeadline()
	timer.PreTx(tcp.TxIntent{Now: deadline + 1, UNA: 1000, NXT: 2000, InFlight: 1000})
	if timer.Expirations() != 1 {
		t.Fatalf("timer recorded %d expirations, want 1", timer.Expirations())
	}
	b.PreTx(tcp.TxIntent{Now: deadline + 1, UNA: 1000, NXT: 2000, InFlight: 1000, MSS: bbrTestMSS})
	if b.timing {
		t.Error("the round-trip sample survived a timeout")
	}
}

// TestBBRResetKeepsConfigurationAndTimer verifies reopening a connection clears the
// model but keeps what was installed, so a second connection does not silently run
// unconfigured or lose sight of timeouts.
func TestBBRResetKeepsConfigurationAndTimer(t *testing.T) {
	b := newTestBBR(t)
	timer := new(rto.Timer)
	timer.Reset()
	b.SetTimer(timer)
	var now int64
	b.onACK(10000, 10000, 100*time.Millisecond, int64(100*time.Millisecond))
	now = int64(200 * time.Millisecond)
	b.onACK(10000, 10000, 100*time.Millisecond, now)
	if b.BandwidthEstimate() == 0 {
		t.Fatal("no bandwidth estimate to clear")
	}

	b.Reset()
	if b.BandwidthEstimate() != 0 {
		t.Errorf("bandwidth estimate %v survived a reset", b.BandwidthEstimate())
	}
	if b.State() != "STARTUP" {
		t.Errorf("state=%q after reset, want STARTUP", b.State())
	}
	if b.CongestionWindow() != 10*bbrTestMSS {
		t.Errorf("cwnd=%d after reset, want the configured initial %d", b.CongestionWindow(), 10*bbrTestMSS)
	}
	if b.shared != timer {
		t.Error("the shared timer was dropped by a reset, so timeouts go unnoticed on reuse")
	}
}

// TestBBRZeroAlloc verifies driving the controller allocates nothing.
func TestBBRZeroAlloc(t *testing.T) {
	b := newTestBBR(t)
	var opts [8]byte
	seq := tcp.Value(1000)
	var now int64
	allocs := testing.AllocsPerRun(200, func() {
		now += int64(time.Millisecond)
		b.PostTx(tcp.Segment{SEQ: seq, ACK: 5000, DATALEN: 100, Flags: tcp.FlagPSH | tcp.FlagACK}, now)
		seq += 100
		b.PostRx(tcp.RxEvent{
			Segment:  tcp.Segment{SEQ: 5000, ACK: seq, Flags: tcp.FlagACK},
			Now:      now,
			Accepted: true,
		})
		b.PreRx(tcp.RxMeta{})
		b.PreTx(tcp.TxIntent{Now: now, MSS: bbrTestMSS, SendWindow: 65535})
		b.WriteOptions(tcp.TxPlan{}, opts[:])
		b.NextDeadline()
	})
	if allocs != 0 {
		t.Errorf("BBR allocated %v times per iteration, want 0", allocs)
	}
}
