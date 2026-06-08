package congestion

import (
	"testing"
	"time"

	"github.com/soypat/lneto/tcp"
)

func newTestBBR(t *testing.T, clock *time.Time) *BBR {
	t.Helper()
	var b BBR
	err := b.Reset(BBRConfig{
		MSS:         1000,
		InitialCwnd: 10,
		Now:         func() time.Time { return *clock },
	})
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	return &b
}

func TestBBRInitialState(t *testing.T) {
	clock := time.Unix(0, 0)
	b := newTestBBR(t, &clock)
	if b.State() != "STARTUP" {
		t.Errorf("initial state=%q, want STARTUP", b.State())
	}
	if b.CongestionWindow() != 10*1000 {
		t.Errorf("initial cwnd=%d, want 10000", b.CongestionWindow())
	}
	if b.BandwidthEstimate() != 0 {
		t.Errorf("initial bw=%v, want 0", b.BandwidthEstimate())
	}
}

func TestBBRBandwidthEstimate(t *testing.T) {
	clock := time.Unix(0, 0)
	b := newTestBBR(t, &clock)
	const rtt = 100 * time.Millisecond
	for range 5 {
		clock = clock.Add(rtt)
		b.OnACK(10000, 10000, rtt) // 100_000 bytes/sec.
	}
	bw := b.BandwidthEstimate()
	if bw < 99000 || bw > 101000 {
		t.Errorf("bw=%v, want ~100000 bytes/sec", bw)
	}
	if b.MinRTT() != rtt {
		t.Errorf("minRTT=%v, want %v", b.MinRTT(), rtt)
	}
	if bdp := b.BDP(); bdp < 9500 || bdp > 10500 {
		t.Errorf("BDP=%v, want ~10000 bytes", bdp)
	}
	// Pacing rate is pacing_gain * bw; across all phases the gain lies between
	// the drain gain (0.5) and the startup gain (~2.77).
	if pr := b.PacingRate(); pr < bw*bbrDrainPacingGain*0.99 || pr > bw*bbrStartupPacingGain*1.01 {
		t.Errorf("PacingRate=%v out of range [%v, %v]", pr, bw*bbrDrainPacingGain, bw*bbrStartupPacingGain)
	}
}

func TestBBRBandwidthMaxFilter(t *testing.T) {
	clock := time.Unix(0, 0)
	b := newTestBBR(t, &clock)
	const rtt = 100 * time.Millisecond
	clock = clock.Add(rtt)
	b.OnACK(20000, 20000, rtt) // 200_000 bytes/sec peak.
	for range 3 {
		clock = clock.Add(rtt)
		b.OnACK(5000, 5000, rtt) // 50_000 bytes/sec.
	}
	if bw := b.BandwidthEstimate(); bw < 199000 {
		t.Errorf("bw=%v, peak should be retained by max filter (~200000)", bw)
	}
}

func TestBBRStartupToDrain(t *testing.T) {
	clock := time.Unix(0, 0)
	b := newTestBBR(t, &clock)
	const rtt = 50 * time.Millisecond

	acked := tcp.Size(4000)
	for range 6 {
		clock = clock.Add(rtt)
		b.OnACK(acked, acked, rtt)
		acked = tcp.Size(float64(acked) * 1.5) // >25% growth each round.
	}
	if b.State() != "STARTUP" {
		t.Fatalf("state=%q while bandwidth still growing, want STARTUP", b.State())
	}

	for range bbrFullBwCount + 2 {
		clock = clock.Add(rtt)
		b.OnACK(acked, acked, rtt) // constant => no growth.
	}
	if b.State() == "STARTUP" {
		t.Errorf("state still STARTUP after bandwidth plateau, want DRAIN/PROBE_BW")
	}
	if !b.fullBwReached {
		t.Error("fullBwReached should be set after plateau")
	}
}

func TestBBRReachesProbeBW(t *testing.T) {
	clock := time.Unix(0, 0)
	b := newTestBBR(t, &clock)
	const rtt = 50 * time.Millisecond
	const rate = 100000.0
	ackPerRound := tcp.Size(rate * rtt.Seconds())

	acked := tcp.Size(4000)
	for range 8 {
		clock = clock.Add(rtt)
		b.OnACK(acked, acked, rtt)
		if acked < ackPerRound {
			acked *= 2
		} else {
			acked = ackPerRound
		}
	}
	for range 20 {
		clock = clock.Add(rtt)
		b.OnACK(ackPerRound, ackPerRound/2, rtt)
	}
	if b.State() != "PROBE_BW" {
		t.Fatalf("state=%q, want PROBE_BW in steady state", b.State())
	}
	bdp := b.BDP()
	if bdp < 4500 || bdp > 5500 {
		t.Errorf("BDP=%v, want ~5000 bytes", bdp)
	}
	if cwnd := b.CongestionWindow(); tcp.Size(bdp) > cwnd {
		t.Errorf("cwnd=%d should cover at least the BDP %v", cwnd, bdp)
	}
}

func TestBBRProbeRTT(t *testing.T) {
	clock := time.Unix(0, 0)
	b := newTestBBR(t, &clock)
	const rtt = 50 * time.Millisecond
	const rate = 100000.0
	ackPerRound := tcp.Size(rate * rtt.Seconds())

	acked := tcp.Size(4000)
	for range 8 {
		clock = clock.Add(rtt)
		b.OnACK(acked, acked, rtt)
		if acked < ackPerRound {
			acked *= 2
		} else {
			acked = ackPerRound
		}
	}
	for range 10 {
		clock = clock.Add(rtt)
		b.OnACK(ackPerRound, ackPerRound/2, rtt)
	}

	// Advance past the min-RTT window with samples *higher* than the 50ms
	// minimum (the path is now queuing), so min_rtt goes stale and ProbeRTT fires.
	const highRTT = 80 * time.Millisecond
	clock = clock.Add(bbrProbeRTTInterval + time.Second)
	b.OnACK(ackPerRound, ackPerRound/2, highRTT)
	if b.State() != "PROBE_RTT" {
		t.Fatalf("state=%q after stale min_rtt, want PROBE_RTT", b.State())
	}
	clock = clock.Add(rtt)
	b.OnACK(ackPerRound, bbrMinPipeCwnd*1000, highRTT)
	if got, want := b.CongestionWindow(), tcp.Size(bbrMinPipeCwnd)*1000; got != want {
		t.Errorf("ProbeRTT cwnd=%d, want %d (min pipe)", got, want)
	}
}

func TestBBROnLossIsNoOp(t *testing.T) {
	clock := time.Unix(0, 0)
	b := newTestBBR(t, &clock)
	const rtt = 50 * time.Millisecond
	for range 4 {
		clock = clock.Add(rtt)
		b.OnACK(5000, 5000, rtt)
	}
	before := b.CongestionWindow()
	b.OnLoss()
	if b.CongestionWindow() != before {
		t.Errorf("BBR cwnd changed on loss: %d -> %d (should be no-op)", before, b.CongestionWindow())
	}
}

// TestBBRControlRoundAccumulation verifies the delivery-rate sample covers all
// bytes acknowledged during a round trip, not just the single ACK that
// completes the RTT sample. Ten 1000-byte segments per 50ms round acked
// individually must produce a ~200kB/s estimate, not ~20kB/s.
func TestBBRControlRoundAccumulation(t *testing.T) {
	clock := time.Unix(0, 0)
	b := newTestBBR(t, &clock)
	const nseg, segBytes = 10, 1000
	const rtt = 50 * time.Millisecond

	iss := tcp.Value(1000)
	// Run several rounds: each transmits a 10-segment window then receives ten
	// individual ACKs one RTT later. The first round only anchors the
	// completion-to-completion rate interval; later rounds measure it.
	for range 3 {
		for i := range tcp.Value(nseg) {
			seq := iss + i*segBytes
			b.Control(tcp.CongestionEvent{
				Segment: tcp.Segment{SEQ: seq, ACK: 5000, DATALEN: segBytes, Flags: tcp.FlagPSH | tcp.FlagACK},
				SndUNA:  iss, SndNXT: seq, Tx: true,
			})
		}
		clock = clock.Add(rtt)
		for i := range tcp.Value(nseg) {
			una := iss + (i+1)*segBytes
			b.Control(tcp.CongestionEvent{
				Segment: tcp.Segment{SEQ: 5000, ACK: una, Flags: tcp.FlagACK},
				SndUNA:  una, SndNXT: iss + nseg*segBytes,
			})
		}
		iss += nseg * segBytes
	}
	// True delivery rate: 10_000 bytes / 50ms = 200_000 bytes/sec.
	bw := b.BandwidthEstimate()
	if bw < 150000 || bw > 250000 {
		t.Errorf("bw=%v, want ~200000 bytes/sec (whole round credited, not a single ACK)", bw)
	}
}

// TestBBRControlEvents drives BBR through tcp.CongestionEvent values, checking
// the event glue yields RTT and bandwidth estimates. The first completed round
// only anchors the rate interval; the second produces a bandwidth sample.
func TestBBRControlEvents(t *testing.T) {
	clock := time.Unix(0, 0)
	b := newTestBBR(t, &clock)

	seq := tcp.Value(1000)
	for round := range 2 {
		// Transmit 4000 bytes of new data (SEQ==SndNXT) → starts RTT sample.
		b.Control(tcp.CongestionEvent{
			Segment: tcp.Segment{SEQ: seq, ACK: 5000, DATALEN: 4000, Flags: tcp.FlagPSH | tcp.FlagACK},
			SndUNA:  seq, SndNXT: seq, Tx: true,
		})
		clock = clock.Add(50 * time.Millisecond)
		seq += 4000
		cwnd := b.Control(tcp.CongestionEvent{
			Segment: tcp.Segment{SEQ: 5000, ACK: seq, Flags: tcp.FlagACK},
			SndUNA:  seq, SndNXT: seq,
		})
		if cwnd != b.CongestionWindow() {
			t.Errorf("round %d: Control returned %d, want CongestionWindow %d", round, cwnd, b.CongestionWindow())
		}
	}
	if b.BandwidthEstimate() <= 0 {
		t.Error("BBR did not estimate bandwidth after two completed rounds")
	}
	if b.MinRTT() != 50*time.Millisecond {
		t.Errorf("minRTT=%v, want 50ms", b.MinRTT())
	}
}
