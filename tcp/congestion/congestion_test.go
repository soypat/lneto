package congestion

import (
	"testing"
	"time"

	"github.com/soypat/lneto/tcp"
)

func TestMinmaxRunningMax(t *testing.T) {
	const win = 10
	var m minmax
	// Feed a rising-then-falling sequence. The windowed max must never report a
	// value older than the window and must track the true running maximum.
	samples := []uint64{1, 5, 3, 8, 2, 4, 9, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	for i, v := range samples {
		got := m.runningMax(win, uint32(i), v)
		var want uint64
		lo := max(i-win, 0)
		for j := lo; j <= i; j++ {
			if samples[j] > want {
				want = samples[j]
			}
		}
		if got < want {
			t.Fatalf("step %d: runningMax=%d, below true window max %d", i, got, want)
		}
	}
	if final := m.runningMax(win, 40, 2); final > 2 {
		t.Errorf("stale max not aged out: got %d, want <= 2", final)
	}
}

func TestMinmaxRunningMin(t *testing.T) {
	const win = 8
	var m minmax
	if got := m.runningMin(win, 0, 100); got != 100 {
		t.Fatalf("first min=%d, want 100", got)
	}
	if got := m.runningMin(win, 1, 40); got != 40 {
		t.Fatalf("min=%d, want 40", got)
	}
	if got := m.runningMin(win, 2, 90); got != 40 {
		t.Fatalf("min=%d, want 40 (higher sample must not raise min)", got)
	}
	got := m.runningMin(win, 20, 70)
	if got < 40 {
		t.Fatalf("min decayed below seen values: %d", got)
	}
	if got > 90 {
		t.Errorf("min=%d, want <= 90 after low sample expired", got)
	}
}

func TestRTTSampler(t *testing.T) {
	var s rttSampler
	base := time.Unix(0, 0)
	s.startSample(1000, base)
	// A second start while pending is ignored (single outstanding sample).
	s.startSample(2000, base.Add(time.Millisecond))
	if rtt, ok := s.observeACK(500, base.Add(10*time.Millisecond)); ok {
		t.Fatalf("premature sample: rtt=%v", rtt)
	}
	rtt, ok := s.observeACK(1000, base.Add(50*time.Millisecond))
	if !ok {
		t.Fatal("expected completed RTT sample")
	}
	if rtt != 50*time.Millisecond {
		t.Errorf("rtt=%v, want 50ms", rtt)
	}
	s.startSample(3000, base.Add(100*time.Millisecond))
	rtt, ok = s.observeACK(3000, base.Add(190*time.Millisecond))
	if !ok {
		t.Fatal("expected second RTT sample")
	}
	if rtt != 90*time.Millisecond {
		t.Errorf("second rtt=%v, want 90ms", rtt)
	}
}

func TestCongestionControlNoAllocs(t *testing.T) {
	clock := time.Unix(0, 0)
	var cubic CUBIC
	cubic.Reset(CUBICConfig{MSS: 1000, Now: func() time.Time { return clock }})
	cubic.ssthresh = 50
	if allocs := testing.AllocsPerRun(200, func() {
		cubic.OnACK(1000, 20*time.Millisecond)
	}); allocs != 0 {
		t.Errorf("CUBIC.OnACK allocates %v objects/op, want 0", allocs)
	}

	var bbr BBR
	bbr.Reset(BBRConfig{MSS: 1000, Now: func() time.Time { return clock }})
	if allocs := testing.AllocsPerRun(200, func() {
		bbr.OnACK(1000, 1000, 20*time.Millisecond)
	}); allocs != 0 {
		t.Errorf("BBR.OnACK allocates %v objects/op, want 0", allocs)
	}
}

// assert both controllers satisfy the interface (mirrors the package var, but
// keeps the import obviously used and documents intent at test time).
var (
	_ tcp.CongestionControl = (*CUBIC)(nil)
	_ tcp.CongestionControl = (*BBR)(nil)
)
