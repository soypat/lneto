package congestion

import "testing"

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
