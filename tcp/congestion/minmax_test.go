package congestion

import (
	"math/rand"
	"testing"
)

// TestMaxFilter verifies the windowed maximum over sequences that take a new
// maximum, keep the second and third best sample of the window and age the
// maximum out by one or two samples, and that over random samples it is never
// below the latest sample nor a sample older than twice the window.
func TestMaxFilter(t *testing.T) {
	const win = 10
	type sample struct {
		t       uint32
		v, want uint64
	}
	for _, tc := range []struct {
		name    string
		samples []sample
	}{
		{name: "new-maximum", samples: []sample{{0, 10, 10}, {1, 30, 30}, {2, 20, 30}}},
		{name: "third-best", samples: []sample{{0, 100, 100}, {3, 50, 100}, {6, 40, 100}, {9, 45, 100}, {10, 47, 100}, {11, 10, 50}, {14, 10, 47}}},
		{name: "aged-out-twice", samples: []sample{{0, 100, 100}, {3, 50, 100}, {6, 40, 100}, {9, 45, 100}, {10, 47, 100}, {14, 10, 47}}},
		{name: "half-window", samples: []sample{{0, 100, 100}, {3, 50, 100}, {6, 40, 100}, {11, 10, 50}, {14, 10, 40}}},
		{name: "window-passed", samples: []sample{{0, 100, 100}, {3, 50, 100}, {14, 5, 5}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m maxFilter
			for _, s := range tc.samples {
				if got := m.update(win, s.t, s.v); got != s.want {
					t.Fatalf("max %d after %d at %d, want %d", got, s.v, s.t, s.want)
				}
			}
		})
	}
	rng := rand.New(rand.NewSource(1))
	var m maxFilter
	var samples []uint64
	for now := range uint32(500) {
		v := uint64(rng.Intn(100))
		samples = append(samples, v)
		got := m.update(win, now, v)
		recent := uint64(0)
		for i, s := range samples {
			if now-uint32(i) <= 2*win {
				recent = max(recent, s)
			}
		}
		if got < v || got > recent {
			t.Fatalf("at %d: max %d, want within [%d, %d]", now, got, v, recent)
		}
	}
}
