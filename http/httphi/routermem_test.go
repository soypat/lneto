package httphi

import (
	"testing"

	"github.com/soypat/lneto/http/httpraw"
)

// budgetMux exposes a settable path value count so budget tests can sweep it
// without registering patterns that bind that many wildcards.
type budgetMux struct {
	MuxSlice
	maxPathValues int
}

func (m *budgetMux) MaxPathValues() int { return m.maxPathValues }

func newBudgetMux(maxPathValues int) *budgetMux {
	mux := &budgetMux{maxPathValues: maxPathValues}
	mux.Handle("GET /", func(*Exchange) {})
	return mux
}

// TestDefaultRouterConfigHonorsBudget sweeps budgets and path value counts and
// checks the returned configuration both fits its budget and configures a
// router. The floor is documented: below it the minimum viable exchange comes
// back instead, which is the only case allowed to exceed the budget.
func TestDefaultRouterConfigHonorsBudget(t *testing.T) {
	minCfg := RouterConfig{
		FixedNumGoroutines:          1,
		RequestHeaderBufferSize:     minRequestHeaderBuffer,
		ResponseHeaderMinBufferSize: minResponseHeaderBuffer,
		RequestNumHeaderKVCap:       1,
	}
	for _, numGoro := range []int{-1, 1, 4} {
		for _, maxPathValues := range []int{0, 1, 4, 32} {
			floor := minCfg.MemoryUsagePerConnection(maxPathValues)
			mux := newBudgetMux(maxPathValues)
			for _, budget := range []int{0, 1, 64, 256, 512, 1024, 4096, 65536, 1 << 20} {
				cfg := DefaultRouterConfig(numGoro, budget, maxPathValues)
				if err := cfg.Validate(); err != nil {
					t.Fatalf("goro=%d pathvals=%d budget=%d: %s", numGoro, maxPathValues, budget, err)
				}
				got := cfg.MemoryUsagePerConnection(maxPathValues)
				if got > budget && budget >= floor {
					t.Errorf("goro=%d pathvals=%d budget=%d: uses %d bytes, over budget",
						numGoro, maxPathValues, budget, got)
				}
				var router Router
				if err := router.Configure(mux, cfg); err != nil {
					t.Fatalf("goro=%d pathvals=%d budget=%d: %s", numGoro, maxPathValues, budget, err)
				}
				router.Shutdown()
			}
		}
	}
}

// TestDefaultRouterConfigSpendsBudget guards the other direction: a config that
// fits but leaves most of the budget unspent is as wrong as one that overruns,
// since the memory is reserved either way.
func TestDefaultRouterConfigSpendsBudget(t *testing.T) {
	const maxPathValues = 2
	for _, budget := range []int{1024, 2048, 4096, 16384} {
		cfg := DefaultRouterConfig(4, budget, maxPathValues)
		used := cfg.MemoryUsagePerConnection(maxPathValues)
		if pct := used * 100 / budget; pct < 95 {
			t.Errorf("budget=%d: spends only %d bytes (%d%%)", budget, used, pct)
		}
	}
}

// TestExchangeMemoryTerms pins each term of MemoryUsagePerConnection to the
// allocation it stands for, so a layout change downstream fails here rather than
// silently letting a router overrun its budget.
func TestExchangeMemoryTerms(t *testing.T) {
	const maxPathValues = 4
	cfg := RouterConfig{
		FixedNumGoroutines:          2,
		RequestHeaderBufferSize:     512,
		ResponseHeaderMinBufferSize: 128,
		RequestNumHeaderKVCap:       16,
	}
	want := sizeofExchange + 512 + 128 + 16*httpraw.SizeKV + maxPathValues*sizeofPathValue + sizeofJob
	if got := cfg.MemoryUsagePerConnection(maxPathValues); got != want {
		t.Errorf("worker mode: got %d want %d", got, want)
	}
	// Unbounded mode has no job queue to reserve a slot in.
	cfg.FixedNumGoroutines = -1
	if got := cfg.MemoryUsagePerConnection(maxPathValues); got != want-sizeofJob {
		t.Errorf("unbounded mode: got %d want %d", got, want-sizeofJob)
	}
	// A mux with no routes registered reports -1, which must not subtract memory.
	if got := cfg.MemoryUsagePerConnection(-1); got != cfg.MemoryUsagePerConnection(0) {
		t.Errorf("unregistered mux: got %d want %d", got, cfg.MemoryUsagePerConnection(0))
	}
}

// TestRouterSharesExchangeStores checks the invariant the memory accounting
// rests on: every exchange's buffer and path values are windows into the two
// stores the router allocates, non-overlapping and exactly the configured size.
// Measuring allocations would only observe this indirectly.
func TestRouterSharesExchangeStores(t *testing.T) {
	const numGoro = 8
	const maxPathValues = 3
	mux := newBudgetMux(maxPathValues)
	cfg := DefaultRouterConfig(numGoro, 1024, maxPathValues)
	var router Router
	if err := router.Configure(mux, cfg); err != nil {
		t.Fatal(err)
	}
	defer router.Shutdown()

	wantRaw := cfg.RequestHeaderBufferSize + cfg.ResponseHeaderMinBufferSize
	if len(router.exchs) != numGoro {
		t.Fatalf("got %d exchanges, want %d", len(router.exchs), numGoro)
	}
	if cap(router.globbuf) < numGoro*wantRaw {
		t.Errorf("raw store holds %d bytes, want %d", cap(router.globbuf), numGoro*wantRaw)
	}
	if cap(router.globpath) < numGoro*maxPathValues {
		t.Errorf("path store holds %d values, want %d", cap(router.globpath), numGoro*maxPathValues)
	}
	rawSeen := make(map[*byte]int, numGoro*wantRaw)
	pathSeen := make(map[*PathValue]int, numGoro*maxPathValues)
	for i := range router.exchs {
		exch := &router.exchs[i]
		if len(exch.rawbuf) != wantRaw {
			t.Errorf("exchange %d: raw buffer is %d bytes, want %d", i, len(exch.rawbuf), wantRaw)
		}
		if len(exch.pathValues) != maxPathValues {
			t.Errorf("exchange %d: %d path values, want %d", i, len(exch.pathValues), maxPathValues)
		}
		// Every byte must come from the shared store and belong to this exchange
		// alone: an exchange allocating its own, or two sharing a window, would
		// make the per-connection accounting a fiction.
		for j := range exch.rawbuf {
			p := &exch.rawbuf[j]
			if owner, dup := rawSeen[p]; dup {
				t.Fatalf("exchanges %d and %d share raw buffer byte %d", owner, i, j)
			}
			rawSeen[p] = i
		}
		for j := range exch.pathValues {
			p := &exch.pathValues[j]
			if owner, dup := pathSeen[p]; dup {
				t.Fatalf("exchanges %d and %d share path value %d", owner, i, j)
			}
			pathSeen[p] = i
		}
	}
	if len(rawSeen) != numGoro*wantRaw {
		t.Errorf("exchanges cover %d raw bytes, want %d", len(rawSeen), numGoro*wantRaw)
	}
}

// TestExchangeConfigureIsAllocationFree checks an exchange handed all of its
// memory allocates none of its own, which is what lets a router carve every
// exchange out of its two stores.
func TestExchangeConfigureIsAllocationFree(t *testing.T) {
	cfg := ExchangeConfig{
		RawBuf:                make([]byte, 640),
		RequestBufferLim:      512,
		NumHeaderKVCap:        16,
		NoRequestBufferGrowth: true,
		PathValuesBuf:         make([]PathValue, 4),
	}
	var exch Exchange
	exch.Configure(cfg) // Field table allocates once, then settles.
	allocs := testing.AllocsPerRun(100, func() {
		exch.Configure(cfg)
	})
	if allocs != 0 {
		t.Errorf("Exchange.Configure allocates %v times, want 0", allocs)
	}
}

// TestMemoryUsagePerConnectionMatchesHeap checks the accounting against the heap
// a router actually takes, which is what makes the number worth budgeting
// against.
//
// It measures two budgets and compares the difference rather than either
// absolute figure. A router's heap carries costs the accounting does not claim
// and should not: size class rounding, the job queue's runtime header and the
// runtime's per-goroutine bookkeeping. Those are identical at both budgets, so
// subtracting cancels them and leaves only the buffers, whose growth is exactly
// what MemoryUsagePerConnection predicts. Goroutine stacks never enter into it,
// the runtime accounting them separately from the heap measured here.
func TestMemoryUsagePerConnectionMatchesHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("measures heap over many Configure iterations")
	}
	const numGoro = 64
	const maxPathValues = 3
	mux := newBudgetMux(maxPathValues)
	measure := func(budget int) (accounted, heap int) {
		cfg := DefaultRouterConfig(numGoro, budget, maxPathValues)
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				var router Router
				if err := router.Configure(mux, cfg); err != nil {
					b.Fatal(err)
				}
				router.Shutdown()
			}
		})
		return numGoro * cfg.MemoryUsagePerConnection(maxPathValues), int(res.AllocedBytesPerOp())
	}
	lowAcct, lowHeap := measure(2048)
	highAcct, highHeap := measure(16384)
	wantGrowth := highAcct - lowAcct
	gotGrowth := highHeap - lowHeap
	t.Logf("accounted %d->%d (+%d), heap %d->%d (+%d)",
		lowAcct, highAcct, wantGrowth, lowHeap, highHeap, gotGrowth)

	// What remains after cancelling is buffer growth, which the accounting covers
	// term for term. Only size class rounding on the grown buffers is left over.
	const tolerancePercent = 2
	if diff := abs(gotGrowth - wantGrowth); diff*100 > wantGrowth*tolerancePercent {
		t.Errorf("budget growth accounted %d bytes, heap grew %d (%+d)",
			wantGrowth, gotGrowth, gotGrowth-wantGrowth)
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
