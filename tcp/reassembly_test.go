package tcp

import (
	"bytes"
	"testing"

	"github.com/soypat/lneto/internal"
)

func TestReassemblyDisabledByDefault(t *testing.T) {
	var r reassembly
	if r.enabled() {
		t.Fatal("zero-value reassembly must be disabled")
	}
	var rx internal.Ring
	if r.store(&rx, 100, 100, []byte("x")) {
		t.Error("store must fail when disabled")
	}
}

func TestReassemblyStoreAndPop(t *testing.T) {
	var r reassembly
	r.reset(4)
	rx := internal.Ring{Buf: make([]byte, 32)}
	if !r.enabled() {
		t.Fatal("reassembly should be enabled after reset")
	}
	// Buffer three out-of-order segments (gap at seq 100).
	if !r.store(&rx, 100, 108, []byte("CCC")) {
		t.Fatal("store 108 failed")
	}
	if !r.store(&rx, 100, 104, []byte("BBBB")) {
		t.Fatal("store 104 failed")
	}
	if r.buffered() != 2 {
		t.Fatalf("buffered=%d, want 2", r.buffered())
	}
	// Nothing starts at 100 yet.
	if _, ok := r.popContiguous(100); ok {
		t.Error("popContiguous(100) should miss with a gap at 100")
	}
	// On a fresh ring the staged offset equals seq-rcvNxt (here seq-100).
	seg, ok := r.popContiguous(104)
	data := rx.Buf[4 : 4+seg.n] // gap = 104-100.
	if !ok || !bytes.Equal(data, []byte("BBBB")) {
		t.Fatalf("popContiguous(104)=%q,%v want BBBB,true", data, ok)
	}
	seg, ok = r.popContiguous(108)
	data = rx.Buf[8 : 8+seg.n] // gap = 108-100.
	if !ok || !bytes.Equal(data, []byte("CCC")) {
		t.Fatalf("popContiguous(108)=%q,%v want CCC,true", data, ok)
	}
	if r.buffered() != 0 {
		t.Errorf("buffered=%d, want 0 after popping all", r.buffered())
	}
}

func TestReassemblyDedup(t *testing.T) {
	var r reassembly
	r.reset(4)
	rx := internal.Ring{Buf: make([]byte, 32)}
	if !r.store(&rx, 100, 100, []byte("AAA")) {
		t.Fatal("first store failed")
	}
	if !r.store(&rx, 100, 100, []byte("AAA")) {
		t.Error("duplicate store of same seq should be idempotent true")
	}
	if r.buffered() != 1 {
		t.Errorf("buffered=%d, want 1 (duplicate must not add a slot)", r.buffered())
	}
}

func TestReassemblyFull(t *testing.T) {
	var r reassembly
	r.reset(2) // only 2 slots.
	rx := internal.Ring{Buf: make([]byte, 32)}
	if !r.store(&rx, 100, 100, []byte("a")) || !r.store(&rx, 100, 108, []byte("b")) {
		t.Fatal("filling slots failed")
	}
	if r.store(&rx, 100, 116, []byte("c")) {
		t.Error("store must fail when all slots are occupied")
	}
	// Freeing a slot lets a new segment in.
	if _, ok := r.popContiguous(100); !ok {
		t.Fatal("pop 100 failed")
	}
	if !r.store(&rx, 100, 116, []byte("c")) {
		t.Error("store should succeed after a slot is freed")
	}
}

func TestReassemblyOversizedRejected(t *testing.T) {
	var r reassembly
	r.reset(2)
	rx := internal.Ring{Buf: make([]byte, 4)}
	if r.store(&rx, 100, 104, []byte("toolong")) {
		t.Error("payload larger than free receive space must be rejected")
	}
}

func TestReassemblyOverlapRejected(t *testing.T) {
	var r reassembly
	r.reset(4)
	rx := internal.Ring{Buf: make([]byte, 32)}
	if !r.store(&rx, 100, 104, []byte("BBBB")) { // covers 104..108
		t.Fatal("store 104 failed")
	}
	// Segments overlapping the held 104..108 region must be rejected.
	if r.store(&rx, 100, 106, []byte("XX")) { // 106..108 overlaps 104..108
		t.Error("overlapping store must be rejected")
	}
	if r.store(&rx, 100, 102, []byte("YYYY")) { // 102..106 overlaps 104..108
		t.Error("overlapping store must be rejected")
	}
	if r.buffered() != 1 {
		t.Errorf("buffered=%d, want 1 (overlaps must not be stored)", r.buffered())
	}
}

func TestReassemblyPrune(t *testing.T) {
	var r reassembly
	r.reset(4)
	rx := internal.Ring{Buf: make([]byte, 32)}
	r.store(&rx, 100, 100, []byte("AAAA")) // covers 100..104
	r.store(&rx, 100, 108, []byte("BBBB")) // covers 108..112
	// Delivery advanced rcv.NXT to 104: the 100-segment is now stale.
	if pruned := r.prune(104); pruned != 1 {
		t.Errorf("pruned=%d, want 1", pruned)
	}
	if r.buffered() != 1 {
		t.Errorf("buffered=%d, want 1 after prune", r.buffered())
	}
	if _, ok := r.popContiguous(108); !ok {
		t.Error("remaining segment at 108 should survive prune")
	}
}

// TestReassemblyPrunePartialOverlap checks a held segment starting before
// rcv.NXT is dropped, not delivered (its staged bytes may have been overwritten).
func TestReassemblyPrunePartialOverlap(t *testing.T) {
	var r reassembly
	r.reset(4)
	rx := internal.Ring{Buf: make([]byte, 32)}
	r.store(&rx, 100, 104, []byte("BBBB")) // covers 104..108
	// rcv.NXT advanced to 106, partway into the held segment.
	if pruned := r.prune(106); pruned != 1 {
		t.Errorf("pruned=%d, want 1 (partial overlap must be dropped)", pruned)
	}
	if r.buffered() != 0 {
		t.Errorf("buffered=%d, want 0", r.buffered())
	}
}

func TestReassemblyResetDisables(t *testing.T) {
	var r reassembly
	rx := internal.Ring{Buf: make([]byte, 16)}
	r.reset(4)
	r.store(&rx, 100, 100, []byte("a"))
	r.reset(0)
	if r.enabled() {
		t.Error("reset(0) must disable reassembly")
	}
	if r.buffered() != 0 {
		t.Error("reset must clear held segments")
	}
}

// TestReassembly_noAllocs verifies the data-path operations allocate nothing
// once configured (metadata is bounded at reset, payloads reuse the ring).
func TestReassembly_noAllocs(t *testing.T) {
	var r reassembly
	r.reset(4)
	rx := internal.Ring{Buf: make([]byte, 32)}
	seg := []byte("DATA")
	allocs := testing.AllocsPerRun(100, func() {
		r.clear()
		rx.Reset()
		r.store(&rx, 100, 108, seg) // buffer out of order.
		r.store(&rx, 100, 104, seg) // buffer out of order.
		_ = r.bufferedBytes()
		_, _ = r.popContiguous(104)
		r.prune(112)
	})
	if allocs != 0 {
		t.Errorf("reassembly data path must not allocate, got %v allocs/op", allocs)
	}
}
