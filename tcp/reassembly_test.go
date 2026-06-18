package tcp

import (
	"bytes"
	"testing"
)

func TestReassemblyDisabledByDefault(t *testing.T) {
	var r reassembly
	if r.enabled() {
		t.Fatal("zero-value reassembly must be disabled")
	}
	if r.store(100, []byte("x")) {
		t.Error("store must fail when disabled")
	}
}

func TestReassemblyStoreAndPop(t *testing.T) {
	var r reassembly
	r.reset(make([]byte, 4*8), 4) // 4 slots of 8 bytes.
	if !r.enabled() {
		t.Fatal("reassembly should be enabled after reset")
	}
	// Buffer three out-of-order segments (gap at seq 100).
	if !r.store(108, []byte("CCC")) {
		t.Fatal("store 108 failed")
	}
	if !r.store(104, []byte("BBBB")) {
		t.Fatal("store 104 failed")
	}
	if r.buffered() != 2 {
		t.Fatalf("buffered=%d, want 2", r.buffered())
	}
	// Nothing starts at 100 yet.
	if _, ok := r.popContiguous(100); ok {
		t.Error("popContiguous(100) should miss with a gap at 100")
	}
	// After 100..104 is delivered, 104 becomes contiguous.
	data, ok := r.popContiguous(104)
	if !ok || !bytes.Equal(data, []byte("BBBB")) {
		t.Fatalf("popContiguous(104)=%q,%v want BBBB,true", data, ok)
	}
	data, ok = r.popContiguous(108)
	if !ok || !bytes.Equal(data, []byte("CCC")) {
		t.Fatalf("popContiguous(108)=%q,%v want CCC,true", data, ok)
	}
	if r.buffered() != 0 {
		t.Errorf("buffered=%d, want 0 after popping all", r.buffered())
	}
}

func TestReassemblyDedup(t *testing.T) {
	var r reassembly
	r.reset(make([]byte, 4*8), 4)
	if !r.store(100, []byte("AAA")) {
		t.Fatal("first store failed")
	}
	if !r.store(100, []byte("AAA")) {
		t.Error("duplicate store of same seq should be idempotent true")
	}
	if r.buffered() != 1 {
		t.Errorf("buffered=%d, want 1 (duplicate must not add a slot)", r.buffered())
	}
}

func TestReassemblyFull(t *testing.T) {
	var r reassembly
	r.reset(make([]byte, 2*8), 2) // only 2 slots.
	if !r.store(100, []byte("a")) || !r.store(108, []byte("b")) {
		t.Fatal("filling slots failed")
	}
	if r.store(116, []byte("c")) {
		t.Error("store must fail when all slots are occupied")
	}
	// Freeing a slot lets a new segment in.
	if _, ok := r.popContiguous(100); !ok {
		t.Fatal("pop 100 failed")
	}
	if !r.store(116, []byte("c")) {
		t.Error("store should succeed after a slot is freed")
	}
}

func TestReassemblyOversizedRejected(t *testing.T) {
	var r reassembly
	r.reset(make([]byte, 2*4), 2) // 4-byte slots.
	if r.store(100, []byte("toolong")) {
		t.Error("payload larger than a slot must be rejected")
	}
}

func TestReassemblyPrune(t *testing.T) {
	var r reassembly
	r.reset(make([]byte, 4*8), 4)
	r.store(100, []byte("AAAA")) // covers 100..104
	r.store(108, []byte("BBBB")) // covers 108..112
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

func TestReassemblyResetDisables(t *testing.T) {
	var r reassembly
	r.reset(make([]byte, 16), 4)
	r.store(100, []byte("a"))
	r.reset(nil, 0)
	if r.enabled() {
		t.Error("reset(nil,0) must disable reassembly")
	}
	if r.buffered() != 0 {
		t.Error("reset must clear held segments")
	}
}

// TestReassembly_noAllocs verifies the out-of-order buffer's data-path
// operations allocate nothing once configured. Storage and slot metadata are
// supplied and bounded at reset (SetReassemblyBuffer) time and reused across
// segments, so a peer cannot drive unbounded heap growth from the network.
func TestReassembly_noAllocs(t *testing.T) {
	var r reassembly
	r.reset(make([]byte, 4*8), 4) // 4 slots of 8 bytes, allocated once here.
	seg := []byte("DATA")
	allocs := testing.AllocsPerRun(100, func() {
		r.clear()
		r.store(108, seg) // buffer out of order.
		r.store(104, seg) // buffer out of order.
		_ = r.bufferedBytes()
		_, _ = r.popContiguous(104)
		r.prune(112)
	})
	if allocs != 0 {
		t.Errorf("reassembly data path must not allocate, got %v allocs/op", allocs)
	}
}
