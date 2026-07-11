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

func TestReassemblyStoreAndReassemble(t *testing.T) {
	var r reassembly
	r.reset(4)
	rx := internal.Ring{Buf: make([]byte, 32)}
	if !r.enabled() {
		t.Fatal("reassembly should be enabled after reset")
	}
	// Buffer two out-of-order segments (gap at seq 100), stored newest-first to
	// prove store keeps held ordered by seq.
	if !r.store(&rx, 100, 108, []byte("CCC")) { // covers 108..111
		t.Fatal("store 108 failed")
	}
	if !r.store(&rx, 100, 104, []byte("BBBB")) { // covers 104..108
		t.Fatal("store 104 failed")
	}
	if r.buffered() != 2 {
		t.Fatalf("buffered=%d, want 2", r.buffered())
	}
	if r.held[0].seq != 104 || r.held[1].seq != 108 {
		t.Fatalf("held not ordered by seq: %+v", r.held)
	}
	// A gap at 100 blocks delivery entirely.
	if got := r.reassemble(&rx, 100); got != 0 {
		t.Fatalf("reassemble(100)=%d, want 0 with a gap at 100", got)
	}
	// Once 100..104 is delivered in order, both held segments become contiguous.
	if _, err := rx.Write([]byte("AAAA")); err != nil {
		t.Fatal("gap write:", err)
	}
	if got := r.reassemble(&rx, 104); got != 7 {
		t.Fatalf("reassemble(104)=%d, want 7", got)
	}
	if r.buffered() != 0 {
		t.Errorf("buffered=%d, want 0 after full delivery", r.buffered())
	}
	out := make([]byte, 16)
	n, _ := rx.Read(out)
	if !bytes.Equal(out[:n], []byte("AAAABBBBCCC")) {
		t.Fatalf("reassembled %q, want AAAABBBBCCC", out[:n])
	}
}

func TestReassemblyDedup(t *testing.T) {
	var r reassembly
	r.reset(4)
	rx := internal.Ring{Buf: make([]byte, 32)}
	if !r.store(&rx, 100, 104, []byte("AAA")) {
		t.Fatal("first store failed")
	}
	if !r.store(&rx, 100, 104, []byte("AAA")) {
		t.Error("duplicate store of same seq should be idempotent true")
	}
	if r.buffered() != 1 {
		t.Errorf("buffered=%d, want 1 (duplicate must not add a segment)", r.buffered())
	}
}

func TestReassemblyFull(t *testing.T) {
	var r reassembly
	r.reset(2) // only 2 slots.
	rx := internal.Ring{Buf: make([]byte, 32)}
	if !r.store(&rx, 100, 104, []byte("a")) || !r.store(&rx, 100, 108, []byte("b")) {
		t.Fatal("filling slots failed")
	}
	if r.store(&rx, 100, 116, []byte("c")) {
		t.Error("store must fail when all slots are occupied")
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
	if r.store(&rx, 100, 106, []byte("XX")) { // 106..108 overlaps its successor
		t.Error("overlapping store must be rejected")
	}
	if r.store(&rx, 100, 102, []byte("YYYY")) { // 102..106 overlaps its predecessor
		t.Error("overlapping store must be rejected")
	}
	if r.buffered() != 1 {
		t.Errorf("buffered=%d, want 1 (overlaps must not be stored)", r.buffered())
	}
}

// TestReassembleDropsStale checks segments beginning before nxt are dropped, not
// delivered (their staged bytes may have been overwritten by the in-order write).
func TestReassembleDropsStale(t *testing.T) {
	var r reassembly
	r.reset(4)
	rx := internal.Ring{Buf: make([]byte, 32)}
	r.store(&rx, 100, 104, []byte("BBBB")) // covers 104..108
	r.store(&rx, 100, 112, []byte("DDDD")) // covers 112..116
	// rcv.NXT advanced to 106, partway into the first held segment, with a gap
	// before the second: the stale segment is dropped and nothing is delivered.
	if got := r.reassemble(&rx, 106); got != 0 {
		t.Errorf("reassemble(106)=%d, want 0", got)
	}
	if r.buffered() != 1 || r.held[0].seq != 112 {
		t.Errorf("held=%+v, want only seq 112", r.held)
	}
}

func TestReassemblyResetDisables(t *testing.T) {
	var r reassembly
	rx := internal.Ring{Buf: make([]byte, 16)}
	r.reset(4)
	r.store(&rx, 100, 104, []byte("a"))
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
		_ = r.reassemble(&rx, 112)
	})
	if allocs != 0 {
		t.Errorf("reassembly data path must not allocate, got %v allocs/op", allocs)
	}
}

// TestReassembleTwoHoleSelective models a SACK-style two-hole recovery on the
// receiver: segments arrive out of order around two gaps, the reader drains
// delivered data as it goes (fully draining the ring between the two hole
// fills), and the gaps are later filled in order. The reassembled+read stream
// must equal the original byte sequence. Guards against the ring resetting its
// write position while the second hole's followers are still staged.
func TestReassembleTwoHoleSelective(t *testing.T) {
	const (
		seg     = 1448
		nseg    = 13
		ringLen = 32 * 1024
	)
	full := make([]byte, nseg*seg)
	for i := range full {
		full[i] = byte(i*131 + 7)
	}
	segAt := func(idx int) []byte { return full[idx*seg : (idx+1)*seg] }

	rx := internal.Ring{Buf: make([]byte, ringLen)}
	var r reassembly
	r.reset(maxReasmSegments)

	nxt := Value(0) // rcv.NXT (ISS=0) in this simplified receiver model.
	var got []byte
	drain := func() {
		buf := make([]byte, seg)
		for {
			n, err := rx.Read(buf)
			if n > 0 {
				got = append(got, buf[:n]...)
			}
			if n == 0 || err != nil {
				break
			}
		}
	}
	inOrder := func(idx int) {
		if _, err := rx.Write(segAt(idx)); err != nil {
			t.Fatalf("in-order write seg %d: %v", idx, err)
		}
		nxt = Add(nxt, seg)
		if d := r.reassemble(&rx, nxt); d > 0 {
			nxt = Add(nxt, d)
		}
	}
	ooo := func(idx int) {
		if !r.store(&rx, nxt, Value(idx*seg), segAt(idx)) {
			t.Fatalf("store out-of-order seg %d rejected (held=%d)", idx, r.buffered())
		}
	}

	inOrder(0)
	inOrder(1)
	inOrder(2)
	inOrder(3)
	drain()
	// seg 4 dropped; its followers arrive out of order.
	ooo(5)
	ooo(6)
	ooo(7)
	ooo(8)
	// seg 9 dropped; its followers arrive out of order.
	ooo(10)
	ooo(11)
	ooo(12)
	inOrder(4) // retransmitted hole unblocks 5..8.
	drain()    // fully drains the ring while 10..12 are still staged.
	inOrder(9) // retransmitted hole unblocks 10..12.
	drain()

	if !bytes.Equal(got, full) {
		for i := range full {
			if i >= len(got) || got[i] != full[i] {
				t.Fatalf("stream corrupted at offset %d (seg %d): got %#x want %#x (len got=%d want=%d)",
					i, i/seg, byteOrEOF(got, i), full[i], len(got), len(full))
			}
		}
	}
}

func byteOrEOF(b []byte, i int) any {
	if i < len(b) {
		return b[i]
	}
	return "EOF"
}
