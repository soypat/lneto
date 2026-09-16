package tcp

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/soypat/lneto/ethernet"
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

// TestReassemblyViewReportsHeldBlocks verifies the view a policy is handed while
// writing options reports exactly the out-of-order blocks being held, in
// ascending order, and that reading it allocates nothing. These are the blocks a
// SACK-generating policy puts on the wire (RFC 2018).
func TestReassemblyViewReportsHeldBlocks(t *testing.T) {
	const ringLen = 4096
	rx := internal.Ring{Buf: make([]byte, ringLen)}
	var r reassembly
	r.reset(maxReasmSegments)
	view := ReassemblyView{r: &r}

	if got := view.Len(); got != 0 {
		t.Errorf("empty reassembly reports %d blocks, want 0", got)
	}
	if got := (ReassemblyView{}).Len(); got != 0 {
		t.Errorf("zero view reports %d blocks, want 0", got)
	}

	// Stage two out-of-order blocks with a gap before each, stored out of order to
	// prove the view reports them sorted rather than as inserted.
	payload := make([]byte, 100)
	const nxt = Value(1000)
	if !r.store(&rx, nxt, 1300, payload) {
		t.Fatal("store second block")
	}
	if !r.store(&rx, nxt, 1100, payload) {
		t.Fatal("store first block")
	}

	if got := view.Len(); got != 2 {
		t.Fatalf("view reports %d blocks, want 2", got)
	}
	wantBlocks := [2][2]Value{{1100, 1200}, {1300, 1400}}
	for i, want := range wantBlocks {
		start, end := view.Block(i)
		if start != want[0] || end != want[1] {
			t.Errorf("block %d = [%d,%d), want [%d,%d)", i, start, end, want[0], want[1])
		}
	}

	allocs := testing.AllocsPerRun(100, func() {
		n := view.Len()
		for i := range n {
			_, _ = view.Block(i)
		}
	})
	if allocs != 0 {
		t.Errorf("reading the view allocated %v times per run, want 0", allocs)
	}
}

// sackWatcher is a Policy that records the out-of-order blocks offered to
// it while a segment's options are written.
type sackWatcher struct {
	nopLoss
	blocks [][2]Value
}

func (w *sackWatcher) WriteOptions(plan TxPlan, _ []byte) uint8 {
	if n := plan.Reassembly.Len(); n > 0 {
		w.blocks = w.blocks[:0]
		for i := range n {
			start, end := plan.Reassembly.Block(i)
			w.blocks = append(w.blocks, [2]Value{start, end})
		}
	}
	return 0
}

// TestHandlerOffersHeldBlocksToWriteOptions verifies the blocks a receiver holds
// out of order reach a policy while it writes the options of an outgoing segment.
// That is where selective acknowledgements go on the wire, so a policy that never
// sees them there could not generate one.
func TestHandlerOffersHeldBlocksToWriteOptions(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(99))
	client, server := newHandler(t, mtu, 4), newHandler(t, mtu, 4)
	watcher := new(sackWatcher)
	server.SetPolicy(watcher, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	pkt1 := emitClientData(t, client, buf[:], "AAAA") // seq S, covers S..S+4.
	pkt2 := emitClientData(t, client, buf[:], "BBBB") // seq S+4, covers S+4..S+8.
	wantStart := mustSegment(t, pkt2, len(pkt2)-sizeHeaderTCP).SEQ

	// Deliver only the second segment, leaving a gap the server holds behind.
	if err := server.Recv(pkt2); err != nil {
		t.Fatalf("out-of-order segment must be accepted, got: %v", err)
	}
	// The ACK the server now emits is the segment a SACK block would ride on.
	var out [mtu]byte
	if n, err := server.Send(out[:]); err != nil {
		t.Fatal("server send:", err)
	} else if n == 0 {
		t.Fatal("server sent no acknowledgement to carry a SACK block")
	}

	if len(watcher.blocks) != 1 {
		t.Fatalf("policy was offered %d blocks, want 1", len(watcher.blocks))
	}
	if got := watcher.blocks[0]; got[0] != wantStart || got[1] != Add(wantStart, 4) {
		t.Errorf("block = [%d,%d), want [%d,%d)", got[0], got[1], wantStart, Add(wantStart, 4))
	}
	_ = pkt1
}
