package tcp

import "github.com/soypat/lneto/internal"

// maxReasmSegments bounds how many distinct out-of-order segments may be held.
// It caps only fixed metadata; payload bytes live in the receive ring, bounded
// by its free space. Independent of the transmit queue depth.
const maxReasmSegments = 8

// reassembly holds in-window TCP segments that arrived ahead of the next
// expected sequence number, so that once the gap is filled the buffered tail is
// delivered without go-back-N. Payloads are staged in the free region of the
// Handler receive ring (see [internal.Ring.PeekWrite]); only fixed, reused
// metadata lives here, so the data path allocates nothing.
//
// held is kept ordered by ascending sequence number (oldest to newest), which
// lets [reassembly.store] locate insertions and overlaps by neighbour and lets
// [reassembly.reassemble] deliver a contiguous prefix and truncate it in one
// pass.
type reassembly struct {
	held []reasmSeg
}

// reasmSeg records a held segment by sequence number and payload length. No
// buffer offset is kept: the ring write pointer advances in lockstep with
// rcv.NXT, so the staged bytes are always where seq implies (see
// [reassembly.reassemble]).
type reasmSeg struct {
	seq Value
	n   int
}

// reset (re)configures bounded metadata for up to maxSegs held segments, or
// disables reassembly when maxSegs is not positive. Held state is cleared;
// metadata capacity persists across connection reopens.
func (r *reassembly) reset(maxSegs int) {
	if maxSegs <= 0 {
		r.held = nil
		return
	}
	internal.SliceReuse(&r.held, maxSegs)
}

// clear drops all held segments without changing configuration.
func (r *reassembly) clear() { r.held = r.held[:0] }

// enabled reports whether out-of-order buffering is configured.
func (r *reassembly) enabled() bool { return cap(r.held) > 0 }

// buffered reports the number of out-of-order segments currently held.
func (r *reassembly) buffered() int { return len(r.held) }

// bufferedBytes reports the total payload bytes currently held out of order.
// The receiver subtracts these from its advertised window so the sender cannot
// overrun the space the held segments already consume.
func (r *reassembly) bufferedBytes() int {
	n := 0
	for i := range r.held {
		n += r.held[i].n
	}
	return n
}

// store stages payload at the offset it will occupy in rx once the gap from
// rcvNxt fills, keeping held ordered by seq. It returns true when held,
// including when already held (storing is idempotent), and false when disabled,
// the payload is empty, metadata is full, it does not fit rx's free region, or
// it overlaps a held segment.
func (r *reassembly) store(rx *internal.Ring, rcvNxt, seq Value, payload []byte) bool {
	if !r.enabled() || len(payload) == 0 || len(r.held) >= cap(r.held) {
		return false
	}
	gap := int(Sizeof(rcvNxt, seq))
	// Early free-space bail before the ordered-insert scan; strictly cautious,
	// as PeekWrite re-checks this below.
	if gap+len(payload) > rx.Free() {
		return false
	}
	// Find the insertion point that keeps held ordered by ascending seq.
	end := Add(seq, Size(len(payload)))
	i := 0
	for i < len(r.held) && r.held[i].seq.LessThan(seq) {
		i++
	}
	if i > 0 { // Overlaps the predecessor?
		if prev := r.held[i-1]; seq.LessThan(Add(prev.seq, Size(prev.n))) {
			return false
		}
	}
	if i < len(r.held) { // Duplicate, or overlaps the successor?
		if next := r.held[i]; next.seq == seq {
			return true // already buffered; idempotent.
		} else if next.seq.LessThan(end) {
			return false
		}
	}
	if !rx.PeekWrite(payload, gap) {
		return false
	}
	r.held = append(r.held, reasmSeg{})
	copy(r.held[i+1:], r.held[i:])
	r.held[i] = reasmSeg{seq: seq, n: len(payload)}
	return true
}

// reassemble delivers held segments contiguous with nxt by committing their
// staged bytes to rx, and drops any beginning before nxt (stale, or overwritten
// by the in-order write that advanced nxt). Because held is ordered, it walks a
// leading prefix and truncates once. It returns the bytes delivered; the caller
// advances rcv.NXT and ACKs. Delivery stops at the first gap, or if rx is full
// (the remainder is delivered on a later call).
func (r *reassembly) reassemble(rx *internal.Ring, nxt Value) Size {
	var delivered Size
	i := 0
	for i < len(r.held) {
		seg := r.held[i]
		switch {
		case seg.seq == nxt:
			if rx.Commit(seg.n) != nil {
				r.held = append(r.held[:0], r.held[i:]...)
				return delivered
			}
			nxt = Add(nxt, Size(seg.n))
			delivered += Size(seg.n)
			i++
		case seg.seq.LessThan(nxt):
			i++ // stale/overwritten: drop.
		default:
			r.held = append(r.held[:0], r.held[i:]...)
			return delivered // gap before the next segment.
		}
	}
	r.held = r.held[:0]
	return delivered
}

// ReassemblyView is a read-only view of the out-of-order data a connection is
// holding, in ascending sequence order. It is what a policy generating selective
// acknowledgements (RFC 2018) advertises: each block is a range the receiver has
// but cannot yet deliver, because data before it is missing.
//
// The view borrows the connection's state for the duration of the call it was
// handed to and must not be retained, like the option area lent to
// [Policy.WriteOptions]. Reading it allocates nothing, which is why blocks
// are reached by index rather than through a range-over-function iterator: the
// closure that would take would allocate on a path walked for every segment.
//
// The zero value is a valid empty view, so a policy needs no nil check.
type ReassemblyView struct {
	r *reassembly
}

// Len returns the number of held blocks, which is zero when the connection holds
// no out-of-order data or has reassembly disabled.
func (v ReassemblyView) Len() int {
	if v.r == nil {
		return 0
	}
	return len(v.r.held)
}

// Block returns the i'th held block as the half-open sequence range
// [start, end). Blocks are ordered by ascending start and never overlap. It
// panics if i is out of range, so callers bound it with [ReassemblyView.Len].
func (v ReassemblyView) Block(i int) (start, end Value) {
	seg := v.r.held[i]
	return seg.seq, Add(seg.seq, Size(seg.n))
}
