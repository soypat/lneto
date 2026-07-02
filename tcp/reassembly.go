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
type reassembly struct {
	held []reasmSeg
}

// reasmSeg records a held segment by sequence number and payload length. No
// buffer offset is kept: the ring write pointer advances in lockstep with
// rcv.NXT, so the staged bytes are always where seq implies (see
// [Handler.flushReassembly]).
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
// rcvNxt fills. It returns true when held, including when already held (storing
// is idempotent). It fails if reassembly is disabled, the payload is empty,
// metadata is full, it does not fit rx's free region, or it overlaps a held
// segment.
func (r *reassembly) store(rx *internal.Ring, rcvNxt, seq Value, payload []byte) bool {
	if !r.enabled() || len(payload) == 0 {
		return false
	}
	end := Add(seq, Size(len(payload)))
	for i := range r.held {
		if r.held[i].seq == seq {
			return true // already buffered; idempotent.
		}
		heldEnd := Add(r.held[i].seq, Size(r.held[i].n))
		if seq.LessThan(heldEnd) && r.held[i].seq.LessThan(end) {
			return false // overlaps a held segment.
		}
	}
	if len(r.held) >= cap(r.held) {
		return false // metadata full.
	}
	gap := int(Sizeof(rcvNxt, seq))
	if !rx.PeekWrite(payload, gap) {
		return false // does not fit in the free region.
	}
	r.held = append(r.held, reasmSeg{seq: seq, n: len(payload)})
	return true
}

// popContiguous removes the held segment that begins exactly at nxt and returns
// it. It returns false when no held segment starts at nxt.
func (r *reassembly) popContiguous(nxt Value) (reasmSeg, bool) {
	for i := range r.held {
		if r.held[i].seq == nxt {
			seg := r.held[i]
			r.held = append(r.held[:i], r.held[i+1:]...)
			return seg, true
		}
	}
	return reasmSeg{}, false
}

// prune drops held segments beginning before nxt and returns the count. These
// are stale or partially overlap the delivered region, where the in-order write
// at nxt may have overwritten their staged bytes; the sender retransmits the
// tail. A segment beginning exactly at nxt is kept for [reassembly.popContiguous].
func (r *reassembly) prune(nxt Value) int {
	n := 0
	for i := 0; i < len(r.held); {
		if r.held[i].seq.LessThan(nxt) {
			r.held = append(r.held[:i], r.held[i+1:]...)
			n++
			continue
		}
		i++
	}
	return n
}
