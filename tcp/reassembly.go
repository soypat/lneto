package tcp

import "github.com/soypat/lneto/internal"

// reassembly is a bounded out-of-order segment reassembly buffer. It stores the
// payloads of in-window TCP segments that arrived ahead of the next expected
// sequence number so that, once the gap is filled by a retransmission, the
// buffered tail can be delivered without the peer re-sending it (avoiding
// go-back-N). It is the receiver-side state a SACK sender relies on.
//
// Storage is a user-provided slab divided into a fixed number of equal slots,
// one per held segment, so memory is bounded and nothing is allocated on the
// data path — suited to the embedded targets lneto serves. A segment larger
// than a slot, a duplicate, or one that does not fit is simply not stored; the
// sender retransmits it (and, as a backstop, the RFC 6298 timer recovers it).
type reassembly struct {
	slab    []byte
	segSize int        // bytes per slot; 0 when reassembly is disabled.
	held    []reasmSeg // current out-of-order segments, cap == number of slots.
}

// reasmSeg records one buffered out-of-order segment: its first sequence
// number, the slab slot holding its payload and the payload length.
type reasmSeg struct {
	seq  Value
	slot int
	n    int
}

// reset (re)configures the buffer to use slab divided into maxSegs slots, or
// disables reassembly when slab is nil or maxSegs is zero. Held state is
// cleared; the slab and slot count persist across connection reopens.
func (r *reassembly) reset(slab []byte, maxSegs int) {
	if len(slab) == 0 || maxSegs <= 0 {
		r.slab = nil
		r.segSize = 0
		r.held = r.held[:0]
		return
	}
	r.slab = slab
	r.segSize = len(slab) / maxSegs
	internal.SliceReuse(&r.held, maxSegs)
}

// clear drops all held segments without changing configuration.
func (r *reassembly) clear() { r.held = r.held[:0] }

// enabled reports whether out-of-order buffering is configured.
func (r *reassembly) enabled() bool { return r.segSize > 0 }

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

// store buffers payload for sequence number seq, returning true if it is now
// held (including when it was already held — the call is idempotent). It fails
// when reassembly is disabled, the payload is empty or larger than a slot, the
// buffer is full, or no slot is free.
func (r *reassembly) store(seq Value, payload []byte) bool {
	if !r.enabled() || len(payload) == 0 || len(payload) > r.segSize {
		return false
	}
	for i := range r.held {
		if r.held[i].seq == seq {
			return true // already buffered; idempotent.
		}
	}
	if len(r.held) >= cap(r.held) {
		return false // all slots occupied.
	}
	slot := r.freeSlot()
	if slot < 0 {
		return false
	}
	copy(r.slab[slot*r.segSize:slot*r.segSize+r.segSize], payload)
	r.held = append(r.held, reasmSeg{seq: seq, slot: slot, n: len(payload)})
	return true
}

// popContiguous removes the held segment that begins exactly at nxt and returns
// its payload (a slice into the slab valid until the next store). It returns
// false when no held segment starts at nxt.
func (r *reassembly) popContiguous(nxt Value) ([]byte, bool) {
	for i := range r.held {
		if r.held[i].seq == nxt {
			seg := r.held[i]
			data := r.slab[seg.slot*r.segSize : seg.slot*r.segSize+seg.n]
			r.held = append(r.held[:i], r.held[i+1:]...)
			return data, true
		}
	}
	return nil, false
}

// prune discards held segments that lie wholly at or below nxt (already
// delivered), freeing their slots. Returns the number pruned.
func (r *reassembly) prune(nxt Value) int {
	n := 0
	for i := 0; i < len(r.held); {
		seg := r.held[i]
		if Add(seg.seq, Size(seg.n)).LessThanEq(nxt) {
			r.held = append(r.held[:i], r.held[i+1:]...)
			n++
			continue
		}
		i++
	}
	return n
}

// freeSlot returns an unused slab slot index, or -1 when all are occupied.
func (r *reassembly) freeSlot() int {
	for s := 0; s < cap(r.held); s++ {
		inUse := false
		for i := range r.held {
			if r.held[i].slot == s {
				inUse = true
				break
			}
		}
		if !inUse {
			return s
		}
	}
	return -1
}
