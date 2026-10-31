package xforward

// flowTable maps flow keys to fixed slots with open addressing and linear probing.
// All memory is allocated in reset; insert and remove never allocate.
type flowTable struct {
	hashKey [16]byte  // SipHash key: resists hash flooding.
	keys    []flowKey // slot → key.
	index   []uint16  // probe entries holding slot+1, 0 is empty. len is a power of two ≥ 2*len(keys).
	free    []uint16  // stack of free slots.
}

// reset sizes the table for maxFlows slots and empties it.
func (t *flowTable) reset(maxFlows int, hashKey [16]byte) {
	panic("unimplemented")
}

// lookup returns the slot holding k or -1 if absent.
func (t *flowTable) lookup(k *flowKey) int {
	panic("unimplemented")
}

// insert stores k in a free slot and returns it, or -1 if full. Caller ensures k is absent.
func (t *flowTable) insert(k *flowKey) int {
	panic("unimplemented")
}

// remove frees slot with backward-shift deletion, leaving no tombstones.
func (t *flowTable) remove(slot int) {
	panic("unimplemented")
}
