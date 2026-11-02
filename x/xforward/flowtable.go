package xforward

import (
	"encoding/binary"

	"github.com/soypat/lneto/internal"
)

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
	n := 1
	for n < 2*maxFlows {
		n <<= 1
	}
	t.hashKey = hashKey
	internal.SliceReuse(&t.keys, maxFlows)
	t.keys = t.keys[:maxFlows]
	clear(t.keys)
	internal.SliceReuse(&t.index, n)
	t.index = t.index[:n]
	clear(t.index)
	internal.SliceReuse(&t.free, maxFlows)
	t.free = t.free[:maxFlows]
	for i := range t.free {
		t.free[i] = uint16(maxFlows - 1 - i) // Popped from the end: slot 0 first.
	}
}

// lookup returns the slot holding k or -1 if absent.
func (t *flowTable) lookup(k *flowKey) int {
	if len(t.free) == len(t.keys) {
		return -1 // Empty or unconfigured.
	}
	mask := len(t.index) - 1
	for i := t.home(k); t.index[i] != 0; i = (i + 1) & mask {
		if slot := int(t.index[i]) - 1; t.keys[slot] == *k {
			return slot
		}
	}
	return -1
}

// insert stores k in a free slot and returns it, or -1 if full. Caller ensures k is absent.
func (t *flowTable) insert(k *flowKey) int {
	if len(t.free) == 0 {
		return -1
	}
	slot := int(t.free[len(t.free)-1])
	t.free = t.free[:len(t.free)-1]
	t.keys[slot] = *k
	mask := len(t.index) - 1
	i := t.home(k)
	for t.index[i] != 0 {
		i = (i + 1) & mask
	}
	t.index[i] = uint16(slot + 1)
	return slot
}

// remove frees slot with backward-shift deletion, leaving no tombstones.
func (t *flowTable) remove(slot int) {
	mask := len(t.index) - 1
	i := t.home(&t.keys[slot])
	for int(t.index[i]) != slot+1 {
		i = (i + 1) & mask
	}
	// i is the hole. Pull each later entry of the probe run back into it
	// unless the hole lies before the entry's home, which would hide it from lookup.
	for j := (i + 1) & mask; t.index[j] != 0; j = (j + 1) & mask {
		home := t.home(&t.keys[t.index[j]-1])
		if (j-home)&mask >= (j-i)&mask {
			t.index[i] = t.index[j]
			i = j
		}
	}
	t.index[i] = 0
	t.keys[slot] = flowKey{}
	*internal.SliceReclaim(&t.free) = uint16(slot)
}

// home returns the index position k probes from.
func (t *flowTable) home(k *flowKey) int {
	var buf [36]byte
	copy(buf[0:16], k.laddr[:])
	copy(buf[16:32], k.raddr[:])
	binary.BigEndian.PutUint16(buf[32:34], k.lport)
	binary.BigEndian.PutUint16(buf[34:36], k.rport)
	return int(uint32(internal.SipHash24(&t.hashKey, buf[:])) & uint32(len(t.index)-1))
}
