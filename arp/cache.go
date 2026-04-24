package arp

import (
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
)

type cache struct {
	entries []entry
}

// entry is designed for compactness. size=class=24 bytes, same as a slice header on x86.
type entry struct {
	addr  [16]byte
	mac   [6]byte
	age   uint8
	flags eflags
}

func (e *entry) use(mac [6]byte, proto []byte, flags eflags) {
	e.flags = eflagInUse | flags
	if copy(e.addr[:], proto) == 16 {
		e.flags |= eflagIPv6
	}
	e.age = 0
	e.mac = mac
}

func (e *entry) destroy() { *e = entry{} }

func (e *entry) put(frame, ourAddr []byte, ourMAC [6]byte, op Operation) (int, error) {
	if len(ourMAC) != 6 {
		return 0, lneto.ErrInvalidAddr
	}
	f, err := NewFrame(frame)
	if err != nil {
		return 0, err
	}
	f.SetHardware(1, 6)
	f.SetOperation(op)
	var n int
	if e.flags&eflagIPv6 != 0 {
		if len(ourAddr) != 16 {
			return 0, lneto.ErrInvalidAddr
		} else if len(frame) < sizeHeaderv6 {
			return 0, lneto.ErrShortBuffer
		}
		f.SetProtocol(ethernet.TypeIPv6, 16)
		hw, addr := f.Sender16()
		*hw = ourMAC
		copy(addr[:], ourAddr)
		hw, addr = f.Target16()
		copy(hw[:], e.mac[:])
		copy(addr[:], e.addr[:])
		n = sizeHeaderv6
	} else {
		if len(ourAddr) != 4 {
			return 0, lneto.ErrInvalidAddr
		}
		f.SetProtocol(ethernet.TypeIPv4, 4)
		hw, addr := f.Sender4()
		*hw = ourMAC
		copy(addr[:], ourAddr)
		hw, addr = f.Target4()
		copy(hw[:], e.mac[:])
		copy(addr[:], e.addr[:])
		n = sizeHeaderv4
	}
	return n, nil
}

func (flags eflags) hasAny(bits eflags) bool { return flags&bits != 0 }

type eflags uint8

// unset eflagInUse to signal the entry can be acquired for a new query.
const (
	// eflagInUse set when in use. Discarded/unused entries have this bit unset.
	eflagInUse eflags = 1 << iota
	// set for IPv6 addressed entries.
	eflagIPv6
	// network device queried our address and we must respond to it.
	// Both MAC and IP are valid in this case.
	eflagPendingResponse
	// user asked to query this address and query has yet to be answered. May or may not be sent.
	eflagIncomplete
	// user asked to query this address and the query has not been sent out yet.
	// The MAC address is invalid in this case.
	eflagIncompletePendingQuery
	// eflagPriority set for prioritized cache entries. These entries are discarded last.
	// i.e: set for user created queries, unset for external incoming network queries.
	eflagPriority
	// trigger callback, you know the drill.
	eflagResolveTriggersCallback
)

func (c *cache) age() {
	for i := range c.entries {
		if c.entries[i].flags&eflagInUse != 0 && c.entries[i].age < 255 {
			c.entries[i].age++
		}
	}
}

func (c *cache) reset(size int) {
	internal.SliceReuse(&c.entries, size)
	c.entries = c.entries[:cap(c.entries)] // maximize queries given allocation.
}

func (c *cache) getNextFlagged(entryHasFlags eflags) *entry {
	for i := range c.entries {
		flags := c.entries[i].flags
		if flags&eflagInUse != 0 && flags.hasAny(entryHasFlags) {
			return &c.entries[i]
		}
	}
	return nil
}

func (c *cache) clearFlags(entryHasFlags, clrTheseFlagsIfMatch eflags) {
	for i := range c.entries {
		// Can clear flags on unused too, simpler.
		if c.entries[i].flags&entryHasFlags != 0 {
			c.entries[i].flags &^= clrTheseFlagsIfMatch
		}
	}
}

func (c *cache) Lookup(addr []byte) *entry {
	n := len(addr)
	for i := range c.entries {
		if c.entries[i].flags&eflagInUse != 0 && internal.BytesEqual(c.entries[i].addr[:n], addr) {
			return &c.entries[i]
		}
	}
	return nil
}

// acquireNext gets next available entry for use. If all are in use evicts
// the oldest passive entry (learned from incoming requests) before touching
// active user queries or pending responses.
func (c *cache) acquireNext() *entry {
	const priorityFlags = eflagPendingResponse | eflagIncomplete | eflagPriority
	oldest, oldestPassive := 0, -1
	for i := range c.entries {
		if c.entries[i].flags&eflagInUse == 0 {
			oldest = i
			break
		}
		if !c.entries[i].flags.hasAny(priorityFlags) {
			if oldestPassive < 0 || c.entries[i].age > c.entries[oldestPassive].age {
				oldestPassive = i
			}
		}
		if c.entries[i].age > c.entries[oldest].age {
			oldest = i
		}
	}
	if oldestPassive >= 0 && c.entries[oldest].flags&eflagInUse != 0 {
		oldest = oldestPassive
	}
	c.age()
	e := &c.entries[oldest]
	e.destroy()
	return e
}
