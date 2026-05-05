package icmpv6

import (
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

type ndpCache struct {
	entries []ndpEntry
}

// ndpEntry maps an IPv6 address to a MAC. Designed for compactness: 24 bytes.
type ndpEntry struct {
	addr  [16]byte
	mac   [6]byte
	age   uint8
	flags ndpFlags
}

type ndpFlags uint8

// unset ndpFlagInUse to signal the entry can be acquired for a new query.
const (
	ndpFlagInUse                   ndpFlags = 1 << iota
	ndpFlagPendingResponse                  // received a NS for our addr; must send NA
	ndpFlagIncomplete                       // query in flight; MAC not yet resolved
	ndpFlagIncompletePendingQuery           // NS not yet transmitted
	ndpFlagPriority                         // user query; evicted last
	ndpFlagResolveTriggersCallback          // call onresolve when MAC is learned
)

func (f ndpFlags) hasAny(bits ndpFlags) bool { return f&bits != 0 }

func (e *ndpEntry) use(mac [6]byte, addr [16]byte, flags ndpFlags) {
	e.flags = ndpFlagInUse | flags
	e.addr = addr
	e.age = 0
	e.mac = mac
}

func (e *ndpEntry) destroy() { *e = ndpEntry{} }

func (e *ndpEntry) put(buf []byte, ourAddr [16]byte, ourMAC [6]byte, tp Type) (int, error) {
	if len(buf) < sizeNDP {
		return 0, lneto.ErrShortBuffer
	}
	buf[0] = uint8(tp)
	buf[1] = 0
	buf[2], buf[3] = 0, 0 // checksum zeroed; caller computes it
	switch tp {
	case TypeNeighborSolicitation:
		buf[4], buf[5], buf[6], buf[7] = 0, 0, 0, 0
		copy(buf[8:24], e.addr[:]) // target = address being queried
		buf[24] = ndpOptSourceLinkAddr
		buf[25] = 1 // length in units of 8 bytes
		copy(buf[26:32], ourMAC[:])
	case TypeNeighborAdvertisement:
		buf[4] = 0x60 // S=1 (solicited), O=1 (override)
		buf[5], buf[6], buf[7] = 0, 0, 0
		copy(buf[8:24], ourAddr[:]) // target = our address being announced
		buf[24] = ndpOptTargetLinkAddr
		buf[25] = 1
		copy(buf[26:32], ourMAC[:])
	default:
		return 0, lneto.ErrUnsupported
	}
	return sizeNDP, nil
}

func (c *ndpCache) ageEntries() {
	for i := range c.entries {
		if c.entries[i].flags&ndpFlagInUse != 0 && c.entries[i].age < 255 {
			c.entries[i].age++
		}
	}
}

func (c *ndpCache) reset(size int) {
	internal.SliceReuse(&c.entries, size)
	c.entries = c.entries[:cap(c.entries)]
}

func (c *ndpCache) getNextFlagged(flags ndpFlags) *ndpEntry {
	for i := range c.entries {
		f := c.entries[i].flags
		if f&ndpFlagInUse != 0 && f.hasAny(flags) {
			return &c.entries[i]
		}
	}
	return nil
}

func (c *ndpCache) clearFlags(entryHasFlags, clrTheseFlagsIfMatch ndpFlags) {
	for i := range c.entries {
		if c.entries[i].flags&entryHasFlags != 0 {
			c.entries[i].flags &^= clrTheseFlagsIfMatch
		}
	}
}

func (c *ndpCache) Lookup(addr [16]byte) *ndpEntry {
	for i := range c.entries {
		if c.entries[i].flags&ndpFlagInUse != 0 && c.entries[i].addr == addr {
			return &c.entries[i]
		}
	}
	return nil
}

// acquireNext returns the next available entry, evicting the oldest passive
// (passively-learned) entry before touching active user queries or pending responses.
func (c *ndpCache) acquireNext() *ndpEntry {
	const priorityFlags = ndpFlagPendingResponse | ndpFlagIncomplete | ndpFlagPriority
	oldest, oldestPassive := 0, -1
	for i := range c.entries {
		if c.entries[i].flags&ndpFlagInUse == 0 {
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
	if oldestPassive >= 0 && c.entries[oldest].flags&ndpFlagInUse != 0 {
		oldest = oldestPassive
	}
	c.ageEntries()
	e := &c.entries[oldest]
	e.destroy()
	return e
}
