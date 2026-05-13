package ipv4

import (
	"encoding/binary"
	"net/netip"
)

// Prefix is a [netip.Prefix] equivalent specifically designed for IPv4.
type Prefix struct {
	addr        uint32
	bitsPlusOne uint8
}

func PrefixFromNetip(pfx netip.Prefix) Prefix {
	addr := pfx.Addr()
	if addr.Is4() {
		return PrefixFrom(addr.As4(), uint8(pfx.Bits()))
	}
	return Prefix{}
}

// PrefixFrom constructs a [Prefix] from an address and prefix bit length.
//
// It does not allocate and does not mask
// off the host bits of ip.
//
// If bits is less than zero or greater than 32, [Prefix.Bits]
// will return an invalid value 255.
func PrefixFrom(addr [4]byte, bits uint8) Prefix {
	if bits > 32 {
		bits = 0
	}
	return Prefix{addr: addr2bits(addr), bitsPlusOne: bits + 1}
}

// IsValid returns true if the [Prefix] is valid.
func (p Prefix) IsValid() bool { return p.bitsPlusOne != 0 }

// Addr returns the IPv4 address.
func (p Prefix) Addr() [4]byte { return bits2addr(p.addr) }

// Bits returns IPv4 prefix bits 0..32 or 255 for invalid prefixes.
func (p Prefix) Bits() uint8 { return p.bitsPlusOne - 1 }

// NetipPrefix returns the equivalent [netip.Prefix].
func (p Prefix) NetipPrefix() netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom4(p.Addr()), int(p.Bits()))
}

func (p Prefix) addrBitmasked() uint32 { return p.addr & p.bitmask() }
func (p Prefix) bitmask() uint32       { return ^uint32(0) << (32 - p.Bits()) }

func addr2bits(addr [4]byte) uint32 { return binary.BigEndian.Uint32(addr[:]) }

func bits2addr(addrbits uint32) (addr [4]byte) {
	binary.BigEndian.PutUint32(addr[:], addrbits)
	return addr
}

// Contains reports whether the network p includes ip.
//
// A zero-value IP will not match any prefix.
func (p Prefix) Contains(addr [4]byte) bool {
	if !p.IsValid() {
		return false
	}
	mask := p.bitmask()
	return p.addr&mask == addr2bits(addr)&mask
}

// Masked returns the Prefix with address bits outside of the prefix masked to zero.
func (p Prefix) Masked() Prefix {
	return Prefix{addr: p.addrBitmasked(), bitsPlusOne: p.bitsPlusOne}
}

// IsSingleIP reports whether p contains exactly one IP address (i.e. a /32).
func (p Prefix) IsSingleIP() bool { return p.IsValid() && p.Bits() == 32 }

// Overlaps reports whether p and o contain any IP addresses in common.
func (p Prefix) Overlaps(o Prefix) bool {
	if !p.IsValid() || !o.IsValid() {
		return false
	}
	mask := ^uint32(0) << (32 - min(p.Bits(), o.Bits()))
	return p.addr&mask == o.addr&mask
}

// Next returns the address following addr in the prefix mask with wrap around semantics.
func (p Prefix) Next(addr [4]byte) (next [4]byte) {
	mask := p.bitmask()
	host := addr2bits(addr) &^ mask
	host = (host + 1) & ^mask
	return bits2addr(p.addrBitmasked() | host)
}

// Compare returns an integer comparing two prefixes.
// The result will be 0 if p == p2, -1 if p < p2, and +1 if p > p2.
// Prefixes sort first by validity (invalid before valid), then masked
// prefix address, then prefix length, then unmasked address.
func (p Prefix) Compare(p2 Prefix) int {
	if p.IsValid() != p2.IsValid() {
		if !p.IsValid() {
			return -1
		}
		return 1
	}
	if !p.IsValid() {
		return 0
	}
	pm, p2m := p.addrBitmasked(), p2.addrBitmasked()
	if pm != p2m {
		if pm < p2m {
			return -1
		}
		return 1
	}
	if p.bitsPlusOne != p2.bitsPlusOne {
		if p.bitsPlusOne < p2.bitsPlusOne {
			return -1
		}
		return 1
	}
	pa, p2a := p.addr, p2.addr
	if pa < p2a {
		return -1
	} else if pa > p2a {
		return 1
	}
	return 0
}
