package ipv6

import "github.com/soypat/lneto/ipv4"

const (
	sizeHeader = 40
)

type ToS = ipv4.ToS

// AppendFormatAddr appends the canonical text representation of an IPv6 address
// to dst following RFC 5952 conventions (lowercase hex, :: compression for the
// longest run of consecutive zero groups of length ≥ 2). Zero heap allocations.
func AppendFormatAddr(dst []byte, addr [16]byte) []byte {
	const hexDigits = "0123456789abcdef"

	// Find the longest run of consecutive all-zero 16-bit groups for :: compression.
	bestStart, bestLen := 0, 0
	curStart := -1
	for i := 0; i < 8; i++ {
		if addr[i*2] == 0 && addr[i*2+1] == 0 {
			if curStart < 0 {
				curStart = i
			}
			if i-curStart+1 > bestLen {
				bestStart = curStart
				bestLen = i - curStart + 1
			}
		} else {
			curStart = -1
		}
	}
	if bestLen < 2 {
		bestLen = 0 // RFC 5952 §4.2.2: do not compress a single 16-bit group.
	}

	needColon := false
	for i := 0; i < 8; i++ {
		if bestLen > 0 && i == bestStart {
			dst = append(dst, ':', ':')
			i += bestLen - 1 // skip compressed groups; loop increments i.
			needColon = false
			continue
		}
		if needColon {
			dst = append(dst, ':')
		}
		needColon = true
		hi := addr[i*2]
		lo := addr[i*2+1]
		v := uint16(hi)<<8 | uint16(lo)
		if v >= 0x1000 {
			dst = append(dst, hexDigits[hi>>4])
		}
		if v >= 0x100 {
			dst = append(dst, hexDigits[hi&0xf])
		}
		if v >= 0x10 {
			dst = append(dst, hexDigits[lo>>4])
		}
		dst = append(dst, hexDigits[lo&0xf])
	}
	return dst
}
