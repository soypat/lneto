package internal

import "strconv"

// AppendStrDecimal appends pfx followed by value in base 10 to dst and returns
// the resulting slice. It condenses the prefixed-number pattern common to
// AppendString/AppendText methods, i.e. `internal.AppendStrDecimal(b, " len=", 4)`.
func AppendStrDecimal(dst []byte, pfx string, value int64) []byte {
	dst = append(dst, pfx...)
	return strconv.AppendInt(dst, value, 10)
}

// IntLen returns the number of bytes [strconv.AppendInt] emits for value in the
// given base, including a leading minus sign for negatives. Lets callers size a
// buffer, or test whether a value fits an existing slot, before writing a byte.
// base must be in the range 2..36, as accepted by [strconv.AppendInt].
func IntLen(value int64, base int) int {
	n := 1
	u := uint64(value)
	if value < 0 {
		n++    // Leading minus sign.
		u = -u // Two's-complement magnitude; correct even for math.MinInt64.
	}
	for u >= uint64(base) {
		u /= uint64(base)
		n++
	}
	return n
}
