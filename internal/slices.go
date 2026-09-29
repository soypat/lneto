package internal

import "unsafe"

// BytesEqual is heapless replacement of [bytes.Equal] since it allocates in tinygo.
// https://github.com/tinygo-org/tinygo/issues/4045
func BytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	return unsafe.String(&a[0], len(a)) == unsafe.String(&b[0], len(b))
}

// EqualFoldASCII reports whether a and b are equal under ASCII case folding.
// Unlike [strings.EqualFold] it does not fold non-ASCII runes, so no multi-byte
// rune such as U+212A KELVIN SIGN can alias an ASCII key.
func EqualFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	const asciiCapDiff = 'a' - 'A'
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += asciiCapDiff
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += asciiCapDiff
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// BytesEqualFoldASCII is the []byte form of [EqualFoldASCII]. Like [BytesEqual]
// it is heapless in tinygo, unlike [bytes.EqualFold] which also folds non-ASCII.
func BytesEqualFoldASCII(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	} else if len(a) == 0 {
		return true
	}
	return EqualFoldASCII(unsafe.String(&a[0], len(a)), unsafe.String(&b[0], len(b)))
}

// IsZeroed returns true if all arguments are set to their zero value.
func IsZeroed[T comparable](a ...T) bool {
	var z T
	for i := range a {
		if a[i] != z {
			return false
		}
	}
	return true
}

// DeleteZeroed deletes zero values in-place contained within the
// slice and returns the modified slice without zero values.
// Does not modify capacity.
func DeleteZeroed[T comparable](a []T) []T {
	var z T
	off := 0
	deleted := false
	for i := range a {
		if a[i] != z {
			if deleted {
				a[off] = a[i]
			}
			off++
		} else if !deleted {
			deleted = true
		}
	}
	return a[:off]
}

// SliceReuse prepares a slice for reuse with capacity at least n.
// After calling SliceReuse, the slice will have:
//   - length = 0
//   - capacity >= n (exactly n if a new allocation was needed)
//
// This function provides specified behavior unlike [slices.Grow] which
// has unspecified capacity growth behavior that differs between Go and TinyGo.
// Use this when the exact capacity matters for subsequent logic.
func SliceReuse[T any](buf *[]T, n int) {
	if cap(*buf) < n {
		*buf = make([]T, 0, n)
	} else {
		*buf = (*buf)[:0]
	}
}

// SliceReclaim extends the slice length by one and returns a pointer to
// the new last element. The returned element is not zeroed, so callers
// can reuse any existing allocations it may hold from prior use.
//
// Beware: as the name implies SliceReclaim reuses previously held memory
// so it is up to caller to ensure the reclaimed data is coherent by zeroing out
// the needed fields and reusing the previously held slices or pointers responsibly.
func SliceReclaim[T any](ptr *[]T) *T {
	b := *ptr
	n := len(b)
	if n == cap(b) {
		var z T
		*ptr = append(b, z)
	} else {
		*ptr = b[:n+1]
	}
	return &(*ptr)[n]
}

// SliceDequeueFront removes and returns the first element of the slice.
// It shifts all remaining elements left by one index and truncates the slice.
// The underlying array capacity remains unchanged; the last element's slot
// is not zeroed before truncation.
//
// Complexity: O(n) where n is the length of the slice, due to the element shift.
//
// Warning: Calling this function on an empty slice will panic (index out of range).
// The caller must ensure len(*a) > 0 before calling.
func SliceDequeueFront[T any](a *[]T) T {
	s := *a
	v := s[0]
	n := copy(s, s[1:])
	*a = s[:n]
	return v
}
