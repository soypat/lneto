package internal

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
	for i := 0; i < len(a); i++ {
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
