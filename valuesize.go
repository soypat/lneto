/*
package tseq implements TCP control flow.

# Transmission Control Block

The Transmission Control Block (TCB) is the core data structure of TCP.
It stores core state of the TCP connection such as the send and receive
sequence number spaces, the current state of the connection, and the
pending control segment flags.

# Values and Sizes

All arithmetic dealing with sequence numbers must be performed modulo 2**32
which brings with it subtleties to computer modulo arithmetic.
*/
package tseq

import "time"

// Value represents the value of a sequence number.
type Value uint32

// Size represents the size (length) of a sequence number window.
type Size uint32

// LessThan checks if v is before w (modulo 32) i.e., v < w.
func LessThan(v, w Value) bool {
	return int32(v-w) < 0
}

// LessThanEq returns true if v==w or v is before (modulo 32) i.e., v < w.
func LessThanEq(v, w Value) bool {
	return v == w || LessThan(v, w)
}

// InRange checks if v is in the range [a,b) (modulo 32), i.e., a <= v < b.
func InRange(v, a, b Value) bool {
	return v-a < b-a
}

// InWindow checks if v is in the window that starts at 'first' and spans 'size'
// sequence numbers (modulo 32).
func InWindow(v, first Value, size Size) bool {
	return InRange(v, first, Add(first, size))
}

// Add calculates the sequence number following the [v, v+s) window.
func Add(v Value, s Size) Value {
	return v + Value(s)
}

// Size calculates the size of the window defined by [v, w).
func Sizeof(v, w Value) Size {
	return Size(w - v)
}

// UpdateForward updates v such that it becomes v + s.
func (v *Value) UpdateForward(s Size) {
	*v += Value(s)
}

// DefaultNewISS returns a new initial send sequence number.
// It's implementation is suggested by RFC9293.
func DefaultNewISS(t time.Time) Value {
	return Value(t.UnixMicro() / 4)
}
