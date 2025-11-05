package internal

import (
	"bytes"
	"errors"
	"io"
	"math"
	"unsafe"
)

var (
	errRingBufferFull = errors.New("lneto/ring: buffer full")
	errRingNoData     = errors.New("lneto/ring: empty write")
)

// Ring implements basic Ring buffer functionality.
type Ring struct {
	// Buf is used to store data written into Ring
	// with Write methods and then read out with Read methods.
	// The capacity of Buf is unused.
	// There is no readable data when End==0.
	Buf []byte
	// Start of readable data which indexes into Buf.
	// If Off==End and End!=0 the buffer is full and data begins at Off. Off<len(Buf) is always true.
	Off int
	// End of readable data which indexes into Buf, not including byte at End index.
	// If End==0 then the buffer is empty. If End==Off and End!=0 the buffer is full.
	End int
}

// FreeLimited returns the amount of bytes that can be written up to the
// argument offset limitOffset. See [Ring.WriteLimited].
// If buffer is empty (End=0) write will begin at Off as a special case.
// If limitOffset is equal to the write starting place then FreeLimited returns 0.
func (r *Ring) FreeLimited(limitOffset int) (free int) {
	if r.isFull() {
		return 0
	}

	// Write start position.
	var writeAt = r.End
	if writeAt == 0 {
		// Write start is End except when empty, in which case we writeAt at Off.
		writeAt = r.Off
		if limitOffset >= writeAt {
			return limitOffset - writeAt // Contiguous case.
		}
		return r.Size() - writeAt + limitOffset // Wrap case.
	}

	// normal (non-empty): write at End up to limitOffset, or Off, whichever comes first.
	if writeAt <= limitOffset && writeAt <= r.Off {
		return min(r.Off, limitOffset) - writeAt
	} else if writeAt <= limitOffset {
		return limitOffset - writeAt
	} else if writeAt <= r.Off {
		return r.Off - writeAt
	}
	return r.Size() - writeAt + min(limitOffset, r.Off)
}

// WriteLimited performs a write that does not write over the ring buffer's
// limitOffset index, which points to a position to r.Buf. Up to [Ring.FreeLimited] bytes can be written.
func (r *Ring) WriteLimited(b []byte, limitOffset int) (int, error) {
	if limitOffset > len(r.Buf) {
		panic("bad limit offset")
	}
	if len(b) > len(r.Buf) {
		return 0, io.ErrShortBuffer
	}
	limit := r.FreeLimited(limitOffset)
	if len(b) > limit {
		return 0, errRingBufferFull
	}
	return r.Write(b)
}

// WriteString is a wrapper around [Ring.Write] that avoids allocation of converting byte slice to string.
func (r *Ring) WriteString(s string) (int, error) {
	return r.Write(unsafe.Slice(unsafe.StringData(s), len(s)))
}

// Write appends data to the ring buffer that can then be read back in order with [Ring.Read] methods.
// An error is returned if length of data too large for buffer. Write is guaranteed to start at buffer index [Ring.Off].
func (r *Ring) Write(b []byte) (int, error) {
	if r.isFull() {
		return 0, errRingBufferFull
	} else if len(b) == 0 {
		return 0, errRingNoData
	}
	midFree := r.midFree()
	if midFree > 0 {
		// start     end       off    len(buf)
		//   |  used  |  mfree  |  used  |
		n := copy(r.Buf[r.End:r.Off], b)
		r.End += n
		if r.End <= 0 {
			panic("zero end after write") // TODO: remove panics after validation.
		}
		return n, nil
	} else if r.End == 0 {
		// To ensure Write begins on r.Off.
		// Specialised for when user controls Off manually instead of by internal calls to [Ring.onReadEnd] or calls to [Ring.Reset].
		r.End = r.Off
	}
	// start       off       end      len(buf)
	//   |  sfree   |  used   |  efree   |
	n := copy(r.Buf[r.End:], b)
	r.End += n
	if n < len(b) {
		n2 := copy(r.Buf, b[n:])
		r.End = n2
		n += n2
	}
	if r.End <= 0 {
		panic("zero end after write")
	}
	return n, nil
}

// ReadDiscard is a performance auxiliary method that performs a dummy read or no-op read
// for advancing the read pointer n bytes without actually copying data.
// This method panics if amount of bytes is more than buffered (see [Ring.Buffered]).
func (r *Ring) ReadDiscard(n int) error {
	if n <= 0 {
		return errors.New("invalid discard amount")
	}
	buffered := r.Buffered()
	switch {
	case n > buffered:
		return errors.New("discard exceeds length")
	case n == buffered:
		r.Reset()
	case n+r.Off > len(r.Buf):
		r.Off = n - (len(r.Buf) - r.Off)
	default:
		r.Off += n
	}
	return nil
}

// ReadAt reads data at an offset from start of readable data but does not advance read pointer. [io.EOF] returned when no data available.
func (r *Ring) ReadAt(p []byte, off64 int64) (int, error) {
	if math.MaxInt != math.MaxInt64 && off64+int64(len(p)) > math.MaxInt32 {
		return 0, errors.New("offset too large (32 bit overflow)") // Check only compiles for 32-bit platforms.
	}
	off := int(off64)
	if off+len(p) > r.Buffered() {
		return 0, io.ErrUnexpectedEOF
	}
	r2 := *r
	r2.Off = r.addOff(r2.Off, off)
	return r2.ReadPeek(p)
}

// ReadPeek reads up to len(b) bytes from the ring buffer but does not advance the read pointer. [io.EOF] returned when no data available.
func (r *Ring) ReadPeek(b []byte) (int, error) {
	n, err := r.read(b)
	return n, err
}

// Read reads up to len(b) bytes from the ring buffer and advances the read pointer. [io.EOF] returned when no data available.
func (r *Ring) Read(b []byte) (int, error) {
	n, err := r.read(b)
	if err != nil {
		return n, err
	}
	r.onReadEnd(n)
	return n, nil
}

func (r *Ring) read(b []byte) (n int, err error) {
	if r.Buffered() == 0 {
		return 0, io.EOF
	}
	if r.End > r.Off {
		// start       off       end      len(buf)
		//   |  sfree   |  used   |  efree   |
		n = copy(b, r.Buf[r.Off:r.End])
		return n, nil
	}
	// start     end       off     len(buf)
	//   |  used  |  mfree  |  used  |
	n = copy(b, r.Buf[r.Off:])
	if n < len(b) {
		n2 := copy(b[n:], r.Buf[:r.End])
		n += n2
	}
	return n, nil
}

// Reset flushes all data from ring buffer so that no data can be further read.
func (r *Ring) Reset() {
	r.Off = 0
	r.End = 0
}

// Size returns the capacity of the ring buffer.
func (r *Ring) Size() int {
	return len(r.Buf)
}

// Buffered returns amount of bytes ready to read from ring buffer. Always less than [ring.Size].
func (r *Ring) Buffered() int {
	return r.Size() - r.Free()
}

// Free returns amount of bytes that can be read into ring buffer before reaching maximum capacity given by [ring.Size]. Always less than [ring.Size].
func (r *Ring) Free() int {
	if r.End == 0 || r.Off == 0 {
		return len(r.Buf) - r.End
	}
	if r.Off < r.End {
		// start       off       end      len(buf)
		//   |  sfree   |  used   |  efree   |
		startFree := r.Off
		endFree := len(r.Buf) - r.End
		return startFree + endFree
	}
	// start     end       off     len(buf)
	//   |  used  |  mfree  |  used  |
	return r.Off - r.End
}

func (r *Ring) midFree() int {
	if r.End >= r.Off || r.End == 0 {
		return 0
	}
	return r.Off - r.End
}

func (r *Ring) isFull() bool {
	return r.End != 0 && (r.End == r.Off || (r.End == len(r.Buf) && r.Off == 0))
}

// onReadEnd does some cleanup of [ring.off] and [ring.end] fields if possible for contiguous read performance benefits.
func (r *Ring) onReadEnd(totalRead int) {
	if totalRead <= 0 {
		panic("invalid onReadEnd bytes read")
	}
	newOff := r.addOff(r.Off, totalRead)
	if newOff == r.End {
		r.Reset()
	} else if newOff == len(r.Buf) {
		r.Off = 0 // Optimization case.
	} else {
		r.Off = newOff
	}
}

// addOff sums a and b to return an index within 1..[Ring.Size] supposing a and b are each less-equal than [Ring.Size].
// Result will never be 0 unless both a and b are 0.
func (r *Ring) addOff(a, b int) int {
	result := a + b
	if result > len(r.Buf) {
		result -= len(r.Buf)
	}
	return result
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (r *Ring) string() string {
	var b bytes.Buffer
	r2 := *r
	b.ReadFrom(&r2)
	return b.String()
}

func (r *Ring) _string(off int64) string {
	s := r.string()
	return s[off:]
}
