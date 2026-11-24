package internal

import (
	"errors"
	"io"
	"math"
	"slices"
	"unsafe"

	"github.com/soypat/lneto"
)

var (
	ErrRingBufferFull = lneto.ErrBufferFull
	errRingNoData     = errors.New("lneto/ring: empty write")
	errInvalidCommit  = errors.New("lneto/ring: invalid commit amount")
	errInvalidDiscard = errors.New("lneto/ring: invalid discard amount")
	errDiscardExceeds = errors.New("lneto/ring: discard exceeds length")
	errOffsetOverflow = errors.New("lneto/ring: offset too large (32 bit overflow)")
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
		return 0, ErrRingBufferFull
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
	if len(b) == 0 {
		return 0, errRingNoData
	} else if r.IsFull() || r.Free() < len(b) {
		return 0, ErrRingBufferFull
	}
	midFree := r.midFree()
	if midFree > 0 {
		// start     end       off    len(buf)
		//   |  used  |  mfree  |  used  |
		n := copy(r.Buf[r.End:r.Off], b)
		r.End += n
		if r.End <= 0 {
			panic("zero end after write") // invariant: End must be >0 after writing into midFree region
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
		panic("zero end after write") // invariant: End must be >0 after appending to the tail region
	}
	return n, nil
}

// writeStart returns the buffer index where the next [Ring.Write] or
// [Ring.Commit] begins, matching [Ring.Write]'s placement (including wrap).
func (r *Ring) writeStart() int {
	if r.End == 0 {
		if r.Off == len(r.Buf) {
			return 0 // Empty with Off at the end: Write wraps to the start.
		}
		return r.Off // Empty: writing begins at Off.
	}
	if r.End == len(r.Buf) {
		return 0 // Tail full: next byte wraps to the start.
	}
	return r.End
}

// PeekWrite stages b offset bytes past the write position (see
// [Ring.writeStart]) without advancing it, so the bytes are not yet readable; a
// later [Ring.Commit] reveals them. It reports false, writing nothing, when
// offset is negative or offset+len(b) exceeds [Ring.Free]. Used to place
// out-of-order data ahead of a gap that a normal Write later fills.
func (r *Ring) PeekWrite(b []byte, offset int) bool {
	if offset < 0 || offset+len(b) > r.Free() {
		return false
	}
	off := r.writeStart() + offset
	if off >= len(r.Buf) {
		off -= len(r.Buf)
	}
	n := copy(r.Buf[off:], b)
	if n < len(b) {
		copy(r.Buf, b[n:])
	}
	return true
}

// Commit advances the write pointer by n bytes, making readable any bytes
// previously staged with [Ring.PeekWrite]. It copies nothing and errors if n is
// not positive or exceeds [Ring.Free].
func (r *Ring) Commit(n int) error {
	if n <= 0 {
		return errInvalidCommit
	} else if n > r.Free() {
		return ErrRingBufferFull
	}
	if r.End == 0 {
		r.End = r.Off // Match Write: commit begins at Off when empty.
	}
	end := r.End + n
	if end > len(r.Buf) {
		end -= len(r.Buf)
	}
	r.End = end // Never 0 here: end==len(Buf) is kept.
	return nil
}

var _ lneto.ReaderBuffered = (*Ring)(nil)

// BufferedData returns the readable bytes without consuming them. data1 is
// non-empty only when the data wraps past the end of Buf. Both are
// capacity-capped, so appending to them never writes over ring data.
func (r *Ring) BufferedData() (data0, data1 []byte) {
	if r.End == 0 {
		return nil, nil
	}
	off := r.Off
	if off == len(r.Buf) {
		off = 0 // Off may sit at the end of Buf after a read or discard; data then begins at index 0.
	}
	if r.End > off {
		return r.Buf[off:r.End:r.End], nil
	}
	return r.Buf[off:len(r.Buf):len(r.Buf)], r.Buf[:r.End:r.End]
}

// LinearizeInput rotates Buf in place so the readable data starts at Buf[0] and is
// contiguous. Bytes staged with [Ring.PeekWrite] keep their offset from the
// write position, so a later [Ring.Commit] still reveals them. It invalidates
// slices returned by earlier [Ring.BufferedData] calls.
func (r *Ring) LinearizeInput() {
	if r.Off == 0 {
		return
	}
	n := r.Buffered()
	slices.Reverse(r.Buf[:r.Off])
	slices.Reverse(r.Buf[r.Off:])
	slices.Reverse(r.Buf)
	r.Off, r.End = 0, n
}

// ReadOnceFrom performs a single rd.Read into the contiguous free space at the
// write position and makes what was read readable. Data returned with io.EOF
// reports a nil error, so io.EOF comes on a later call. It returns
// [ErrRingBufferFull] without reading when the ring is full.
func (r *Ring) ReadOnceFrom(rd io.Reader) (int, error) {
	if r.IsFull() {
		return 0, ErrRingBufferFull
	}
	start := r.writeStart()
	span := r.Buf[start:]
	if r.End != 0 && start < r.Off {
		span = r.Buf[start:r.Off] // Free space ends where readable data begins.
	}
	n, err := rd.Read(span)
	if n > 0 {
		if cerr := r.Commit(n); cerr != nil {
			return 0, cerr
		} else if err == io.EOF {
			err = nil
		}
	}
	return n, err
}

// DiscardInput advances the read pointer n bytes without copying data, as a
// [Ring.Read] of n bytes would. n == 0 is a no-op. It errors, discarding nothing,
// if n is negative or more than [Ring.Buffered].
func (r *Ring) DiscardInput(n int) error {
	if n < 0 {
		return errInvalidDiscard
	}
	buffered := r.Buffered()
	switch {
	case n == 0:
	case n > buffered:
		return errDiscardExceeds
	case n == buffered:
		r.emptied()
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
		return 0, errOffsetOverflow // Check only compiles for 32-bit platforms.
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
	if err != nil || len(b) == 0 {
		return n, err
	}
	r.onReadEnd(n)
	return n, nil
}

func (r *Ring) read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	data0, data1 := r.BufferedData()
	if len(data0) == 0 {
		return 0, io.EOF
	}
	n = copy(b, data0)
	n += copy(b[n:], data1)
	return n, nil
}

// Reset flushes all data from ring buffer so that no data can be further read.
func (r *Ring) Reset() {
	r.Off = 0
	r.End = 0
}

// emptied marks the ring empty keeping the write position where it is, unlike
// [Ring.Reset] which rewinds it to index 0. Bytes staged past that position with
// [Ring.PeekWrite] are addressed relative to it, so moving it makes a later
// [Ring.Commit] hand back the wrong bytes.
func (r *Ring) emptied() {
	off := r.End
	if off == len(r.Buf) {
		off = 0 // Tail exhausted, next write wraps.
	}
	r.Off, r.End = off, 0
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

// FreeLimited returns the amount of bytes that can be written up to the
// argument offset limitOffset. See [Ring.WriteLimited].
// If buffer is empty (End=0) write will begin at Off as a special case.
// If limitOffset is equal to the write starting place then FreeLimited returns 0.
func (r *Ring) FreeLimited(limitOffset int) (free int) {
	if r.IsFull() {
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

// IsFull checks if ring buffer is full and cannot accept more data.
func (r *Ring) IsFull() bool {
	return r.End != 0 && (r.End == r.Off || (r.End == len(r.Buf) && r.Off == 0))
}

// IsEmpty checks if ring buffer is empty of data to read. Calls to Read on an empty buffer will return [io.EOF].
func (r *Ring) IsEmpty() bool {
	return r.End == 0
}

// onReadEnd does some cleanup of [ring.off] and [ring.end] fields if possible for contiguous read performance benefits.
func (r *Ring) onReadEnd(totalRead int) {
	if totalRead <= 0 {
		panic("invalid onReadEnd bytes read")
	}
	newOff := r.addOff(r.Off, totalRead)
	if newOff == r.End {
		r.emptied()
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

func (r *Ring) string() string {
	data0, data1 := r.BufferedData()
	return string(data0) + string(data1)
}

func (r *Ring) _string(off int64) string {
	s := r.string()
	return s[off:]
}
