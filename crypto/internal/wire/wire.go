// Package wire implements the fixed buffer encoder and validating decoder shared
// by the tlsraw and sshraw packages. Their methods are meant to be called with no
// error checking between them for maximum readability while not sacrificing panic
// risk: the first error sticks and later calls are no-ops. Performance is secondary.
// Protocol packages embed these types and add their protocol's structures on top.
package wire

import (
	"encoding/binary"

	"github.com/soypat/lneto"
)

// Encoder writes big endian structures to a fixed buffer, the counterpart of [Decoder].
// A write past the end of buf sets err and all later writes are dropped, so
// callers check err once after writing.
type Encoder struct {
	buf []byte
	off int
	err error
}

// Reset makes e write to buf starting at off, keeping buf[:off].
func (e *Encoder) Reset(buf []byte, off int) { *e = Encoder{buf: buf, off: off} }

// Len returns the number of bytes of buf written, including the ones kept by Reset.
func (e *Encoder) Len() int { return e.off }

// Err returns the first error, usually [lneto.ErrShortBuffer].
func (e *Encoder) Err() error { return e.err }

// Fail sets err if no error is set yet.
func (e *Encoder) Fail(err error) {
	if e.err == nil {
		e.err = err
	}
}

// next reserves n bytes. It returns nil if they do not fit.
func (e *Encoder) next(n int) []byte {
	if e.err == nil && (n < 0 || len(e.buf)-e.off < n) {
		e.err = lneto.ErrShortBuffer
	}
	if e.err != nil {
		return nil
	}
	e.off += n
	return e.buf[e.off-n : e.off]
}

func (e *Encoder) Uint8(v uint8) {
	if b := e.next(1); b != nil {
		b[0] = v
	}
}

func (e *Encoder) Uint16(v uint16) {
	if b := e.next(2); b != nil {
		binary.BigEndian.PutUint16(b, v)
	}
}

func (e *Encoder) Uint32(v uint32) {
	if b := e.next(4); b != nil {
		binary.BigEndian.PutUint32(b, v)
	}
}

func (e *Encoder) Uint64(v uint64) {
	if b := e.next(8); b != nil {
		binary.BigEndian.PutUint64(b, v)
	}
}

// Bytes writes v as is, without a length prefix.
func (e *Encoder) Bytes(v []byte) {
	if b := e.next(len(v)); b != nil {
		copy(b, v)
	}
}

// Rest returns the unwritten part of buf for a callee to write into. Commit with Advance.
func (e *Encoder) Rest() []byte {
	if e.err != nil {
		return nil
	}
	return e.buf[e.off:]
}

// Advance commits n bytes written into Rest. It fails if n is negative or does not fit.
func (e *Encoder) Advance(n int) { e.next(n) }

// Reserve commits n bytes and returns them to be written into.
// Reserve returns nil if n bytes don't fit or if Encoder is in failed state.
func (e *Encoder) Reserve(n int) []byte { return e.next(n) }

// Since returns the bytes written since start with the capacity of the rest of buf,
// for in-place transforms that grow the data. Commit growth with Advance.
// Since returns nil if Encoder is in failed state.
func (e *Encoder) Since(start int) []byte {
	if e.err != nil {
		return nil
	}
	return e.buf[start:e.off:len(e.buf)]
}

// Open reserves a length prefix of width bytes and returns where its content starts.
func (e *Encoder) Open(width int) (start int) {
	e.next(width)
	return e.off
}

// Close writes the length of the content written since Open returned start.
func (e *Encoder) Close(start, width int) {
	if e.err != nil {
		return
	}
	n := uint64(e.off - start) // uint64 so 8*width never reaches the shifted width on 32-bit targets.
	if n>>(8*width) != 0 {
		e.err = lneto.ErrInvalidLengthField
		return
	}
	for i := start - 1; i >= start-width; i-- {
		e.buf[i] = byte(n)
		n >>= 8
	}
}

// Decoder reads big endian structures, adding the first error to its validator.
// Once the validator has an error all reads return zero values and do not advance.
type Decoder struct {
	buf []byte
	off int
	vld *lneto.Validator
}

// Reset makes d read buf from its start, adding errors to vld.
func (d *Decoder) Reset(buf []byte, vld *lneto.Validator) { *d = Decoder{buf: buf, vld: vld} }

// Off returns the number of bytes read.
func (d *Decoder) Off() int { return d.off }

// Remaining returns the number of bytes left to read.
func (d *Decoder) Remaining() int { return len(d.buf) - d.off }

// Fail adds err to the validator if it has no error yet.
func (d *Decoder) Fail(err error) {
	if !d.vld.HasError() {
		d.vld.AddError(err)
	}
}

func (d *Decoder) Uint8() (v uint8) {
	if d.failLen(1) {
		return
	}
	v = d.buf[d.off]
	d.off++
	return v
}

func (d *Decoder) Uint16() (v uint16) {
	if d.failLen(2) {
		return
	}
	v = binary.BigEndian.Uint16(d.buf[d.off:])
	d.off += 2
	return v
}

func (d *Decoder) Uint32() (v uint32) {
	if d.failLen(4) {
		return
	}
	v = binary.BigEndian.Uint32(d.buf[d.off:])
	d.off += 4
	return v
}

// Take returns the next n bytes, or nil if there are fewer.
func (d *Decoder) Take(n uint32) []byte {
	if d.failLen(n) {
		return nil
	}
	d.off += int(n)
	return d.buf[d.off-int(n) : d.off]
}

// Advance skips n bytes.
func (d *Decoder) Advance(n uint32) {
	if !d.failLen(n) {
		d.off += int(n)
	}
}

// failLen takes a uint32 so that a peer's length never converts to a negative int on 32-bit targets.
func (d *Decoder) failLen(n uint32) (failed bool) {
	if d.vld.HasError() {
		return true
	} else if uint64(len(d.buf)-d.off) < uint64(n) {
		d.vld.AddError(lneto.ErrTruncatedFrame)
		return true
	}
	return false
}
