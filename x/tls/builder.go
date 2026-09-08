package tls

import (
	"encoding/binary"
	"unsafe"
)

// maxBuilderNest is the deepest length-prefix nesting the [Builder] supports.
// The deepest real TLS 1.3 structure is the ClientHello key_share extension:
// handshake body, extensions block, extension, client_shares list,
// key_exchange. Eight leaves generous headroom.
const maxBuilderNest = 8

// Builder writes TLS wire structures into a caller-supplied buffer that never
// grows. It exists because TLS nests length-prefixed vectors several levels
// deep and the length of each is only known after its contents are written;
// the standard answer, golang.org/x/crypto/cryptobyte, allocates.
//
// Open a length prefix, write the contents, then Close to backpatch the real
// length:
//
//	var b tls.Builder
//	b.Reset(buf)
//	b.AddU16(uint16(tls.ExtSupportedVersions))
//	b.OpenU16()             // extension_data length
//	b.AddU16(tls.VersionTLS13)
//	b.Close()
//	out, err := b.Bytes()
//
// Errors are sticky: once the destination buffer overflows or the nesting is
// misused, every later call is a no-op and [Builder.Err] reports the first
// failure. Callers therefore need to check only once, at the end.
//
// The zero Builder is not usable; call [Builder.Reset] first.
type Builder struct {
	buf   []byte
	stack [maxBuilderNest]int32 // offset of each open length field
	width [maxBuilderNest]int8  // 1, 2 or 3 byte length prefix
	n     int8                  // open prefix count
	err   error
}

// Reset prepares the Builder to write into dst, discarding any previous state
// and error. The Builder writes into dst[:0] and never reallocates, so dst's
// capacity is a hard ceiling on the structure being built.
func (b *Builder) Reset(dst []byte) {
	b.buf = dst[:0]
	b.n = 0
	b.err = nil
}

// Err returns the first error encountered since [Builder.Reset], if any.
func (b *Builder) Err() error { return b.err }

// Len returns the number of bytes written so far, including the placeholder
// bytes of any currently open length prefix.
func (b *Builder) Len() int { return len(b.buf) }

// Bytes returns the built structure. It reports an error if the Builder failed
// at any point, or if a length prefix was opened and never closed, since the
// resulting bytes would contain an unpatched placeholder.
func (b *Builder) Bytes() ([]byte, error) {
	if b.err != nil {
		return nil, b.err
	}
	if b.n != 0 {
		return nil, errBuilderUnbal
	}
	return b.buf, nil
}

// fail records err if no error has been recorded yet.
func (b *Builder) fail(err error) {
	if b.err == nil {
		b.err = err
	}
}

// grow extends the buffer by n bytes and returns the new region, or nil if the
// buffer is full or the Builder has already failed.
func (b *Builder) grow(n int) []byte {
	if b.err != nil {
		return nil
	}
	if n > cap(b.buf)-len(b.buf) {
		b.fail(errShortBuffer)
		return nil
	}
	start := len(b.buf)
	b.buf = b.buf[:start+n]
	return b.buf[start:]
}

// AddU8 appends a single byte.
func (b *Builder) AddU8(v uint8) {
	if p := b.grow(1); p != nil {
		p[0] = v
	}
}

// AddU16 appends a big-endian uint16.
func (b *Builder) AddU16(v uint16) {
	if p := b.grow(2); p != nil {
		binary.BigEndian.PutUint16(p, v)
	}
}

// AddU24 appends a big-endian 24-bit value, the length encoding used by
// handshake message headers and certificate entries.
func (b *Builder) AddU24(v uint32) {
	if p := b.grow(3); p != nil {
		p[0] = byte(v >> 16)
		p[1] = byte(v >> 8)
		p[2] = byte(v)
	}
}

// AddU32 appends a big-endian uint32.
func (b *Builder) AddU32(v uint32) {
	if p := b.grow(4); p != nil {
		binary.BigEndian.PutUint32(p, v)
	}
}

// AddBytes appends raw bytes.
func (b *Builder) AddBytes(v []byte) {
	if p := b.grow(len(v)); p != nil {
		copy(p, v)
	}
}

// AddString appends the bytes of s without allocating. TLS labels and ALPN
// protocol names are naturally string constants, and converting them with
// []byte(s) would copy to the heap on every call.
func (b *Builder) AddString(s string) {
	if len(s) == 0 {
		return
	}
	// unsafe.Slice over the string's backing array; the bytes are only read,
	// and only for the duration of the copy inside AddBytes.
	b.AddBytes(unsafe.Slice(unsafe.StringData(s), len(s)))
}

// openN reserves width bytes for a length prefix whose value is filled in by
// the matching [Builder.Close].
func (b *Builder) openN(width int8) {
	if b.err != nil {
		return
	}
	if int(b.n) >= maxBuilderNest {
		b.fail(errBuilderNest)
		return
	}
	start := len(b.buf)
	if b.grow(int(width)) == nil {
		return
	}
	b.stack[b.n] = int32(start)
	b.width[b.n] = width
	b.n++
}

// OpenU8 begins a vector with a one-byte length prefix.
func (b *Builder) OpenU8() { b.openN(1) }

// OpenU16 begins a vector with a two-byte length prefix.
func (b *Builder) OpenU16() { b.openN(2) }

// OpenU24 begins a vector with a three-byte length prefix, as used by the
// handshake message header.
func (b *Builder) OpenU24() { b.openN(3) }

// Close ends the innermost open vector and backpatches its length prefix with
// the number of bytes written since the matching Open.
//
// A length that does not fit the reserved prefix width is a failure rather
// than a silent truncation: writing a value modulo 2^16 into a two-byte prefix
// would produce a structurally valid but semantically wrong record.
func (b *Builder) Close() {
	if b.err != nil {
		return
	}
	if b.n == 0 {
		b.fail(errBuilderUnbal)
		return
	}
	b.n--
	start := int(b.stack[b.n])
	width := int(b.width[b.n])
	n := len(b.buf) - start - width
	p := b.buf[start:]
	switch width {
	case 1:
		if n > 0xff {
			b.fail(errBadLength)
			return
		}
		p[0] = byte(n)
	case 2:
		if n > 0xffff {
			b.fail(errBadLength)
			return
		}
		binary.BigEndian.PutUint16(p, uint16(n))
	case 3:
		if n > 0xffffff {
			b.fail(errBadLength)
			return
		}
		p[0] = byte(n >> 16)
		p[1] = byte(n >> 8)
		p[2] = byte(n)
	}
}
