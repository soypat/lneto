package sshraw

import (
	"encoding/binary"
	"io"

	"github.com/soypat/lneto"
)

// ValidateNameList validates the contents of a name-list, RFC 4251 5: comma
// separated names of printable US-ASCII without whitespace, each at most
// [MaxNameLen] long. The empty list is valid.
func ValidateNameList(list []byte) error {
	if len(list) == 0 {
		return nil
	}
	start := 0
	for i := 0; i <= len(list); i++ {
		if i == len(list) || list[i] == ',' {
			if err := validateName(list[start:i]); err != nil {
				return err
			}
			start = i + 1
		}
	}
	return nil
}

// NextName returns the first name of a name-list and the rest of the list after its comma.
// list should be validated with [ValidateNameList]: a trailing comma is not reported.
func NextName(list []byte) (name, rest []byte) {
	for i, c := range list {
		if c == ',' {
			return list[:i], list[i+1:]
		}
	}
	return list, nil
}

// HasName reports whether name is one of the names of list. The empty name is
// never in a list, even an unvalidated one.
func HasName(list []byte, name string) bool {
	if name == "" {
		return false
	}
	for len(list) > 0 {
		var got []byte
		got, list = NextName(list)
		if string(got) == name {
			return true
		}
	}
	return false
}

// Negotiate returns the first name of client also in server, or nil if none,
// the base rule of RFC 4253 7.1. The key exchange and host key algorithms add
// compatibility conditions between the two which the caller checks. The
// caller must also reject a pseudo algorithm such as [KexStrictClient] as a
// result: a peer can list it to make it the agreed name.
func Negotiate(client, server []byte) []byte {
	for len(client) > 0 {
		var name []byte
		name, client = NextName(client)
		if HasName(server, string(name)) {
			return name
		}
	}
	return nil
}

func validateName[T ~string | ~[]byte](name T) error {
	if len(name) == 0 {
		return lneto.ErrInvalidField
	} else if len(name) > MaxNameLen {
		return lneto.ErrInvalidLengthField
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; c <= ' ' || c > '~' || c == ',' {
			return lneto.ErrInvalidField
		}
	}
	return nil
}

// decoder provides an API to readably decode SSH messages, RFC 4251 5.
// Its decoding methods are meant to be used with no error checking between them
// for maximum readability while not sacrificing panic risk; performance is secondary.
type decoder struct {
	buf []byte
	off int
	vld *lneto.Validator
}

func (dec *decoder) Uint8() (v uint8) {
	if dec.failLen(1) {
		return
	}
	v = dec.buf[dec.off]
	dec.off++
	return v
}

// Bool decodes a boolean. Any non-zero value is true, RFC 4251 5.
func (dec *decoder) Bool() bool { return dec.Uint8() != 0 }

func (dec *decoder) Uint32() (v uint32) {
	if dec.failLen(4) {
		return
	}
	v = binary.BigEndian.Uint32(dec.buf[dec.off:])
	dec.off += 4
	return v
}

// String decodes a length prefixed string and returns its contents.
func (dec *decoder) String() []byte {
	n := dec.Uint32()
	if dec.failLen(n) {
		return nil
	}
	dec.off += int(n)
	return dec.buf[dec.off-int(n) : dec.off]
}

// NameList decodes a string and validates it as a name-list.
func (dec *decoder) NameList() []byte {
	list := dec.String()
	if dec.vld.HasError() {
		return nil
	} else if err := ValidateNameList(list); err != nil {
		dec.vld.AddError(err)
		return nil
	}
	return list
}

// msgType decodes the message type byte and requires it to be want.
func (dec *decoder) msgType(want MsgType) {
	if MsgType(dec.Uint8()) != want && !dec.vld.HasError() {
		dec.vld.AddError(lneto.ErrInvalidField)
	}
}

// end requires the message to have been decoded whole.
func (dec *decoder) end() {
	if !dec.vld.HasError() && dec.off != len(dec.buf) {
		dec.vld.AddError(lneto.ErrInvalidLengthField)
	}
}

func (dec *decoder) Advance(n uint32) {
	if !dec.failLen(n) {
		dec.off += int(n)
	}
}

// failLen takes a uint32 so that a peer's length never converts to a negative int on 32-bit targets.
func (dec *decoder) failLen(n uint32) (failed bool) {
	if dec.vld.HasError() {
		return true
	} else if uint32(len(dec.buf)-dec.off) < n {
		dec.vld.AddError(lneto.ErrTruncatedFrame)
		return true
	}
	return false
}

// Encoder writes SSH structures to a fixed buffer, the counterpart of [decoder].
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

// fail sets err if no error is set yet.
func (e *Encoder) fail(err error) {
	if e.err == nil {
		e.err = err
	}
}

// next reserves n bytes. It returns nil if they do not fit.
func (e *Encoder) next(n int) []byte {
	if e.err == nil && len(e.buf)-e.off < n {
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

// Bool writes 1 for true and 0 for false, the only values RFC 4251 5 allows to be sent.
func (e *Encoder) Bool(v bool) {
	var b uint8
	if v {
		b = 1
	}
	e.Uint8(b)
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

func (e *Encoder) str(v string) {
	if b := e.next(len(v)); b != nil {
		copy(b, v)
	}
}

// String writes v as a length prefixed string.
func (e *Encoder) String(v []byte) {
	e.Uint32(uint32(len(v)))
	e.Bytes(v)
}

// Str writes s as a length prefixed string, as String does for a byte slice.
func (e *Encoder) Str(s string) {
	e.Uint32(uint32(len(s)))
	e.str(s)
}

// NameList writes names as a name-list. A name that is not valid sets
// [lneto.ErrInvalidField] or [lneto.ErrInvalidLengthField].
func (e *Encoder) NameList(names ...string) {
	start := e.Open(4)
	for i, name := range names {
		if err := validateName(name); err != nil {
			e.fail(err)
			return
		} else if i > 0 {
			e.Uint8(',')
		}
		e.str(name)
	}
	e.Close(start, 4)
}

// MPInt writes the unsigned big endian magnitude mag as an mpint, RFC 4251 5:
// without leading zero bytes and with a zero byte prepended when the high bit
// is set so the value does not read as negative.
func (e *Encoder) MPInt(mag []byte) {
	for len(mag) > 0 && mag[0] == 0 {
		mag = mag[1:]
	}
	pad := len(mag) > 0 && mag[0]&0x80 != 0
	if pad {
		e.Uint32(uint32(len(mag) + 1))
		e.Uint8(0)
	} else {
		e.Uint32(uint32(len(mag)))
	}
	e.Bytes(mag)
}

// Rest returns the unwritten part of buf for a callee to write into. Commit with Advance.
func (e *Encoder) Rest() []byte {
	if e.err != nil {
		return nil
	}
	return e.buf[e.off:]
}

func (e *Encoder) Advance(n int) { e.next(n) }

// Reserve commits n bytes and returns them to be written into.
// Reserve returns nil if n bytes don't fit or if Encoder is in failed state.
func (e *Encoder) Reserve(n int) []byte { return e.next(n) }

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
	n := uint64(e.off - start)
	if n>>(8*width) != 0 {
		e.err = lneto.ErrInvalidLengthField
		return
	}
	for i := start - 1; i >= start-width; i-- {
		e.buf[i] = byte(n)
		n >>= 8
	}
}

// StartPacket writes a binary packet header and the message type. The lengths
// and padding are written by EndPacket.
func (e *Encoder) StartPacket(typ MsgType) (start int) {
	start = e.off
	e.Advance(SizeHeaderPacket)
	e.Uint8(uint8(typ))
	return start
}

// EndPacket pads the packet started at start to blockSize with bytes read from
// rand, sets its lengths and returns the unprotected packet. blockSize is the
// cipher block size; values below [MinBlockSize] mean [MinBlockSize].
// aad is true when packet_length is not encrypted and thus not part of the
// alignment: the AEAD ciphers and -etm MACs.
func (e *Encoder) EndPacket(start, blockSize int, aad bool, rand io.Reader) []byte {
	bs := max(blockSize, MinBlockSize)
	if bs+MinPadding-1 > MaxPadding {
		e.fail(lneto.ErrInvalidConfig)
	}
	if e.err != nil {
		return nil
	}
	covered := e.off - start
	if aad {
		covered -= 4
	}
	padLen := bs - covered%bs
	if padLen < MinPadding {
		padLen += bs
	}
	pad := e.next(padLen)
	if pad == nil {
		return nil
	} else if _, err := io.ReadFull(rand, pad); err != nil {
		e.fail(err)
		return nil
	}
	pkt := e.buf[start:e.off]
	if len(pkt) > MaxPacket {
		e.fail(lneto.ErrInvalidLengthField)
		return nil
	}
	binary.BigEndian.PutUint32(pkt, uint32(len(pkt)-4))
	pkt[4] = byte(padLen)
	return pkt
}
