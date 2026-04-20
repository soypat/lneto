package ntp

import (
	"encoding/binary"

	"github.com/soypat/lneto"
)

// ExtType identifies the type of an NTP extension field.
// See RFC 7822 and RFC 8915.
type ExtType uint16

const (
	// NTS Unique Identifier extension field (RFC 8915 §5.3, critical).
	// Contains a random nonce used to prevent replay attacks.
	ExtNTSUniqueID ExtType = 0x0104
	// NTS Cookie extension field (RFC 8915 §5.4).
	// Contains an encrypted cookie obtained during NTS-KE key exchange.
	ExtNTSCookie ExtType = 0x0204
	// NTS Cookie Placeholder extension field (RFC 8915 §5.5).
	// Requests additional cookies from the server in its response.
	ExtNTSCookiePlaceholder ExtType = 0x0304
	// NTS Authenticator and Encrypted Extension Fields (RFC 8915 §5.6, critical).
	// Contains the AEAD-authenticated and encrypted extension fields.
	//
	// Full NTS authentication using this field requires an AEAD cipher
	// (AEAD_AES_SIV_CMAC_256 per RFC 8915 §5.7) and session keys obtained
	// during NTS-KE (RFC 8915 §4). The crypto portion is not implemented
	// here due to AES-SIV not being available in the Go standard library.
	// Callers may supply their own cipher.AEAD to build/verify this field.
	ExtNTSAuthAndEEF ExtType = 0x0404
)

// sizeExtHeader is the fixed 4-byte header size of every NTP extension field (RFC 7822).
const sizeExtHeader = 4

// ExtField provides zero-copy access to a single NTP extension field
// within an existing packet buffer.
type ExtField struct {
	buf []byte
}

// Type returns the extension field type.
func (ef ExtField) Type() ExtType {
	return ExtType(binary.BigEndian.Uint16(ef.buf[0:2]))
}

// TotalLen returns the total length of the extension field, including the
// 4-byte header. Always a multiple of 4.
func (ef ExtField) TotalLen() uint16 {
	return binary.BigEndian.Uint16(ef.buf[2:4])
}

// Value returns the extension field value bytes (body only, without the 4-byte header).
// Returns nil if the length field is inconsistent with the buffer.
func (ef ExtField) Value() []byte {
	n := int(ef.TotalLen())
	if n < sizeExtHeader || n > len(ef.buf) {
		return nil
	}
	return ef.buf[sizeExtHeader:n]
}

// RawData returns the complete extension field bytes including the 4-byte header.
func (ef ExtField) RawData() []byte { return ef.buf }

// NextExtField parses the first NTP extension field from buf and returns it
// along with the number of bytes consumed. An empty buf returns a zero n
// with nil error. Use this in a loop:
//
//	for off := 0; off < len(payload); {
//	    field, n, err := ntp.NextExtField(payload[off:])
//	    if err != nil { break }
//	    // process field
//	    off += n
//	}
func NextExtField(buf []byte) (field ExtField, n int, err error) {
	if len(buf) == 0 {
		return ExtField{}, 0, nil
	}
	if len(buf) < sizeExtHeader {
		return ExtField{}, 0, lneto.ErrTruncatedFrame
	}
	totalLen := int(binary.BigEndian.Uint16(buf[2:4]))
	if totalLen < sizeExtHeader {
		return ExtField{}, 0, lneto.ErrInvalidLengthField
	}
	if totalLen%4 != 0 {
		return ExtField{}, 0, lneto.ErrInvalidLengthField
	}
	if totalLen > len(buf) {
		return ExtField{}, 0, lneto.ErrTruncatedFrame
	}
	return ExtField{buf: buf[:totalLen]}, totalLen, nil
}

// AppendExtField appends a single NTP extension field with the given type and value
// to dst. The value is zero-padded to the nearest 4-byte boundary. Returns the
// extended dst slice. Panics if the padded total length exceeds 65535 (the uint16 maximum),
// which cannot occur with any valid NTP packet payload.
func AppendExtField(dst []byte, typ ExtType, value []byte) []byte {
	padded := (len(value) + 3) &^ 3
	total := sizeExtHeader + padded
	if total > 0xFFFF {
		panic("ntp: AppendExtField: value too large to encode in uint16 length field")
	}
	var hdr [sizeExtHeader]byte
	binary.BigEndian.PutUint16(hdr[0:2], uint16(typ))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(total))
	dst = append(dst, hdr[:]...)
	dst = append(dst, value...)
	for i := len(value); i < padded; i++ {
		dst = append(dst, 0)
	}
	return dst
}
