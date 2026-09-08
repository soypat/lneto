package tls

import (
	"encoding/binary"

	"github.com/soypat/lneto"
)

// RecordFrame provides zero-copy access to a TLS record (RFC 8446 5.1).
//
//	struct {
//	    ContentType type;                   // 1 byte
//	    ProtocolVersion legacy_record_version; // 2 bytes
//	    uint16 length;                      // 2 bytes
//	    opaque fragment[length];
//	} TLSPlaintext;
//
// A RecordFrame may be constructed over a buffer holding only the header, so
// that [RecordFrame.Length] can be consulted to decide how many more bytes to
// read. Accessors that reach into the fragment return nil until the whole
// record is present; call [RecordFrame.Complete] to test for that explicitly.
type RecordFrame struct {
	buf []byte
}

// NewRecordFrame wraps buf as a [RecordFrame]. It validates only that the
// 5-byte header is present, since the fragment commonly arrives later.
func NewRecordFrame(buf []byte) (RecordFrame, error) {
	if len(buf) < SizeHeaderRecord {
		return RecordFrame{}, lneto.ErrTruncatedFrame
	}
	return RecordFrame{buf: buf}, nil
}

// ContentType returns the record's outer content type. For a protected record
// this is always [ContentTypeApplicationData]; the real type lives in the
// encrypted [InnerPlaintext].
func (rf RecordFrame) ContentType() ContentType { return ContentType(rf.buf[0]) }

// SetContentType sets the outer content type.
func (rf RecordFrame) SetContentType(ct ContentType) { rf.buf[0] = byte(ct) }

// LegacyVersion returns the legacy_record_version field. TLS 1.3 requires
// receivers to ignore this field entirely; it is exposed for logging only.
func (rf RecordFrame) LegacyVersion() uint16 {
	return binary.BigEndian.Uint16(rf.buf[1:3])
}

// SetLegacyVersion sets the legacy_record_version field.
func (rf RecordFrame) SetLegacyVersion(v uint16) {
	binary.BigEndian.PutUint16(rf.buf[1:3], v)
}

// Length returns the declared fragment length. It is attacker controlled and
// must be checked against [MaxCiphertext] before being used to size a read;
// [RecordFrame.ValidateSize] does this.
func (rf RecordFrame) Length() uint16 {
	return binary.BigEndian.Uint16(rf.buf[3:5])
}

// SetLength sets the declared fragment length.
func (rf RecordFrame) SetLength(n uint16) {
	binary.BigEndian.PutUint16(rf.buf[3:5], n)
}

// RecordLength returns the total wire size of this record, header included.
func (rf RecordFrame) RecordLength() int {
	return SizeHeaderRecord + int(rf.Length())
}

// Complete reports whether the whole record, header and fragment, is present
// in the underlying buffer.
func (rf RecordFrame) Complete() bool {
	return len(rf.buf) >= rf.RecordLength()
}

// Payload returns the record fragment, or nil if the whole record has not
// arrived yet. The result aliases the underlying buffer.
func (rf RecordFrame) Payload() []byte {
	if !rf.Complete() {
		return nil
	}
	return rf.buf[SizeHeaderRecord:rf.RecordLength()]
}

// RawData returns the record bytes, header included, truncated to the declared
// length when the full record is present.
func (rf RecordFrame) RawData() []byte {
	if !rf.Complete() {
		return rf.buf
	}
	return rf.buf[:rf.RecordLength()]
}

// ValidateSize adds an error to v if the record is structurally invalid.
// It does not require the fragment to have arrived; it only rejects a declared
// length that could never be legal.
func (rf RecordFrame) ValidateSize(v *lneto.Validator) {
	if len(rf.buf) < SizeHeaderRecord {
		v.AddError(lneto.ErrTruncatedFrame)
		return
	}
	if rf.Length() > MaxCiphertext {
		// Checked before the length is ever used to size a read.
		v.AddError(lneto.ErrInvalidLengthField)
	}
}

// InnerPlaintext provides access to a decrypted TLSInnerPlaintext
// (RFC 8446 5.2):
//
//	struct {
//	    opaque content[length];
//	    ContentType type;
//	    uint8 zeros[length_of_padding];
//	} TLSInnerPlaintext;
//
// The real content type is the last non-zero byte, and everything after the
// content is padding that must be stripped before use.
type InnerPlaintext struct {
	buf     []byte // content only, padding and type byte already stripped
	ctype   ContentType
	padding int
}

// NewInnerPlaintext scans decrypted for its trailing content type byte,
// stripping any zero padding that follows it.
//
// A record whose plaintext is entirely zeros carries no content type and is a
// protocol violation; it is reported so the caller can send an
// unexpected_message alert rather than silently treating it as empty.
func NewInnerPlaintext(decrypted []byte) (InnerPlaintext, error) {
	i := len(decrypted) - 1
	for i >= 0 && decrypted[i] == 0 {
		i--
	}
	if i < 0 {
		return InnerPlaintext{}, errAllZeroPlaintext
	}
	return InnerPlaintext{
		buf:     decrypted[:i],
		ctype:   ContentType(decrypted[i]),
		padding: len(decrypted) - i - 1,
	}, nil
}

// ContentType returns the true content type recovered from the inner plaintext.
func (ip InnerPlaintext) ContentType() ContentType { return ip.ctype }

// Content returns the plaintext with the content type byte and padding removed.
// The result aliases the buffer passed to [NewInnerPlaintext].
func (ip InnerPlaintext) Content() []byte { return ip.buf }

// PaddingLen returns how many padding bytes followed the content type byte.
func (ip InnerPlaintext) PaddingLen() int { return ip.padding }

// HandshakeFrame provides zero-copy access to a handshake message
// (RFC 8446 4):
//
//	struct {
//	    HandshakeType msg_type;  // 1 byte
//	    uint24 length;           // 3 bytes
//	    opaque body[length];
//	} Handshake;
//
// As with [RecordFrame], a HandshakeFrame may be constructed over a buffer
// holding only the 4-byte header so that the body length can be consulted
// before the rest has arrived.
type HandshakeFrame struct {
	buf []byte
}

// NewHandshakeFrame wraps buf as a [HandshakeFrame], validating that the
// 4-byte header is present.
func NewHandshakeFrame(buf []byte) (HandshakeFrame, error) {
	if len(buf) < SizeHeaderHandshake {
		return HandshakeFrame{}, lneto.ErrTruncatedFrame
	}
	return HandshakeFrame{buf: buf}, nil
}

// MsgType returns the handshake message type.
func (hf HandshakeFrame) MsgType() HandshakeType { return HandshakeType(hf.buf[0]) }

// SetMsgType sets the handshake message type.
func (hf HandshakeFrame) SetMsgType(t HandshakeType) { hf.buf[0] = byte(t) }

// Length returns the declared 24-bit body length. It is attacker controlled;
// the value is returned as an int32 rather than an int so that behaviour is
// identical on 32- and 64-bit targets.
func (hf HandshakeFrame) Length() int32 {
	return int32(hf.buf[1])<<16 | int32(hf.buf[2])<<8 | int32(hf.buf[3])
}

// SetLength sets the declared 24-bit body length. Values outside the 24-bit
// range are silently masked; callers building messages should ensure the body
// fits first.
func (hf HandshakeFrame) SetLength(n int32) {
	hf.buf[1] = byte(n >> 16)
	hf.buf[2] = byte(n >> 8)
	hf.buf[3] = byte(n)
}

// MessageLength returns the total size of this handshake message, header
// included.
func (hf HandshakeFrame) MessageLength() int {
	return SizeHeaderHandshake + int(hf.Length())
}

// Complete reports whether the entire handshake message is present.
func (hf HandshakeFrame) Complete() bool {
	return len(hf.buf) >= hf.MessageLength()
}

// Body returns the handshake message body, or nil if the whole message has not
// arrived. The result aliases the underlying buffer.
func (hf HandshakeFrame) Body() []byte {
	if !hf.Complete() {
		return nil
	}
	return hf.buf[SizeHeaderHandshake:hf.MessageLength()]
}

// RawData returns the handshake message bytes, header included. This is what
// must be fed to the transcript hash: the header is hashed along with the body,
// exactly once per message, even when the message spanned several records.
func (hf HandshakeFrame) RawData() []byte {
	if !hf.Complete() {
		return hf.buf
	}
	return hf.buf[:hf.MessageLength()]
}

// ValidateSize adds an error to v if the handshake header is malformed.
func (hf HandshakeFrame) ValidateSize(v *lneto.Validator) {
	if len(hf.buf) < SizeHeaderHandshake {
		v.AddError(lneto.ErrTruncatedFrame)
		return
	}
	if hf.Length() > MaxPlaintext {
		// No handshake message this server accepts approaches 2^14 bytes.
		v.AddError(lneto.ErrInvalidLengthField)
	}
}
