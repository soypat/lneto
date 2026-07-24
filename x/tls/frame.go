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

// ExtensionFrame provides access to a single hello extension (RFC 8446 4.2):
//
//	struct {
//	    ExtensionType extension_type; // 2 bytes
//	    opaque extension_data<0..2^16-1>;
//	} Extension;
type ExtensionFrame struct {
	buf []byte
}

// NewExtensionFrame wraps buf as an [ExtensionFrame]. Unlike the record and
// handshake frames, an extension is only ever parsed out of a fully buffered
// hello, so the whole extension must be present.
func NewExtensionFrame(buf []byte) (ExtensionFrame, error) {
	if len(buf) < 4 {
		return ExtensionFrame{}, lneto.ErrTruncatedFrame
	}
	n := int(binary.BigEndian.Uint16(buf[2:4]))
	if 4+n > len(buf) {
		return ExtensionFrame{}, lneto.ErrTruncatedFrame
	}
	return ExtensionFrame{buf: buf[:4+n]}, nil
}

// Type returns the extension type.
func (ef ExtensionFrame) Type() ExtensionType {
	return ExtensionType(binary.BigEndian.Uint16(ef.buf[0:2]))
}

// Length returns the declared extension_data length.
func (ef ExtensionFrame) Length() uint16 {
	return binary.BigEndian.Uint16(ef.buf[2:4])
}

// Data returns the extension_data bytes.
func (ef ExtensionFrame) Data() []byte { return ef.buf[4:] }

// RawData returns the extension bytes, type and length included.
func (ef ExtensionFrame) RawData() []byte { return ef.buf }

// ForEachExtension walks an extension list, calling fn for each extension in
// wire order. exts is the contents of the extensions block, with the outer
// two-byte list length already stripped; [ClientHelloFrame.Extensions] returns
// it in that form.
//
// The walker is deliberately permissive about extension types: unknown types,
// including every GREASE value Chrome injects, are passed to fn like any other.
// It is the caller's switch that skips them. The walker is strict about
// framing: a length field that overruns the list aborts with
// [lneto.ErrTruncatedFrame].
//
// Modelled on tcp.OptionCodec.ForEachOption.
func ForEachExtension(exts []byte, fn func(ExtensionType, []byte) error) error {
	for off := 0; off < len(exts); {
		ef, err := NewExtensionFrame(exts[off:])
		if err != nil {
			return err
		}
		err = fn(ef.Type(), ef.Data())
		if err != nil {
			return err
		}
		off += len(ef.RawData())
	}
	return nil
}

// ForEachU16 walks a bare list of big-endian uint16 values, such as the
// cipher_suites vector of a ClientHello. b must have even length.
func ForEachU16(b []byte, fn func(uint16) error) error {
	if len(b)%2 != 0 {
		return lneto.ErrInvalidLengthField
	}
	for off := 0; off < len(b); off += 2 {
		err := fn(binary.BigEndian.Uint16(b[off : off+2]))
		if err != nil {
			return err
		}
	}
	return nil
}

// ForEachSupportedGroup walks the contents of a supported_groups extension,
// whose payload is a uint16-length-prefixed list of [NamedGroup] values.
func ForEachSupportedGroup(extData []byte, fn func(NamedGroup) error) error {
	body, err := vectorU16(extData)
	if err != nil {
		return err
	}
	return ForEachU16(body, func(v uint16) error { return fn(NamedGroup(v)) })
}

// ForEachSignatureScheme walks the contents of a signature_algorithms (or
// signature_algorithms_cert) extension.
func ForEachSignatureScheme(extData []byte, fn func(SignatureScheme) error) error {
	body, err := vectorU16(extData)
	if err != nil {
		return err
	}
	return ForEachU16(body, func(v uint16) error { return fn(SignatureScheme(v)) })
}

// ForEachSupportedVersion walks the contents of a supported_versions extension
// as it appears in a ClientHello. Note the prefix here is a single byte, unlike
// every other list in the hello; the ServerHello form carries a bare uint16
// instead and is not parsed by this function.
func ForEachSupportedVersion(extData []byte, fn func(uint16) error) error {
	body, err := vectorU8(extData)
	if err != nil {
		return err
	}
	return ForEachU16(body, fn)
}

// ForEachKeyShare walks the client_shares list of a key_share extension:
//
//	struct {
//	    NamedGroup group;
//	    opaque key_exchange<1..2^16-1>;
//	} KeyShareEntry;
//
// GREASE key shares carry a deliberately absurd body, commonly a single byte,
// and must not be treated as malformed. The walker therefore places no
// constraint on key_exchange length beyond it fitting inside the list; group
// selection is the caller's job.
func ForEachKeyShare(extData []byte, fn func(NamedGroup, []byte) error) error {
	body, err := vectorU16(extData)
	if err != nil {
		return err
	}
	for off := 0; off < len(body); {
		if len(body)-off < 4 {
			return lneto.ErrTruncatedFrame
		}
		group := NamedGroup(binary.BigEndian.Uint16(body[off : off+2]))
		n := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if n > len(body)-off {
			return lneto.ErrTruncatedFrame
		}
		err = fn(group, body[off:off+n])
		if err != nil {
			return err
		}
		off += n
	}
	return nil
}

// ForEachALPNProto walks the protocol name list of an ALPN extension. Each
// name is a single-byte-length-prefixed string. Chrome includes a GREASE entry
// here too, so callers must match against their own offer list rather than
// assuming the first entry is meaningful.
//
// A zero-length protocol name is a protocol violation and aborts the walk.
func ForEachALPNProto(extData []byte, fn func([]byte) error) error {
	body, err := vectorU16(extData)
	if err != nil {
		return err
	}
	for off := 0; off < len(body); {
		n := int(body[off])
		off++
		if n == 0 {
			return lneto.ErrInvalidLengthField
		} else if n > len(body)-off {
			return lneto.ErrTruncatedFrame
		}
		err = fn(body[off : off+n])
		if err != nil {
			return err
		}
		off += n
	}
	return nil
}

// ForEachServerName walks the server_name_list of an SNI extension:
//
//	struct {
//	    NameType name_type;          // 1 byte, 0 = host_name
//	    opaque HostName<1..2^16-1>;
//	} ServerName;
func ForEachServerName(extData []byte, fn func(nameType uint8, name []byte) error) error {
	body, err := vectorU16(extData)
	if err != nil {
		return err
	}
	for off := 0; off < len(body); {
		if len(body)-off < 3 {
			return lneto.ErrTruncatedFrame
		}
		nameType := body[off]
		n := int(binary.BigEndian.Uint16(body[off+1 : off+3]))
		off += 3
		if n > len(body)-off {
			return lneto.ErrTruncatedFrame
		}
		err = fn(nameType, body[off:off+n])
		if err != nil {
			return err
		}
		off += n
	}
	return nil
}

// vectorU16 strips a two-byte length prefix and returns the vector contents.
// It requires the prefix to describe the buffer exactly: trailing bytes mean
// the sender and this parser disagree on the structure, which is precisely the
// ambiguity parser-differential attacks exploit.
func vectorU16(b []byte) ([]byte, error) {
	if len(b) < 2 {
		return nil, lneto.ErrTruncatedFrame
	}
	n := int(binary.BigEndian.Uint16(b[0:2]))
	if n != len(b)-2 {
		if n > len(b)-2 {
			return nil, lneto.ErrTruncatedFrame
		}
		return nil, errTrailingBytes
	}
	return b[2:], nil
}

// vectorU8 strips a one-byte length prefix. See [vectorU16] for why trailing
// bytes are rejected.
func vectorU8(b []byte) ([]byte, error) {
	if len(b) < 1 {
		return nil, lneto.ErrTruncatedFrame
	}
	n := int(b[0])
	if n != len(b)-1 {
		if n > len(b)-1 {
			return nil, lneto.ErrTruncatedFrame
		}
		return nil, errTrailingBytes
	}
	return b[1:], nil
}
