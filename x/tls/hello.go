package tls

import (
	"encoding/binary"

	"github.com/soypat/lneto"
)

// SizeRandom is the length of the client_random and server_random fields.
const SizeRandom = 32

// MaxSessionIDLen is the largest legal legacy_session_id. TLS 1.3 does not use
// session IDs, but a client sends a 32-byte one to trigger middlebox
// compatibility mode and the server must echo it verbatim.
const MaxSessionIDLen = 32

// Span is the position and length of a field within a message body.
type Span struct {
	Off int
	Len int
}

// HelloSpans locates the fields of a ClientHello or ServerHello body. Packet
// decoders need a field's wire position, which the slice returning accessors
// cannot give.
type HelloSpans struct {
	Random       Span
	SessionID    Span
	CipherSuites Span // ServerHello: the single selected suite.
	Compression  Span
	Extensions   Span
}

// ClientHelloMsg provides zero-copy access to a ClientHello body
// (RFC 8446 4.1.2), wrapping the handshake message body returned by
// [HandshakeFrame.Body], not the handshake header.
//
//	struct {
//	    ProtocolVersion legacy_version = 0x0303;
//	    Random random;                              // 32 bytes
//	    opaque legacy_session_id<0..32>;
//	    CipherSuite cipher_suites<2..2^16-2>;
//	    opaque legacy_compression_methods<1..2^8-1>;
//	    Extension extensions<8..2^16-1>;
//	} ClientHello;
//
// Unlike a [RecordFrame] or [HandshakeFrame], whose fields sit at fixed offsets,
// a hello's fields are length-prefixed and its extensions may arrive in any
// order. [ParseClientHello] resolves every offset once so accessors and
// iterators need no bounds checks and cannot fail.
type ClientHelloMsg struct {
	buf  []byte
	exts ExtensionList
	// Offsets of each variable-length field's contents, resolved at parse time.
	sessionIDOff, sessionIDLen int
	suitesOff, suitesLen       int
	compOff, compLen           int
}

// ParseClientHello parses a ClientHello body, validating that every length
// prefix is consistent with the buffer, down to the lists inside the extensions
// this package recognizes. It performs no policy checks: version negotiation,
// cipher suite selection and extension validation are the handshake state
// machine's job.
//
// Trailing bytes after the extensions block are rejected. A sender and parser
// that disagree about where a structure ends is the ambiguity that
// parser-differential attacks are built on.
func ParseClientHello(body []byte) (ClientHelloMsg, error) {
	var ch ClientHelloMsg
	// legacy_version(2) + random(32) + session_id length(1)
	const fixed = 2 + SizeRandom + 1
	if len(body) < fixed {
		return ch, lneto.ErrTruncatedFrame
	}
	off := 2 + SizeRandom

	sidLen := int(body[off])
	off++
	if sidLen > MaxSessionIDLen {
		// Bounds-checked before it can reach a fixed [32]byte echo buffer.
		return ch, lneto.ErrInvalidLengthField
	} else if sidLen > len(body)-off {
		return ch, lneto.ErrTruncatedFrame
	}
	ch.sessionIDOff, ch.sessionIDLen = off, sidLen
	off += sidLen

	if len(body)-off < 2 {
		return ch, lneto.ErrTruncatedFrame
	}
	suitesLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if suitesLen > len(body)-off {
		return ch, lneto.ErrTruncatedFrame
	} else if suitesLen%2 != 0 || suitesLen == 0 {
		return ch, lneto.ErrInvalidLengthField
	}
	ch.suitesOff, ch.suitesLen = off, suitesLen
	off += suitesLen

	if len(body)-off < 1 {
		return ch, lneto.ErrTruncatedFrame
	}
	compLen := int(body[off])
	off++
	if compLen > len(body)-off {
		return ch, lneto.ErrTruncatedFrame
	}
	ch.compOff, ch.compLen = off, compLen
	off += compLen

	// TLS 1.3 requires extensions; a ClientHello without them cannot possibly
	// carry supported_versions and so cannot be a 1.3 hello.
	if len(body)-off < 2 {
		return ch, lneto.ErrTruncatedFrame
	}
	extsLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if extsLen > len(body)-off {
		return ch, lneto.ErrTruncatedFrame
	} else if extsLen != len(body)-off {
		return ch, errTrailingBytes
	}
	exts, err := ParseClientExtensions(body[off:off+extsLen], off)
	if err != nil {
		return ClientHelloMsg{}, err
	}
	ch.exts = exts
	ch.buf = body
	return ch, nil
}

// LegacyVersion returns the legacy_version field, which TLS 1.3 pins to
// 0x0303 regardless of the version actually negotiated.
func (ch ClientHelloMsg) LegacyVersion() uint16 {
	return binary.BigEndian.Uint16(ch.buf[0:2])
}

// Random returns the 32-byte client_random.
func (ch ClientHelloMsg) Random() *[SizeRandom]byte {
	return (*[SizeRandom]byte)(ch.buf[2 : 2+SizeRandom])
}

// LegacySessionID returns the legacy_session_id, at most 32 bytes. A TLS 1.3
// server must echo this verbatim in its ServerHello; a non-empty value means
// the client is using middlebox compatibility mode and expects a dummy
// ChangeCipherSpec record.
func (ch ClientHelloMsg) LegacySessionID() []byte {
	return ch.buf[ch.sessionIDOff : ch.sessionIDOff+ch.sessionIDLen]
}

// CipherSuites iterates the offered suites in wire order, keyed by each suite's
// offset within the body. The list includes GREASE values.
func (ch ClientHelloMsg) CipherSuites(yield func(off int, suite CipherSuite) bool) {
	suites := ch.CipherSuiteBytes()
	for off := 0; off+2 <= len(suites); off += 2 {
		if !yield(ch.suitesOff+off, CipherSuite(binary.BigEndian.Uint16(suites[off:off+2]))) {
			return
		}
	}
}

// CipherSuiteBytes returns the cipher_suites vector with its length prefix
// stripped.
func (ch ClientHelloMsg) CipherSuiteBytes() []byte {
	return ch.buf[ch.suitesOff : ch.suitesOff+ch.suitesLen]
}

// LegacyCompressionMethods returns the legacy_compression_methods vector
// contents. For a TLS 1.3 hello this must be exactly one zero byte; see
// [ClientHelloMsg.ValidateCompression].
func (ch ClientHelloMsg) LegacyCompressionMethods() []byte {
	return ch.buf[ch.compOff : ch.compOff+ch.compLen]
}

// Extensions iterates this hello's extensions in wire order, keyed by the
// offset of each extension's data within the body. Duplicates were rejected at
// parse time, so the walk needs no bookkeeping.
func (ch ClientHelloMsg) Extensions(yield func(off int, ext ExtensionFrame) bool) {
	ch.exts.All(yield)
}

// ExtensionList returns the validated extensions block, for passing the block
// itself around rather than ranging over it here.
func (ch ClientHelloMsg) ExtensionList() ExtensionList { return ch.exts }

// ExtensionBytes returns the extensions block contents with the outer length
// prefix stripped.
func (ch ClientHelloMsg) ExtensionBytes() []byte { return ch.exts.Bytes() }

// RawData returns the whole ClientHello body.
func (ch ClientHelloMsg) RawData() []byte { return ch.buf }

// Spans locates this hello's fields inside [ClientHelloMsg.RawData].
func (ch ClientHelloMsg) Spans() HelloSpans {
	return HelloSpans{
		Random:       Span{Off: 2, Len: SizeRandom},
		SessionID:    Span{Off: ch.sessionIDOff, Len: ch.sessionIDLen},
		CipherSuites: Span{Off: ch.suitesOff, Len: ch.suitesLen},
		Compression:  Span{Off: ch.compOff, Len: ch.compLen},
		Extensions:   Span{Off: ch.exts.base, Len: len(ch.exts.buf)},
	}
}

// ValidateSize adds an error to v if the ClientHello is structurally invalid.
// Since [ParseClientHello] already rejects every inconsistent length, this only
// re-checks that the message was successfully parsed.
func (ch ClientHelloMsg) ValidateSize(v *lneto.Validator) {
	if ch.buf == nil {
		v.AddError(lneto.ErrTruncatedFrame)
	}
}

// ValidateCompression reports whether legacy_compression_methods is exactly
// the single null method TLS 1.3 mandates (RFC 8446 4.1.2). Anything else must
// be rejected with an illegal_parameter alert: a client offering real
// compression methods is either pre-1.3 or attempting a downgrade.
func (ch ClientHelloMsg) ValidateCompression() bool {
	return ch.compLen == 1 && ch.buf[ch.compOff] == 0
}

// ServerHelloMsg provides zero-copy access to a ServerHello body
// (RFC 8446 4.1.3). Like [ClientHelloMsg] it wraps the handshake message body.
//
//	struct {
//	    ProtocolVersion legacy_version = 0x0303;
//	    Random random;                              // 32 bytes
//	    opaque legacy_session_id_echo<0..32>;
//	    CipherSuite cipher_suite;                   // 2 bytes
//	    uint8 legacy_compression_method = 0;
//	    Extension extensions<6..2^16-1>;
//	} ServerHello;
//
// A HelloRetryRequest has this same structure; it is told apart by its random
// being the special value of RFC 8446 4.1.3, which is policy, not framing.
type ServerHelloMsg struct {
	buf                        []byte
	exts                       ExtensionList
	sessionIDOff, sessionIDLen int
	suiteOff                   int
}

// ParseServerHello parses a ServerHello body. Like [ParseClientHello] it
// validates framing only, rejects trailing bytes, and validates the lists
// inside recognized extensions, in their server forms.
func ParseServerHello(body []byte) (ServerHelloMsg, error) {
	var sh ServerHelloMsg
	const fixed = 2 + SizeRandom + 1
	if len(body) < fixed {
		return sh, lneto.ErrTruncatedFrame
	}
	off := 2 + SizeRandom

	sidLen := int(body[off])
	off++
	if sidLen > MaxSessionIDLen {
		return sh, lneto.ErrInvalidLengthField
	} else if sidLen > len(body)-off {
		return sh, lneto.ErrTruncatedFrame
	}
	sh.sessionIDOff, sh.sessionIDLen = off, sidLen
	off += sidLen

	// cipher_suite(2) + legacy_compression_method(1)
	if len(body)-off < 3 {
		return sh, lneto.ErrTruncatedFrame
	}
	sh.suiteOff = off
	off += 3

	if len(body)-off < 2 {
		return sh, lneto.ErrTruncatedFrame
	}
	extsLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if extsLen > len(body)-off {
		return sh, lneto.ErrTruncatedFrame
	} else if extsLen != len(body)-off {
		return sh, errTrailingBytes
	}
	exts, err := ParseServerExtensions(body[off:off+extsLen], off)
	if err != nil {
		return ServerHelloMsg{}, err
	}
	sh.exts = exts
	sh.buf = body
	return sh, nil
}

// LegacyVersion returns the legacy_version field, pinned to 0x0303 by TLS 1.3.
func (sh ServerHelloMsg) LegacyVersion() uint16 {
	return binary.BigEndian.Uint16(sh.buf[0:2])
}

// Random returns the 32-byte server_random.
func (sh ServerHelloMsg) Random() *[SizeRandom]byte {
	return (*[SizeRandom]byte)(sh.buf[2 : 2+SizeRandom])
}

// LegacySessionIDEcho returns the client's legacy_session_id as echoed back. A
// client in middlebox compatibility mode requires it to match what it sent.
func (sh ServerHelloMsg) LegacySessionIDEcho() []byte {
	return sh.buf[sh.sessionIDOff : sh.sessionIDOff+sh.sessionIDLen]
}

// CipherSuite returns the selected cipher suite.
func (sh ServerHelloMsg) CipherSuite() CipherSuite {
	return CipherSuite(binary.BigEndian.Uint16(sh.buf[sh.suiteOff : sh.suiteOff+2]))
}

// LegacyCompressionMethod returns the legacy_compression_method, which TLS 1.3
// requires to be zero.
func (sh ServerHelloMsg) LegacyCompressionMethod() uint8 {
	return sh.buf[sh.suiteOff+2]
}

// Extensions iterates this hello's extensions in wire order, keyed by the
// offset of each extension's data within the body.
func (sh ServerHelloMsg) Extensions(yield func(off int, ext ExtensionFrame) bool) {
	sh.exts.All(yield)
}

// ExtensionList returns the validated extensions block.
func (sh ServerHelloMsg) ExtensionList() ExtensionList { return sh.exts }

// ExtensionBytes returns the extensions block contents with the outer length
// prefix stripped.
func (sh ServerHelloMsg) ExtensionBytes() []byte { return sh.exts.Bytes() }

// RawData returns the whole ServerHello body.
func (sh ServerHelloMsg) RawData() []byte { return sh.buf }

// Spans locates this hello's fields inside [ServerHelloMsg.RawData].
func (sh ServerHelloMsg) Spans() HelloSpans {
	return HelloSpans{
		Random:       Span{Off: 2, Len: SizeRandom},
		SessionID:    Span{Off: sh.sessionIDOff, Len: sh.sessionIDLen},
		CipherSuites: Span{Off: sh.suiteOff, Len: 2},
		Compression:  Span{Off: sh.suiteOff + 2, Len: 1},
		Extensions:   Span{Off: sh.exts.base, Len: len(sh.exts.buf)},
	}
}

// ValidateSize adds an error to v if the ServerHello was not parsed.
func (sh ServerHelloMsg) ValidateSize(v *lneto.Validator) {
	if sh.buf == nil {
		v.AddError(lneto.ErrTruncatedFrame)
	}
}

// extSeen tracks which known extension types have already been encountered in
// a single hello. RFC 8446 4.2 forbids a duplicate extension type, and
// tolerating duplicates invites parser-differential attacks where this parser
// and a middlebox act on different copies.
//
// Only known types are tracked; unknown and GREASE types are exempt because
// they are skipped without being acted upon.
type extSeen uint64

// mark records ext and reports whether it had already been seen. Extension
// types with no assigned bit are never reported as duplicates.
func (s *extSeen) mark(ext ExtensionType) (duplicate bool) {
	bit, ok := extBit(ext)
	if !ok {
		return false
	}
	if *s&bit != 0 {
		return true
	}
	*s |= bit
	return false
}

// extBit maps an extension type to its bit in [extSeen]. The mapping covers
// every extension this server reads or must reject a duplicate of.
func extBit(ext ExtensionType) (extSeen, bool) {
	var i uint
	switch ext {
	case ExtServerName:
		i = 0
	case ExtMaxFragmentLength:
		i = 1
	case ExtStatusRequest:
		i = 2
	case ExtSupportedGroups:
		i = 3
	case ExtSignatureAlgorithms:
		i = 4
	case ExtALPN:
		i = 5
	case ExtSignedCertificateTimestamp:
		i = 6
	case ExtPadding:
		i = 7
	case ExtExtendedMasterSecret:
		i = 8
	case ExtCompressCertificate:
		i = 9
	case ExtRecordSizeLimit:
		i = 10
	case ExtSessionTicket:
		i = 11
	case ExtPreSharedKey:
		i = 12
	case ExtEarlyData:
		i = 13
	case ExtSupportedVersions:
		i = 14
	case ExtCookie:
		i = 15
	case ExtPSKKeyExchangeModes:
		i = 16
	case ExtCertificateAuthorities:
		i = 17
	case ExtSignatureAlgorithmsCert:
		i = 18
	case ExtKeyShare:
		i = 19
	case ExtApplicationSettings:
		i = 20
	case ExtEncryptedClientHello:
		i = 21
	case ExtRenegotiationInfo:
		i = 22
	case ExtECPointFormats:
		i = 23
	default:
		return 0, false
	}
	return 1 << i, true
}
