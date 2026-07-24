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

// ClientHelloFrame provides zero-copy access to a ClientHello body
// (RFC 8446 4.1.2). The frame wraps the handshake message *body*, that is the
// bytes returned by [HandshakeFrame.Body], not the handshake header.
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
// Every variable-length field is bounds-checked once by
// [NewClientHelloFrame], so the accessors cannot slice out of range.
type ClientHelloFrame struct {
	buf []byte
	// Offsets of each variable-length field's contents, resolved once at
	// construction so accessors stay branch-free.
	sessionIDOff, sessionIDLen int
	suitesOff, suitesLen       int
	compOff, compLen           int
	extsOff, extsLen           int
}

// NewClientHelloFrame parses the structure of a ClientHello body, validating
// that every length prefix is consistent with the buffer. It performs no
// policy checks: version negotiation, cipher suite selection and extension
// validation are the handshake state machine's job.
//
// Trailing bytes after the extensions block are rejected. A sender and parser
// that disagree about where a structure ends is the ambiguity that
// parser-differential attacks are built on.
func NewClientHelloFrame(body []byte) (ClientHelloFrame, error) {
	var ch ClientHelloFrame
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
	ch.extsOff, ch.extsLen = off, extsLen

	ch.buf = body
	return ch, nil
}

// LegacyVersion returns the legacy_version field, which TLS 1.3 pins to
// 0x0303 regardless of the version actually negotiated.
func (ch ClientHelloFrame) LegacyVersion() uint16 {
	return binary.BigEndian.Uint16(ch.buf[0:2])
}

// Random returns the 32-byte client_random.
func (ch ClientHelloFrame) Random() *[SizeRandom]byte {
	return (*[SizeRandom]byte)(ch.buf[2 : 2+SizeRandom])
}

// LegacySessionID returns the legacy_session_id, at most 32 bytes. A TLS 1.3
// server must echo this verbatim in its ServerHello; a non-empty value means
// the client is using middlebox compatibility mode and expects a dummy
// ChangeCipherSpec record.
func (ch ClientHelloFrame) LegacySessionID() []byte {
	return ch.buf[ch.sessionIDOff : ch.sessionIDOff+ch.sessionIDLen]
}

// CipherSuites returns the cipher_suites vector with its length prefix
// stripped, ready for [ForEachU16]. The list includes GREASE values.
func (ch ClientHelloFrame) CipherSuites() []byte {
	return ch.buf[ch.suitesOff : ch.suitesOff+ch.suitesLen]
}

// LegacyCompressionMethods returns the legacy_compression_methods vector
// contents. For a TLS 1.3 hello this must be exactly one zero byte; see
// [ClientHelloFrame.ValidateCompression].
func (ch ClientHelloFrame) LegacyCompressionMethods() []byte {
	return ch.buf[ch.compOff : ch.compOff+ch.compLen]
}

// Extensions returns the extensions block contents with the outer length
// prefix stripped, ready for [ForEachExtension].
func (ch ClientHelloFrame) Extensions() []byte {
	return ch.buf[ch.extsOff : ch.extsOff+ch.extsLen]
}

// RawData returns the whole ClientHello body.
func (ch ClientHelloFrame) RawData() []byte { return ch.buf }

// ForEachExtension walks this hello's extensions, rejecting a repeated known
// extension type with [lneto.ErrInvalidField]. RFC 8446 4.2 forbids duplicates,
// and tolerating them invites parser-differential attacks in which this parser
// and a middlebox act on different copies of the same extension.
//
// Unknown and GREASE extension types are passed through without duplicate
// checking, since they are skipped rather than acted upon. Prefer this over
// the bare [ForEachExtension] when parsing an untrusted hello.
func (ch ClientHelloFrame) ForEachExtension(fn func(ExtensionType, []byte) error) error {
	var seen extSeen
	return ForEachExtension(ch.Extensions(), func(ext ExtensionType, data []byte) error {
		if seen.mark(ext) {
			return lneto.ErrInvalidField
		}
		return fn(ext, data)
	})
}

// ValidateSize adds an error to v if the ClientHello is structurally invalid.
// Since [NewClientHelloFrame] already rejects every inconsistent length, this
// only re-checks that the frame was successfully constructed.
func (ch ClientHelloFrame) ValidateSize(v *lneto.Validator) {
	if ch.buf == nil {
		v.AddError(lneto.ErrTruncatedFrame)
	}
}

// ValidateCompression reports whether legacy_compression_methods is exactly
// the single null method TLS 1.3 mandates (RFC 8446 4.1.2). Anything else must
// be rejected with an illegal_parameter alert: a client offering real
// compression methods is either pre-1.3 or attempting a downgrade.
func (ch ClientHelloFrame) ValidateCompression() bool {
	return ch.compLen == 1 && ch.buf[ch.compOff] == 0
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
	default:
		return 0, false
	}
	return 1 << i, true
}
