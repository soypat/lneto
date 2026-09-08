package tls

// Sizes of fixed length headers and the record size limits of RFC 8446 5.2.
const (
	// SizeHeaderRecord is the size of a TLSPlaintext/TLSCiphertext header: content type(1) + legacy record version(2) + length(2).
	SizeHeaderRecord = 5
	// SizeHeaderHandshake is the size of a Handshake header: message type(1) + 24-bit length(3).
	SizeHeaderHandshake = 4
	// MaxPlaintext is the largest legal TLSPlaintext.fragment.
	MaxPlaintext = 1 << 14 // 16384
	// MaxCiphertext is the largest legal TLSCiphertext.encrypted_record.
	// The extra 256 bytes cover the content type byte, padding and the AEAD tag.
	MaxCiphertext = 1<<14 + 256 // 16640
	// MaxRecord is the largest legal record as it appears on the wire.
	MaxRecord = SizeHeaderRecord + MaxCiphertext // 16645
	// MinRecordSizeLimit is the smallest value a peer may advertise in the record_size_limit extension of RFC 8449 4.
	MinRecordSizeLimit = 64
)

// ContentType is the outermost record demultiplexing tag of RFC 8446 5.1.
type ContentType uint8

// Record content types. Values below are the only ones TLS 1.3 defines;
// everything else must be rejected with an unexpected_message alert.
const (
	ContentTypeInvalid          ContentType = 0  // invalid
	ContentTypeChangeCipherSpec ContentType = 20 // change_cipher_spec
	ContentTypeAlert            ContentType = 21 // alert
	ContentTypeHandshake        ContentType = 22 // handshake
	ContentTypeApplicationData  ContentType = 23 // application_data
)

// HandshakeType identifies a handshake message, RFC 8446 4.
type HandshakeType uint8

// Handshake message types. Types this server never sends or accepts are still
// listed so that a peer sending one can be logged and rejected precisely.
const (
	HandshakeTypeClientHello         HandshakeType = 1   // client_hello
	HandshakeTypeServerHello         HandshakeType = 2   // server_hello
	HandshakeTypeNewSessionTicket    HandshakeType = 4   // new_session_ticket
	HandshakeTypeEndOfEarlyData      HandshakeType = 5   // end_of_early_data
	HandshakeTypeEncryptedExtensions HandshakeType = 8   // encrypted_extensions
	HandshakeTypeCertificate         HandshakeType = 11  // certificate
	HandshakeTypeCertificateRequest  HandshakeType = 13  // certificate_request
	HandshakeTypeCertificateVerify   HandshakeType = 15  // certificate_verify
	HandshakeTypeFinished            HandshakeType = 20  // finished
	HandshakeTypeKeyUpdate           HandshakeType = 24  // key_update
	HandshakeTypeMessageHash         HandshakeType = 254 // message_hash
)

// ExtensionType identifies a hello extension, RFC 8446 4.2.
type ExtensionType uint16

// Extension types. Those marked "ignored" are ones a browser sends and this
// server parses past without erroring; being strict about unknown extensions
// breaks real clients.
const (
	ExtServerName                 ExtensionType = 0     // server_name
	ExtMaxFragmentLength          ExtensionType = 1     // max_fragment_length
	ExtStatusRequest              ExtensionType = 5     // status_request
	ExtSupportedGroups            ExtensionType = 10    // supported_groups
	ExtECPointFormats             ExtensionType = 11    // ec_point_formats
	ExtSignatureAlgorithms        ExtensionType = 13    // signature_algorithms
	ExtALPN                       ExtensionType = 16    // application_layer_protocol_negotiation
	ExtSignedCertificateTimestamp ExtensionType = 18    // signed_certificate_timestamp
	ExtPadding                    ExtensionType = 21    // padding
	ExtExtendedMasterSecret       ExtensionType = 23    // extended_master_secret
	ExtCompressCertificate        ExtensionType = 27    // compress_certificate
	ExtRecordSizeLimit            ExtensionType = 28    // record_size_limit
	ExtSessionTicket              ExtensionType = 35    // session_ticket
	ExtPreSharedKey               ExtensionType = 41    // pre_shared_key
	ExtEarlyData                  ExtensionType = 42    // early_data
	ExtSupportedVersions          ExtensionType = 43    // supported_versions
	ExtCookie                     ExtensionType = 44    // cookie
	ExtPSKKeyExchangeModes        ExtensionType = 45    // psk_key_exchange_modes
	ExtCertificateAuthorities     ExtensionType = 47    // certificate_authorities
	ExtSignatureAlgorithmsCert    ExtensionType = 50    // signature_algorithms_cert
	ExtKeyShare                   ExtensionType = 51    // key_share
	ExtApplicationSettings        ExtensionType = 17513 // application_settings
	ExtEncryptedClientHello       ExtensionType = 65037 // encrypted_client_hello
	ExtRenegotiationInfo          ExtensionType = 65281 // renegotiation_info
)

// AlertLevel is the legacy severity byte of an alert. In TLS 1.3 every alert
// except close_notify and user_canceled is fatal regardless of this field
// (RFC 8446 6.1), so it is carried for wire compatibility only and must never
// be used to decide whether to continue.
type AlertLevel uint8

// Alert levels.
const (
	AlertLevelWarning AlertLevel = 1 // warning
	AlertLevelFatal   AlertLevel = 2 // fatal
)

// AlertDescription is the alert code of RFC 8446 6.
type AlertDescription uint8

// Alert descriptions. Only the subset a TLS 1.3 server can legitimately send
// or receive is listed.
const (
	AlertCloseNotify                  AlertDescription = 0   // close_notify
	AlertUnexpectedMessage            AlertDescription = 10  // unexpected_message
	AlertBadRecordMAC                 AlertDescription = 20  // bad_record_mac
	AlertRecordOverflow               AlertDescription = 22  // record_overflow
	AlertHandshakeFailure             AlertDescription = 40  // handshake_failure
	AlertBadCertificate               AlertDescription = 42  // bad_certificate
	AlertUnsupportedCertificate       AlertDescription = 43  // unsupported_certificate
	AlertCertificateRevoked           AlertDescription = 44  // certificate_revoked
	AlertCertificateExpired           AlertDescription = 45  // certificate_expired
	AlertCertificateUnknown           AlertDescription = 46  // certificate_unknown
	AlertIllegalParameter             AlertDescription = 47  // illegal_parameter
	AlertUnknownCA                    AlertDescription = 48  // unknown_ca
	AlertAccessDenied                 AlertDescription = 49  // access_denied
	AlertDecodeError                  AlertDescription = 50  // decode_error
	AlertDecryptError                 AlertDescription = 51  // decrypt_error
	AlertProtocolVersion              AlertDescription = 70  // protocol_version
	AlertInsufficientSecurity         AlertDescription = 71  // insufficient_security
	AlertInternalError                AlertDescription = 80  // internal_error
	AlertInappropriateFallback        AlertDescription = 86  // inappropriate_fallback
	AlertUserCanceled                 AlertDescription = 90  // user_canceled
	AlertMissingExtension             AlertDescription = 109 // missing_extension
	AlertUnsupportedExtension         AlertDescription = 110 // unsupported_extension
	AlertUnrecognizedName             AlertDescription = 112 // unrecognized_name
	AlertBadCertificateStatusResponse AlertDescription = 113 // bad_certificate_status_response
	AlertUnknownPSKIdentity           AlertDescription = 115 // unknown_psk_identity
	AlertCertificateRequired          AlertDescription = 116 // certificate_required
	AlertNoApplicationProtocol        AlertDescription = 120 // no_application_protocol
)

// Protocol versions as they appear on the wire.
const (
	// VersionTLS12 is the value TLS 1.3 requires in ClientHello.legacy_version
	// and in ServerHello.legacy_version for middlebox compatibility.
	VersionTLS12 uint16 = 0x0303
	// VersionTLS13 is the real negotiated version, carried only in the
	// supported_versions extension.
	VersionTLS13 uint16 = 0x0304
	// VersionTLS10 appears in the legacy_record_version of an initial
	// ClientHello record. The field is ignored entirely on receipt.
	VersionTLS10 uint16 = 0x0301
)

// NamedGroup identifies a key exchange group, RFC 8446 4.2.7.
type NamedGroup uint16

// Named groups. Only X25519 is implemented; the rest are recognized so that
// group selection and HelloRetryRequest can report precisely what was offered.
const (
	GroupSECP256R1      NamedGroup = 0x0017 // secp256r1
	GroupSECP384R1      NamedGroup = 0x0018 // secp384r1
	GroupSECP521R1      NamedGroup = 0x0019 // secp521r1
	GroupX25519         NamedGroup = 0x001d // x25519
	GroupX448           NamedGroup = 0x001e // x448
	GroupX25519MLKEM768 NamedGroup = 0x11ec // x25519mlkem768
)

// SignatureScheme identifies a signature algorithm, RFC 8446 4.2.3.
type SignatureScheme uint16

// Signature schemes. Browsers do not accept Ed25519 certificates, so
// [SigECDSAP256SHA256] is the practical minimum for a public-facing server.
const (
	SigRSAPKCS1SHA256   SignatureScheme = 0x0401 // rsa_pkcs1_sha256
	SigRSAPKCS1SHA384   SignatureScheme = 0x0501 // rsa_pkcs1_sha384
	SigRSAPKCS1SHA512   SignatureScheme = 0x0601 // rsa_pkcs1_sha512
	SigECDSAP256SHA256  SignatureScheme = 0x0403 // ecdsa_secp256r1_sha256
	SigECDSAP384SHA384  SignatureScheme = 0x0503 // ecdsa_secp384r1_sha384
	SigECDSAP521SHA512  SignatureScheme = 0x0603 // ecdsa_secp521r1_sha512
	SigRSAPSSRSAESHA256 SignatureScheme = 0x0804 // rsa_pss_rsae_sha256
	SigRSAPSSRSAESHA384 SignatureScheme = 0x0805 // rsa_pss_rsae_sha384
	SigRSAPSSRSAESHA512 SignatureScheme = 0x0806 // rsa_pss_rsae_sha512
	SigEd25519          SignatureScheme = 0x0807 // ed25519
	SigRSAPSSPSSSHA256  SignatureScheme = 0x0809 // rsa_pss_pss_sha256
)

// CipherSuite identifies an AEAD plus hash pair, RFC 8446 B.4.
type CipherSuite uint16

// TLS 1.3 cipher suites. Only [SuiteAES128GCMSHA256] is implemented; it is the
// one suite RFC 8446 9.1 makes mandatory to implement.
const (
	SuiteAES128GCMSHA256        CipherSuite = 0x1301 // TLS_AES_128_GCM_SHA256
	SuiteAES256GCMSHA384        CipherSuite = 0x1302 // TLS_AES_256_GCM_SHA384
	SuiteChaCha20Poly1305SHA256 CipherSuite = 0x1303 // TLS_CHACHA20_POLY1305_SHA256
	SuiteAES128CCMSHA256        CipherSuite = 0x1304 // TLS_AES_128_CCM_SHA256
	SuiteAES128CCM8SHA256       CipherSuite = 0x1305 // TLS_AES_128_CCM_8_SHA256
)

// IsGREASE reports whether v is one of the 16 reserved Generate Random Extensions And Sustain Extensibility
// (GREASE) values of RFC 8701. GREASE is intended to prevent implementations from rejecting unknown
// extensions, this way catching interoperation mistakes in the future and preventing API "rusted joints" from forming.
func IsGREASE[T ~uint16](v T) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}
