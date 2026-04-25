// Package nts implements the Network Time Security (NTS) key exchange and
// authenticated NTP packet construction as specified in RFC 8915.
//
// # Protocol overview
//
// NTS adds an authentication layer on top of NTPv4.  It has two phases:
//
//  1. Key Exchange (NTS-KE, TCP port 4460): a TLS 1.3 handshake followed by
//     a small application-layer record exchange that negotiates the AEAD
//     algorithm and distributes opaque cookies.  Use [PerformKE] to run this
//     phase over a caller-owned *tls.Conn.
//
//  2. Authenticated NTP: each request carries a Unique-ID extension field, a
//     Cookie extension field (from the pool obtained in phase 1), and an
//     NTS-Authenticator-and-EEF field sealed with the C2S AEAD key.  Use
//     [Client] as the lneto [StackNode] for this phase.
//
// # Cipher
//
// RFC 8915 mandates AEAD_AES_SIV_CMAC_256 ([AlgAESSIVCMAC256]).  Because
// this algorithm is not in the Go standard library, callers must provide a
// [cipher.AEAD] implementation.  [github.com/soypat/lneto/x/siv] ships a
// pure-Go implementation that can be constructed from the keys in [KESecrets]:
//
//	c2s, err := siv.NewAESSIVCMAC256(secrets.C2SKey[:])
//	s2c, err := siv.NewAESSIVCMAC256(secrets.S2CKey[:])
//
//go:generate stringer -type=KERecordType,AEADAlgorithmID -linecomment -output stringers.go
package nts

// KEPort is the IANA-assigned TCP port for the NTS Key Exchange protocol.
const KEPort = 4460

// MaxCookies is the maximum number of cookies the client stores at one time.
// RFC 8915 §5.7 says servers SHOULD send eight cookies.
const MaxCookies = 8

// MaxCookieLen is the maximum byte length of a single NTS cookie.
// Real-world servers typically use 100–200 bytes; 256 provides headroom.
const MaxCookieLen = 256

// maxNonceLen is the largest nonce we pre-allocate space for.
// AES-SIV uses 16 bytes; GCM uses 12 bytes.
const maxNonceLen = 16

// KERecordType identifies NTS-KE record types (RFC 8915 §4.1.2).
type KERecordType uint16

const (
	RecordEndOfMessage KERecordType = 0 // end of message
	RecordNextProtoNeg KERecordType = 1 // next protocol negotiation
	RecordError        KERecordType = 2 // error
	RecordWarning      KERecordType = 3 // warning
	RecordAEADAlgNeg   KERecordType = 4 // AEAD algorithm negotiation
	RecordNewCookie    KERecordType = 5 // new cookie for NTPv4
	RecordNTPv4Server  KERecordType = 6 // NTPv4 server negotiation
	RecordNTPv4Port    KERecordType = 7 // NTPv4 port negotiation
)

// AEADAlgorithmID identifies AEAD algorithms used in NTS (RFC 8915 §5.1).
type AEADAlgorithmID uint16

const (
	// AlgAESSIVCMAC256 is AEAD_AES_SIV_CMAC_256 (algorithm number 15).
	// This is the only algorithm mandated by RFC 8915 §5.1 and the sole
	// registered algorithm at time of writing.
	AlgAESSIVCMAC256 AEADAlgorithmID = 15 // AEAD_AES_SIV_CMAC_256
)

// ntpv4ProtocolID is the NTS-KE protocol identifier for NTPv4 (RFC 8915 §4).
const ntpv4ProtocolID uint16 = 0
