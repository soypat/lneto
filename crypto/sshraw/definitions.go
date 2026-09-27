/*
package sshraw implements low level SSH 2.0 transport functionality.
This package is not externally audited. Use only if you understand the risks.

It prioritizes readability and security. Performance is a secondary priority.
As in tlsraw, messages are decoded with the [decoder] type for readable
decoding at the expense of more branching.
*/

package sshraw

//go:generate stringer -type=MsgType,DisconnectReason,ChannelOpenFailureReason -linecomment -output stringers.go .

// Sizes and limits of the binary packet protocol, RFC 4253 6.
const (
	// SizeHeaderPacket is the size of the binary packet header: packet_length(4) + padding_length(1).
	SizeHeaderPacket = 5
	// SizeCookie is the size of the random cookie of SSH_MSG_KEXINIT.
	SizeCookie = 16
	// MinPadding is the least random padding a packet carries.
	MinPadding = 4
	// MaxPadding is the most random padding padding_length can declare.
	MaxPadding = 255
	// MinBlockSize is the alignment of packets when no cipher, or a stream cipher, is in use.
	MinBlockSize = 8
	// MaxPayload is the largest uncompressed payload every implementation must process, RFC 4253 6.1.
	MaxPayload = 32768
	// MaxPacket is the largest packet every implementation must process, RFC 4253 6.1.
	// It counts packet_length, padding_length, payload, padding and MAC.
	// Larger packets are rejected. OpenSSH and x/crypto/ssh accept up to 256KiB
	// but only send more than this when the peer advertises a larger channel
	// maximum packet size, so a stack using this package must not advertise one.
	MaxPacket = 35000
	// MaxIdentLen is the longest identification string, CR LF included, RFC 4253 4.2.
	MaxIdentLen = 255
	// MaxNameLen is the longest algorithm name in a name-list, RFC 4251 6.
	MaxNameLen = 64
)

// IdentPrefix starts an identification string. A server may send other lines
// before it which a client must skip, RFC 4253 4.2.
const IdentPrefix = "SSH-"

// MsgType is the first byte of every packet payload, RFC 4250 4.1.
type MsgType uint8

// Message numbers. Numbers 30 through 49 are key exchange method specific and
// numbers 60 through 79 are user authentication method specific; the values
// listed for those ranges are the ones of ECDH (RFC 5656) and publickey auth.
const (
	MsgDisconnect              MsgType = 1   // SSH_MSG_DISCONNECT
	MsgIgnore                  MsgType = 2   // SSH_MSG_IGNORE
	MsgUnimplemented           MsgType = 3   // SSH_MSG_UNIMPLEMENTED
	MsgDebug                   MsgType = 4   // SSH_MSG_DEBUG
	MsgServiceRequest          MsgType = 5   // SSH_MSG_SERVICE_REQUEST
	MsgServiceAccept           MsgType = 6   // SSH_MSG_SERVICE_ACCEPT
	MsgExtInfo                 MsgType = 7   // SSH_MSG_EXT_INFO
	MsgKexInit                 MsgType = 20  // SSH_MSG_KEXINIT
	MsgNewKeys                 MsgType = 21  // SSH_MSG_NEWKEYS
	MsgKexECDHInit             MsgType = 30  // SSH_MSG_KEX_ECDH_INIT
	MsgKexECDHReply            MsgType = 31  // SSH_MSG_KEX_ECDH_REPLY
	MsgUserauthRequest         MsgType = 50  // SSH_MSG_USERAUTH_REQUEST
	MsgUserauthFailure         MsgType = 51  // SSH_MSG_USERAUTH_FAILURE
	MsgUserauthSuccess         MsgType = 52  // SSH_MSG_USERAUTH_SUCCESS
	MsgUserauthBanner          MsgType = 53  // SSH_MSG_USERAUTH_BANNER
	MsgUserauthPKOK            MsgType = 60  // SSH_MSG_USERAUTH_PK_OK
	MsgGlobalRequest           MsgType = 80  // SSH_MSG_GLOBAL_REQUEST
	MsgRequestSuccess          MsgType = 81  // SSH_MSG_REQUEST_SUCCESS
	MsgRequestFailure          MsgType = 82  // SSH_MSG_REQUEST_FAILURE
	MsgChannelOpen             MsgType = 90  // SSH_MSG_CHANNEL_OPEN
	MsgChannelOpenConfirmation MsgType = 91  // SSH_MSG_CHANNEL_OPEN_CONFIRMATION
	MsgChannelOpenFailure      MsgType = 92  // SSH_MSG_CHANNEL_OPEN_FAILURE
	MsgChannelWindowAdjust     MsgType = 93  // SSH_MSG_CHANNEL_WINDOW_ADJUST
	MsgChannelData             MsgType = 94  // SSH_MSG_CHANNEL_DATA
	MsgChannelExtendedData     MsgType = 95  // SSH_MSG_CHANNEL_EXTENDED_DATA
	MsgChannelEOF              MsgType = 96  // SSH_MSG_CHANNEL_EOF
	MsgChannelClose            MsgType = 97  // SSH_MSG_CHANNEL_CLOSE
	MsgChannelRequest          MsgType = 98  // SSH_MSG_CHANNEL_REQUEST
	MsgChannelSuccess          MsgType = 99  // SSH_MSG_CHANNEL_SUCCESS
	MsgChannelFailure          MsgType = 100 // SSH_MSG_CHANNEL_FAILURE
)

// DisconnectReason is the reason code of SSH_MSG_DISCONNECT, RFC 4250 4.2.2.
type DisconnectReason uint32

// Disconnect reason codes.
const (
	DisconnectHostNotAllowedToConnect     DisconnectReason = 1  // SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT
	DisconnectProtocolError               DisconnectReason = 2  // SSH_DISCONNECT_PROTOCOL_ERROR
	DisconnectKeyExchangeFailed           DisconnectReason = 3  // SSH_DISCONNECT_KEY_EXCHANGE_FAILED
	DisconnectReserved                    DisconnectReason = 4  // SSH_DISCONNECT_RESERVED
	DisconnectMACError                    DisconnectReason = 5  // SSH_DISCONNECT_MAC_ERROR
	DisconnectCompressionError            DisconnectReason = 6  // SSH_DISCONNECT_COMPRESSION_ERROR
	DisconnectServiceNotAvailable         DisconnectReason = 7  // SSH_DISCONNECT_SERVICE_NOT_AVAILABLE
	DisconnectProtocolVersionNotSupported DisconnectReason = 8  // SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED
	DisconnectHostKeyNotVerifiable        DisconnectReason = 9  // SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE
	DisconnectConnectionLost              DisconnectReason = 10 // SSH_DISCONNECT_CONNECTION_LOST
	DisconnectByApplication               DisconnectReason = 11 // SSH_DISCONNECT_BY_APPLICATION
	DisconnectTooManyConnections          DisconnectReason = 12 // SSH_DISCONNECT_TOO_MANY_CONNECTIONS
	DisconnectAuthCancelledByUser         DisconnectReason = 13 // SSH_DISCONNECT_AUTH_CANCELLED_BY_USER
	DisconnectNoMoreAuthMethodsAvailable  DisconnectReason = 14 // SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE
	DisconnectIllegalUserName             DisconnectReason = 15 // SSH_DISCONNECT_ILLEGAL_USER_NAME
)

// ChannelOpenFailureReason is the reason code of SSH_MSG_CHANNEL_OPEN_FAILURE, RFC 4250 4.3.
type ChannelOpenFailureReason uint32

// Channel open failure reason codes.
const (
	OpenAdministrativelyProhibited ChannelOpenFailureReason = 1 // SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
	OpenConnectFailed              ChannelOpenFailureReason = 2 // SSH_OPEN_CONNECT_FAILED
	OpenUnknownChannelType         ChannelOpenFailureReason = 3 // SSH_OPEN_UNKNOWN_CHANNEL_TYPE
	OpenResourceShortage           ChannelOpenFailureReason = 4 // SSH_OPEN_RESOURCE_SHORTAGE
)

// Algorithm names as they appear in SSH_MSG_KEXINIT name-lists. Unlike TLS
// code points they are strings; only those this package has a reading of are listed.
const (
	KexCurve25519SHA256       = "curve25519-sha256"            // RFC 8731.
	KexCurve25519SHA256LibSSH = "curve25519-sha256@libssh.org" // Pre-RFC 8731 name, same method.
	KexMLKEM768X25519SHA256   = "mlkem768x25519-sha256"
	KexECDHP256               = "ecdh-sha2-nistp256" // RFC 5656.
	// KexStrictClient and KexStrictServer signal strict key exchange, the
	// countermeasure to the Terrapin attack (CVE-2023-48795). They are pseudo
	// algorithms that are never negotiated, only looked for, and only in the
	// first key exchange: they are ignored when rekeying.
	KexStrictClient = "kex-strict-c-v00@openssh.com"
	KexStrictServer = "kex-strict-s-v00@openssh.com"
	// ExtInfoClient and ExtInfoServer signal support for SSH_MSG_EXT_INFO, RFC 8308 2.1.
	ExtInfoClient = "ext-info-c"
	ExtInfoServer = "ext-info-s"

	HostKeyEd25519    = "ssh-ed25519"         // RFC 8709.
	HostKeyECDSAP256  = "ecdsa-sha2-nistp256" // RFC 5656.
	HostKeyECDSAP384  = "ecdsa-sha2-nistp384" // RFC 5656.
	HostKeyRSASHA256  = "rsa-sha2-256"        // RFC 8332.
	HostKeyRSASHA512  = "rsa-sha2-512"        // RFC 8332.
	CipherAES128GCM   = "aes128-gcm@openssh.com"
	CipherAES256GCM   = "aes256-gcm@openssh.com"
	CipherChaCha20    = "chacha20-poly1305@openssh.com"
	CompressionNone   = "none"
	MACHMACSHA256     = "hmac-sha2-256"
	MACHMACSHA256ETM  = "hmac-sha2-256-etm@openssh.com"
	ServiceUserauth   = "ssh-userauth"
	ServiceConnection = "ssh-connection"
)
