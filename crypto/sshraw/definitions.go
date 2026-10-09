package sshraw

import (
	"encoding/binary"

	"github.com/soypat/lneto"
)

const (
	// RFC Section 6: Note that the length of the concatenation of 'packet_length',
	// 'padding_length', 'payload', and 'random padding' MUST be a multiple
	// of the cipher block size or 8, whichever is larger.
	MinFrameSize = ((SizeHeader + minPadding + 7) / 8) * 8
	// SizeHeader is the size of the on-the-wire frame header in bytes: packet_len(4)+padding_len(1)
	SizeHeader = 5
	// SizeCookie is the size of random cookie sent during [MsgKexInit].
	SizeCookie = 16
	// MinPadding is the least random padding a packet carries. Max of 255 is defined by uint8 data type.
	minPadding = 4
	// minPacketLen is the smallest packet_length value, RFC 4253 6: a 16 byte frame minus the packet_length field.
	minPacketLen = MinFrameSize - 4
	// MaxPayload is the largest uncompressed payload every implementation must process, RFC 4253 6.1.
	maxPayload = 32768
	// minBlockSize is the alignment of packets when no cipher, or a stream cipher, is in use.
	minBlockSize = 8
	// sizeGCMBlock is the AES block size, the alignment of aes-gcm@openssh.com packets.
	sizeGCMBlock = 16
	// maxPacket is the largest frame every implementation must process, RFC 4253 6.1.
	// It counts packet_length, padding_length, payload, padding and MAC.
	// Larger packets are rejected. OpenSSH and x/crypto/ssh accept up to 256KiB
	// but only send more than this when the peer advertises a larger channel
	// maximum packet size, so a stack using this package must not advertise one.
	maxPacket = 35000
	// maxIdentLen is longest identification string, cr/lf included.
	maxIdentLen = 255
	// maxNameLen is longest algorithm name in a name-list
	maxNameLen = 64
)

// MsgType is the first byte of every packet payload, RFC 4250 4.1.
type MsgType uint8

//go:generate stringer -type=MsgType,DisconnectReason,ChannelOpenFailureReason -linecomment -output stringers.go .

// SSH_MSG message numbers including control, authentication and data types.
const (
	_msgUndefined MsgType = 0 // undefined

	MsgDisconnect     MsgType = 1  // DISCONNECT
	MsgIgnore         MsgType = 2  // IGNORE
	MsgUnimplemented  MsgType = 3  // UNIMPLEMENTED
	MsgDebug          MsgType = 4  // DEBUG
	MsgServiceRequest MsgType = 5  // SERVICE_REQUEST
	MsgServiceAccept  MsgType = 6  // SERVICE_ACCEPT
	MsgExtInfo        MsgType = 7  // EXT_INFO
	MsgKexInit        MsgType = 20 // KEXINIT
	MsgNewKeys        MsgType = 21 // NEWKEYS
	MsgKexECDHInit    MsgType = 30 // KEX_ECDH_INIT
	MsgKexECDHReply   MsgType = 31 // KEX_ECDH_REPLY

	// User authentication messages

	MsgUserauthRequest MsgType = 50 // USERAUTH_REQUEST
	MsgUserauthFailure MsgType = 51 // USERAUTH_FAILURE
	MsgUserauthSuccess MsgType = 52 // USERAUTH_SUCCESS
	MsgUserauthBanner  MsgType = 53 // USERAUTH_BANNER
	MsgUserauthPKOK    MsgType = 60 // USERAUTH_PK_OK

	// ...

	MsgGlobalRequest           MsgType = 80  // GLOBAL_REQUEST
	MsgRequestSuccess          MsgType = 81  // REQUEST_SUCCESS
	MsgRequestFailure          MsgType = 82  // REQUEST_FAILURE
	MsgChannelOpen             MsgType = 90  // CHANNEL_OPEN
	MsgChannelOpenConfirmation MsgType = 91  // CHANNEL_OPEN_CONFIRMATION
	MsgChannelOpenFailure      MsgType = 92  // CHANNEL_OPEN_FAILURE
	MsgChannelWindowAdjust     MsgType = 93  // CHANNEL_WINDOW_ADJUST
	MsgChannelData             MsgType = 94  // CHANNEL_DATA
	MsgChannelExtendedData     MsgType = 95  // CHANNEL_EXTENDED_DATA
	MsgChannelEOF              MsgType = 96  // CHANNEL_EOF
	MsgChannelClose            MsgType = 97  // CHANNEL_CLOSE
	MsgChannelRequest          MsgType = 98  // CHANNEL_REQUEST
	MsgChannelSuccess          MsgType = 99  // CHANNEL_SUCCESS
	MsgChannelFailure          MsgType = 100 // CHANNEL_FAILURE
)

// DisconnectReason is the reason code of SSH_MSG_DISCONNECT, RFC 4250 4.2.2.
type DisconnectReason uint32

// SSH_DISCONNECT reason codes.
const (
	DisconnectHostNotAllowedToConnect     DisconnectReason = 1  // HOST_NOT_ALLOWED_TO_CONNECT
	DisconnectProtocolError               DisconnectReason = 2  // PROTOCOL_ERROR
	DisconnectKeyExchangeFailed           DisconnectReason = 3  // KEY_EXCHANGE_FAILED
	DisconnectReserved                    DisconnectReason = 4  // RESERVED
	DisconnectMACError                    DisconnectReason = 5  // MAC_ERROR
	DisconnectCompressionError            DisconnectReason = 6  // COMPRESSION_ERROR
	DisconnectServiceNotAvailable         DisconnectReason = 7  // SERVICE_NOT_AVAILABLE
	DisconnectProtocolVersionNotSupported DisconnectReason = 8  // PROTOCOL_VERSION_NOT_SUPPORTED
	DisconnectHostKeyNotVerifiable        DisconnectReason = 9  // HOST_KEY_NOT_VERIFIABLE
	DisconnectConnectionLost              DisconnectReason = 10 // CONNECTION_LOST
	DisconnectByApplication               DisconnectReason = 11 // BY_APPLICATION
	DisconnectTooManyConnections          DisconnectReason = 12 // TOO_MANY_CONNECTIONS
	DisconnectAuthCancelledByUser         DisconnectReason = 13 // AUTH_CANCELLED_BY_USER
	DisconnectNoMoreAuthMethodsAvailable  DisconnectReason = 14 // NO_MORE_AUTH_METHODS_AVAILABLE
	DisconnectIllegalUserName             DisconnectReason = 15 // ILLEGAL_USER_NAME
)

// ChannelOpenFailureReason is the reason code of SSH_MSG_CHANNEL_OPEN_FAILURE, RFC 4250 4.3.
type ChannelOpenFailureReason uint32

// Channel open failure reason codes.
const (
	OpenAdministrativelyProhibited ChannelOpenFailureReason = 1 // ADMINISTRATIVELY_PROHIBITED
	OpenConnectFailed              ChannelOpenFailureReason = 2 // CONNECT_FAILED
	OpenUnknownChannelType         ChannelOpenFailureReason = 3 // UNKNOWN_CHANNEL_TYPE
	OpenResourceShortage           ChannelOpenFailureReason = 4 // RESOURCE_SHORTAGE
)

// Frame represents the binary over-the-wire SSH frame that may be encrypted or decrypted.
// Fields are packet_length(4), followed by padding_length(1) followed by payload, padding and tag authentication, also known as Message Authentication Code(MAC).
//
// RFC 4253 6 encrypts packet_length along with the rest of the packet, as
// chacha20-poly1305@openssh.com does with a key of its own, while
// aes-gcm@openssh.com sends it in the clear, RFC 5647 7.3. So on a frame as
// received, before [HalfConn.Open], read the length with [HalfConn.LenPacket]
// and check it with [HalfConn.ValidateLength]; besides those only [Frame.RawData]
// and [Frame.LimitData] are valid. After Open, or before [HalfConn.Seal], the
// frame is plaintext and every method is valid.
type Frame struct {
	buf []byte
}

// NewFrame constructs a [Frame]. The first byte should be the start of packet_length field.
// The frame needs to be at least [MinFrameSize] bytes long.
func NewFrame(buf []byte) (Frame, error) {
	if len(buf) < MinFrameSize {
		return Frame{}, lneto.ErrTruncatedFrame
	}
	return Frame{buf: buf}, nil
}

// SetLenPacket sets packet_length. See [Frame.LenPacket].
func (pf Frame) SetLenPacket(v uint32) { binary.BigEndian.PutUint32(pf.buf[0:4], v) }

// LenPacket returns packet_length, the length of the packet excluding itself and the authentication tag (MAC).
func (pf Frame) LenPacket() uint32 { return binary.BigEndian.Uint32(pf.buf[0:4]) }

// SetLenPadding sets padding_length. See [Frame.LenPadding].
func (pf Frame) SetLenPadding(v uint8) { pf.buf[4] = v }

// LenPadding returns padding_length. Valid values range from 4 to 255.
func (pf Frame) LenPadding() uint8 { return pf.buf[4] }

// Payload returns the payload using [Frame.PaddingOffset] for length calculation.
func (pf Frame) Payload() []byte {
	return pf.buf[SizeHeader:pf.PaddingOffset()]
}

// PaddingOffset returns the offset at which padding begins.
func (pf Frame) PaddingOffset() uint32 { return 4 + pf.LenPacket() - uint32(pf.LenPadding()) }

// SetMsgType sets the message type. See [MsgType].
func (pf Frame) SetMsgType(mt MsgType) { pf.buf[SizeHeader] = uint8(mt) }

// MsgType returns the message type, the first byte of the payload.
func (pf Frame) MsgType() MsgType { return MsgType(pf.buf[SizeHeader]) }

// Padding returns the random padding.
func (pf Frame) Padding() []byte {
	off := pf.PaddingOffset()
	return pf.buf[off : off+uint32(pf.LenPadding())]
}

// RawData returns the buffer with which the [Frame] was created.
func (pf Frame) RawData() []byte { return pf.buf }

// LimitData reslices underlying buffer with new length wirelen.
func (pf *Frame) LimitData(wirelen int) {
	pf.buf = pf.buf[:wirelen]
}

// WireLength returns the length of the frame on the wire: packet_length field, packet and tag.
// tagSizeOrOverhead is zero before keys are installed.
func (pf Frame) WireLength(tagSizeOrOverhead uint32) int {
	return int(4 + pf.LenPacket() + tagSizeOrOverhead)
}

// Validation.

// ValidateLength checks the plaintext packet_length against the limits of RFC 4253 6.1 and
// cipher alignment, and that the buffer holds [Frame.WireLength] bytes. On a frame as received,
// before [HalfConn.Open], use [HalfConn.ValidateLength]: packet_length may be encrypted.
// overhead is the tag size, zero before keys are installed, in which case packet_length
// is included in alignment. Alignment is to the larger of blockSize and 8.
func (pf Frame) ValidateLength(vld *lneto.Validator, overhead, blockSize uint32) {
	validateLength(vld, pf.LenPacket(), overhead, blockSize, len(pf.buf))
}

// validateLength checks packet_length plen of a frame of buflen bytes. Every keyed mode
// supported excludes packet_length from alignment: aes-gcm@openssh.com sends it as additional
// data, chacha20-poly1305@openssh.com encrypts it with a key of its own. The encrypt-and-MAC
// ciphers of RFC 4253 6, which align it, are not supported.
func validateLength(vld *lneto.Validator, plen, overhead, blockSize uint32, buflen int) {
	aligned, minLen := plen+4, uint32(minPacketLen)
	if overhead != 0 {
		// RFC 4253 6's 16 byte minimum packet is not honored by peers when packet_length is
		// excluded from alignment: OpenSSH and x/crypto/ssh send 12 byte chacha20-poly1305
		// packets for 1 byte payloads. Require room for padding_length, message type and
		// padding; alignment does the rest.
		aligned, minLen = plen, 1+1+minPadding
	}
	if plen < minLen || plen > maxPacket-4-overhead ||
		aligned%max(blockSize, minBlockSize) != 0 {
		vld.AddError(lneto.ErrInvalidLengthField)
	} else if int(4+plen+overhead) > buflen {
		vld.AddError(lneto.ErrTruncatedFrame)
	}
}

// ValidateSize checks packet_length as [Frame.ValidateLength] does and padding_length so that
// [Frame.Payload] and [Frame.Padding] do not panic. padding_length is encrypted on the wire,
// so call ValidateSize on plaintext frames only: before [HalfConn.Seal] and after [HalfConn.Open].
func (pf Frame) ValidateSize(vld *lneto.Validator, overhead, blockSize uint32) {
	pf.ValidateLength(vld, overhead, blockSize)
	padding := uint32(pf.LenPadding())
	if padding < minPadding || padding+2 > pf.LenPacket() { // Message type present and not part of padding.
		vld.AddError(lneto.ErrInvalidLengthField)
	}
}
