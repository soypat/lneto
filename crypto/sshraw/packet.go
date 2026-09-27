package sshraw

import (
	"encoding/binary"

	"github.com/soypat/lneto"
)

// PacketFrame is an unprotected binary packet, RFC 4253 6:
//
//	uint32    packet_length
//	byte      padding_length
//	byte[n1]  payload; n1 = packet_length - padding_length - 1
//	byte[n2]  random padding; n2 = padding_length
//
// It is what goes on the wire before the first SSH_MSG_NEWKEYS, and what
// remains once a protected packet is decrypted. The MAC, if any, is not part of it.
type PacketFrame struct {
	buf []byte
}

// NewPacketFrame returns the packet at the start of buf. Bytes after it, the
// MAC or the next packet, are not part of the frame; see [PacketFrame.RawData].
// It checks lengths are consistent but not alignment, which depends on the
// cipher: see [PacketFrame.ValidateAlignment].
func NewPacketFrame(buf []byte) (PacketFrame, error) {
	if len(buf) < SizeHeaderPacket {
		return PacketFrame{}, lneto.ErrTruncatedFrame
	}
	plen := binary.BigEndian.Uint32(buf)
	if plen > MaxPacket-4 {
		return PacketFrame{}, lneto.ErrInvalidLengthField
	} else if int(plen) > len(buf)-4 {
		return PacketFrame{}, lneto.ErrTruncatedFrame
	}
	padLen := int(buf[4])
	if padLen < MinPadding {
		return PacketFrame{}, lneto.ErrInvalidLengthField
	} else if padLen > int(plen)-2 {
		// Every payload carries at least the message type byte.
		return PacketFrame{}, lneto.ErrInvalidLengthField
	}
	return PacketFrame{buf: buf[:4+plen]}, nil
}

// PacketLength returns packet_length, the length of the packet excluding itself and the MAC.
func (pf PacketFrame) PacketLength() uint32 { return binary.BigEndian.Uint32(pf.buf) }

// PaddingLength returns padding_length.
func (pf PacketFrame) PaddingLength() uint8 { return pf.buf[4] }

// Payload returns the payload, message type byte first.
func (pf PacketFrame) Payload() []byte {
	return pf.buf[SizeHeaderPacket : len(pf.buf)-int(pf.PaddingLength())]
}

// MsgType returns the message type, the first byte of the payload.
func (pf PacketFrame) MsgType() MsgType { return MsgType(pf.buf[SizeHeaderPacket]) }

// Padding returns the random padding.
func (pf PacketFrame) Padding() []byte { return pf.buf[len(pf.buf)-int(pf.PaddingLength()):] }

// RawData returns the whole packet, header included. Its length is the
// distance to the MAC or, when there is none, to the next packet.
func (pf PacketFrame) RawData() []byte { return pf.buf }

// ValidateAlignment checks the packet is a multiple of the cipher block size,
// RFC 4253 6. blockSize values below [MinBlockSize] mean [MinBlockSize].
// aad is true when packet_length is not encrypted and thus excluded from the
// alignment: the AEAD ciphers and -etm MACs. Implementations must reject misaligned packets.
func (pf PacketFrame) ValidateAlignment(blockSize int, aad bool) error {
	n := len(pf.buf)
	if aad {
		n -= 4
	}
	if n%max(blockSize, MinBlockSize) != 0 {
		return lneto.ErrInvalidLengthField
	}
	return nil
}
