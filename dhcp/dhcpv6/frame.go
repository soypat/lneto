package dhcpv6

import (
	"encoding/binary"
	"io"

	"github.com/soypat/lneto"
)

// NewFrame returns a Frame backed by buf.
// Returns an error if buf is shorter than [OptionsOffset] bytes.
func NewFrame(buf []byte) (Frame, error) {
	if len(buf) < OptionsOffset {
		return Frame{}, lneto.ErrTruncatedFrame
	}
	return Frame{buf: buf}, nil
}

// Frame encapsulates the raw bytes of a DHCPv6 client-server message (RFC 8415 §8)
// and provides methods for accessing and modifying its fields.
//
// Layout:
//
//	Byte 0:    msg-type
//	Bytes 1-3: transaction-id (24-bit big-endian)
//	Bytes 4+:  options (code(2) + length(2) + data)
type Frame struct {
	buf []byte
}

// MsgType returns the message type field.
func (frm Frame) MsgType() MsgType { return MsgType(frm.buf[0]) }

// SetMsgType sets the message type field.
func (frm Frame) SetMsgType(t MsgType) { frm.buf[0] = byte(t) }

// TransactionID returns the 24-bit transaction ID as a uint32 (upper byte is always zero).
func (frm Frame) TransactionID() uint32 {
	return uint32(frm.buf[1])<<16 | uint32(frm.buf[2])<<8 | uint32(frm.buf[3])
}

// SetTransactionID writes the lower 24 bits of id into bytes 1–3.
func (frm Frame) SetTransactionID(id uint32) {
	frm.buf[1] = byte(id >> 16)
	frm.buf[2] = byte(id >> 8)
	frm.buf[3] = byte(id)
}

// Options returns the options section of the frame (bytes from [OptionsOffset] onward).
func (frm Frame) Options() []byte { return frm.buf[OptionsOffset:] }

// ForEachOption iterates over all DHCPv6 options in the frame's options section.
// Each option is passed to fn as (byteOffset, optionCode, optionData).
// Iteration stops early if fn returns [io.EOF]; any other non-nil error is returned directly.
// If fn is nil, the function only validates the structure.
func (frm Frame) ForEachOption(fn func(off int, code OptCode, data []byte) error) error {
	buf := frm.buf
	ptr := OptionsOffset
	for ptr+4 <= len(buf) {
		code := OptCode(binary.BigEndian.Uint16(buf[ptr:]))
		optlen := int(binary.BigEndian.Uint16(buf[ptr+2:]))
		if ptr+4+optlen > len(buf) {
			return lneto.ErrInvalidLengthField
		}
		if fn != nil {
			err := fn(ptr, code, buf[ptr+4:ptr+4+optlen])
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
		}
		ptr += 4 + optlen
	}
	if ptr != len(buf) {
		// 1–3 trailing bytes that cannot form a valid option header.
		return lneto.ErrTruncatedFrame
	}
	return nil
}

// ValidateSize validates the structure of the options section without invoking a callback.
func (frm Frame) ValidateSize() error { return frm.ForEachOption(nil) }
