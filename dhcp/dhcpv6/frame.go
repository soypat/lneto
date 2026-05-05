package dhcpv6

import "github.com/soypat/lneto"

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
func (frm Frame) MsgType() MsgType {
	panic("not implemented")
}

// SetMsgType sets the message type field.
func (frm Frame) SetMsgType(t MsgType) {
	panic("not implemented")
}

// TransactionID returns the 24-bit transaction ID as a uint32 (upper byte is always zero).
func (frm Frame) TransactionID() uint32 {
	panic("not implemented")
}

// SetTransactionID writes the lower 24 bits of id into bytes 1–3.
func (frm Frame) SetTransactionID(id uint32) {
	panic("not implemented")
}

// Options returns the options section of the frame (bytes from [OptionsOffset] onward).
func (frm Frame) Options() []byte {
	panic("not implemented")
}

// ForEachOption iterates over all DHCPv6 options in the frame's options section.
// Each option is passed to fn as (byteOffset, optionCode, optionData).
// Iteration stops early if fn returns [io.EOF]; any other error is returned directly.
// If fn is nil the function only validates the structure.
func (frm Frame) ForEachOption(fn func(off int, code OptCode, data []byte) error) error {
	panic("not implemented")
}

// ValidateSize validates the structure of the options section without invoking a callback.
func (frm Frame) ValidateSize() error {
	panic("not implemented")
}
