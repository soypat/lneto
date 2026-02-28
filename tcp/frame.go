package tcp

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/soypat/lneto"
)

const (
	sizeHeaderTCP = 20
)

// NewFrame returns a new TCPFrame with data set to buf.
// An error is returned if the buffer size is smaller than 20.
// Users should still call [Frame.ValidateSize] before working
// with payload/options of frames to avoid panics.
func NewFrame(buf []byte) (Frame, error) {
	if len(buf) < sizeHeaderTCP {
		return Frame{buf: nil}, lneto.ErrShortBuffer
	}
	return Frame{buf: buf}, nil
}

// Frame encapsulates the raw data of a TCP segment
// and provides methods for manipulating, validating and
// retrieving fields and payload data. See [RFC9293].
//
// [RFC9293]: https://datatracker.ietf.org/doc/html/rfc9293
type Frame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (tfrm Frame) RawData() []byte { return tfrm.buf }

// SourcePort identifies the sending port of the TCP packet. Must be non-zero.
func (tfrm Frame) SourcePort() uint16 {
	return binary.BigEndian.Uint16(tfrm.buf[0:2])
}

// SetSourcePort sets TCP source port. See [Frame.SetSourcePort]
func (tfrm Frame) SetSourcePort(src uint16) {
	binary.BigEndian.PutUint16(tfrm.buf[0:2], src)
}

// DestinationPort identifies the receiving port for the TCP packet. Must be non-zero.
func (tfrm Frame) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(tfrm.buf[2:4])
}

// SetDestinationPort sets TCP destination port. See [Frame.DestinationPort]
func (tfrm Frame) SetDestinationPort(dst uint16) {
	binary.BigEndian.PutUint16(tfrm.buf[2:4], dst)
}

// Seq returns sequence number of the first data octet in this segment (except when SYN present)
// If SYN present this is the Initial Sequence Number (ISN) and the first data octet would be ISN+1.
func (tfrm Frame) Seq() Value {
	return Value(binary.BigEndian.Uint32(tfrm.buf[4:8]))
}

// SetSeq sets Seq field. See [Frame.Seq].
func (tfrm Frame) SetSeq(v Value) {
	binary.BigEndian.PutUint32(tfrm.buf[4:8], uint32(v))
}

// Ack is the next sequence number (Seq field) the sender is expecting to receive (when ACK is present).
// In other words an Ack of X indicates all octets up to but not including X have been received.
// Once a connection is established the ACK flag should always be set.
func (tfrm Frame) Ack() Value {
	return Value(binary.BigEndian.Uint32(tfrm.buf[8:12]))
}

// SetAck sets Ack field. See [Frame.Ack].
func (tfrm Frame) SetAck(v Value) {
	binary.BigEndian.PutUint32(tfrm.buf[8:12], uint32(v))
}

// OffsetAndFlags returns the offset and flag fields of TCP header.
// Offset is amount of 32-bit words used for TCP header including TCP options (see [Frame.HeaderLength]).
// See [Flags] for more information on TCP flags.
func (tfrm Frame) OffsetAndFlags() (offset uint8, flags Flags) {
	v := binary.BigEndian.Uint16(tfrm.buf[12:14])
	offset = uint8(v >> 12)
	flags = Flags(v).Mask()
	return offset, flags
}

// SetOffsetAndFlags returns offset and flag fields of TCP header. See [Frame.OffsetAndFlags].
func (tfrm Frame) SetOffsetAndFlags(offset uint8, flags Flags) {
	v := uint16(offset)<<12 | uint16(flags.Mask())
	binary.BigEndian.PutUint16(tfrm.buf[12:14], v)
}

// HeaderLength uses Offset field to calculate the total length of
// the TCP header including options. Performs no validation.
func (tfrm Frame) HeaderLength() (lengthInBytes int) {
	offset, _ := tfrm.OffsetAndFlags()
	return 4 * int(offset)
}

func (tfrm Frame) WindowSize() uint16 { return binary.BigEndian.Uint16(tfrm.buf[14:16]) }
func (tfrm Frame) SetWindowSize(v uint16) {
	binary.BigEndian.PutUint16(tfrm.buf[14:16], v)
}

// CRC returns the checksum field in the TCP header.
func (tfrm Frame) CRC() uint16 {
	return binary.BigEndian.Uint16(tfrm.buf[16:18])
}

// SetCRC sets the checksum field of the TCP header. See [Frame.CRC].
func (tfrm Frame) SetCRC(checksum uint16) {
	binary.BigEndian.PutUint16(tfrm.buf[16:18], checksum)
}

func (tfrm Frame) UrgentPtr() uint16      { return binary.BigEndian.Uint16(tfrm.buf[18:20]) }
func (tfrm Frame) SetUrgentPtr(up uint16) { binary.BigEndian.PutUint16(tfrm.buf[18:20], up) }

// Payload returns the payload content section of the TCP packet (not including TCP options).
// Be sure to call [Frame.ValidateSize] beforehand to avoid panic.
func (tfrm Frame) Payload() []byte {
	return tfrm.buf[tfrm.HeaderLength():]
}

// Segment returns the [Segment] representation of the TCP header and data length.
func (tfrm Frame) Segment(payloadSize int) Segment {
	if payloadSize > math.MaxInt32 {
		panic("TCP overflow payload size")
	}
	return Segment{
		SEQ:     tfrm.Seq(),
		ACK:     tfrm.Ack(),
		WND:     Size(tfrm.WindowSize()),
		DATALEN: Size(payloadSize),
		Flags:   Flags(binary.BigEndian.Uint16(tfrm.buf[12:14])).Mask(),
	}
}

// SetSegment sets the sequence, acknowledgment, offset, window and flag fields of the TCP header from the the [Segment].
// Offset, like in [Frame.SetOffset], is expressed in words with minimum being 5.
func (tfrm Frame) SetSegment(seg Segment, offset uint8) {
	if offset >= 1<<4 {
		panic("tcp offset too large")
	} else if seg.WND > math.MaxUint16 {
		panic("tcp window overflow")
	}
	tfrm.SetSeq(seg.SEQ)
	tfrm.SetAck(seg.ACK)
	tfrm.SetOffsetAndFlags(offset, seg.Flags)
	tfrm.SetWindowSize(uint16(seg.WND))
}

// Options returns the TCP option buffer portion of the frame. The returned slice may be zero length.
// Be sure to call [Frame.ValidateSize] beforehand to avoid panic.
func (tfrm Frame) Options() []byte {
	return tfrm.buf[sizeHeaderTCP:tfrm.HeaderLength()]
}

// ClearHeader zeros out the fixed(non-variable) header contents.
func (frm Frame) ClearHeader() {
	for i := range frm.buf[:sizeHeaderTCP] {
		frm.buf[i] = 0
	}
}

func (tfrm Frame) String() string {
	src := tfrm.SourcePort()
	dst := tfrm.DestinationPort()
	seg := tfrm.Segment(len(tfrm.Payload()))
	return fmt.Sprintf("TCP :%d -> :%d %s", src, dst, seg.String())
}

//
// Validation API
//


// func (tfrm Frame) Validate(v *lneto.Validator) {
// tfrm.ValidateSize(v)
// tfrm.ValidateExceptCRC(v)
// }

// ValidateSize checks the frame's size fields and compares with the actual buffer
// the frame. It returns a non-nil error on finding an inconsistency.
func (tfrm Frame) ValidateSize(v *lneto.Validator) {
	off := tfrm.HeaderLength()
	if off < sizeHeaderTCP {
		v.AddBitPosErr(12*8, 4, lneto.ErrInvalidLengthField)
	}
	if off > len(tfrm.RawData()) {
		v.AddBitPosErr(12*8, 4, lneto.ErrInvalidLengthField)
	}
}

func (tfrm Frame) ValidateExceptCRC(v *lneto.Validator) {
	tfrm.ValidateSize(v)
	if tfrm.DestinationPort() == 0 {
		v.AddBitPosErr(2*8, 16, lneto.ErrZeroDestination)
	}
	if tfrm.SourcePort() == 0 {
		v.AddBitPosErr(0, 16, lneto.ErrZeroSource)
	}
}
