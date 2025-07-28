package icmpv4

import (
	"encoding/binary"
	"errors"

	"github.com/soypat/lneto"
)

type Type uint8

const (
	TypeEchoReply Type = 0 // echo reply
	TypeEcho      Type = 8 // echo

	TypeDestinationUnreachable Type = 3 // destination unreachable
	TypeSourceQuench           Type = 4 // source quench
	TypeRedirect               Type = 5 // redirect

	TypeTimeExceeded     Type = 11 // time exceeded
	TypeParameterProblem Type = 12 // parameter problem

	TypeTimestamp      Type = 13 // timestamp
	TypeTimestampReply Type = 14 // timestamp reply

	TypeInfoRequest      Type = 15 // information request
	TypeInfoRequestReply Type = 16 // information request reply
)

type CodeTimeExceeded uint8

const (
	CodeExceededInTransit  CodeTimeExceeded = iota // TTL exceeded in transit
	CodeFragmentReassembly                         // fragment reassembly time exceeded
)

type CodeDestinationUnreachable uint8

const (
	CodeNetUnreachable     CodeDestinationUnreachable = iota // net unreachable
	CodeHostUnreachable                                      // host unreachable
	CodeProtoUnreachable                                     // protocol unreachable
	CodePortUnreachable                                      // port unreachable
	CodeFragNeededAndDFSet                                   // fragmentation needed and DF set
	CodeSourceRouteFailed                                    // source route failed
)

type CodeRedirect uint8

const (
	CodeRedirectForNetwork       CodeRedirect = iota // redirect for network
	CodeRedirectForHost                              // redirect for host
	CodeRedirectForToSAndNetwork                     // redirect for ToS+network
	CodeRedirectToSAndHost                           // redirect for ToS+host
)

var (
	errShortFrame = errors.New("icmpv4: short frame")
)

func NewFrame(buf []byte) (Frame, error) {
	if len(buf) < 8 {
		return Frame{}, errShortFrame
	}
	return Frame{buf: buf}, nil
}

type Frame struct {
	buf []byte
}

func (frm Frame) Type() Type { return Type(frm.buf[0]) }

func (frm Frame) SetType(t Type) { frm.buf[0] = uint8(t) }

func (frm Frame) Code() uint8 { return frm.buf[1] }

func (frm Frame) SetCode(code uint8) { frm.buf[1] = code }

// CRC returns the checksum field of the frame.
func (frm Frame) CRC() uint16 {
	return binary.BigEndian.Uint16(frm.buf[2:4])
}

// SetCRC sets the checksum field of the frame.
func (frm Frame) SetCRC(crc uint16) {
	binary.BigEndian.PutUint16(frm.buf[2:4], crc)
}

// CRCWrite calculates the checksum of the ICMP packet. Treats the checksum field as zero as per RFC 792.
func (frm Frame) CRCWrite(crc *lneto.CRC791) {
	crc.AddUint16(binary.BigEndian.Uint16(frm.buf[0:2]))
	crc.Write(frm.buf[4:])
}

func (frm Frame) payload() []byte {
	return frm.buf[4:]
}

type FrameDestinationUnreachable struct {
	Frame
}

func (frm FrameDestinationUnreachable) Code() CodeDestinationUnreachable {
	return CodeDestinationUnreachable(frm.Frame.Code())
}

func (frm FrameDestinationUnreachable) SetCode(code CodeDestinationUnreachable) {
	frm.Frame.SetCode(uint8(code))
}

type FrameEcho struct {
	Frame
}

func (frm FrameEcho) Identifier() uint16 {
	return binary.BigEndian.Uint16(frm.buf[4:6])
}

func (frm FrameEcho) SetIdentifier(id uint16) {
	binary.BigEndian.PutUint16(frm.buf[4:6], id)
}

func (frm FrameEcho) SequenceNumber() uint16 {
	return binary.BigEndian.Uint16(frm.buf[6:8])
}

func (frm FrameEcho) SetSequenceNumber(seq uint16) {
	binary.BigEndian.PutUint16(frm.buf[6:8], seq)
}

func (frm FrameEcho) Data() []byte {
	return frm.buf[8:]
}

func (frm FrameEcho) RawData() []byte {
	return frm.buf
}
