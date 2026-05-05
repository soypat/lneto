package icmpv6

import (
	"encoding/binary"

	"github.com/soypat/lneto"
)

//go:generate stringer -type=Type,CodeDestinationUnreachable,CodeParameterProblem -linecomment -output stringers.go

const (
	sizeHeader    = 8
	sizeNDPBase   = sizeHeader + 16 // 24: ICMPv6 header + 16-byte target address
	sizeNDPOption = 8               // 1 type + 1 len + 6 MAC (Ethernet link-layer option, RFC 4861 §4.6.1)
	sizeNDP       = sizeNDPBase + sizeNDPOption
)

type Type uint8

const (
	TypeDestinationUnreachable Type = 1 // destination unreachable
	TypePacketTooBig           Type = 2 // packet too big
	TypeTimeExceeded           Type = 3 // time exceeded
	TypeParameterProblem       Type = 4 // parameter problem

	TypeEchoRequest Type = 128 // echo request
	TypeEchoReply   Type = 129 // echo reply

	TypeRouterSolicitation    Type = 133 // router solicitation
	TypeRouterAdvertisement   Type = 134 // router advertisement
	TypeNeighborSolicitation  Type = 135 // neighbor solicitation
	TypeNeighborAdvertisement Type = 136 // neighbor advertisement
	TypeRedirectMessage       Type = 137 // redirect message
)

type CodeTimeExceeded uint8

const (
	CodeHopLimitExceeded   CodeTimeExceeded = iota // hop limit exceeded in transit
	CodeFragmentReassembly                         // fragment reassembly time exceeded
)

type CodeDestinationUnreachable uint8

const (
	CodeNoRoute             CodeDestinationUnreachable = iota // no route to destination
	CodeAdminProhibited                                       // communication administratively prohibited
	CodeBeyondScope                                           // beyond scope of source address
	CodeAddressUnreachable                                    // address unreachable
	CodePortUnreachable                                       // port unreachable
	CodeIngressEgressPolicy                                   // source address failed ingress/egress policy
	CodeRejectRoute                                           // reject route to destination
)

type CodeParameterProblem uint8

const (
	CodeErroneousHeaderField   CodeParameterProblem = iota // erroneous header field encountered
	CodeUnrecognizedNextHeader                             // unrecognized next header type encountered
	CodeUnrecognizedIPv6Option                             // unrecognized IPv6 option encountered
)

func NewFrame(buf []byte) (Frame, error) {
	if len(buf) < sizeHeader {
		return Frame{}, lneto.ErrTruncatedFrame
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

type FramePacketTooBig struct {
	Frame
}

func (frm FramePacketTooBig) MTU() uint32 {
	return binary.BigEndian.Uint32(frm.buf[4:8])
}

func (frm FramePacketTooBig) SetMTU(mtu uint32) {
	binary.BigEndian.PutUint32(frm.buf[4:8], mtu)
}

type FrameParameterProblem struct {
	Frame
}

func (frm FrameParameterProblem) Code() CodeParameterProblem {
	return CodeParameterProblem(frm.Frame.Code())
}

func (frm FrameParameterProblem) SetCode(code CodeParameterProblem) {
	frm.Frame.SetCode(uint8(code))
}

// Pointer identifies the octet offset within the invoking packet where the error was detected.
func (frm FrameParameterProblem) Pointer() uint32 {
	return binary.BigEndian.Uint32(frm.buf[4:8])
}

func (frm FrameParameterProblem) SetPointer(ptr uint32) {
	binary.BigEndian.PutUint32(frm.buf[4:8], ptr)
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

// FrameNeighborSolicitation accesses a Neighbor Solicitation message (RFC 4861 §4.3).
// Layout after ICMPv6 base header: Reserved(4B) | TargetAddr(16B) | Options.
type FrameNeighborSolicitation struct {
	Frame
}

// TargetAddr returns the IPv6 address being queried.
func (frm FrameNeighborSolicitation) TargetAddr() *[16]byte {
	return (*[16]byte)(frm.buf[8:24])
}

// Options returns the bytes following the fixed header for parsing NDP options.
func (frm FrameNeighborSolicitation) Options() []byte {
	return frm.buf[24:]
}

// FrameNeighborAdvertisement accesses a Neighbor Advertisement message (RFC 4861 §4.4).
// Layout after ICMPv6 base header: R|S|O|Reserved(4B) | TargetAddr(16B) | Options.
type FrameNeighborAdvertisement struct {
	Frame
}

// Flags returns the R (router), S (solicited), O (override) flag bits.
func (frm FrameNeighborAdvertisement) Flags() (router, solicited, override bool) {
	b := frm.buf[4]
	return b&0x80 != 0, b&0x40 != 0, b&0x20 != 0
}

// SetFlags sets the R, S, O flags and zeroes the reserved bits.
func (frm FrameNeighborAdvertisement) SetFlags(router, solicited, override bool) {
	var b byte
	if router {
		b |= 0x80
	}
	if solicited {
		b |= 0x40
	}
	if override {
		b |= 0x20
	}
	frm.buf[4] = b
	frm.buf[5] = 0
	frm.buf[6] = 0
	frm.buf[7] = 0
}

// TargetAddr returns the IPv6 address being announced.
func (frm FrameNeighborAdvertisement) TargetAddr() *[16]byte {
	return (*[16]byte)(frm.buf[8:24])
}

// Options returns the bytes following the fixed header for parsing NDP options.
func (frm FrameNeighborAdvertisement) Options() []byte {
	return frm.buf[24:]
}
