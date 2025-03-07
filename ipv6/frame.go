package ipv6

import (
	"encoding/binary"
	"errors"

	"github.com/soypat/lneto"
)

// NewIPv6Frame returns a new IPv6Frame with data set to buf.
// An error is returned if the buffer size is smaller than 40.
// Users should still call [IPv6Frame.ValidateSize] before working
// with payload/options of frames to avoid panics.
func NewFrame(buf []byte) (Frame, error) {
	if len(buf) < sizeHeader {
		return Frame{buf: nil}, errShortBuf
	}
	return Frame{buf: buf}, nil
}

// Frame encapsulates the raw data of an IPv6 packet
// and provides methods for manipulating, validating and
// retrieving fields and payload data. See [RFC8200].
//
// [RFC8200]: https://tools.ietf.org/html/rfc8200
type Frame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (i6frm Frame) RawData() []byte { return i6frm.buf }

// Payload returns the contents of the IPv6 packet, which may be zero sized.
// Be sure to call [Frame.ValidateSize] beforehand to avoid panic.
func (i6frm Frame) Payload() []byte {
	pl := i6frm.PayloadLength()
	return i6frm.buf[sizeHeader : sizeHeader+pl]
}

// VersionTrafficAndFlow returns the version, Traffic and Flow label fields of the IPv6 header.
// See [ToS] Traffic Class. Version should be 6 for IPv6.
func (i6frm Frame) VersionTrafficAndFlow() (version uint8, tos ToS, flow uint32) {
	v := binary.BigEndian.Uint32(i6frm.buf[0:4])
	version = uint8(v >> (32 - 4))
	tos = ToS(v >> (32 - 12))
	flow = v & 0x000f_ffff
	return version, tos, flow
}

// SetVersionTrafficAndFlow sets the version, ToS and Flow label in the IPv6 header. Version must be equal to 6.
// See [Frame.VersionTrafficAndFlow].
func (i6frm Frame) SetVersionTrafficAndFlow(version uint8, tos ToS, flow uint32) {
	v := flow | uint32(tos)<<(32-12) | uint32(version)<<(32-4)
	binary.BigEndian.PutUint32(i6frm.buf[0:4], v)
}

// PayloadLength returns the size of payload in octets(bytes) including any extension headers.
// The length is set to zero when a Hop-by-Hop extension header carries a Jumbo Payload option.
func (i6frm Frame) PayloadLength() uint16 {
	return binary.BigEndian.Uint16(i6frm.buf[4:6])
}

// SetPayloadLength sets the payload length field of the IPv6 header. See [Frame.PayloadLength].
func (i6frm Frame) SetPayloadLength(pl uint16) {
	binary.BigEndian.PutUint16(i6frm.buf[4:6], pl)
}

// NextHeader returns the Next Header field of the IPv6 header which usually specifies the transport layer
// protocol used by packet's payload.
func (i6frm Frame) NextHeader() lneto.IPProto {
	return lneto.IPProto(i6frm.buf[6])
}

// SetNextHeader sets the Next Header (protocol) field of the IPv6 header. See [Frame.NextHeader].
func (i6frm Frame) SetNextHeader(proto lneto.IPProto) {
	i6frm.buf[6] = uint8(proto)
}

// HopLimit returns the Hop Limit of the IPv6 header.
// This value is decremented by one at each forwarding node and the packet is discarded if it becomes 0.
// However, the destination node should process the packet normally even if received with a hop limit of 0.
func (i6frm Frame) HopLimit() uint8 {
	return i6frm.buf[7]
}

// SetHopLimit sets the Hop Limit field of the IPv6 header. See [Frame.HopLimiy].
func (i6frm Frame) SetHopLimit(hop uint8) {
	i6frm.buf[7] = hop
}

// SourceAddr returns pointer to the sending node unicast IPv6 address in the IP header.
func (i6frm Frame) SourceAddr() *[16]byte {
	return (*[16]byte)(i6frm.buf[8:24])
}

// DestinationAddr returns pointer to the destination node unicast or multicast IPv6 address in the IP header.
func (i6frm Frame) DestinationAddr() *[16]byte {
	return (*[16]byte)(i6frm.buf[24:40])
}

func (i6frm Frame) CRCWritePseudo(crc *lneto.CRC791) {
	crc.Write(i6frm.SourceAddr()[:])
	crc.Write(i6frm.DestinationAddr()[:])
	crc.AddUint32(uint32(i6frm.PayloadLength()))
	crc.AddUint32(uint32(i6frm.NextHeader()))
}

// ClearHeader zeros out the header contents.
func (i6frm Frame) ClearHeader() {
	for i := range i6frm.buf[:sizeHeader] {
		i6frm.buf[i] = 0
	}
}

//
// Validate API.
//

var (
	errShortFrame = errors.New("ipv6: short frame")
	errShortBuf   = errors.New("ipv6: short buffer for frame")
)

// ValidateSize checks the frame's size fields and compares with the actual buffer
// the frame. It returns a non-nil error on finding an inconsistency.
func (i6frm Frame) ValidateSize(v *lneto.Validator) {
	tl := i6frm.PayloadLength()
	if int(tl)+sizeHeader > len(i6frm.RawData()) {
		v.AddError(errShortFrame)
	}
}
