package udp

import (
	"encoding/binary"
	"errors"

	"github.com/soypat/lneto"
)

// NewUDPFrame returns a new UDPFrame with data set to buf.
// An error is returned if the buffer size is smaller than 8.
// Users should still call [Frame.ValidateSize] before working
// with payload/options of frames to avoid panics.
func NewFrame(buf []byte) (Frame, error) {
	if len(buf) < sizeHeader {
		return Frame{buf: buf}, errors.New("UDP packet too short")
	}
	return Frame{buf: buf}, nil
}

// Frame encapsulates the raw data of a UDP datagram
// and provides methods for manipulating, validating and
// retrieving fields and payload data. See [RFC768].
//
// [RFC768]: https://tools.ietf.org/html/rfc768
type Frame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (ufrm Frame) RawData() []byte { return ufrm.buf }

// SourcePort identifies the sending port for the UDP packet. Must be non-zero.
func (ufrm Frame) SourcePort() uint16 {
	return binary.BigEndian.Uint16(ufrm.buf[0:2])
}

// SetSourcePort sets UDP source port. See [Frame.SourcePort]
func (ufrm Frame) SetSourcePort(src uint16) {
	binary.BigEndian.PutUint16(ufrm.buf[0:2], src)
}

// DestinationPort identifies the receiving port for the UDP packet. Must be non-zero.
func (ufrm Frame) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(ufrm.buf[2:4])
}

// SetDestinationPort sets UDP destination port. See [Frame.DestinationPort]
func (ufrm Frame) SetDestinationPort(dst uint16) {
	binary.BigEndian.PutUint16(ufrm.buf[2:4], dst)
}

// Length specifies length in bytes of UDP header and UDP payload. The minimum length
// is 8 bytes (UDP header length). This field should match the result of the IP header
// TotalLength field minus the IP header size: udp.Length == ip.TotalLength - 4*ip.IHL
func (ufrm Frame) Length() uint16 {
	return binary.BigEndian.Uint16(ufrm.buf[4:6])
}

// SetLength sets the UDP header's length field. See [Frame.Length].
func (ufrm Frame) SetLength(length uint16) {
	binary.BigEndian.PutUint16(ufrm.buf[4:6], length)
}

// CRC returns the checksum field in the UDP header.
func (ufrm Frame) CRC() uint16 {
	return binary.BigEndian.Uint16(ufrm.buf[6:8])
}

// SetCRC sets the UDP header's CRC field. See [Frame.CRC].
func (ufrm Frame) SetCRC(checksum uint16) {
	binary.BigEndian.PutUint16(ufrm.buf[6:8], checksum)
}

// Payload returns the payload content section of the UDP packet.
// Be sure to call [Frame.ValidateSize] beforehand to avoid panic.
func (ufrm Frame) Payload() []byte {
	l := ufrm.Length()
	return ufrm.buf[sizeHeader:l]
}

// func (ufrm Frame) CalculateIPv4Checksum(ifrm IPv4Frame) uint16 {
// 	var crc lneto.CRC791
// 	ifrm.crcWriteUDPPseudo(&crc)
// 	crc.AddUint16(ufrm.Length())
// 	crc.AddUint16(ufrm.SourcePort())
// 	crc.AddUint16(ufrm.DestinationPort())
// 	crc.AddUint16(ufrm.Length()) // Length double tap.
// 	crc.Write(ufrm.Payload())
// 	return crc.Sum16()
// }

// func (ufrm Frame) CalculateIPv6Checksum(ifrm IPv6Frame) uint16 {
// 	var crc lneto.CRC791
// 	ifrm.crcWritePseudo(&crc)
// 	crc.AddUint16(ufrm.SourcePort())
// 	crc.AddUint16(ufrm.DestinationPort())
// 	crc.AddUint16(ufrm.Length()) // Length double tap.
// 	crc.Write(ufrm.Payload())
// 	return crc.Sum16()
// }

// ClearHeader zeros out the header contents.
func (frm Frame) ClearHeader() {
	for i := range frm.buf[:sizeHeader] {
		frm.buf[i] = 0
	}
}

//
// Validation API.
//

var (
	errBadLen = errors.New("udp: bad UDP length")
	errShort  = errors.New("udp: short buffer")
)

// ValidateSize checks the frame's size fields and compares with the actual buffer
// the frame. It returns a non-nil error on finding an inconsistency.
func (ufrm Frame) ValidateSize(v *lneto.Validator) {
	ul := ufrm.Length()
	if ul < sizeHeader {
		v.AddError(errBadLen)
	}
	if int(ul) > len(ufrm.RawData()) {
		v.AddError(errShort)
	}
}
