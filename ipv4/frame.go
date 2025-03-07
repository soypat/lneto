package ipv4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/soypat/lneto"
)

// NewIPv4Frame returns a new IPv4Frame with data set to buf.
// An error is returned if the buffer size is smaller than 20.
// Users should still call [IPv4Frame.ValidateSize] before working
// with payload/options of frames to avoid panics.
func NewFrame(buf []byte) (Frame, error) {
	if len(buf) < sizeHeader {
		return Frame{buf: nil}, errors.New("ipv4: short buffer")
	}
	return Frame{buf: buf}, nil
}

// Frame encapsulates the raw data of an IPv4 packet
// and provides methods for manipulating, validating and
// retreiving fields and payload data. See [RFC791].
//
// [RFC791]: https://tools.ietf.org/html/rfc791
type Frame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (ifrm Frame) RawData() []byte { return ifrm.buf }

// HeaderLength returns the length of the IPv4 header as calculated using IHL. It includes IP options.
func (ifrm Frame) HeaderLength() int {
	return int(ifrm.ihl()) * 4
}

func (ifrm Frame) ihl() uint8     { return ifrm.buf[0] & 0xf }
func (ifrm Frame) version() uint8 { return ifrm.buf[0] >> 4 }

// VersionAndIHL returns the version and IHL fields in the IPv4 header. Version should always be 4.
func (ifrm Frame) VersionAndIHL() (version, IHL uint8) {
	v := ifrm.buf[0]
	return v >> 4, v & 0xf
}

// SetVersionAndIHL sets the version and IHL fields in the IPv4 header. Version should always be 4.
func (ifrm Frame) SetVersionAndIHL(version, IHL uint8) { ifrm.buf[0] = version<<4 | IHL&0xf }

// ToS (Type of Service) contains Differential Services Code Point (DSCP) and
// Explicit Congestion Notification (ECN) union data.
//
// DSCP originally defined as the type of service (ToS), this field specifies
// differentiated services (DiffServ) per RFC 2474. Real-time data streaming
// makes use of the DSCP field. An example is Voice over IP (VoIP), which is
// used for interactive voice services.
//
// ECN is defined in RFC 3168 and allows end-to-end notification of
// network congestion without dropping packets. ECN is an optional feature available
// when both endpoints support it and effective when also supported by the underlying network.
func (ifrm Frame) ToS() ToS {
	return ToS(ifrm.buf[1])
}

// SetToS sets ToS field. See [Frame.ToS].
func (ifrm Frame) SetToS(tos ToS) { ifrm.buf[1] = byte(tos) }

// TotalLength defines the entire packet size in bytes, including IP header and data.
// The minimum size is 20 bytes (IPv4 header without data) and the maximum is 65,535 bytes.
// All hosts are required to be able to reassemble datagrams of size up to 576 bytes,
// but most modern hosts handle much larger packets.
//
// Links may impose further restrictions on the packet size, in which case datagrams
// must be fragmented. Fragmentation in IPv4 is performed in either the
// sending host or in routers. Reassembly is performed at the receiving host.
func (ifrm Frame) TotalLength() uint16 {
	return binary.BigEndian.Uint16(ifrm.buf[2:4])
}

// SetTotalLength sets TotalLength field. See [Frame.TotalLength].
func (ifrm Frame) SetTotalLength(tl uint16) { binary.BigEndian.PutUint16(ifrm.buf[2:4], tl) }

// ID is an identification field and is primarily used for uniquely
// identifying the group of fragments of a single IP datagram.
func (ifrm Frame) ID() uint16 {
	return binary.BigEndian.Uint16(ifrm.buf[4:6])
}

// SetID sets ID field. See [Frame.ID].
func (ifrm Frame) SetID(id uint16) { binary.BigEndian.PutUint16(ifrm.buf[4:6], id) }

// Flags returns the [Flags] of the IP packet.
func (ifrm Frame) Flags() Flags {
	return Flags(binary.BigEndian.Uint16(ifrm.buf[6:8]))
}

// SetFlags sets the IPv4 flags field. See [Flags].
func (ifrm Frame) SetFlags(flags Flags) {
	binary.BigEndian.PutUint16(ifrm.buf[6:8], uint16(flags))
}

// TTL is an eight-bit time to live field limits a datagram's lifetime to prevent
// network failure in the event of a routing loop. In practice, the field
// is used as a hop count—when the datagram arrives at a router,
// the router decrements the TTL field by one. When the TTL field hits zero,
// the router discards the packet and typically sends an ICMP time exceeded message to the sender.
func (ifrm Frame) TTL() uint8 { return ifrm.buf[8] }

// SetTTL sets the IP frame's TTL field. See [Frame.TTL].
func (ifrm Frame) SetTTL(ttl uint8) { ifrm.buf[8] = ttl }

// Protocol field defines the protocol used in the data portion of the IP datagram. TCP is 6, UDP is 17.
// See [IPProto].
func (ifrm Frame) Protocol() lneto.IPProto { return lneto.IPProto(ifrm.buf[9]) }

// SetProtocol sets protocol field. See [Frame.Protocol] and [lneto.IPProto].
func (ifrm Frame) SetProtocol(proto lneto.IPProto) { ifrm.buf[9] = uint8(proto) }

// CRC returns the cyclic-redundancy-check (checksum) field of the IPv4 header.
func (ifrm Frame) CRC() uint16 {
	return binary.BigEndian.Uint16(ifrm.buf[10:12])
}

// SetCRC sets the CRC field of the IP packet. See [Frame.CRC].
func (ifrm Frame) SetCRC(cs uint16) {
	binary.BigEndian.PutUint16(ifrm.buf[10:12], cs)
}

// CalculateHeaderCRC calculates the CRC for this IPv4 frame.
func (ifrm Frame) CalculateHeaderCRC() uint16 {
	var crc lneto.CRC791
	crc.Write(ifrm.buf[0:10])
	crc.Write(ifrm.buf[12:20])
	return crc.Sum16()
}

func (ifrm Frame) CRCWriteTCPPseudo(crc *lneto.CRC791) {
	crc.Write(ifrm.SourceAddr()[:])
	crc.Write(ifrm.DestinationAddr()[:])
	crc.AddUint16(ifrm.TotalLength() - 4*uint16(ifrm.ihl()))
	crc.AddUint16(uint16(ifrm.Protocol()))
}

func (ifrm Frame) CRCWriteUDPPseudo(crc *lneto.CRC791) {
	crc.Write(ifrm.SourceAddr()[:])
	crc.Write(ifrm.DestinationAddr()[:])
	crc.AddUint16(uint16(ifrm.Protocol()))
}

// SourceAddr returns pointer to the source IPv4 address in the IP header.
func (ifrm Frame) SourceAddr() *[4]byte {
	return (*[4]byte)(ifrm.buf[12:16])
}

// DestinationAddr returns pointer to the destination IPv4 address in the IP header.
func (ifrm Frame) DestinationAddr() *[4]byte {
	return (*[4]byte)(ifrm.buf[16:20])
}

// Payload returns the contents of the IPv4 packet, which may be zero sized.
// Be sure to call [Frame.ValidateSize] beforehand to avoid panic.
func (ifrm Frame) Payload() []byte {
	off := ifrm.HeaderLength()
	l := ifrm.TotalLength()
	return ifrm.buf[off:l]
}

// Options returns the options portion of the IPv4 header. May be zero lengthed.
// Be sure to call [Frame.ValidateSize] beforehand to avoid panic.
func (ifrm Frame) Options() []byte {
	off := ifrm.HeaderLength()
	return ifrm.buf[sizeHeader:off]
}

// ClearHeader zeros out the fixed(non-variable) header contents.
func (ifrm Frame) ClearHeader() {
	for i := range ifrm.buf[:sizeHeader] {
		ifrm.buf[i] = 0
	}
}

//
// Validation API.
//

var (
	errBadTL      = errors.New("ipv4: bad total length")
	errShort      = errors.New("ipv4: short data")
	errBadIHL     = errors.New("ipv4: bad IHL")
	errBadVersion = errors.New("ipv4: bad version")
	errEvil       = errors.New("ipv4: evil packet")
)

// ValidateSize checks the frame's size fields and compares with the actual buffer
// the frame. It returns a non-nil error on finding an inconsistency.
func (ifrm Frame) ValidateSize(v *lneto.Validator) {
	ihl := ifrm.ihl()
	tl := ifrm.TotalLength()
	if tl < sizeHeader {
		v.AddError(errBadTL)
	}
	if int(tl) > len(ifrm.RawData()) {
		v.AddError(errShort)
	}
	if ihl < 5 {
		v.AddError(errBadIHL)
	}
}

// ValidateExceptCRC checks for invalid frame values but does not check CRC.
func (ifrm Frame) ValidateExceptCRC(v *lneto.Validator) {
	ifrm.ValidateSize(v)
	flags := ifrm.Flags()
	if ifrm.version() != 4 {
		v.AddError(errBadVersion)
	}
	if v.Flags()&lneto.ValidateEvilBit != 0 && flags.IsEvil() {
		v.AddError(errEvil)
	}
}

func (ifrm Frame) String() string {
	dst := netip.AddrFrom4(*ifrm.DestinationAddr())
	src := netip.AddrFrom4(*ifrm.SourceAddr())

	hl := ifrm.HeaderLength()
	tl := int(ifrm.TotalLength())
	ttl := ifrm.TTL()
	id := ifrm.ID()
	proto := ifrm.Protocol()
	tos := ifrm.ToS()
	return fmt.Sprintf("IP %s SRC=%s DST=%s LEN=%d OPT=%d TTL=%d ID=%d ToS=0x%x", proto.String(), src.String(), dst.String(), tl, tl-hl, ttl, id, tos)
}
