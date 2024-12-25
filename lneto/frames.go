package lneto

import (
	"encoding/binary"
	"errors"

	"github.com/soypat/tseq/lneto/tcp"
)

// NewEthFrame returns a EthFrame with data set to buf.
// Users should still call [EthFrame.ValidateSize] before working
// with payload/options of frames to avoid panics.
func NewEthFrame(buf []byte) (EthFrame, error) {
	if len(buf) < sizeHeaderEthNoVLAN {
		return EthFrame{buf: nil}, errors.New("ethernet packet too short")
	}
	return EthFrame{buf: buf}, nil
}

// NewARPFrame returns a ARPFrame with data set to buf.
// Users should still call [ARPFrame.ValidateSize] before working
// with payload/options of frames to avoid panics.
func NewARPFrame(buf []byte) (ARPFrame, error) {
	if len(buf) < sizeHeaderARPv4 {
		return ARPFrame{buf: nil}, errors.New("ARP packet too short")
	}
	return ARPFrame{buf: buf}, nil
}

// NewIPv4Frame returns a new IPv4Frame with data set to buf.
// Users should still call [IPv4Frame.ValidateSize] before working
// with payload/options of frames to avoid panics.
func NewIPv4Frame(buf []byte) (IPv4Frame, error) {
	if len(buf) < sizeHeaderIPv4 {
		return IPv4Frame{buf: nil}, errors.New("IPv4 packet too short")
	}
	return IPv4Frame{buf: buf}, nil
}

// NewIPv6Frame returns a new IPv6Frame with data set to buf.
// Users should still call [IPv6Frame.ValidateSize] before working
// with payload/options of frames to avoid panics.
func NewIPv6Frame(buf []byte) (IPv6Frame, error) {
	if len(buf) < sizeHeaderIPv6 {
		return IPv6Frame{buf: nil}, errors.New("IPv6 packet too short")
	}
	return IPv6Frame{buf: buf}, nil
}

// NewTCPFrame returns a new TCPFrame with data set to buf.
// Users should still call [TCPFrame.ValidateSize] before working
// with payload/options of frames to avoid panics.
func NewTCPFrame(buf []byte) (TCPFrame, error) {
	if len(buf) < sizeHeaderTCP {
		return TCPFrame{buf: nil}, errors.New("TCP packet too short")
	}
	return TCPFrame{buf: buf}, nil
}

// NewUDPFrame returns a new UDPFrame with data set to buf.
// Users should still call [UDPFrame.ValidateSize] before working
// with payload/options of frames to avoid panics.
func NewUDPFrame(buf []byte) (UDPFrame, error) {
	if len(buf) < sizeHeaderUDP {
		return UDPFrame{buf: buf}, errors.New("UDP packet too short")
	}
	return UDPFrame{buf: buf}, nil
}

// EthFrame encapsulates the raw data of an Ethernet frame
// without including preamble (first byte is start of destination address)
// and provides methods for manipulating, validating and
// retrieving fields and payload data. See [IEEE 802.3].
//
// [IEEE 802.3]: https://standards.ieee.org/ieee/802.3/7071/
type EthFrame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (efrm EthFrame) RawData() []byte { return efrm.buf }

// HeaderLength returns the length of the ethernet packet header. Nominally returns 14; or 18 for VLAN packets.
func (efrm EthFrame) HeaderLength() int {
	if efrm.IsVLAN() {
		return 18
	}
	return sizeHeaderEthNoVLAN
}

// Payload returns the data portion of the ethernet packet with handling of VLAN packets.
func (efrm EthFrame) Payload() []byte {
	hl := efrm.HeaderLength()
	return efrm.buf[hl:]
}

// DestinationHardwareAddr returns the target's MAC/hardware address for the ethernet packet.
func (efrm EthFrame) DestinationHardwareAddr() (dst *[6]byte) {
	return (*[6]byte)(efrm.buf[0:6])
}

// SourceHardwareAddr returns the sender's MAC/hardware address of the ethernet packet.
func (efrm EthFrame) SourceHardwareAddr() (src *[6]byte) {
	return (*[6]byte)(efrm.buf[6:12])
}

// EtherTypeOrSize returns the EtherType/Size field of the ethernet packet.
// Caller should check if the field is actually a valid EtherType or if it represents the Ethernet payload size with [EtherType.IsSize].
func (efrm EthFrame) EtherTypeOrSize() EtherType {
	return EtherType(binary.BigEndian.Uint16(efrm.buf[12:14]))
}

// SetEtherType sets the EtherType field of the ethernet packet. See [EtherType] and [EthFrame.EtherTypeOrSize].
func (efrm EthFrame) SetEtherType(v EtherType) {
	binary.BigEndian.PutUint16(efrm.buf[12:14], uint16(v))
}

// IsVLAN returns true if the SizeOrEtherType is set to the VLAN tag 0x8100. This
// indicates the EthernetHeader is invalid as-is and instead of EtherType the field
// contains the first two octets of a 4 octet 802.1Q VLAN tag. In this case 4 more bytes
// must be read from the wire, of which the last 2 of these bytes contain the actual
// SizeOrEtherType field, which needs to be validated yet again in case the packet is
// a VLAN double-tap packet.
func (efrm EthFrame) IsVLAN() bool {
	return efrm.EtherTypeOrSize() == EtherTypeVLAN
}

// ARPFrame encapsulates the raw data of an ARP packet
// and provides methods for manipulating, validating and
// retrieving fields and payload data. See [RFC826].
//
// [RFC826]: https://tools.ietf.org/html/rfc826
type ARPFrame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (afrm ARPFrame) RawData() []byte { return afrm.buf }

// HardwareType specifies the network link protocol type. Example: Ethernet is 1.
func (afrm ARPFrame) Hardware() (Type uint16, length uint8) {
	Type = binary.BigEndian.Uint16(afrm.buf[0:2])
	length = afrm.buf[4]
	return Type, length
}

// SetHardware sets the networl link protocol type. See [ARPFrame.SetHardware].
func (afrm ARPFrame) SetHardware(Type uint16, length uint8) {
	binary.BigEndian.PutUint16(afrm.buf[0:2], Type)
	afrm.buf[4] = length
}

// Protocol returns the internet protocol type and length. See [EtherType].
func (afrm ARPFrame) Protocol() (Type EtherType, length uint8) {
	Type = EtherType(binary.BigEndian.Uint16(afrm.buf[2:4]))
	length = afrm.buf[5]
	return Type, length
}

// SetProtocol sets the protocol type and length fields of the ARP frame. See [ARPFrame.Protocol] and [EtherType].
func (afrm ARPFrame) SetProtocol(Type EtherType, length uint8) {
	binary.BigEndian.PutUint16(afrm.buf[2:4], uint16(Type))
	afrm.buf[5] = length
}

// Operation returns the ARP header operation field. See [ARPOp].
func (afrm ARPFrame) Operation() ARPOp { return ARPOp(afrm.buf[6]) }

// SetOperation sets the ARP header operation field. See [ARPOp].
func (afrm ARPFrame) SetOperation(b ARPOp) { afrm.buf[6] = uint8(b) }

// Sender returns the hardware (MAC) and protocol addresses of sender of ARP packet.
// In an ARP request MAC address is used to indicate
// the address of the host sending the request. In an ARP reply MAC address is
// used to indicate the address of the host that the request was looking for.
func (afrm ARPFrame) Sender() (hardwareAddr []byte, proto []byte) {
	_, hlen := afrm.Hardware()
	_, ilen := afrm.Protocol()
	return afrm.buf[8 : 8+hlen], afrm.buf[8+hlen : 8+hlen+ilen]
}

// Target returns the hardware (MAC) and protocol addresses of target of ARP packet.
// In an ARP request MAC target is ignored. In ARP reply MAC is used to indicate the address of host that originated request.
func (afrm ARPFrame) Target() (hardwareAddr []byte, proto []byte) {
	_, hlen := afrm.Hardware()
	_, ilen := afrm.Protocol()
	toff := 8 + hlen + ilen
	return afrm.buf[toff : toff+hlen], afrm.buf[toff+hlen : toff+hlen+ilen]
}

// Sender4 returns the IPv4 sender addresses. See [ARPFrame.Sender].
func (afrm ARPFrame) Sender4() (hardwareAddr *[6]byte, proto *[4]byte) {
	return (*[6]byte)(afrm.buf[8:14]), (*[4]byte)(afrm.buf[14:18])
}

// Target4 returns the IPv4 target addresses. See [ARPFrame.Sender].
func (afrm ARPFrame) Target4() (hardwareAddr *[6]byte, proto *[4]byte) {
	return (*[6]byte)(afrm.buf[18:24]), (*[4]byte)(afrm.buf[24:28])
}

// Sender6 returns the IPv6 sender addresses. See [ARPFrame.Sender].
func (afrm ARPFrame) Sender16() (hardwareAddr *[6]byte, proto *[16]byte) {
	return (*[6]byte)(afrm.buf[8:14]), (*[16]byte)(afrm.buf[14:30])
}

// Target6 returns the IPv6 target addresses. See [ARPFrame.Sender].
func (afrm ARPFrame) Target16() (hardwareAddr *[6]byte, proto *[16]byte) {
	return (*[6]byte)(afrm.buf[30:36]), (*[16]byte)(afrm.buf[36:52])
}

// IPv4Frame encapsulates the raw data of an IPv4 packet
// and provides methods for manipulating, validating and
// retreiving fields and payload data. See [RFC791].
//
// [RFC791]: https://tools.ietf.org/html/rfc791
type IPv4Frame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (ifrm IPv4Frame) RawData() []byte { return ifrm.buf }

// HeaderLength returns the length of the IPv4 header as calculated using IHL. It includes IP options.
func (ifrm IPv4Frame) HeaderLength() int {
	return int(ifrm.ihl()) * 4
}

func (ifrm IPv4Frame) ihl() uint8 {
	return ifrm.buf[0] >> 4
}

// VersionAndIHL returns the version and IHL fields in the IPv4 header. Version should always be 4.
func (ifrm IPv4Frame) VersionAndIHL() (version, IHL uint8) {
	v := ifrm.buf[0]
	return v & 0xf, v >> 4
}

// SetVersionAndIHL sets the version and IHL fields in the IPv4 header. Version should always be 4.
func (ifrm IPv4Frame) SetVersionAndIHL(version, IHL uint8) { ifrm.buf[0] = version&0xf | IHL<<4 }

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
func (ifrm IPv4Frame) ToS() IPToS {
	return IPToS(ifrm.buf[1])
}

// SetToS sets ToS field. See [IPv4Frame.ToS].
func (ifrm IPv4Frame) SetToS(tos IPToS) { ifrm.buf[1] = byte(tos) }

// TotalLength defines the entire packet size in bytes, including IP header and data.
// The minimum size is 20 bytes (IPv4 header without data) and the maximum is 65,535 bytes.
// All hosts are required to be able to reassemble datagrams of size up to 576 bytes,
// but most modern hosts handle much larger packets.
//
// Links may impose further restrictions on the packet size, in which case datagrams
// must be fragmented. Fragmentation in IPv4 is performed in either the
// sending host or in routers. Reassembly is performed at the receiving host.
func (ifrm IPv4Frame) TotalLength() uint16 {
	return binary.BigEndian.Uint16(ifrm.buf[2:4])
}

// SetTotalLength sets TotalLength field. See [IPv4Frame.TotalLength].
func (ifrm IPv4Frame) SetTotalLength(tl uint16) { binary.BigEndian.PutUint16(ifrm.buf[2:4], tl) }

// ID is an identification field and is primarily used for uniquely
// identifying the group of fragments of a single IP datagram.
func (ifrm IPv4Frame) ID() uint16 {
	return binary.BigEndian.Uint16(ifrm.buf[4:6])
}

// SetID sets ID field. See [IPv4Frame.ID].
func (ifrm IPv4Frame) SetID(id uint16) { binary.BigEndian.PutUint16(ifrm.buf[4:6], id) }

// Flags returns the [IPv4Flags] of the IP packet.
func (ifrm IPv4Frame) Flags() IPv4Flags {
	return IPv4Flags(binary.BigEndian.Uint16(ifrm.buf[6:8]))
}

// SetFlags sets the IPv4 flags field. See [IPv4Flags].
func (ifrm IPv4Frame) SetFlags(flags IPv4Flags) {
	binary.BigEndian.PutUint16(ifrm.buf[6:8], uint16(flags))
}

// TTL is an eight-bit time to live field limits a datagram's lifetime to prevent
// network failure in the event of a routing loop. In practice, the field
// is used as a hop count—when the datagram arrives at a router,
// the router decrements the TTL field by one. When the TTL field hits zero,
// the router discards the packet and typically sends an ICMP time exceeded message to the sender.
func (ifrm IPv4Frame) TTL() uint8 { return ifrm.buf[8] }

// SetTTL sets the IP frame's TTL field. See [IPv4Frame.TTL].
func (ifrm IPv4Frame) SetTTL(ttl uint8) { ifrm.buf[8] = ttl }

// Protocol field defines the protocol used in the data portion of the IP datagram. TCP is 6, UDP is 17.
// See [IPProto].
func (ifrm IPv4Frame) Protocol() IPProto { return IPProto(ifrm.buf[9]) }

// SetProtocol sets protocol field. See [IPv4Frame.Protocol] and [IPProto].
func (ifrm IPv4Frame) SetProtocol(proto IPProto) { ifrm.buf[9] = uint8(proto) }

// CRC returns the cyclic-redundancy-check (checksum) field of the IPv4 header.
func (ifrm IPv4Frame) CRC() uint16 {
	return binary.BigEndian.Uint16(ifrm.buf[10:12])
}

// SetCRC sets the CRC field of the IP packet. See [IPv4Frame.CRC].
func (ifrm IPv4Frame) SetCRC(cs uint16) {
	binary.BigEndian.PutUint16(ifrm.buf[10:12], cs)
}

// CalculateHeaderCRC calculates the CRC for this IPv4 frame.
func (ifrm IPv4Frame) CalculateHeaderCRC() uint16 {
	var crc CRC791
	crc.Write(ifrm.buf[0:10])
	crc.Write(ifrm.buf[12:20])
	return crc.Sum16()
}

func (ifrm IPv4Frame) crcWriteTCPPseudo(crc *CRC791) {
	crc.Write(ifrm.SourceAddr()[:])
	crc.Write(ifrm.DestinationAddr()[:])
	crc.AddUint16(ifrm.TotalLength() - 4*uint16(ifrm.ihl()))
	crc.AddUint16(uint16(ifrm.Protocol()))
}

func (ifrm IPv4Frame) crcWriteUDPPseudo(crc *CRC791) {
	crc.Write(ifrm.SourceAddr()[:])
	crc.Write(ifrm.DestinationAddr()[:])
	crc.AddUint16(uint16(ifrm.Protocol()))
}

// SourceAddr returns pointer to the source IPv4 address in the IP header.
func (ifrm IPv4Frame) SourceAddr() *[4]byte {
	return (*[4]byte)(ifrm.buf[12:16])
}

// DestinationAddr returns pointer to the destination IPv4 address in the IP header.
func (ifrm IPv4Frame) DestinationAddr() *[4]byte {
	return (*[4]byte)(ifrm.buf[16:20])
}

// Payload returns the contents of the IPv4 packet, which may be zero sized.
// Be sure to call [IPv4Frame.ValidateSize] beforehand to avoid panic.
func (ifrm IPv4Frame) Payload() []byte {
	off := ifrm.HeaderLength()
	l := ifrm.TotalLength()
	return ifrm.buf[off:l]
}

// IPv6Frame encapsulates the raw data of an IPv6 packet
// and provides methods for manipulating, validating and
// retrieving fields and payload data. See [RFC8200].
//
// [RFC8200]: https://tools.ietf.org/html/rfc8200
type IPv6Frame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (i6frm IPv6Frame) RawData() []byte { return i6frm.buf }

// Payload returns the contents of the IPv6 packet, which may be zero sized.
// Be sure to call [IPv6Frame.ValidateSize] beforehand to avoid panic.
func (i6frm IPv6Frame) Payload() []byte {
	pl := i6frm.PayloadLength()
	return i6frm.buf[sizeHeaderIPv6 : sizeHeaderIPv6+pl]
}

// VersionTrafficAndFlow returns the version, Traffic and Flow label fields of the IPv6 header.
// See [IPToS] Traffic Class. Version should be 6 for IPv6.
func (i6frm IPv6Frame) VersionTrafficAndFlow() (version uint8, tos IPToS, flow uint32) {
	v := binary.BigEndian.Uint32(i6frm.buf[0:4])
	version = uint8(v >> (32 - 4))
	tos = IPToS(v >> (32 - 12))
	flow = v & 0x000f_ffff
	return version, tos, flow
}

// SetVersionTrafficAndFlow sets the version, ToS and Flow label in the IPv6 header. Version must be equal to 6.
// See [IPv6Frame.VersionTrafficAndFlow].
func (i6frm IPv6Frame) SetVersionTrafficAndFlow(version uint8, tos IPToS, flow uint32) {
	v := flow | uint32(tos)<<(32-12) | uint32(version)<<(32-4)
	binary.BigEndian.PutUint32(i6frm.buf[0:4], v)
}

// PayloadLength returns the size of payload in octets(bytes) including any extension headers.
// The length is set to zero when a Hop-by-Hop extension header carries a Jumbo Payload option.
func (i6frm IPv6Frame) PayloadLength() uint16 {
	return binary.BigEndian.Uint16(i6frm.buf[4:6])
}

// SetPayloadLength sets the payload length field of the IPv6 header. See [IPv6Frame.PayloadLength].
func (i6frm IPv6Frame) SetPayloadLength(pl uint16) {
	binary.BigEndian.PutUint16(i6frm.buf[4:6], pl)
}

// NextHeader returns the Next Header field of the IPv6 header which usually specifies the transport layer
// protocol used by packet's payload.
func (i6frm IPv6Frame) NextHeader() IPProto {
	return IPProto(i6frm.buf[6])
}

// SetNextHeader sets the Next Header (protocol) field of the IPv6 header. See [IPv6Frame.NextHeader].
func (i6frm IPv6Frame) SetNextHeader(proto IPProto) {
	i6frm.buf[6] = uint8(proto)
}

// HopLimit returns the Hop Limit of the IPv6 header.
// This value is decremented by one at each forwarding node and the packet is discarded if it becomes 0.
// However, the destination node should process the packet normally even if received with a hop limit of 0.
func (i6frm IPv6Frame) HopLimit() uint8 {
	return i6frm.buf[7]
}

// SetHopLimit sets the Hop Limit field of the IPv6 header. See [IPv6Frame.HopLimiy].
func (i6frm IPv6Frame) SetHopLimit(hop uint8) {
	i6frm.buf[7] = hop
}

// SourceAddr returns pointer to the sending node unicast IPv6 address in the IP header.
func (i6frm IPv6Frame) SourceAddr() *[16]byte {
	return (*[16]byte)(i6frm.buf[8:24])
}

// DestinationAddr returns pointer to the destination node unicast or multicast IPv6 address in the IP header.
func (i6frm IPv6Frame) DestinationAddr() *[16]byte {
	return (*[16]byte)(i6frm.buf[24:40])
}

func (ifrm IPv6Frame) crcWritePseudo(crc *CRC791) {
	crc.Write(ifrm.SourceAddr()[:])
	crc.Write(ifrm.DestinationAddr()[:])
	crc.AddUint32(uint32(ifrm.PayloadLength()))
	crc.AddUint32(uint32(ifrm.NextHeader()))
}

// TCPFrame encapsulates the raw data of a TCP segment
// and provides methods for manipulating, validating and
// retrieving fields and payload data. See [RFC9293].
//
// [RFC9293]: https://datatracker.ietf.org/doc/html/rfc9293
type TCPFrame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (tfrm TCPFrame) RawData() []byte { return tfrm.buf }

// SourcePort identifies the sending port of the TCP packet. Must be non-zero.
func (tfrm TCPFrame) SourcePort() uint16 {
	return binary.BigEndian.Uint16(tfrm.buf[0:2])
}

// SetSourcePort sets TCP source port. See [TCPFrame.SetSourcePort]
func (tfrm TCPFrame) SetSourcePort(src uint16) {
	binary.BigEndian.PutUint16(tfrm.buf[0:2], src)
}

// DestinationPort identifies the receiving port for the TCP packet. Must be non-zero.
func (tfrm TCPFrame) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(tfrm.buf[2:4])
}

// SetDestinationPort sets TCP destination port. See [TCPFrame.DestinationPort]
func (tfrm TCPFrame) SetDestinationPort(dst uint16) {
	binary.BigEndian.PutUint16(tfrm.buf[2:4], dst)
}

// Seq returns sequence number of the first data octet in this segment (except when SYN present)
// If SYN present this is the Initial Sequence Number (ISN) and the first data octet would be ISN+1.
func (tfrm TCPFrame) Seq() tcp.Value {
	return tcp.Value(binary.BigEndian.Uint32(tfrm.buf[4:8]))
}

// SetSeq sets Seq field. See [TCPFrame.Seq].
func (tfrm TCPFrame) SetSeq(v tcp.Value) {
	binary.BigEndian.PutUint32(tfrm.buf[4:8], uint32(v))
}

// Ack is the next sequence number (Seq field) the sender is expecting to receive (when ACK is present).
// In other words an Ack of X indicates all octets up to but not including X have been received.
// Once a connection is established the ACK flag should always be set.
func (tfrm TCPFrame) Ack() tcp.Value {
	return tcp.Value(binary.BigEndian.Uint32(tfrm.buf[8:12]))
}

// SetAck sets Ack field. See [TCPFrame.Ack].
func (tfrm TCPFrame) SetAck(v tcp.Value) {
	binary.BigEndian.PutUint32(tfrm.buf[8:12], uint32(v))
}

// OffsetAndFlags returns the offset and flag fields of TCP header.
// Offset is amount of 32-bit words used for TCP header including TCP options (see [TCPFrame.HeaderLength]).
// See [tcp.Flags] for more information on TCP flags.
func (tfrm TCPFrame) OffsetAndFlags() (offset uint8, flags tcp.Flags) {
	v := binary.BigEndian.Uint16(tfrm.buf[12:14])
	offset = uint8(v >> 12)
	flags = tcp.Flags(v).Mask()
	return offset, flags
}

// SetOffsetAndFlags returns offset and flag fields of TCP header. See [TCPFrame.OffsetAndFlags].
func (tfrm TCPFrame) SetOffsetAndFlags(offset uint8, flags tcp.Flags) {
	v := uint16(offset)<<12 | uint16(flags.Mask())
	binary.BigEndian.PutUint16(tfrm.buf[12:14], v)
}

// HeaderLength uses Offset field to calculate the total length of
// the TCP header including options. Performs no validation.
func (tfrm TCPFrame) HeaderLength() (tcpWords int) {
	offset, _ := tfrm.OffsetAndFlags()
	return 4 * int(offset)
}

// CRC returns the checksum field in the TCP header.
func (tfrm TCPFrame) CRC() uint16 {
	return binary.BigEndian.Uint16(tfrm.buf[16:18])
}

// SetCRC sets the checksum field of the TCP header. See [TCPFrame.CRC].
func (tfrm TCPFrame) SetCRC(checksum uint16) {
	binary.BigEndian.PutUint16(tfrm.buf[16:18], checksum)
}

// CalculateIPv4CRC returns the CRC for the TCP header over an IPv4 protocol.
func (tfrm TCPFrame) CalculateIPv4CRC(ifrm IPv4Frame) uint16 {
	var crc CRC791
	ifrm.crcWriteTCPPseudo(&crc)
	expectLen := int(ifrm.TotalLength()) - ifrm.HeaderLength()
	if expectLen != len(tfrm.buf) {
		println("unexpected TCP buffer length mismatches IPv4 header total length", expectLen, len(tfrm.buf))
	}
	tfrm.crcWrite(&crc)
	return crc.Sum16()
}

// CalculateIPv4CRC returns the CRC for the TCP header over an IPv4 protocol.
func (tfrm TCPFrame) CalculateIPv6CRC(ifrm IPv6Frame) uint16 {
	var crc CRC791
	ifrm.crcWritePseudo(&crc)
	expectLen := int(ifrm.PayloadLength())
	if expectLen != len(tfrm.buf) {
		println("unexpected TCP buffer length mismatches IPv4 header total length", expectLen, len(tfrm.buf))
	}
	tfrm.crcWrite(&crc)
	return crc.Sum16()
}

func (tfrm TCPFrame) crcWrite(crc *CRC791) {
	// Write excluding CRC
	crc.Write(tfrm.buf[:16])
	crc.Write(tfrm.buf[18:])
}

func (tfrm TCPFrame) SetUrgentPtr(up uint16) {
	binary.BigEndian.PutUint16(tfrm.buf[18:20], up)
}

func (tfrm TCPFrame) UrgentPtr() uint16 {
	return binary.BigEndian.Uint16(tfrm.buf[18:20])
}

// Payload returns the payload content section of the TCP packet (not including TCP options).
// Be sure to call [TCPFrame.ValidateSize] beforehand to avoid panic.
func (tfrm TCPFrame) Payload() []byte {
	return tfrm.buf[tfrm.HeaderLength():]
}

// Options returns the TCP option buffer portion of the frame. The returned slice may be zero length.
// Be sure to call [TCPFrame.ValidateSize] beforehand to avoid panic.
func (tfrm TCPFrame) Options() []byte {
	return tfrm.buf[sizeHeaderTCP:tfrm.HeaderLength()]
}

// UDPFrame encapsulates the raw data of a UDP datagram
// and provides methods for manipulating, validating and
// retrieving fields and payload data. See [RFC768].
//
// [RFC768]: https://tools.ietf.org/html/rfc768
type UDPFrame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (ufrm UDPFrame) RawData() []byte { return ufrm.buf }

// SourcePort identifies the sending port for the UDP packet. Must be non-zero.
func (ufrm UDPFrame) SourcePort() uint16 {
	return binary.BigEndian.Uint16(ufrm.buf[0:2])
}

// SetSourcePort sets UDP source port. See [UDPFrame.SourcePort]
func (ufrm UDPFrame) SetSourcePort(src uint16) {
	binary.BigEndian.PutUint16(ufrm.buf[0:2], src)
}

// DestinationPort identifies the receiving port for the UDP packet. Must be non-zero.
func (ufrm UDPFrame) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(ufrm.buf[2:4])
}

// SetDestinationPort sets UDP destination port. See [UDPFrame.DestinationPort]
func (ufrm UDPFrame) SetDestinationPort(dst uint16) {
	binary.BigEndian.PutUint16(ufrm.buf[2:4], dst)
}

// Length specifies length in bytes of UDP header and UDP payload. The minimum length
// is 8 bytes (UDP header length). This field should match the result of the IP header
// TotalLength field minus the IP header size: udp.Length == ip.TotalLength - 4*ip.IHL
func (ufrm UDPFrame) Length() uint16 {
	return binary.BigEndian.Uint16(ufrm.buf[4:6])
}

// SetLength sets the UDP header's length field. See [UDPFrame.Length].
func (ufrm UDPFrame) SetLength(length uint16) {
	binary.BigEndian.PutUint16(ufrm.buf[4:6], length)
}

// CRC returns the checksum field in the UDP header.
func (ufrm UDPFrame) CRC() uint16 {
	return binary.BigEndian.Uint16(ufrm.buf[6:8])
}

// SetCRC sets the UDP header's CRC field. See [UDPFrame.CRC].
func (ufrm UDPFrame) SetCRC(checksum uint16) {
	binary.BigEndian.PutUint16(ufrm.buf[6:8], checksum)
}

// Payload returns the payload content section of the UDP packet.
// Be sure to call [UDPFrame.ValidateSize] beforehand to avoid panic.
func (ufrm UDPFrame) Payload() []byte {
	l := ufrm.Length()
	return ufrm.buf[sizeHeaderUDP:l]
}

func (ufrm UDPFrame) CalculateIPv4Checksum(ifrm IPv4Frame) uint16 {
	var crc CRC791
	ifrm.crcWriteUDPPseudo(&crc)
	crc.AddUint16(ufrm.Length())
	crc.AddUint16(ufrm.SourcePort())
	crc.AddUint16(ufrm.DestinationPort())
	crc.AddUint16(ufrm.Length()) // Length double tap.
	crc.Write(ufrm.Payload())
	return crc.Sum16()
}

func (ufrm UDPFrame) CalculateIPv6Checksum(ifrm IPv6Frame) uint16 {
	var crc CRC791
	ifrm.crcWritePseudo(&crc)
	crc.AddUint16(ufrm.SourcePort())
	crc.AddUint16(ufrm.DestinationPort())
	crc.AddUint16(ufrm.Length()) // Length double tap.
	crc.Write(ufrm.Payload())
	return crc.Sum16()
}
