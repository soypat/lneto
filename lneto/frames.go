package lneto

import (
	"encoding/binary"

	"github.com/soypat/tseq"
)

func NewEthFrame(buf []byte) EthFrame     { return EthFrame{buf: buf} }
func NewARPv4Frame(buf []byte) ARPv4Frame { return ARPv4Frame{buf: buf} }
func NewIPv4Frame(buf []byte) IPv4Frame   { return IPv4Frame{buf: buf} }
func NewTCPFrame(buf []byte) TCPFrame     { return TCPFrame{buf: buf} }
func NewUDPFrame(buf []byte) UDPFrame     { return UDPFrame{buf: buf} }

type EthFrame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (frm EthFrame) RawData() []byte {	return frm.buf}

func (frm EthFrame) Payload() []byte {
	if frm.IsVLAN() {
		return frm.buf[18:]
	}
	return frm.buf[14:]
}

func (frm EthFrame) DstHardwareAddr6() (dst *[6]byte) {
	return (*[6]byte)(frm.buf[:6])
}

func (frm EthFrame) SrcHardwareAddr6() (src *[6]byte) {
	return (*[6]byte)(frm.buf[6:12])
}

func (frm EthFrame) EtherTypeOrSize() uint16 {
	return binary.BigEndian.Uint16(frm.buf[12:14])
}

// IsVLAN returns true if the SizeOrEtherType is set to the VLAN tag 0x8100. This
// indicates the EthernetHeader is invalid as-is and instead of EtherType the field
// contains the first two octets of a 4 octet 802.1Q VLAN tag. In this case 4 more bytes
// must be read from the wire, of which the last 2 of these bytes contain the actual
// SizeOrEtherType field, which needs to be validated yet again in case the packet is
// a VLAN double-tap packet.
func (frm EthFrame) IsVLAN() bool {
	return frm.EtherTypeOrSize() == uint16(EtherTypeVLAN)
}

type ARPv4Frame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (frm ARPv4Frame) RawData() []byte {	return frm.buf}

// HardwareType specifies the network link protocol type. Example: Ethernet is 1.
func (arp ARPv4Frame) Hardware() (Type uint16, length uint8) {
	Type = binary.BigEndian.Uint16(arp.buf[0:2])
	length = arp.buf[4]
	return Type, length
}

func (arp ARPv4Frame) SetHardware(Type uint16, length uint8) {
	binary.BigEndian.PutUint16(arp.buf[0:2], Type)
	arp.buf[4] = length
}

func (arp ARPv4Frame) Protocol() (Type uint16, length uint8) {
	Type = binary.BigEndian.Uint16(arp.buf[2:4])
	length = arp.buf[5]
	return Type, length
}

func (arp ARPv4Frame) SetProtocol(Type uint16, length uint8) {
	binary.BigEndian.PutUint16(arp.buf[2:4], Type)
	arp.buf[5] = length
}

func (arp ARPv4Frame) SetOperation(b uint8) { arp.buf[6] = b }

func (arp ARPv4Frame) IsOperationRequest() bool { return arp.buf[6] == 1 }
func (arp ARPv4Frame) IsOperationReply() bool   { return arp.buf[6] == 2 }

// Sender returns the MAC (hardware) and IP (protocol) addresses of sender of ARP packet.
// In an ARP request MAC is used to indicate
// the address of the host sending the request. In an ARP reply MAC is
// used to indicate the address of the host that the request was looking for.
func (arp ARPv4Frame) Sender() (hardwareAddr *[6]byte, proto *[4]byte) {
	return (*[6]byte)(arp.buf[8:14]), (*[4]byte)(arp.buf[14:18])
}

// Target returns the MAC (hardware) and IP (protocol) addresses of target of ARP packet.
// In an ARP request MAC target is ignored. In ARP reply MAC is used to indicate the address of host that originated request.
func (arp ARPv4Frame) Target() (hardwareAddr *[6]byte, proto *[4]byte) {
	return (*[6]byte)(arp.buf[18:24]), (*[4]byte)(arp.buf[24:28])
}

type IPv4Frame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (frm IPv4Frame) RawData() []byte {	return frm.buf}


func (ip IPv4Frame) Version() uint8 { return ip.buf[0] & 0xf }
func (ip IPv4Frame) IHL() uint8     { return ip.buf[0] >> 4 }

// HeaderLength returns the length of the IPv4 header as calculated using IHL. It includes IP options.
func (ip IPv4Frame) HeaderLength() int {
	return int(ip.IHL()) * 4
}

func (ip IPv4Frame) SetVersionAndIHL(version, IHL uint8) { ip.buf[0] = version&0xf | IHL<<4 }

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
func (ip IPv4Frame) ToS() IPToS {
	return IPToS(ip.buf[1])
}

// SetToS sets ToS field. See [IPv4Frame.ToS].
func (ip IPv4Frame) SetToS(tos IPToS) { ip.buf[1] = byte(tos) }

// TotalLength defines the entire packet size in bytes, including IP header and data.
// The minimum size is 20 bytes (IPv4 header without data) and the maximum is 65,535 bytes.
// All hosts are required to be able to reassemble datagrams of size up to 576 bytes,
// but most modern hosts handle much larger packets.
//
// Links may impose further restrictions on the packet size, in which case datagrams
// must be fragmented. Fragmentation in IPv4 is performed in either the
// sending host or in routers. Reassembly is performed at the receiving host.
func (ip IPv4Frame) TotalLength() uint16 {
	return binary.BigEndian.Uint16(ip.buf[2:4])
}

// SetTotalLength sets TotalLength field. See [IPv4Frame.TotalLength].
func (ip IPv4Frame) SetTotalLength(tl uint16) { binary.BigEndian.PutUint16(ip.buf[2:4], tl) }

// ID is an identification field and is primarily used for uniquely
// identifying the group of fragments of a single IP datagram.
func (ip IPv4Frame) ID() uint16 {
	return binary.BigEndian.Uint16(ip.buf[4:6])
}

// SetID sets ID field. See [IPv4Frame.ID].
func (ip IPv4Frame) SetID(id uint16) { binary.BigEndian.PutUint16(ip.buf[4:6], id) }

// Flags returns the [IPv4Flags] of the IP packet.
func (ip IPv4Frame) Flags() IPv4Flags {
	return IPv4Flags(binary.BigEndian.Uint16(ip.buf[6:8]))
}

// SetFlags sets the IPv4 flags field. See [IPv4Flags].
func (ip IPv4Frame) SetFlags(flags IPv4Flags) { binary.BigEndian.PutUint16(ip.buf[6:8], uint16(flags)) }

// TTL is an eight-bit time to live field limits a datagram's lifetime to prevent
// network failure in the event of a routing loop. In practice, the field
// is used as a hop count—when the datagram arrives at a router,
// the router decrements the TTL field by one. When the TTL field hits zero,
// the router discards the packet and typically sends an ICMP time exceeded message to the sender.
func (ip IPv4Frame) TTL() uint8 { return ip.buf[8] }

// SetTTL sets the IP frame's TTL field. See [IPv4Frame.TTL].
func (ip IPv4Frame) SetTTL(ttl uint8) { ip.buf[8] = ttl }

// Protocol field defines the protocol used in the data portion of the IP datagram. TCP is 6, UDP is 17.
func (ip IPv4Frame) Protocol() uint8 { return ip.buf[9] }

// SetProtocol sets protocol field. See [IPv4Frame.Protocol].
func (ip IPv4Frame) SetProtocol(proto uint8) { ip.buf[9] = proto }

// CRC returns the cyclic-redundancy check field of the IPv4 packet.
func (ip IPv4Frame) CRC() uint16 {
	return binary.BigEndian.Uint16(ip.buf[10:12])
}

// SetCRC sets the CRC field of the IP packet. See [IPv4Frame.CRC].
func (ip IPv4Frame) SetCRC(cs uint16) {
	binary.BigEndian.PutUint16(ip.buf[10:12], cs)
}

func (ip IPv4Frame) CalculateHeaderCRC() uint16 {
	var crc CRC791
	crc.Write(ip.buf[0:10])
	crc.Write(ip.buf[12:20])
	return crc.Sum16()
}

func (ip IPv4Frame) writeTCPPseudoCRC(crc *CRC791) {
	crc.Write(ip.SourceAddr()[:])
	crc.Write(ip.DestinationAddr()[:])
	crc.AddUint16(ip.TotalLength() - 4*uint16(ip.IHL()))
	crc.AddUint16(uint16(ip.Protocol()))
}

func (ip IPv4Frame) writeUDPPseudoCRC(crc *CRC791) {
	crc.Write(ip.SourceAddr()[:])
	crc.Write(ip.DestinationAddr()[:])
	crc.AddUint16(uint16(ip.Protocol()))
}

// SourceAddr returns pointer to the source IPv4 address in the IP header.
func (ip IPv4Frame) SourceAddr() *[4]byte {
	return (*[4]byte)(ip.buf[12:16])
}

// DestinationAddr returns pointer to the destination IPv4 address in the IP header.
func (ip IPv4Frame) DestinationAddr() *[4]byte {
	return (*[4]byte)(ip.buf[16:20])
}

func (ip IPv4Frame) Payload() []byte {
	off := ip.HeaderLength()
	l := ip.TotalLength()
	return ip.buf[off:l]
}

type TCPFrame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (frm TCPFrame) RawData() []byte {	return frm.buf}


func (tcp TCPFrame) SourcePort() uint16 {
	return binary.BigEndian.Uint16(tcp.buf[0:2])
}

// SetSourcePort sets TCP source port. See [TCPFrame.SetSourcePort]
func (tcp TCPFrame) SetSourcePort(src uint16) {
	binary.BigEndian.PutUint16(tcp.buf[0:2], src)
}

func (tcp TCPFrame) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(tcp.buf[2:4])
}

// SetDestinationPort sets TCP destination port. See [TCPFrame.DestinationPort]
func (tcp TCPFrame) SetDestinationPort(dst uint16) {
	binary.BigEndian.PutUint16(tcp.buf[2:4], dst)
}

// Seq returns sequence number of the first data octet in this segment (except when SYN present)
// If SYN present this is the Initial Sequence Number (ISN) and the first data octet would be ISN+1.
func (tcp TCPFrame) Seq() tseq.Value {
	return tseq.Value(binary.BigEndian.Uint32(tcp.buf[4:8]))
}

// SetSeq sets Seq field. See [TCPFrame.Seq].
func (tcp TCPFrame) SetSeq(v tseq.Value) {
	binary.BigEndian.PutUint32(tcp.buf[4:8], uint32(v))
}

// Ack is the next sequence number (Seq field) the sender is expecting to receive (when ACK is present).
// In other words an Ack of X indicates all octets up to but not including X have been received.
// Once a connection is established the ACK flag should always be set.
func (tcp TCPFrame) Ack() tseq.Value {
	return tseq.Value(binary.BigEndian.Uint32(tcp.buf[8:12]))
}

// SetAck sets Ack field. See [TCPFrame.Ack].
func (tcp TCPFrame) SetAck(v tseq.Value) {
	binary.BigEndian.PutUint32(tcp.buf[8:12], uint32(v))
}

// HeaderLength uses Offset field to calculate the total length of
// the TCP header including options. Performs no validation.
func (tcp TCPFrame) HeaderLength() (tcpWords int) {
	return 4 * int(tcp.Offset())
}

// Offset returns the number of 32 bit words used to represent the header. Is a TCP field.
func (tcp TCPFrame) Offset() (tcpWords uint8) {
	return tcp.buf[12] & 0xf
}

// SetOffset sets TCP offset field. See [TCPFrame.Offset].
func (tcp TCPFrame) SetOffset() (tcpWords uint8) {
	return tcp.buf[12] & 0xf
}

// Flags returns the TCP flags contained in TCP header. See [TCPFlags].
func (tcp TCPFrame) Flags() TCPFlags { return TCPFlags(tcp.buf[13]) }

// SetFlags sets the TCP flags. See [TCPFlags].
func (tcp TCPFrame) SetFlags(flags TCPFlags) { tcp.buf[13] = uint8(flags) }

func (tcp TCPFrame) CRC() uint16 {
	return binary.BigEndian.Uint16(tcp.buf[16:18])
}

// SetCRC sets the checksum field of the TCP header. See [TCPFrame.CRC].
func (tcp TCPFrame) SetCRC(checksum uint16) {
	binary.BigEndian.PutUint16(tcp.buf[16:18], checksum)
}

func (tcp TCPFrame) CalculateCRC(ipPseudo IPv4Frame) uint16 {
	var crc CRC791
	ipPseudo.writeTCPPseudoCRC(&crc)
	expectLen := int(ipPseudo.TotalLength()) - 4*int(ipPseudo.IHL())
	if expectLen != len(tcp.buf) {
		panic("unexpected TCP buffer length mismatches IPv4 header total length")
	}
	tcp.writeCRC(&crc)
	return crc.Sum16()
}

func (tcp TCPFrame) writeCRC(crc *CRC791) {
	// Write excluding
	crc.Write(tcp.buf[:16])
	crc.Write(tcp.buf[18:])
}

func (tcp TCPFrame) SetUrgentPtr(up uint16) {
	binary.BigEndian.PutUint16(tcp.buf[18:20], up)
}

func (tcp TCPFrame) Payload() []byte {
	return tcp.buf[tcp.HeaderLength():]
}

type UDPFrame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (frm UDPFrame) RawData() []byte {	return frm.buf}


func (udp UDPFrame) SourcePort() uint16 {
	return binary.BigEndian.Uint16(udp.buf[0:2])
}

// SetSourcePort sets UDP source port. See [UDPFrame.SetSourcePort]
func (udp UDPFrame) SetSourcePort(src uint16) {
	binary.BigEndian.PutUint16(udp.buf[0:2], src)
}

func (udp UDPFrame) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(udp.buf[2:4])
}

// SetDestinationPort sets UDP destination port. See [UDPFrame.DestinationPort]
func (udp UDPFrame) SetDestinationPort(dst uint16) {
	binary.BigEndian.PutUint16(udp.buf[2:4], dst)
}

// Length specifies length in bytes of UDP header and UDP payload. The minimum length
// is 8 bytes (UDP header length). This field should match the result of the IP header
// TotalLength field minus the IP header size: udp.Length == ip.TotalLength - 4*ip.IHL
func (udp UDPFrame) Length() uint16 {
	return binary.BigEndian.Uint16(udp.buf[4:6])
}

// SetLength sets the UDP header's length field. See [UDPFrame.Length].
func (udp UDPFrame) SetLength(length uint16) {
	binary.BigEndian.PutUint16(udp.buf[4:6], length)
}

func (udp UDPFrame) CRC() uint16 {
	return binary.BigEndian.Uint16(udp.buf[6:8])
}

// SetCRC sets the UDP header's CRC field. See [UDPFrame.CRC].
func (udp UDPFrame) SetCRC(checksum uint16) {
	binary.BigEndian.PutUint16(udp.buf[6:8], checksum)
}

// Payload returns the data part of the UDP frame.
func (udp UDPFrame) Payload() []byte {
	l := udp.Length()
	return udp.buf[8:l]
}

func (udp UDPFrame) CalculateChecksum(pseudoHeader IPv4Frame) uint16 {
	var crc CRC791
	pseudoHeader.writeUDPPseudoCRC(&crc)
	crc.AddUint16(udp.Length())
	crc.AddUint16(udp.SourcePort())
	crc.AddUint16(udp.DestinationPort())
	crc.AddUint16(udp.Length())
	crc.Write(udp.Payload())
	return crc.Sum16()
}
