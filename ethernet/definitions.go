package ethernet

import (
	"strconv"
)

const (
	sizeHeaderNoVLAN = 14
)

// AppendAddr appends the text representation of the hardware address to the destination buffer.
func AppendAddr(dst []byte, hwAddr [6]byte) []byte {
	for i, b := range hwAddr {
		if i != 0 {
			dst = append(dst, ':')
		}
		if b < 16 {
			dst = append(dst, '0')
		}
		dst = strconv.AppendUint(dst, uint64(b), 16)
	}
	return dst
}

// BroadcastAddr returns the all 0xff's broadcast hardware/MAC/EUI/OUI address.
func BroadcastAddr() [6]byte {
	return [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
}

//go:generate stringer -type=Type -linecomment -output stringers.go .

type Type uint16

// IsSize returns true if the EtherType is actually the size of the payload
// and should NOT be interpreted as an EtherType.
func (et Type) IsSize() bool { return et <= 1500 }

// Ethernet type flags
const (
	TypeIPv4                Type = 0x0800 // IPv4
	TypeARP                 Type = 0x0806 // ARP
	TypeWakeOnLAN           Type = 0x0842 // wake on LAN
	TypeTRILL               Type = 0x22F3 // TRILL
	TypeDECnetPhase4        Type = 0x6003 // DECnetPhase4
	TypeRARP                Type = 0x8035 // RARP
	TypeAppleTalk           Type = 0x809B // AppleTalk
	TypeAARP                Type = 0x80F3 // AARP
	TypeIPX1                Type = 0x8137 // IPx1
	TypeIPX2                Type = 0x8138 // IPx2
	TypeQNXQnet             Type = 0x8204 // QNXQnet
	TypeIPv6                Type = 0x86DD // IPv6
	TypeEthernetFlowControl Type = 0x8808 // EthernetFlowCtl
	TypeIEEE802_3           Type = 0x8809 // IEEE802.3
	TypeCobraNet            Type = 0x8819 // CobraNet
	TypeMPLSUnicast         Type = 0x8847 // MPLS Unicast
	TypeMPLSMulticast       Type = 0x8848 // MPLS Multicast
	TypePPPoEDiscovery      Type = 0x8863 // PPPoE discovery
	TypePPPoESession        Type = 0x8864 // PPPoE session
	TypeJumboFrames         Type = 0x8870 // jumbo frames
	TypeHomePlug1_0MME      Type = 0x887B // home plug 1 0mme
	TypeIEEE802_1X          Type = 0x888E // IEEE 802.1x
	TypePROFINET            Type = 0x8892 // profinet
	TypeHyperSCSI           Type = 0x889A // hyper SCSI
	TypeAoE                 Type = 0x88A2 // AoE
	TypeEtherCAT            Type = 0x88A4 // EtherCAT
	TypeEthernetPowerlink   Type = 0x88AB // Ethernet powerlink
	TypeLLDP                Type = 0x88CC // LLDP
	TypeSERCOS3             Type = 0x88CD // SERCOS3
	TypeHomePlugAVMME       Type = 0x88E1 // home plug AVMME
	TypeMRP                 Type = 0x88E3 // MRP
	TypeIEEE802_1AE         Type = 0x88E5 // IEEE 802.1ae
	TypeIEEE1588            Type = 0x88F7 // IEEE 1588
	TypeIEEE802_1ag         Type = 0x8902 // IEEE 802.1ag
	TypeFCoE                Type = 0x8906 // FCoE
	TypeFCoEInit            Type = 0x8914 // FCoE init
	TypeRoCE                Type = 0x8915 // RoCE
	TypeCTP                 Type = 0x9000 // CTP
	TypeVeritasLLT          Type = 0xCAFE // Veritas LLT
	TypeVLAN                Type = 0x8100 // VLAN
	TypeServiceVLAN         Type = 0x88a8 // service VLAN
	// minEthPayload is the minimum payload size for an Ethernet frame, assuming
	// that no 802.1Q VLAN tags are present.
	minEthPayload = 46
)

// VLANTag holds priority (PCP) Drop indicator (DEI) and VLAN ID bits of the VLAN tag field.
type VLANTag uint16

// DropEligibleIndicator returns true if the DEI bit is set.
// DEI may be used separately or in conjunction with PCP to indicate frames eligible to be dropped in the presence of congestion.
func (vt VLANTag) DropEligibleIndicator() bool { return vt&(1<<3) != 0 }

// PriorityCodePoint is 3-bit field which refers to the IEEE 802.1p class of service (CoS) and maps to the frame priority level. Different PCP values can be used to prioritize different classes of traffic
func (vt VLANTag) PriorityCodePoint() uint8 { return uint8(vt & 0b111) }

// VLANIdentifier 12 bit field which specifies which VLAN the frame belongs to. Values of 0 and 4095 are reserved.
func (vt VLANTag) VLANIdentifier() uint16 { return uint16(vt) >> 4 }
