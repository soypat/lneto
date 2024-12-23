package lneto

//go:generate stringer -type=EtherType -linecomment -output stringers.go .

type EtherType uint16

// Ethernet type flags
const (
	EtherTypeIPv4                EtherType = 0x0800 // IPv4
	EtherTypeARP                 EtherType = 0x0806 // ARP
	EtherTypeWakeOnLAN           EtherType = 0x0842 // wake on LAN
	EtherTypeTRILL               EtherType = 0x22F3 // TRILL
	EtherTypeDECnetPhase4        EtherType = 0x6003 // DECnetPhase4
	EtherTypeRARP                EtherType = 0x8035 // RARP
	EtherTypeAppleTalk           EtherType = 0x809B // AppleTalk
	EtherTypeAARP                EtherType = 0x80F3 // AARP
	EtherTypeIPX1                EtherType = 0x8137 // IPx1
	EtherTypeIPX2                EtherType = 0x8138 // IPx2
	EtherTypeQNXQnet             EtherType = 0x8204 // QNXQnet
	EtherTypeIPv6                EtherType = 0x86DD // IPv6
	EtherTypeEthernetFlowControl EtherType = 0x8808 // EthernetFlowCtl
	EtherTypeIEEE802_3           EtherType = 0x8809 // IEEE802.3
	EtherTypeCobraNet            EtherType = 0x8819 // CobraNet
	EtherTypeMPLSUnicast         EtherType = 0x8847 // MPLS Unicast
	EtherTypeMPLSMulticast       EtherType = 0x8848 // MPLS Multicast
	EtherTypePPPoEDiscovery      EtherType = 0x8863 // PPPoE discovery
	EtherTypePPPoESession        EtherType = 0x8864 // PPPoE session
	EtherTypeJumboFrames         EtherType = 0x8870 // jumbo frames
	EtherTypeHomePlug1_0MME      EtherType = 0x887B // home plug 1 0mme
	EtherTypeIEEE802_1X          EtherType = 0x888E // IEEE 802.1x
	EtherTypePROFINET            EtherType = 0x8892 // profinet
	EtherTypeHyperSCSI           EtherType = 0x889A // hyper SCSI
	EtherTypeAoE                 EtherType = 0x88A2 // AoE
	EtherTypeEtherCAT            EtherType = 0x88A4 // EtherCAT
	EtherTypeEthernetPowerlink   EtherType = 0x88AB // Ethernet powerlink
	EtherTypeLLDP                EtherType = 0x88CC // LLDP
	EtherTypeSERCOS3             EtherType = 0x88CD // SERCOS3
	EtherTypeHomePlugAVMME       EtherType = 0x88E1 // home plug AVMME
	EtherTypeMRP                 EtherType = 0x88E3 // MRP
	EtherTypeIEEE802_1AE         EtherType = 0x88E5 // IEEE 802.1ae
	EtherTypeIEEE1588            EtherType = 0x88F7 // IEEE 1588
	EtherTypeIEEE802_1ag         EtherType = 0x8902 // IEEE 802.1ag
	EtherTypeFCoE                EtherType = 0x8906 // FCoE
	EtherTypeFCoEInit            EtherType = 0x8914 // FCoE init
	EtherTypeRoCE                EtherType = 0x8915 // RoCE
	EtherTypeCTP                 EtherType = 0x9000 // CTP
	EtherTypeVeritasLLT          EtherType = 0xCAFE // Veritas LLT
	EtherTypeVLAN                EtherType = 0x8100 // VLAN
	EtherTypeServiceVLAN         EtherType = 0x88a8 // service VLAN
	// minEthPayload is the minimum payload size for an Ethernet frame, assuming
	// that no 802.1Q VLAN tags are present.
	minEthPayload = 46
)

type IPToS uint8

func (tos IPToS) DSCP() uint8 { return uint8(tos) >> 2 }

func (tos IPToS) ECN() uint8 { return uint8(tos & 0b11) }

type IPv4Flags uint16

func (f IPv4Flags) DontFragment() bool     { return f&0x4000 != 0 }
func (f IPv4Flags) MoreFragments() bool    { return f&0x8000 != 0 }
func (f IPv4Flags) FragmentOffset() uint16 { return uint16(f) & 0x1fff }

type TCPFlags uint8
