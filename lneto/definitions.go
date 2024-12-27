package lneto

//go:generate stringer -type=EtherType,IPProto,ARPOp -linecomment -output stringers.go .

type EtherType uint16

// IsSize returns true if the EtherType is actually the size of the payload
// and should NOT be interpreted as an EtherType.
func (et EtherType) IsSize() bool { return et <= 1500 }

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

// VLANTag holds priority (PCP) Drop indicator (DEI) and VLAN ID bits of the VLAN tag field.
type VLANTag uint16

// DropEligibleIndicator returns true if the DEI bit is set.
// DEI may be used separately or in conjunction with PCP to indicate frames eligible to be dropped in the presence of congestion.
func (vt VLANTag) DropEligibleIndicator() bool { return vt&(1<<3) != 0 }

// PriorityCodePoint is 3-bit field which refers to the IEEE 802.1p class of service (CoS) and maps to the frame priority level. Different PCP values can be used to prioritize different classes of traffic
func (vt VLANTag) PriorityCodePoint() uint8 { return uint8(vt & 0b111) }

// VLANIdentifier 12 bit field which specifies which VLAN the frame belongs to. Values of 0 and 4095 are reserved.
func (vt VLANTag) VLANIdentifier() uint16 { return uint16(vt) >> 4 }

// IPToS represents the Traffic Class (a.k.a Type of Service).
type IPToS uint8

// DS returns the top 6 bits of the IPv4 ToS holding the Differentiated Services field
// which is used to classify packets.
func (tos IPToS) DS() uint8 { return uint8(tos) >> 2 }

// ECN is the Explicit Congestion Notification which provides congestion control and non-congestion control traffic.
func (tos IPToS) ECN() uint8 { return uint8(tos & 0b11) }

// IPv4Flags holds fragmentation field data of an IPv4 header.
type IPv4Flags uint16

// IsEvil returns true if evil bit set as per [RFC3514].
//
// [RFC3514]: https://datatracker.ietf.org/doc/html/rfc3514
func (f IPv4Flags) IsEvil() bool { return f&2000 != 0 }

// DontFragment specifies whether the datagram can not be fragmented.
// This can be used when sending packets to a host that does not have resources to perform reassembly of fragments.
// If the DontFragment(DF) flag is set, and fragmentation is required to route the packet, then the packet is dropped.
func (f IPv4Flags) DontFragment() bool { return f&0x4000 != 0 }

// MoreFragments is cleared for unfragmented packets.
// For fragmented packets, all fragments except the last have the MF flag set.
// The last fragment has a non-zero Fragment Offset field, so it can still be differentiated from an unfragmented packet.
func (f IPv4Flags) MoreFragments() bool { return f&0x8000 != 0 }

// FragmentOffset specifies the offset of a particular fragment relative to the beginning of the original unfragmented IP datagram.
// Fragments are specified in units of 8 bytes, which is why fragment lengths are always a multiple of 8; except the last, which may be smaller.
// The fragmentation offset value for the first fragment is always 0.
func (f IPv4Flags) FragmentOffset() uint16 { return uint16(f) & 0x1fff }

const (
	sizeHeaderIPv4      = 20
	sizeHeaderTCP       = 20
	sizeHeaderEthNoVLAN = 14
	sizeHeaderUDP       = 8
	sizeHeaderARPv4     = 28
	sizeHeaderIPv6      = 40
)

// IPProto represents the IP protocol number.
type IPProto uint8

// IP protocol numbers.
const (
	IPProtoHopByHop        IPProto = 0   // IPv6 Hop-by-Hop Option [RFC8200]
	IPProtoICMP            IPProto = 1   // Internet Control Message [RFC792]
	IPProtoIGMP            IPProto = 2   // Internet Group Management [RFC1112]
	IPProtoGGP             IPProto = 3   // Gateway-to-Gateway [RFC823]
	IPProtoIPv4            IPProto = 4   // IPv4 encapsulation [RFC2003]
	IPProtoST              IPProto = 5   // Stream [RFC1190, RFC1819]
	IPProtoTCP             IPProto = 6   // Transmission Control [RFC793]
	IPProtoCBT             IPProto = 7   // CBT [Ballardie]
	IPProtoEGP             IPProto = 8   // Exterior Gateway Protocol [RFC888]
	IPProtoIGP             IPProto = 9   // any private interior gateway (used by Cisco for their IGRP)
	IPProtoBBNRCCMON       IPProto = 10  // BBN RCC Monitoring
	IPProtoNVP             IPProto = 11  // Network Voice Protocol [RFC741]
	IPProtoPUP             IPProto = 12  // PUP
	IPProtoARGUS           IPProto = 13  // ARGUS
	IPProtoEMCON           IPProto = 14  // EMCON
	IPProtoXNET            IPProto = 15  // Cross Net Debugger
	IPProtoCHAOS           IPProto = 16  // Chaos
	IPProtoUDP             IPProto = 17  // User Datagram [RFC768]
	IPProtoMUX             IPProto = 18  // Multiplexing
	IPProtoDCNMEAS         IPProto = 19  // DCN Measurement Subsystems
	IPProtoHMP             IPProto = 20  // Host Monitoring [RFC869]
	IPProtoPRM             IPProto = 21  // Packet Radio Measurement
	IPProtoXNSIDP          IPProto = 22  // XEROX NS IDP
	IPProtoTRUNK1          IPProto = 23  // Trunk-1
	IPProtoTRUNK2          IPProto = 24  // Trunk-2
	IPProtoLEAF1           IPProto = 25  // Leaf-1
	IPProtoLEAF2           IPProto = 26  // Leaf-2
	IPProtoRDP             IPProto = 27  // Reliable Data Protocol [RFC908]
	IPProtoIRTP            IPProto = 28  // Internet Reliable Transaction [RFC938]
	IPProtoISO_TP4         IPProto = 29  // ISO Transport Protocol Class 4 [RFC905]
	IPProtoNETBLT          IPProto = 30  // Bulk Data Transfer Protocol [RFC998]
	IPProtoMFE_NSP         IPProto = 31  // MFE Network Services Protocol
	IPProtoMERIT_INP       IPProto = 32  // MERIT Internodal Protocol
	IPProtoDCCP            IPProto = 33  // Datagram Congestion Control Protocol [RFC4340]
	IPProto3PC             IPProto = 34  // Third Party Connect Protocol
	IPProtoIDPR            IPProto = 35  // Inter-Domain Policy Routing Protocol
	IPProtoXTP             IPProto = 36  // XTP
	IPProtoDDP             IPProto = 37  // Datagram Delivery Protocol
	IPProtoIDPRCMTP        IPProto = 38  // IDPR Control Message Transport Proto
	IPProtoTPPLUSPLUS      IPProto = 39  // TP++ Transport Protocol
	IPProtoIL              IPProto = 40  // IL Transport Protocol
	IPProtoIPv6            IPProto = 41  // IPv6 encapsulation [RFC2473]
	IPProtoSDRP            IPProto = 42  // Source Demand Routing Protocol
	IPProtoIPv6Route       IPProto = 43  // Routing Header for IPv6 [RFC8200]
	IPProtoIPv6Frag        IPProto = 44  // Fragment Header for IPv6 [RFC8200]
	IPProtoIDRP            IPProto = 45  // Inter-Domain Routing Protocol
	IPProtoRSVP            IPProto = 46  // Reservation Protocol [RFC2205]
	IPProtoGRE             IPProto = 47  // Generic Routing Encapsulation [RFC2784]
	IPProtoDSR             IPProto = 48  // Dynamic Source Routing Protocol
	IPProtoBNA             IPProto = 49  // BNA
	IPProtoESP             IPProto = 50  // Encap Security Payload [RFC4303]
	IPProtoAH              IPProto = 51  // Authentication Header [RFC4302]
	IPProtoINLSP           IPProto = 52  // Integrated Net Layer Security TUBA
	IPProtoSWIPE           IPProto = 53  // IP with Encryption
	IPProtoNARP            IPProto = 54  // NBMA Address Resolution Protocol
	IPProtoMOBILE          IPProto = 55  // IP Mobility
	IPProtoTLSP            IPProto = 56  // Transport Layer Security Protocol using Kryptonet key management
	IPProtoSKIP            IPProto = 57  // SKIP
	IPProtoIPv6ICMP        IPProto = 58  // ICMP for IPv6 [RFC8200]
	IPProtoIPv6NoNxt       IPProto = 59  // No Next Header for IPv6 [RFC8200]
	IPProtoIPv6Opts        IPProto = 60  // Destination Options for IPv6 [RFC8200]
	IPProtoCFTP            IPProto = 62  // CFTP
	IPProtoSATEXPAK        IPProto = 64  // SATNET and Backroom EXPAK
	IPProtoKRYPTOLAN       IPProto = 65  // Kryptolan
	IPProtoRVD             IPProto = 66  // MIT Remote Virtual Disk Protocol
	IPProtoIPPC            IPProto = 67  // Internet Pluribus Packet Core
	IPProtoSATMON          IPProto = 69  // SATNET Monitoring
	IPProtoVISA            IPProto = 70  // VISA Protocol
	IPProtoIPCV            IPProto = 71  // Internet Packet Core Utility
	IPProtoCPNX            IPProto = 72  // Computer Protocol Network Executive
	IPProtoCPHB            IPProto = 73  // Computer Protocol Heart Beat
	IPProtoWSN             IPProto = 74  // Wang Span Network
	IPProtoPVP             IPProto = 75  // Packet Video Protocol
	IPProtoBRSATMON        IPProto = 76  // Backroom SATNET Monitoring
	IPProtoSUNND           IPProto = 77  // SUN ND PROTOCOL-Temporary
	IPProtoWBMON           IPProto = 78  // WIDEBAND Monitoring
	IPProtoWBEXPAK         IPProto = 79  // WIDEBAND EXPAK
	IPProtoISOIP           IPProto = 80  // ISO Internet Protocol
	IPProtoVMTP            IPProto = 81  // VMTP
	IPProtoSECUREVMTP      IPProto = 82  // SECURE-VMTP
	IPProtoVINES           IPProto = 83  // VINES
	IPProtoTTP             IPProto = 84  // TTP
	IPProtoNSFNETIGP       IPProto = 85  // NSFNET-IGP
	IPProtoDGP             IPProto = 86  // Dissimilar Gateway Protocol
	IPProtoTCF             IPProto = 87  // TCF
	IPProtoEIGRP           IPProto = 88  // EIGRP
	IPProtoOSPFIGP         IPProto = 89  // OSPFIGP
	IPProtoSpriteRPC       IPProto = 90  // Sprite RPC Protocol
	IPProtoLARP            IPProto = 91  // Locus Address Resolution Protocol
	IPProtoMTP             IPProto = 92  // Multicast Transport Protocol
	IPProtoAX25            IPProto = 93  // AX.25 Frames
	IPProtoIPIP            IPProto = 94  // IP-within-IP Encapsulation Protocol
	IPProtoMICP            IPProto = 95  // Mobile Internetworking Control Pro.
	IPProtoSCCSP           IPProto = 96  // Semaphore Communications Sec. Pro.
	IPProtoETHERIP         IPProto = 97  // Ethernet-within-IP Encapsulation
	IPProtoENCAP           IPProto = 98  // Encapsulation Header
	IPProtoGMTP            IPProto = 100 // GMTP
	IPProtoIFMP            IPProto = 101 // Ipsilon Flow Management Protocol
	IPProtoPNNI            IPProto = 102 // PNNI over IP
	IPProtoPIM             IPProto = 103 // Protocol Independent Multicast
	IPProtoARIS            IPProto = 104 // ARIS
	IPProtoSCPS            IPProto = 105 // SCPS
	IPProtoQNX             IPProto = 106 // QNX
	IPProtoAN              IPProto = 107 // Active Networks
	IPProtoIPComp          IPProto = 108 // IP Payload Compression Protocol
	IPProtoSNP             IPProto = 109 // Sitara Networks Protocol
	IPProtoCompaqPeer      IPProto = 110 // Compaq Peer Protocol
	IPProtoIPXInIP         IPProto = 111 // IPX in IP
	IPProtoVRRP            IPProto = 112 // Virtual Router Redundancy Protocol
	IPProtoPGM             IPProto = 113 // PGM Reliable Transport Protocol
	IPProtoL2TP            IPProto = 115 // Layer Two Tunneling Protocol v3
	IPProtoDDX             IPProto = 116 // D-II Data Exchange (DDX)
	IPProtoIATP            IPProto = 117 // Interactive Agent Transfer Protocol
	IPProtoSTP             IPProto = 118 // Schedule Transfer Protocol
	IPProtoSRP             IPProto = 119 // SpectraLink Radio Protocol
	IPProtoUTI             IPProto = 120 // UTI
	IPProtoSMP             IPProto = 121 // Simple Message Protocol
	IPProtoSM              IPProto = 122 // SM
	IPProtoPTP             IPProto = 123 // Performance Transparency Protocol
	IPProtoISIS            IPProto = 124 // ISIS over IPv4
	IPProtoFIRE            IPProto = 125 // FIRE
	IPProtoCRTP            IPProto = 126 // Combat Radio Transport Protocol
	IPProtoCRUDP           IPProto = 127 // Combat Radio User Datagram
	IPProtoSSCOPMCE        IPProto = 128 // SSCOPMCE
	IPProtoIPLT            IPProto = 129 // IPLT
	IPProtoSPS             IPProto = 130 // Secure Packet Shield
	IPProtoPIPE            IPProto = 131 // Private IP Encapsulation within IP
	IPProtoSCTP            IPProto = 132 // Stream Control Transmission Protocol
	IPProtoFC              IPProto = 133 // Fibre Channel
	IPProtoRSVP_E2E_IGNORE IPProto = 134 // RSVP-E2E-IGNORE
	IPProtoMobilityHeader  IPProto = 135 // Mobility Header
	IPProtoUDPLite         IPProto = 136 // UDPLite
	IPProtoMPLSInIP        IPProto = 137 // MPLS-in-IP
	IPProtoMANET           IPProto = 138 // MANET Protocols
	IPProtoHIP             IPProto = 139 // Host Identity Protocol
	IPProtoShim6           IPProto = 140 // Shim6 Protocol
	IPProtoWESP            IPProto = 141 // Wrapped Encapsulating Security Payload
	IPProtoROHC            IPProto = 142 // Robust Header Compression
	IPProtoEthernet        IPProto = 143 // Ethernet
	IPProtoAGGFRAG         IPProto = 144 // AGGFRAG Encapsulation payload for ESP
	IPProtoNSH             IPProto = 145 // Network Service Header
)

// ARPOp represents the type of ARP packet, either request or reply/response.
type ARPOp uint8

const (
	ARPRequest ARPOp = 1 // request
	ARPReply   ARPOp = 2 // reply
)
