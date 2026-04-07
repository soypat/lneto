package lneto

// StackNode is an abstraction of a packet exchanging protocol controller. This is the building block for all protocols,
// from Ethernet to IP to TCP, practically any protocol can be expressed as a StackNode and function completely.
type StackNode interface {
	// Encapsulate writes the stack node's frame into carrierData[offsetToFrame:]
	// along with any other frame or payload the stack node encapsulates.
	// The returned integer is amount of bytes written such that carrierData[offsetToFrame:offsetToFrame+n]
	// contains written data. Data inside carrierData[:offsetToFrame] usually contains data necessary for
	// a StackNode to correctly emit valid frame data: such is the case for TCP packets which require IP
	// frame data for checksum calculation. Thus StackNodes must provide fields in their own frame
	// required by sub-stacknodes for correct encapsulation; in the case of IPv4/6 this means including fields
	// used in pseudo-header checksum like local IP (see [ipv4.CRCWriteUDPPseudo]).
	//
	// offsetToIP is the offset to the IP frame, if present, else its value should be -1.
	// The relation offsetToIP<=offsetToFrame should always hold.
	//
	// When [net.ErrClosed] is returned the StackNode should be discarded and any written data passed up normally.
	// Errors returned by Encapsulate are "extraordinary" and should not be returned unless the StackNode is receiving invalid carrierData/frameOffset.
	Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error)
	// Demux reads from the argument buffer where frameOffset is the offset of this StackNode's frame first byte.
	// The stack node then dispatches(demuxes) the encapsulated frames to its corresponding sub-stack-node(s).
	Demux(carrierData []byte, frameOffset int) error
	// LocalPort returns the local port of this StackNode or zero if not set/relevant.
	LocalPort() uint16
	// Protocol returns a number identifying the protocol used by this [StackNode].
	// Can be an [IPProto] among other types of protocols, i.e: ethernet.Protocol for a link layer [StackNode].
	Protocol() uint64
	// ConnectionID returns the pointer to the connection context number or ConnectionID. If the value this pointer changes
	// since the first connection registration that means the [StackNode] should be discarded since its lifetime has terminated.
	ConnectionID() *uint64
	// TODO(pato,ddirect): Do we eventually want to trigger writes to buffers asynchronously?
	// SetFlagPending(flagPending func(numPendingEncapsulations int))
}

//go:generate stringer -type=IPProto,errGeneric -linecomment -output stringers.go .

// IPProto represents the IP protocol number.
type IPProto uint8

// IP protocol numbers.
const (
	IPProtoHopByHop        IPProto = 0   // IPv6 Hop-by-Hop Option [RFC8200]
	IPProtoICMP            IPProto = 1   // ICMP [RFC792]
	IPProtoIGMP            IPProto = 2   // IGMP [RFC1112]
	IPProtoGGP             IPProto = 3   // Gateway-to-Gateway [RFC823]
	IPProtoIPv4            IPProto = 4   // IPv4 encapsulation [RFC2003]
	IPProtoST              IPProto = 5   // Stream [RFC1190, RFC1819]
	IPProtoTCP             IPProto = 6   // TCP [RFC9293]
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
	IPProtoUDP             IPProto = 17  // UDP [RFC768]
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
	IPProtoUDPLite         IPProto = 136 // UDP-Lite [RFC3828]
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
