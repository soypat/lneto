package dhcpv4

import (
	"errors"
)

//go:generate stringer -type=OptNum,Op,MessageType,ClientState -linecomment -output stringers.go

// ClientState transition table during request:
//
//	StateInit      -> | Send out Discover  | -> StateSelecting
//	StateSelecting -> |Accept Offer+Request| -> StateRequesting
//	StateRequesting-> |    Receive Ack     | -> StateBound
type ClientState uint8

const (
	_ ClientState = iota
	// On clean slate boot, abort, NAK or decline enter the INIT state.
	StateInit // init
	// After sending out a Discover enter SELECTING.
	StateSelecting // selecting
	// After receiving a worthy offer and sending out request for offer enter REQUESTING.
	StateRequesting // requesting
	// On ACK to Request enter BOUND.
	StateBound      // bound
	StateRenewing   // renewing
	StateRebinding  // rebinding
	StateInitReboot // init-reboot
	StateRebooting  // rebooting
)

func AppendOption(dst []byte, opt OptNum, data ...byte) []byte {
	if len(data) > 255 {
		panic("option data too long")
	}
	dst = append(dst, byte(opt), byte(len(data)))
	dst = append(dst, data...)
	return dst
}

func EncodeOption(dst []byte, opt OptNum, data ...byte) (int, error) {
	if len(data) > 255 {
		return 0, errors.New("DHCPv4 option data too long (>255)")
	} else if len(dst) < 2+len(data) {
		return 0, errors.New("DHCP option buffer too short")
	}
	_ = dst[2+len(data)]
	dst[0] = byte(opt)
	dst[1] = byte(len(data))
	copy(dst[2:], data)
	return 2 + len(data), nil
}

type OptNum uint8

// DHCP options. Taken from https://help.sonicwall.com/help/sw/eng/6800/26/2/3/content/Network_DHCP_Server.042.12.htm.
const (
	OptWordAligned                 OptNum = 0  // word-aligned
	OptSubnetMask                  OptNum = 1  // subnet mask
	OptTimeOffset                  OptNum = 2  // Time offset in seconds from UTC
	OptRouter                      OptNum = 3  // N/4 router addresses
	OptTimeServers                 OptNum = 4  // N/4 time server addresses
	OptNameServers                 OptNum = 5  // N/4 IEN-116 server addresses
	OptDNSServers                  OptNum = 6  // N/4 DNS server addresses
	OptLogServers                  OptNum = 7  // N/4 logging server addresses
	OptCookieServers               OptNum = 8  // N/4 quote server addresses
	OptLPRServers                  OptNum = 9  // N/4 printer server addresses
	OptImpressServers              OptNum = 10 // N/4 impress server addresses
	OptRLPServers                  OptNum = 11 // N/4 RLP server addresses
	OptHostName                    OptNum = 12 // Hostname string
	OptBootFileSize                OptNum = 13 // Size of boot file in 512 byte chunks
	OptMeritDumpFile               OptNum = 14 // Client to dump and name of file to dump to
	OptDomainName                  OptNum = 15 // The DNS domain name of the client
	OptSwapServer                  OptNum = 16 // Swap server addresses
	OptRootPath                    OptNum = 17 // Path name for root disk
	OptExtensionFile               OptNum = 18 // Patch name for more BOOTP info
	OptIPLayerForwarding           OptNum = 19 // Enable or disable IP forwarding
	OptSrcrouteenabler             OptNum = 20 // Enable or disable source routing
	OptPolicyFilter                OptNum = 21 // Routing policy filters
	OptMaximumDGReassemblySize     OptNum = 22 // Maximum datagram reassembly size
	OptDefaultIPTTL                OptNum = 23 // Default IP time-to-live
	OptPathMTUAgingTimeout         OptNum = 24 // Path MTU aging timeout
	OptMTUPlateau                  OptNum = 25 // Path MTU plateau table
	OptInterfaceMTUSize            OptNum = 26 // Interface MTU size
	OptAllSubnetsAreLocal          OptNum = 27 // All subnets are local
	OptBroadcastAddress            OptNum = 28 // Broadcast address
	OptPerformMaskDiscovery        OptNum = 29 // Perform mask discovery
	OptProvideMasktoOthers         OptNum = 30 // Provide mask to others
	OptPerformRouterDiscovery      OptNum = 31 // Perform router discovery
	OptRouterSolicitationAddress   OptNum = 32 // Router solicitation address
	OptStaticRoutingTable          OptNum = 33 // Static routing table
	OptTrailerEncapsulation        OptNum = 34 // Trailer encapsulation
	OptARPCacheTimeout             OptNum = 35 // ARP cache timeout
	OptEthernetEncapsulation       OptNum = 36 // Ethernet encapsulation
	OptDefaultTCPTimetoLive        OptNum = 37 // Default TCP time to live
	OptTCPKeepaliveInterval        OptNum = 38 // TCP keepalive interval
	OptTCPKeepaliveGarbage         OptNum = 39 // TCP keepalive garbage
	OptNISDomainName               OptNum = 40 // NIS domain name
	OptNISServerAddresses          OptNum = 41 // NIS server addresses
	OptNTPServersAddresses         OptNum = 42 // NTP servers addresses
	OptVendorSpecificInformation   OptNum = 43 // Vendor specific information
	OptNetBIOSNameServer           OptNum = 44 // NetBIOS name server
	OptNetBIOSDatagramDistribution OptNum = 45 // NetBIOS datagram distribution
	OptNetBIOSNodeType             OptNum = 46 // NetBIOS node type
	OptNetBIOSScope                OptNum = 47 // NetBIOS scope
	OptXWindowFontServer           OptNum = 48 // X window font server
	OptXWindowDisplayManager       OptNum = 49 // X window display manager
	OptRequestedIPaddress          OptNum = 50 // Requested IP address
	OptIPAddressLeaseTime          OptNum = 51 // IP address lease time
	OptOptionOverload              OptNum = 52 // Overload “sname” or “file”
	OptMessageType                 OptNum = 53 // DHCP message type.
	OptServerIdentification        OptNum = 54 // DHCP server identification
	OptParameterRequestList        OptNum = 55 // Parameter request list
	OptMessage                     OptNum = 56 // DHCP error message
	OptMaximumMessageSize          OptNum = 57 // DHCP maximum message size
	OptRenewTimeValue              OptNum = 58 // DHCP renewal (T1) time
	OptRebindingTimeValue          OptNum = 59 // DHCP rebinding (T2) time
	OptClientIdentifier            OptNum = 60 // Client identifier
	OptClientIdentifier1           OptNum = 61 // Client identifier(1)
)

type Op byte

const (
	opUndefined Op = iota // undefined
	OpRequest             // request
	OpReply               // reply
)

type MessageType uint8

const (
	msg         MessageType = iota // undefined
	MsgDiscover                    // discover
	MsgOffer                       // offer
	MsgRequest                     // request
	MsgDecline                     // decline
	MsgAck                         // ack
	MsgNack                        // nak
	MsgRelease                     // release
	MsgInform                      // inform
)

type Flags uint16
