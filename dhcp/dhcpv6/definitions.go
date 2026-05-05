package dhcpv6

import (
	"encoding/binary"

	"github.com/soypat/lneto"
)

// ClientState transition table during request:
//
//	StateInit        -> | Send out Solicit  | -> StateSoliciting
//	StateSoliciting  -> | Accept Advertise  | -> StateRequesting
//	StateRequesting  -> | Receive Reply     | -> StateBound

//go:generate stringer -type=MsgType,ClientState,OptCode,StatusCode,DUIDType -linecomment -output stringers.go

const (
	// ClientPort is the UDP port DHCPv6 clients listen on.
	ClientPort = 546
	// ServerPort is the UDP port DHCPv6 servers listen on.
	ServerPort = 547
	// OptionsOffset is the byte offset where DHCPv6 options begin in a client-server message.
	// Layout: MsgType(1) + TransactionID(3).
	OptionsOffset = 4
)

// MsgType is the DHCPv6 message type (RFC 8415 §7.3).
type MsgType uint8

const (
	MsgSolicit       MsgType = 1  // solicit
	MsgAdvertise     MsgType = 2  // advertise
	MsgRequest       MsgType = 3  // request
	MsgConfirm       MsgType = 4  // confirm
	MsgRenew         MsgType = 5  // renew
	MsgRebind        MsgType = 6  // rebind
	MsgReply         MsgType = 7  // reply
	MsgRelease       MsgType = 8  // release
	MsgDecline       MsgType = 9  // decline
	MsgReconfigure   MsgType = 10 // reconfigure
	MsgInformRequest MsgType = 11 // inform-request
	MsgRelayForw     MsgType = 12 // relay-forw
	MsgRelayRepl     MsgType = 13 // relay-repl
)

// ClientState is the DHCPv6 client DORA state machine state.
type ClientState uint8

const (
	_               ClientState = iota
	StateInit                   // init
	StateSoliciting             // soliciting
	StateRequesting             // requesting
	StateBound                  // bound
	StateRenewing               // renewing
	StateRebinding              // rebinding
)

// HasIP returns true if the state indicates the Client has an IPv6 address assigned.
func (s ClientState) HasIP() bool {
	return s == StateBound || s == StateRenewing || s == StateRebinding
}

// OptCode is a DHCPv6 option code (RFC 8415 §21), encoded as a 2-byte big-endian value.
type OptCode uint16

const (
	OptClientID     OptCode = 1  // client-id
	OptServerID     OptCode = 2  // server-id
	OptIANA         OptCode = 3  // ia-na
	OptIATA         OptCode = 4  // ia-ta
	OptIAAddr       OptCode = 5  // iaaddr
	OptORO          OptCode = 6  // oro
	OptPreference   OptCode = 7  // preference
	OptElapsedTime  OptCode = 8  // elapsed-time
	OptRelayMsg     OptCode = 9  // relay-msg
	OptAuth         OptCode = 11 // auth
	OptUnicast      OptCode = 12 // unicast
	OptStatusCode   OptCode = 13 // status-code
	OptRapidCommit  OptCode = 14 // rapid-commit
	OptUserClass    OptCode = 15 // user-class
	OptVendorClass  OptCode = 16 // vendor-class
	OptVendorOpts   OptCode = 17 // vendor-opts
	OptInterfaceID  OptCode = 18 // interface-id
	OptReconfMsg    OptCode = 19 // reconf-msg
	OptReconfAccept OptCode = 20 // reconf-accept
	OptDNSServers   OptCode = 23 // dns-servers
	OptDomainList   OptCode = 24 // domain-list
	OptIAPD         OptCode = 25 // ia-pd
	OptIAPrefix     OptCode = 26 // iaprefix
	OptNTPServer    OptCode = 56 // ntp-server
)

// DUIDType is the DHCP Unique Identifier type (RFC 8415 §11).
type DUIDType uint16

const (
	DUIDTypeLLT DUIDType = 1 // duid-llt
	DUIDTypeEN  DUIDType = 2 // duid-en
	DUIDTypeLL  DUIDType = 3 // duid-ll
)

// StatusCode is the DHCPv6 status code value (RFC 8415 §21.13).
type StatusCode uint16

const (
	StatusSuccess      StatusCode = 0 // success
	StatusUnspecFail   StatusCode = 1 // unspec-fail
	StatusNoAddrsAvail StatusCode = 2 // no-addrs-avail
	StatusNoBinding    StatusCode = 3 // no-binding
	StatusNotOnLink    StatusCode = 4 // not-on-link
	StatusUseMulticast StatusCode = 5 // use-multicast
)

// EncodeOption writes a DHCPv6 TLV option into dst.
// Format: code(2) + length(2) + data.
func EncodeOption(dst []byte, code OptCode, data ...byte) (int, error) {
	if len(data) > 0xffff {
		return 0, lneto.ErrInvalidLengthField
	} else if len(dst) < 4+len(data) {
		return 0, lneto.ErrShortBuffer
	}
	binary.BigEndian.PutUint16(dst[0:2], uint16(code))
	binary.BigEndian.PutUint16(dst[2:4], uint16(len(data)))
	copy(dst[4:], data)
	return 4 + len(data), nil
}

// EncodeOption16 encodes a single uint16 value as a DHCPv6 option.
func EncodeOption16(dst []byte, code OptCode, v uint16) (int, error) {
	return EncodeOption(dst, code, byte(v>>8), byte(v))
}

// EncodeOption32 encodes a single uint32 value as a DHCPv6 option.
func EncodeOption32(dst []byte, code OptCode, v uint32) (int, error) {
	return EncodeOption(dst, code, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// EncodeOptionIANA encodes an IA_NA option (RFC 8415 §21.4).
// Layout: code(2) + len(2) + IAID(4) + T1(4) + T2(4) + subOpts.
func EncodeOptionIANA(dst []byte, iaid [4]byte, t1, t2 uint32, subOpts []byte) (int, error) {
	const fixedLen = 12 // IAID(4) + T1(4) + T2(4)
	dataLen := fixedLen + len(subOpts)
	if len(dst) < 4+dataLen {
		return 0, lneto.ErrShortBuffer
	}
	binary.BigEndian.PutUint16(dst[0:2], uint16(OptIANA))
	binary.BigEndian.PutUint16(dst[2:4], uint16(dataLen))
	copy(dst[4:8], iaid[:])
	binary.BigEndian.PutUint32(dst[8:12], t1)
	binary.BigEndian.PutUint32(dst[12:16], t2)
	copy(dst[16:], subOpts)
	return 4 + dataLen, nil
}

// EncodeOptionIAAddr encodes an IAADDR option (RFC 8415 §21.6).
// Layout: code(2) + len(2) + addr(16) + preferred(4) + valid(4).
func EncodeOptionIAAddr(dst []byte, addr [16]byte, preferred, valid uint32) (int, error) {
	const dataLen = 24 // addr(16) + preferred(4) + valid(4)
	if len(dst) < 4+dataLen {
		return 0, lneto.ErrShortBuffer
	}
	binary.BigEndian.PutUint16(dst[0:2], uint16(OptIAAddr))
	binary.BigEndian.PutUint16(dst[2:4], dataLen)
	copy(dst[4:20], addr[:])
	binary.BigEndian.PutUint32(dst[20:24], preferred)
	binary.BigEndian.PutUint32(dst[24:28], valid)
	return 4 + dataLen, nil
}

// AppendDUIDLL appends a DUID-LL (type 3) for an Ethernet MAC to dst.
// Format: DUIDType(2) + hwtype=1(2) + mac(6).
func AppendDUIDLL(dst []byte, mac [6]byte) []byte {
	return append(dst,
		byte(DUIDTypeLL>>8), byte(DUIDTypeLL), // type 3
		0, 1, // hardware type 1 = Ethernet
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
	)
}
