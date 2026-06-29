package dhcpv6

import (
	"encoding/binary"
	"net"
	"net/netip"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/internal"
)

// RequestConfig holds the parameters for starting a DHCPv6 exchange.
type RequestConfig struct {
	// ClientHardwareAddr is the client's Ethernet MAC address.
	// It is used to construct the client DUID-LL and IAID.
	ClientHardwareAddr [6]byte
}

// DelegatedPrefix is an IPv6 prefix delegated by a DHCPv6 server.
type DelegatedPrefix struct {
	Prefix            netip.Prefix
	PreferredLifetime uint32
	ValidLifetime     uint32
}

// Client is a stateful DHCPv6 client implementing the [lneto.StackNode] interface.
// It manages the Solicit→Advertise→Request→Reply exchange (RFC 8415 §18).
//
// Typical usage:
//
//	var cl Client
//	cl.BeginRequest(xid, RequestConfig{ClientHardwareAddr: mac})
//	// drive Encapsulate / Demux calls via the network stack
type Client struct {
	connID uint64
	state  ClientState
	xid    uint32 // lower 24 bits used

	// duid is the client's DUID-LL. Client owns the backing array; it is set
	// once from the MAC in BeginRequest and carried across resets unchanged.
	duid []byte
	// serverDUID is the selected server's DUID. Client owns the backing array;
	// it is cleared (len=0) on reset so capacity is reused without allocation.
	serverDUID []byte

	// dns accumulates DNS recursive name server addresses (OptDNSServers).
	// Client owns the backing array; cleared on reset, capacity reused.
	dns []netip.Addr
	// domainSearch accumulates DNS domain search names (OptDomainList).
	// Client owns the backing array; cleared on reset, capacity reused.
	domainSearch []dns.Name
	// ntps accumulates NTP server addresses (OptNTPServer, suboption 1).
	// Client owns the backing array; cleared on reset, capacity reused.
	ntps []netip.Addr
	// ntpMulticast accumulates NTP multicast addresses (OptNTPServer, suboption 2).
	// Client owns the backing array; cleared on reset, capacity reused.
	ntpMulticast []netip.Addr
	// ntpNames accumulates NTP server FQDNs (OptNTPServer, suboption 3).
	// Client owns the backing array; cleared on reset, capacity reused.
	ntpNames []dns.Name
	// delegatedPrefixes accumulates IA_PD prefixes (OptIAPD/OptIAPrefix).
	// Client owns the backing array; cleared on reset, capacity reused.
	delegatedPrefixes []DelegatedPrefix

	assignedAddr      [16]byte
	assignedAddrValid bool

	// iaid is derived from the first 4 bytes of the client MAC.
	iaid [4]byte

	// IA_NA timers from the server's Advertise/Reply.
	t1, t2            uint32
	preferredLifetime uint32
	validLifetime     uint32
	// IA_PD timers from the server's Advertise/Reply.
	pdT1, pdT2     uint32
	reconfigureMsg MsgType
	reconfigureOK  bool

	clientMAC [6]byte

	// auxbuf is a scratch buffer used during Encapsulate to avoid allocations.
	auxbuf [128]byte
}

// BeginRequest initialises a new DHCPv6 exchange with the given 24-bit transaction ID.
// It must be called before any Encapsulate or Demux calls.
func (c *Client) BeginRequest(xid uint32, cfg RequestConfig) error {
	if xid == 0 {
		return lneto.ErrInvalidConfig
	} else if c.state != StateInit && c.state != 0 {
		return lneto.ErrInvalidConfig
	} else if internal.IsZeroed(cfg.ClientHardwareAddr[:]...) {
		return lneto.ErrInvalidConfig
	}
	c.clientMAC = cfg.ClientHardwareAddr
	c.iaid = [4]byte(cfg.ClientHardwareAddr[:4])
	c.xid = xid & 0xFFFFFF
	c.reset()
	c.duid = AppendDUIDLL(c.duid[:0], cfg.ClientHardwareAddr)
	c.state = StateInit
	return nil
}

// Reset clears the DHCPv6 exchange state and invalidates stack registrations.
func (c *Client) Reset() { c.reset() }

// reset clears exchange state while preserving slice backing arrays and the
// connection ID is incremented to invalidate any existing stack registrations.
func (c *Client) reset() {
	*c = Client{
		connID:            c.connID + 1,
		xid:               c.xid,
		clientMAC:         c.clientMAC,
		iaid:              c.iaid,
		duid:              c.duid,
		serverDUID:        c.serverDUID[:0],
		dns:               c.dns[:0],
		domainSearch:      c.domainSearch[:0],
		ntps:              c.ntps[:0],
		ntpMulticast:      c.ntpMulticast[:0],
		ntpNames:          c.ntpNames[:0],
		delegatedPrefixes: c.delegatedPrefixes[:0],
	}
}

// Encapsulate writes the next outgoing DHCPv6 message into carrierData[offsetToFrame:].
// Returns the number of bytes written or 0 if there is nothing to send in the current state.
// Implements [lneto.StackNode].
func (c *Client) Encapsulate(carrierData []byte, _, offsetToFrame int) (int, error) {
	if c.isClosed() {
		return 0, net.ErrClosed
	}
	dst := carrierData[offsetToFrame:]
	if len(dst) < OptionsOffset+128 {
		return 0, lneto.ErrShortBuffer
	}
	frm, err := NewFrame(dst)
	if err != nil {
		return 0, err
	}

	var numOpts int
	var nextState ClientState

	switch c.state {
	case StateInit:
		frm.SetMsgType(MsgSolicit)
		frm.SetTransactionID(c.xid)
		n, _ := EncodeOption(dst[OptionsOffset+numOpts:], OptClientID, c.duid...)
		numOpts += n
		n, _ = EncodeOption(dst[OptionsOffset+numOpts:], OptReconfAccept)
		numOpts += n
		n, _ = EncodeOptionIANA(dst[OptionsOffset+numOpts:], c.iaid, 0, 0, nil)
		numOpts += n
		n, _ = EncodeOption(dst[OptionsOffset+numOpts:], OptORO, defaultOptRequestList...)
		numOpts += n
		n, _ = EncodeOption16(dst[OptionsOffset+numOpts:], OptElapsedTime, 0)
		numOpts += n
		nextState = StateSoliciting

	case StateRequesting:
		frm.SetMsgType(MsgRequest)
		frm.SetTransactionID(c.xid)
		n, _ := EncodeOption(dst[OptionsOffset+numOpts:], OptClientID, c.duid...)
		numOpts += n
		n, _ = EncodeOption(dst[OptionsOffset+numOpts:], OptServerID, c.serverDUID...)
		numOpts += n
		n, _ = EncodeOption(dst[OptionsOffset+numOpts:], OptReconfAccept)
		numOpts += n
		auxN, _ := EncodeOptionIAAddr(c.auxbuf[:], c.assignedAddr, 0, 0)
		n, _ = EncodeOptionIANA(dst[OptionsOffset+numOpts:], c.iaid, 0, 0, c.auxbuf[:auxN])
		numOpts += n
		n, _ = EncodeOption(dst[OptionsOffset+numOpts:], OptORO, defaultOptRequestList...)
		numOpts += n
		n, _ = EncodeOption16(dst[OptionsOffset+numOpts:], OptElapsedTime, 0)
		numOpts += n
		nextState = StateRequesting // retransmittable; Demux(Reply) advances to Bound

	case StateRenewing:
		frm.SetMsgType(MsgRenew)
		frm.SetTransactionID(c.xid)
		n, _ := EncodeOption(dst[OptionsOffset+numOpts:], OptClientID, c.duid...)
		numOpts += n
		n, _ = EncodeOption(dst[OptionsOffset+numOpts:], OptServerID, c.serverDUID...)
		numOpts += n
		auxN, _ := EncodeOptionIAAddr(c.auxbuf[:], c.assignedAddr, 0, 0)
		n, _ = EncodeOptionIANA(dst[OptionsOffset+numOpts:], c.iaid, 0, 0, c.auxbuf[:auxN])
		numOpts += n
		n, _ = EncodeOption16(dst[OptionsOffset+numOpts:], OptElapsedTime, 0)
		numOpts += n
		nextState = StateRenewing

	case StateRebinding:
		frm.SetMsgType(MsgRebind)
		frm.SetTransactionID(c.xid)
		n, _ := EncodeOption(dst[OptionsOffset+numOpts:], OptClientID, c.duid...)
		numOpts += n
		// No OptServerID in Rebind (RFC 8415 §18.2.5).
		auxN, _ := EncodeOptionIAAddr(c.auxbuf[:], c.assignedAddr, 0, 0)
		n, _ = EncodeOptionIANA(dst[OptionsOffset+numOpts:], c.iaid, 0, 0, c.auxbuf[:auxN])
		numOpts += n
		n, _ = EncodeOption16(dst[OptionsOffset+numOpts:], OptElapsedTime, 0)
		numOpts += n
		nextState = StateRebinding

	default:
		return 0, nil // StateSoliciting, StateBound, or uninitialised.
	}

	c.state = nextState
	return OptionsOffset + numOpts, nil
}

// Demux processes an incoming DHCPv6 message at carrierData[frameOffset:].
// It validates the transaction ID and advances the client state machine on success.
// Implements [lneto.StackNode].
func (c *Client) Demux(carrierData []byte, frameOffset int) error {
	if c.isClosed() {
		return net.ErrClosed
	}
	frm, err := NewFrame(carrierData[frameOffset:])
	if err != nil {
		return err
	}
	if frm.MsgType() == MsgReconfigure {
		return c.handleReconfigure(frm)
	}
	if frm.TransactionID() != c.xid {
		return lneto.ErrMismatch
	}

	msgType := frm.MsgType()
	var nextState ClientState
	switch c.state {
	case StateSoliciting:
		if msgType != MsgAdvertise {
			return lneto.ErrPacketDrop
		}
		nextState = StateRequesting
	case StateRequesting, StateRenewing, StateRebinding:
		if msgType != MsgReply {
			return lneto.ErrPacketDrop
		}
		nextState = StateBound
	default:
		return lneto.ErrPacketDrop
	}

	if err := c.setOptions(frm); err != nil {
		return err
	}
	c.state = nextState
	return nil
}

func (c *Client) handleReconfigure(frm Frame) error {
	if !c.state.HasIP() {
		return lneto.ErrPacketDrop
	}
	var clientOK, serverOK bool
	var reconf MsgType
	err := frm.ForEachOption(func(_ int, code OptCode, data []byte) error {
		switch code {
		case OptClientID:
			clientOK = internal.BytesEqual(data, c.duid)
		case OptServerID:
			serverOK = len(c.serverDUID) == 0 || internal.BytesEqual(data, c.serverDUID)
		case OptReconfMsg:
			if len(data) != 1 {
				return lneto.ErrInvalidLengthField
			}
			reconf = MsgType(data[0])
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !clientOK || !serverOK {
		return lneto.ErrMismatch
	}
	c.reconfigureMsg = reconf
	c.reconfigureOK = true
	if reconf != MsgRenew {
		return lneto.ErrUnsupported
	}
	c.state = StateRenewing
	return nil
}

// setOptions parses all DHCPv6 options in frm and stores relevant values.
func (c *Client) setOptions(frm Frame) error {
	return frm.ForEachOption(func(_ int, code OptCode, data []byte) error {
		switch code {
		case OptServerID:
			c.serverDUID = append(c.serverDUID[:0], data...)
		case OptIANA:
			c.parseIANA(data)
		case OptIAPD:
			c.parseIAPD(data)
		case OptDNSServers:
			if len(c.dns) > 0 || len(data)%16 != 0 {
				break // skip if already populated or malformed
			}
			for i := 0; i+16 <= len(data); i += 16 {
				c.dns = append(c.dns, netip.AddrFrom16([16]byte(data[i:i+16])))
			}
		case OptDomainList:
			c.parseDomainSearch(data)
		case OptNTPServer:
			c.parseNTPServer(data)
		}
		return nil
	})
}

func (c *Client) parseIAPD(data []byte) {
	if len(c.delegatedPrefixes) > 0 {
		return
	}
	if len(data) < 12 {
		return
	}
	t1 := binary.BigEndian.Uint32(data[4:8])
	t2 := binary.BigEndian.Uint32(data[8:12])

	for ptr := 12; ptr+4 <= len(data); {
		subCode := OptCode(binary.BigEndian.Uint16(data[ptr:]))
		subLen := int(binary.BigEndian.Uint16(data[ptr+2:]))
		if ptr+4+subLen > len(data) {
			break
		}
		if subCode == OptIAPrefix && subLen >= 25 {
			sub := data[ptr+4 : ptr+4+subLen]
			bits := int(sub[8])
			prefix := netip.PrefixFrom(netip.AddrFrom16([16]byte(sub[9:25])), bits)
			if prefix.IsValid() {
				c.delegatedPrefixes = append(c.delegatedPrefixes, DelegatedPrefix{
					Prefix:            prefix.Masked(),
					PreferredLifetime: binary.BigEndian.Uint32(sub[:4]),
					ValidLifetime:     binary.BigEndian.Uint32(sub[4:8]),
				})
			}
		}
		ptr += 4 + subLen
	}
	if len(c.delegatedPrefixes) > 0 {
		c.pdT1 = t1
		c.pdT2 = t2
	}
}

func (c *Client) parseNTPServer(data []byte) {
	if len(c.ntps) > 0 || len(c.ntpMulticast) > 0 || len(c.ntpNames) > 0 {
		return
	}
	for ptr := 0; ptr+4 <= len(data); {
		subCode := binary.BigEndian.Uint16(data[ptr:])
		subLen := int(binary.BigEndian.Uint16(data[ptr+2:]))
		if ptr+4+subLen > len(data) {
			break
		}
		subData := data[ptr+4 : ptr+4+subLen]
		switch subCode {
		case 1:
			if subLen != 16 {
				break
			}
			c.ntps = append(c.ntps, netip.AddrFrom16([16]byte(data[ptr+4:ptr+20])))
		case 2:
			if subLen != 16 {
				break
			}
			c.ntpMulticast = append(c.ntpMulticast, netip.AddrFrom16([16]byte(data[ptr+4:ptr+20])))
		case 3:
			idx := len(c.ntpNames)
			if idx < cap(c.ntpNames) {
				c.ntpNames = c.ntpNames[:idx+1]
			} else {
				c.ntpNames = append(c.ntpNames, dns.Name{})
			}
			next, err := c.ntpNames[idx].Decode(subData, 0)
			if err != nil || next != uint16(len(subData)) {
				c.ntpNames[idx].Reset()
				c.ntpNames = c.ntpNames[:idx]
			}
		}
		ptr += 4 + subLen
	}
}

func (c *Client) parseDomainSearch(data []byte) {
	if len(c.domainSearch) > 0 {
		return
	}
	for off := uint16(0); off < uint16(len(data)); {
		idx := len(c.domainSearch)
		if idx < cap(c.domainSearch) {
			c.domainSearch = c.domainSearch[:idx+1]
		} else {
			c.domainSearch = append(c.domainSearch, dns.Name{})
		}
		next, err := c.domainSearch[idx].Decode(data, off)
		if err != nil || next <= off {
			c.domainSearch[idx].Reset()
			c.domainSearch = c.domainSearch[:idx]
			return
		}
		off = next
	}
}

// parseIANA processes the payload of an OptIANA option, extracting the
// assigned address and lease timers from any embedded OptIAAddr sub-option.
func (c *Client) parseIANA(data []byte) {
	if len(data) < 12 {
		return
	}
	if [4]byte(data[:4]) != c.iaid {
		return // not our Identity Association
	}
	t1 := binary.BigEndian.Uint32(data[4:8])
	t2 := binary.BigEndian.Uint32(data[8:12])

	// Iterate sub-options manually (same 4-byte TLV format).
	ptr := 12
	for ptr+4 <= len(data) {
		subCode := OptCode(binary.BigEndian.Uint16(data[ptr:]))
		subLen := int(binary.BigEndian.Uint16(data[ptr+2:]))
		if ptr+4+subLen > len(data) {
			break // malformed sub-option; stop safely
		}
		if subCode == OptIAAddr && subLen >= 24 {
			sub := data[ptr+4 : ptr+4+subLen]
			c.assignedAddr = [16]byte(sub[:16])
			c.assignedAddrValid = true
			c.preferredLifetime = binary.BigEndian.Uint32(sub[16:20])
			c.validLifetime = binary.BigEndian.Uint32(sub[20:24])
		}
		ptr += 4 + subLen
	}
	if c.assignedAddrValid {
		c.t1 = t1
		c.t2 = t2
	}
}

func (c *Client) isClosed() bool { return c.state == 0 || c.xid == 0 }

// State returns the current client state.
func (c *Client) State() ClientState { return c.state }

// LastReconfigure returns the last accepted Reconfigure message target.
func (c *Client) LastReconfigure() (MsgType, bool) { return c.reconfigureMsg, c.reconfigureOK }

// AssignedAddr returns the IPv6 address assigned by the server and whether it is valid.
func (c *Client) AssignedAddr() ([16]byte, bool) { return c.assignedAddr, c.assignedAddrValid }

// RebindingSeconds returns the IA_NA T2 timer from the server.
func (c *Client) RebindingSeconds() uint32 { return c.t2 }

// RenewalSeconds returns the IA_NA T1 timer from the server.
func (c *Client) RenewalSeconds() uint32 { return c.t1 }

// PreferredLifetimeSeconds returns the preferred lifetime of the assigned address.
func (c *Client) PreferredLifetimeSeconds() uint32 { return c.preferredLifetime }

// ValidLifetimeSeconds returns the valid lifetime of the assigned address.
func (c *Client) ValidLifetimeSeconds() uint32 { return c.validLifetime }

// PrefixDelegationRebindingSeconds returns the IA_PD T2 timer from the server.
func (c *Client) PrefixDelegationRebindingSeconds() uint32 { return c.pdT2 }

// PrefixDelegationRenewalSeconds returns the IA_PD T1 timer from the server.
func (c *Client) PrefixDelegationRenewalSeconds() uint32 { return c.pdT1 }

// AppendDelegatedPrefixes appends delegated IPv6 prefixes received from the server to dst.
func (c *Client) AppendDelegatedPrefixes(dst []DelegatedPrefix) []DelegatedPrefix {
	return append(dst, c.delegatedPrefixes...)
}

// NumDelegatedPrefixes returns the number of delegated IPv6 prefixes received.
func (c *Client) NumDelegatedPrefixes() int { return len(c.delegatedPrefixes) }

// AppendDNSServers appends the DNS server addresses received from the server to dst.
func (c *Client) AppendDNSServers(dst []netip.Addr) []netip.Addr { return append(dst, c.dns...) }

// NumDNSServers returns the number of DNS server addresses received.
func (c *Client) NumDNSServers() int { return len(c.dns) }

// AppendDomainSearch appends the DNS domain search names received from the server to dst.
func (c *Client) AppendDomainSearch(dst []dns.Name) []dns.Name { return append(dst, c.domainSearch...) }

// NumDomainSearch returns the number of DNS domain search names received.
func (c *Client) NumDomainSearch() int { return len(c.domainSearch) }

// AppendNTPServers appends the NTP server addresses received from the server to dst.
func (c *Client) AppendNTPServers(dst []netip.Addr) []netip.Addr { return append(dst, c.ntps...) }

// NumNTPServers returns the number of NTP server addresses received.
func (c *Client) NumNTPServers() int { return len(c.ntps) }

// AppendNTPMulticastServers appends NTP multicast addresses received from the server to dst.
func (c *Client) AppendNTPMulticastServers(dst []netip.Addr) []netip.Addr {
	return append(dst, c.ntpMulticast...)
}

// NumNTPMulticastServers returns the number of NTP multicast addresses received.
func (c *Client) NumNTPMulticastServers() int { return len(c.ntpMulticast) }

// AppendNTPServerNames appends NTP server FQDNs received from the server to dst.
func (c *Client) AppendNTPServerNames(dst []dns.Name) []dns.Name { return append(dst, c.ntpNames...) }

// NumNTPServerNames returns the number of NTP server FQDNs received.
func (c *Client) NumNTPServerNames() int { return len(c.ntpNames) }

// ConnectionID returns a pointer to the client's connection ID.
// The value increments on each reset; callers should discard registrations when it changes.
// Implements [lneto.StackNode].
func (c *Client) ConnectionID() *uint64 { return &c.connID }

// LocalPort returns the DHCPv6 client port (546).
// Implements [lneto.StackNode].
func (c *Client) LocalPort() uint16 { return ClientPort }

// Protocol returns the IP protocol number for UDP.
// Implements [lneto.StackNode].
func (c *Client) Protocol() uint64 { return uint64(lneto.IPProtoUDP) }

// defaultOptRequestList is the ORO payload (RFC 8415 §21.7) listing the options
// the client wants the server to include in its reply.
var defaultOptRequestList = []byte{
	byte(OptDNSServers >> 8), byte(OptDNSServers), // 23
	byte(OptDomainList >> 8), byte(OptDomainList), // 24
	byte(OptNTPServer >> 8), byte(OptNTPServer), // 56
}
