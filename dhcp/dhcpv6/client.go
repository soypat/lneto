package dhcpv6

import (
	"net/netip"

	"github.com/soypat/lneto"
)

// RequestConfig holds the parameters for starting a DHCPv6 exchange.
type RequestConfig struct {
	// ClientHardwareAddr is the client's Ethernet MAC address.
	// It is used to construct the client DUID-LL and IAID.
	ClientHardwareAddr [6]byte
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

	assignedAddr      [16]byte
	assignedAddrValid bool

	// iaid is derived from the first 4 bytes of the client MAC.
	iaid [4]byte

	// IA_NA timers from the server's Advertise/Reply.
	t1, t2            uint32
	preferredLifetime uint32
	validLifetime     uint32

	clientMAC [6]byte

	// auxbuf is a scratch buffer used during Encapsulate to avoid allocations.
	auxbuf [128]byte
}

// BeginRequest initialises a new DHCPv6 exchange with the given 24-bit transaction ID.
// It must be called before any Encapsulate or Demux calls.
func (c *Client) BeginRequest(xid uint32, cfg RequestConfig) error {
	panic("not implemented")
}

// Encapsulate writes the next outgoing DHCPv6 message into carrierData[offsetToFrame:].
// Returns the number of bytes written or 0 if there is nothing to send in the current state.
// Implements [lneto.StackNode].
func (c *Client) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	panic("not implemented")
}

// Demux processes an incoming DHCPv6 message at carrierData[frameOffset:].
// It validates the transaction ID and advances the client state machine on success.
// Implements [lneto.StackNode].
func (c *Client) Demux(carrierData []byte, frameOffset int) error {
	panic("not implemented")
}

// State returns the current client state.
func (c *Client) State() ClientState { return c.state }

// AssignedAddr returns the IPv6 address assigned by the server and whether it is valid.
func (c *Client) AssignedAddr() ([16]byte, bool) {
	panic("not implemented")
}

// AppendDNSServers appends the DNS server addresses received from the server to dst.
func (c *Client) AppendDNSServers(dst []netip.Addr) []netip.Addr {
	panic("not implemented")
}

// NumDNSServers returns the number of DNS server addresses received.
func (c *Client) NumDNSServers() int {
	panic("not implemented")
}

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
