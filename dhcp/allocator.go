package dhcp

import "net/netip"

// Request is the decoded, allocation-relevant view of an inbound client message
// passed to an [Allocator]. All slice fields alias the caller's receive buffer
// and are only valid for the duration of the call; an implementation that needs
// to persist them must copy.
type Request struct {
	// ClientID identifies the client. For DHCPv4 this is the client identifier
	// option when present, otherwise the client hardware address. For DHCPv6 it
	// is the client DUID.
	ClientID []byte
	// Requested is the address the client asked for (DHCPv4 "Requested IP
	// Address" option), or the zero value when the client expressed no
	// preference.
	Requested netip.Addr
	// Subnet is the server's configured allocation prefix. It is the zero value
	// when the server does not constrain allocation to a prefix.
	Subnet netip.Prefix
	// Hostname is the client-supplied hostname, or nil.
	Hostname []byte
	// ParamReqList is the client's parameter request list, or nil.
	ParamReqList []byte
}

// Allocator owns a DHCP server's lease database: the address pool, the
// persisted client-to-address bindings, and the lease lifetime / expiration
// policy. A server delegates address assignment to an Allocator so that it only
// has to drive the protocol state machine.
//
// Implementations that expire leases must obtain time from a caller-injected
// clock rather than calling time.Now directly, in keeping with lneto's
// time-independent design.
//
// Offer and Commit model the two phases of acquisition: Offer makes a tentative
// reservation in response to a DHCPv4 DISCOVER (or DHCPv6 SOLICIT), and Commit
// binds it in response to a REQUEST. Implementations may treat Offer
// idempotently so that a repeated DISCOVER for the same client returns the same
// reservation.
type Allocator interface {
	// Offer tentatively reserves a binding for the requesting client and
	// returns it. It is called when the server receives a DISCOVER/SOLICIT.
	Offer(Request) (Binding, error)
	// Commit binds a previously offered reservation, finalizing the lease, and
	// returns the committed binding. It is called when the server receives a
	// REQUEST.
	Commit(Request) (Binding, error)
	// Release frees the binding held for the given client identity. It is
	// called when the server receives a RELEASE. Releasing an unknown client is
	// not an error.
	Release(clientID []byte) error
	// Decline marks the addresses in the request as unusable, typically because
	// the client detected an address conflict. It is called when the server
	// receives a DECLINE.
	Decline(Request) error

	// AppendOptions lets the allocator customize the option bytes the server is
	// about to send. dst already contains the options the server derived from
	// its own configuration (server identifier, router, subnet mask, DNS, lease
	// times, ...) for the given client and binding. The implementation may
	// append further options, or rewrite the existing ones, and must return the
	// resulting slice. The returned slice must not exceed dst's capacity.
	AppendOptions(dst []byte, clientID []byte, b Binding) ([]byte, error)
}
