// Package dhcp holds protocol-version-independent types shared by the DHCPv4
// and DHCPv6 implementations. In particular it defines the [Allocator]
// interface a DHCP server delegates address assignment and lease lifetime
// management to, decoupling the higher-level state machine from the backing
// lease database.
//
// The lease lifetime model follows the common shape described by RFC 2131
// (DHCPv4) and RFC 8415 (DHCPv6): a per-client [Binding] carries renewal (T1)
// and rebind (T2) times and holds one or more [Lease]s, each with a preferred
// and valid lifetime. DHCPv4 assigns a single address whose preferred and
// valid lifetimes equal the lease time; DHCPv6 may assign several addresses
// (and prefixes) through identity associations, each with its own lifetimes.
package dhcp

import "net/netip"

// Lease is a single address binding offered or assigned to a client.
type Lease struct {
	// Addr is the assigned address. For DHCPv4 this is an IPv4 address.
	Addr netip.Addr
	// Preferred is the preferred lifetime in seconds (RFC 8415 §7.1). For
	// DHCPv4, where there is no distinct preferred lifetime, set it equal to
	// Valid.
	Preferred uint32
	// Valid is the valid lifetime in seconds. This is the DHCPv4 "IP Address
	// Lease Time" (RFC 2132 option 51).
	Valid uint32
}

// Binding groups the leases assigned to a single client identity association
// together with the renewal and rebind times that govern when the client
// should attempt to extend them.
type Binding struct {
	// T1 is the renewal time in seconds: when the client should contact the
	// allocating server to extend its leases. RFC 2131 §4.4.5 / RFC 8415 §14.2
	// default this to half the (shortest) lease time.
	T1 uint32
	// T2 is the rebinding time in seconds: when the client should broadcast to
	// any server to extend its leases. The RFCs default this to 0.875 of the
	// (shortest) lease time.
	T2 uint32
	// Leases holds the addresses bound to the client. DHCPv4 uses exactly one
	// lease; DHCPv6 may use more than one (IA_NA / IA_PD).
	Leases []Lease
}

// Addr returns the first lease address and whether the binding holds any lease.
// It is a convenience for single-address (DHCPv4) callers.
func (b Binding) Addr() (netip.Addr, bool) {
	if len(b.Leases) == 0 {
		return netip.Addr{}, false
	}
	return b.Leases[0].Addr, true
}

// DefaultT1T2 returns the RFC 2131 §4.4.5 default renewal (T1) and rebind (T2)
// times for a given lease duration: T1 = 0.5·lease and T2 = 0.875·lease.
func DefaultT1T2(leaseSeconds uint32) (t1Renewal, t2Rebinding uint32) {
	return leaseSeconds / 2, leaseSeconds * 7 / 8
}
