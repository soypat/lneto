package dhcpv4

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"

	"github.com/soypat/lneto/dhcp"
	"github.com/soypat/lneto/ipv4"
)

// MapAllocator is the built-in [dhcp.Allocator] used by [Server] when no
// allocator is supplied. It keeps the lease database in a map and allocates
// addresses sequentially from the configured subnet, preferring a client's
// requested address when it is free and in-subnet.
//
// When configured with a clock (see [AllocatorConfig.Now]) it reclaims expired
// leases back into the pool; with no clock leases never expire, matching the
// behaviour of a server that does not track time.
//
// The map makes MapAllocator unsuitable for the most memory-constrained
// targets; such deployments should provide their own [dhcp.Allocator]. This
// mirrors the existing allowance for the DHCP server to use a map on capable
// hardware.
type MapAllocator struct {
	subnet       ipv4.Prefix
	serverAddr   [4]byte
	nextAddr     [4]byte
	leaseSeconds uint32
	now          func() time.Time
	leases       map[[36]byte]mapLease
	declined     map[[4]byte]struct{}
}

type mapLease struct {
	addr      [4]byte
	expiry    time.Time // zero means no expiry (no clock configured).
	committed bool
}

// AllocatorConfig configures a [MapAllocator].
type AllocatorConfig struct {
	// ServerAddr is the server's own address, excluded from the pool.
	ServerAddr [4]byte
	// Subnet is the allocation prefix.
	Subnet ipv4.Prefix
	// LeaseSeconds is the lease duration handed to clients. Zero defaults to 3600.
	LeaseSeconds uint32
	// Now, when non-nil, is used to expire and reclaim leases. When nil leases
	// never expire.
	Now func() time.Time
}

// NewMapAllocator returns a configured [MapAllocator].
func NewMapAllocator(cfg AllocatorConfig) (*MapAllocator, error) {
	if !cfg.Subnet.IsValid() {
		return nil, errors.New("dhcpv4 allocator: invalid subnet")
	} else if !cfg.Subnet.Contains(cfg.ServerAddr) {
		return nil, errors.New("dhcpv4 allocator: server address outside subnet")
	}
	lease := cfg.LeaseSeconds
	if lease == 0 {
		lease = 3600
	}
	return &MapAllocator{
		subnet:       cfg.Subnet,
		serverAddr:   cfg.ServerAddr,
		nextAddr:     cfg.Subnet.Next(cfg.ServerAddr),
		leaseSeconds: lease,
		now:          cfg.Now,
		leases:       make(map[[36]byte]mapLease),
		declined:     make(map[[4]byte]struct{}),
	}, nil
}

var _ dhcp.Allocator = (*MapAllocator)(nil)

// Offer implements [dhcp.Allocator]. It returns the binding already reserved for
// the client if one exists, otherwise it reserves a new address.
func (a *MapAllocator) Offer(req dhcp.Request) (dhcp.Binding, error) {
	a.sweepExpired()
	key, ok := keyOf(req.ClientID)
	if !ok {
		return dhcp.Binding{}, errors.New("dhcpv4 allocator: client id too long")
	}
	if existing, ok := a.leases[key]; ok {
		existing.expiry = a.expiry()
		a.leases[key] = existing
		return a.binding(existing.addr), nil
	}
	addr, ok := a.allocAddr(req.Requested)
	if !ok {
		return dhcp.Binding{}, errors.New("dhcpv4 allocator: address pool exhausted")
	}
	a.leases[key] = mapLease{addr: addr, expiry: a.expiry()}
	return a.binding(addr), nil
}

// Commit implements [dhcp.Allocator], finalizing the client's lease.
func (a *MapAllocator) Commit(req dhcp.Request) (dhcp.Binding, error) {
	a.sweepExpired()
	key, ok := keyOf(req.ClientID)
	if !ok {
		return dhcp.Binding{}, errors.New("dhcpv4 allocator: client id too long")
	}
	lease, ok := a.leases[key]
	if !ok {
		// Reservation expired or never made; allocate afresh.
		addr, ok := a.allocAddr(req.Requested)
		if !ok {
			return dhcp.Binding{}, errors.New("dhcpv4 allocator: address pool exhausted")
		}
		lease = mapLease{addr: addr}
	}
	lease.committed = true
	lease.expiry = a.expiry()
	a.leases[key] = lease
	return a.binding(lease.addr), nil
}

// Release implements [dhcp.Allocator], freeing the client's lease.
func (a *MapAllocator) Release(clientID []byte) error {
	key, ok := keyOf(clientID)
	if !ok {
		return nil
	}
	delete(a.leases, key)
	return nil
}

// Decline implements [dhcp.Allocator], marking the client's address unusable.
func (a *MapAllocator) Decline(req dhcp.Request) error {
	key, ok := keyOf(req.ClientID)
	if !ok {
		return nil
	}
	if lease, ok := a.leases[key]; ok {
		a.declined[lease.addr] = struct{}{}
		delete(a.leases, key)
	} else if req.Requested.Is4() {
		a.declined[req.Requested.As4()] = struct{}{}
	}
	return nil
}

// AppendOptions implements [dhcp.Allocator]. The server already wrote the
// configuration-derived options, so the default allocator leaves them as-is.
func (a *MapAllocator) AppendOptions(dst []byte, _ []byte, _ dhcp.Binding) ([]byte, error) {
	return dst, nil
}

func (a *MapAllocator) binding(addr [4]byte) dhcp.Binding {
	t1, t2 := dhcp.DefaultT1T2(a.leaseSeconds)
	return dhcp.Binding{
		T1: t1,
		T2: t2,
		Leases: []dhcp.Lease{{
			Addr:      netip.AddrFrom4(addr),
			Preferred: a.leaseSeconds,
			Valid:     a.leaseSeconds,
		}},
	}
}

func (a *MapAllocator) expiry() time.Time {
	if a.now == nil {
		return time.Time{}
	}
	return a.now().Add(time.Duration(a.leaseSeconds) * time.Second)
}

func (a *MapAllocator) sweepExpired() {
	if a.now == nil {
		return
	}
	now := a.now()
	for k, v := range a.leases {
		if !v.expiry.IsZero() && now.After(v.expiry) {
			delete(a.leases, k)
		}
	}
}

// allocAddr allocates the next available address from the pool, preferring a
// valid in-subnet requested address that is free.
func (a *MapAllocator) allocAddr(requested netip.Addr) ([4]byte, bool) {
	if requested.Is4() {
		candidate := requested.As4()
		if a.subnet.Contains(candidate) && candidate != a.serverAddr && !a.isAssigned(candidate) {
			return candidate, true
		}
	}
	addr := a.nextAddr
	a.nextAddr = a.subnet.Next(a.nextAddr)
	if a.nextAddr == a.serverAddr {
		a.nextAddr = a.subnet.Next(a.nextAddr)
	}
	// Reject the broadcast address (all host bits set).
	hostBits := uint(32 - a.subnet.Bits())
	hostMask := ^uint32(0) >> (32 - hostBits)
	if binary.BigEndian.Uint32(addr[:])&hostMask == hostMask {
		return [4]byte{}, false
	}
	return addr, true
}

func (a *MapAllocator) isAssigned(addr [4]byte) bool {
	if _, ok := a.declined[addr]; ok {
		return true
	}
	for _, v := range a.leases {
		if v.addr == addr {
			return true
		}
	}
	return false
}

func keyOf(clientID []byte) ([36]byte, bool) {
	var key [36]byte
	if len(clientID) > len(key) {
		return key, false
	}
	copy(key[:], clientID)
	return key, true
}
