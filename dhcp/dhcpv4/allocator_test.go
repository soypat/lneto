package dhcpv4

import (
	"net/netip"
	"testing"
	"time"

	"github.com/soypat/lneto/dhcp"
	"github.com/soypat/lneto/ipv4"
)

// recordingAllocator is a test [dhcp.Allocator] that hands out a fixed address,
// records whether the server-derived options reached its AppendOptions hook, and
// appends a marker option of its own.
type recordingAllocator struct {
	addr      netip.Addr
	sawRouter bool
	appended  bool
}

func (a *recordingAllocator) binding() dhcp.Binding {
	return dhcp.Binding{
		T1:     30,
		T2:     52,
		Leases: []dhcp.Lease{{Addr: a.addr, Preferred: 60, Valid: 60}},
	}
}

func (a *recordingAllocator) Offer(dhcp.Request) (dhcp.Binding, error)  { return a.binding(), nil }
func (a *recordingAllocator) Commit(dhcp.Request) (dhcp.Binding, error) { return a.binding(), nil }
func (a *recordingAllocator) Release([]byte) error                      { return nil }
func (a *recordingAllocator) Decline(dhcp.Request) error                { return nil }

func (a *recordingAllocator) AppendOptions(dst []byte, _ []byte, _ dhcp.Binding) ([]byte, error) {
	// dst already contains the server-derived options. Confirm the router
	// option the server was configured to send is present.
	for i := 0; i+1 < len(dst); {
		op := OptNum(dst[i])
		if op == OptEnd {
			break
		}
		if op == OptRouter {
			a.sawRouter = true
		}
		i += 2 + int(dst[i+1])
	}
	// Append our own option into the remaining capacity.
	tail := dst[len(dst):cap(dst)]
	n, err := EncodeOptionString(tail, OptDomainName, "example")
	if err != nil {
		return dst, err
	}
	a.appended = true
	return dst[:len(dst)+n], nil
}

// TestServerCustomAllocator verifies the server delegates address assignment to
// an injected allocator, that the allocator's AppendOptions hook sees the
// server-derived options, and that options it appends reach the client.
func TestServerCustomAllocator(t *testing.T) {
	svAddr := [4]byte{192, 168, 1, 1}
	want := netip.AddrFrom4([4]byte{10, 9, 8, 7})
	alloc := &recordingAllocator{addr: want}

	var sv Server
	err := sv.Configure(ServerConfig{
		ServerAddr: svAddr,
		Gateway:    [4]byte{192, 168, 1, 254},
		Subnet:     ipv4.PrefixFrom(svAddr, 24),
		Allocator:  alloc,
	})
	if err != nil {
		t.Fatal(err)
	}

	var cl Client
	if err := cl.BeginRequest(42, RequestConfig{ClientHardwareAddr: [6]byte{1, 2, 3, 4, 5, 6}}); err != nil {
		t.Fatal(err)
	}

	var buf [1024]byte
	n, err := cl.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := sv.Demux(buf[:n], 0); err != nil {
		t.Fatal(err)
	}
	n, err = sv.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("no offer emitted")
	}

	frm, _ := NewFrame(buf[:n])
	if got := *frm.YIAddr(); got != want.As4() {
		t.Errorf("offered address: got %v want %v", got, want)
	}
	if !alloc.sawRouter {
		t.Error("allocator AppendOptions did not see the server-derived router option")
	}
	var foundDomain bool
	frm.ForEachOption(func(_ int, opt OptNum, data []byte) error {
		if opt == OptDomainName && string(data) == "example" {
			foundDomain = true
		}
		return nil
	})
	if !foundDomain {
		t.Error("allocator-appended domain option did not reach the emitted frame")
	}
}

// TestMapAllocatorExpiration verifies that the default allocator reclaims an
// expired lease back into the pool once its valid lifetime has elapsed.
func TestMapAllocatorExpiration(t *testing.T) {
	svAddr := [4]byte{192, 168, 1, 1}
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }

	a, err := NewMapAllocator(AllocatorConfig{
		ServerAddr:   svAddr,
		Subnet:       ipv4.PrefixFrom(svAddr, 24),
		LeaseSeconds: 10,
		Now:          clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Client 1 acquires and commits an address.
	b1, err := a.Offer(dhcp.Request{ClientID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	addr1, _ := b1.Addr()
	if _, err := a.Commit(dhcp.Request{ClientID: []byte{1}}); err != nil {
		t.Fatal(err)
	}

	// While client 1 holds the lease, another client requesting the same
	// address must not be granted it.
	b2, err := a.Offer(dhcp.Request{ClientID: []byte{2}, Requested: addr1})
	if err != nil {
		t.Fatal(err)
	}
	if addr2, _ := b2.Addr(); addr2 == addr1 {
		t.Fatalf("addr %v handed out while still leased to client 1", addr1)
	}
	if err := a.Release([]byte{2}); err != nil {
		t.Fatal(err)
	}

	// Advance time past client 1's lease; its address must be reclaimable.
	now = now.Add(20 * time.Second)
	b3, err := a.Offer(dhcp.Request{ClientID: []byte{3}, Requested: addr1})
	if err != nil {
		t.Fatal(err)
	}
	if addr3, _ := b3.Addr(); addr3 != addr1 {
		t.Errorf("expired address not reclaimed: got %v want %v", addr3, addr1)
	}
}
