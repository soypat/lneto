package xnet

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestARPLocal(t *testing.T) {
	const mtu = 1500
	const seed = 1
	s1, s2, c1, c2 := newTCPStacks(t, seed, mtu)
	routerHw := [6]byte{1, 2, 3, 4, 5, 6}
	// Most common case: we have a router in between computers.
	s1.SetGateway6(routerHw)
	s2.SetGateway6(routerHw)
	addr1 := netip.AddrPortFrom(s1.Addr(), 1024) // dialer, client.
	addr2 := netip.AddrPortFrom(s2.Addr(), 80)   // listener, server.
	err := s1.AssimilateDHCPResults(&DHCPResults{
		Router:        netip.AddrFrom4([4]byte{10, 0, 0, 255}),
		BroadcastAddr: netip.AddrFrom4([4]byte{255, 255, 255, 255}),
		AssignedAddr:  s1.Addr(),
		Subnet:        netip.PrefixFrom(s2.Addr(), 24), // Subnet containing s2 will force an ARP on s1.
		TRenewal:      1000,
		TRebind:       1000,
		TLease:        1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	hw2 := s2.HardwareAddress()
	err = s1.DialTCP(c1, addr1.Port(), addr2) // addr2 MAC address is unknown and must be resolved by stack.
	if err != nil {
		t.Fatal(err)
	}
	err = s2.ListenTCP(c2, addr2.Port())
	if err != nil {
		t.Fatal(err)
	}
	tst := testerFrom(t, mtu)
	_ = tst
	tst.ARPExchangeOnly(s1, s2)
	hwaddr, err := s1.arp.QueryResult(addr2.Addr().AsSlice())
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(hwaddr[:], hw2[:]) {
		t.Errorf("expected hardware address %x, got %x", hw2, hwaddr)
	}
}
