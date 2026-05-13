package xnet

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

func TestARPLocal(t *testing.T) {
	const mtu = ethernet.MaxMTU
	const seed = 1
	s1, s2, c1, c2 := newTCPStacks(t, seed, mtu)
	routerHw := [6]byte{1, 2, 3, 4, 5, 6}
	// Most common case: we have a router in between computers.
	s1.SetGatewayHardwareAddr(routerHw)
	s2.SetGatewayHardwareAddr(routerHw)
	addr1 := netip.AddrPortFrom(netip.AddrFrom4(s1.Addr4()), 1024) // dialer, client.
	addr2 := netip.AddrPortFrom(netip.AddrFrom4(s2.Addr4()), 80)   // listener, server.
	err := s1.AssimilateDHCPResults(&DHCPResults{
		Router:        netip.AddrFrom4([4]byte{10, 0, 0, 255}),
		BroadcastAddr: netip.AddrFrom4([4]byte{255, 255, 255, 255}),
		AssignedAddr4: s1.Addr4(),
		Subnet:        netip.PrefixFrom(netip.AddrFrom4(s2.Addr4()), 24), // Subnet containing s2 will force an ARP on s1.
		TRenewal:      1000,
		TRebind:       1000,
		TLease:        1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	hw2 := s2.HardwareAddr()
	err = s1.DialTCP(c1, addr1.Port(), addr2) // addr2 MAC address is unknown and must be resolved by stack.
	if err != nil {
		t.Fatal(err)
	}
	err = s2.ListenTCP4(c2, addr2.Port())
	if err != nil {
		t.Fatal(err)
	}
	tst := testerFrom(t, mtu)
	_ = tst
	tst.ARPExchangeOnly(s1, s2)
	hwaddr, err := s1.arp.CacheLookup(addr2.Addr().AsSlice())
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(hwaddr[:], hw2[:]) {
		t.Errorf("expected hardware address %x, got %x", hw2, hwaddr)
	}
}
