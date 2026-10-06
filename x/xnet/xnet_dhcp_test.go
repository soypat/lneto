package xnet

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dhcp/dhcpv4"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
)

const dhcpTestMTU = 1500

// newDHCPServerStack returns a stack hosting a dhcpv4.Server registered as a user UDP node.
func newDHCPServerStack(t *testing.T, svcfg dhcpv4.ServerConfig) (*StackAsync, *dhcpv4.Server) {
	t.Helper()
	var stack StackAsync
	err := stack.Reset(StackConfig{
		Hostname:            "dhcpsv-1",
		RandSeed:            1,
		StaticAddress4:      svcfg.ServerAddr,
		HardwareAddress:     [6]byte{0xde, 0xad, 0, 0, 0, 1},
		MTU:                 dhcpTestMTU,
		MaxActiveUDPPorts:   1,
		AcceptIPv4Broadcast: true, // DISCOVER and REQUEST are broadcast.
	})
	if err != nil {
		t.Fatal(err)
	}
	sv := new(dhcpv4.Server)
	err = sv.Configure(svcfg)
	if err != nil {
		t.Fatal(err)
	}
	err = stack.RegisterUDP4(sv, [4]byte{}, dhcpv4.DefaultClientPort)
	if err != nil {
		t.Fatal(err)
	}
	return &stack, sv
}

// newDHCPClientStack returns a stack with no IPv4 address configured.
func newDHCPClientStack(t *testing.T) *StackAsync {
	t.Helper()
	var stack StackAsync
	err := stack.Reset(StackConfig{
		Hostname:        "dhcpcl-2",
		RandSeed:        2,
		HardwareAddress: [6]byte{0xbe, 0xef, 0, 0, 0, 2},
		MTU:             dhcpTestMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &stack
}

// shuttle exchanges ethernet frames between a and b, a sending first each round.
// It stops after rounds, when done returns true or when a round moves no data.
func shuttle(t *testing.T, a, b *StackAsync, rounds int, done func() bool) {
	t.Helper()
	buf := make([]byte, dhcpTestMTU+ethernet.MaxOverheadSize)
	pass := func(src, dst *StackAsync) int {
		n, err := src.EgressEthernet(buf)
		if err != nil {
			t.Fatal("egress:", err)
		} else if n == 0 {
			return 0
		}
		err = dst.IngressEthernet(buf[:n])
		if err != nil && err != lneto.ErrPacketDrop {
			t.Fatal("ingress:", err)
		}
		return n
	}
	for i := 0; i < rounds; i++ {
		if done != nil && done() {
			return
		}
		moved := pass(a, b)
		moved += pass(b, a)
		if moved == 0 {
			return
		}
	}
}

func TestStackAsyncDHCP(t *testing.T) {
	var (
		svAddr  = [4]byte{192, 168, 1, 1}
		gwAddr  = [4]byte{192, 168, 1, 254}
		dnsAddr = [4]byte{8, 8, 8, 8}
		subnet  = ipv4.PrefixFrom(svAddr, 24)
		svAddr2 = [4]byte{10, 1, 0, 1}
	)
	addr := netip.AddrFrom4
	tests := []struct {
		name    string
		svcfg   dhcpv4.ServerConfig
		request [4]byte
		preMAC  [6]byte
		wantErr string
		want    DHCPResults
	}{
		{
			name:  "full-options",
			svcfg: dhcpv4.ServerConfig{ServerAddr: svAddr, Gateway: gwAddr, DNS: dnsAddr, Subnet: subnet, LeaseSeconds: 7200},
			want: DHCPResults{
				DNSServers:    []netip.Addr{addr(dnsAddr)},
				Router:        addr(gwAddr),
				AssignedAddr4: [4]byte{192, 168, 1, 2},
				ServerAddr:    addr(svAddr),
				Gateway:       addr(gwAddr),
				Subnet:        netip.MustParsePrefix("192.168.1.0/24"),
				TLease:        7200, TRenewal: 3600, TRebind: 6300,
			},
		},
		{
			name:  "default-lease",
			svcfg: dhcpv4.ServerConfig{ServerAddr: svAddr, Gateway: gwAddr, DNS: dnsAddr, Subnet: subnet},
			want: DHCPResults{
				DNSServers:    []netip.Addr{addr(dnsAddr)},
				Router:        addr(gwAddr),
				AssignedAddr4: [4]byte{192, 168, 1, 2},
				ServerAddr:    addr(svAddr),
				Gateway:       addr(gwAddr),
				Subnet:        netip.MustParsePrefix("192.168.1.0/24"),
				TLease:        3600, TRenewal: 1800, TRebind: 3150,
			},
		},
		{
			name:  "no-dns",
			svcfg: dhcpv4.ServerConfig{ServerAddr: svAddr, Gateway: gwAddr, Subnet: subnet},
			want: DHCPResults{
				Router:        addr(gwAddr),
				AssignedAddr4: [4]byte{192, 168, 1, 2},
				ServerAddr:    addr(svAddr),
				Gateway:       addr(gwAddr),
				Subnet:        netip.MustParsePrefix("192.168.1.0/24"),
				TLease:        3600, TRenewal: 1800, TRebind: 3150,
			},
		},
		{
			name:    "requested-addr",
			svcfg:   dhcpv4.ServerConfig{ServerAddr: svAddr, Gateway: gwAddr, Subnet: subnet},
			request: [4]byte{192, 168, 1, 50},
			want: DHCPResults{
				Router:        addr(gwAddr),
				AssignedAddr4: [4]byte{192, 168, 1, 50},
				ServerAddr:    addr(svAddr),
				Gateway:       addr(gwAddr),
				Subnet:        netip.MustParsePrefix("192.168.1.0/24"),
				TLease:        3600, TRenewal: 1800, TRebind: 3150,
			},
		},
		{
			name:  "subnet-16",
			svcfg: dhcpv4.ServerConfig{ServerAddr: svAddr2, Gateway: svAddr2, Subnet: ipv4.PrefixFrom(svAddr2, 16)},
			want: DHCPResults{
				Router:        addr(svAddr2),
				AssignedAddr4: [4]byte{10, 1, 0, 2},
				ServerAddr:    addr(svAddr2),
				Gateway:       addr(svAddr2),
				Subnet:        netip.MustParsePrefix("10.1.0.0/16"),
				TLease:        3600, TRenewal: 1800, TRebind: 3150,
			},
		},
		{
			name:   "mac-changed",
			svcfg:  dhcpv4.ServerConfig{ServerAddr: svAddr, Gateway: gwAddr, Subnet: subnet},
			preMAC: [6]byte{0x02, 0, 0, 0, 0xca, 0xfe},
			want: DHCPResults{
				Router:        addr(gwAddr),
				AssignedAddr4: [4]byte{192, 168, 1, 2},
				ServerAddr:    addr(svAddr),
				Gateway:       addr(gwAddr),
				Subnet:        netip.MustParsePrefix("192.168.1.0/24"),
				TLease:        3600, TRenewal: 1800, TRebind: 3150,
			},
		},
		{
			name:    "no-router",
			svcfg:   dhcpv4.ServerConfig{ServerAddr: svAddr, Subnet: subnet},
			wantErr: "no DHCP router address",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := newDHCPServerStack(t, tc.svcfg)
			client := newDHCPClientStack(t)
			if tc.preMAC != ([6]byte{}) {
				err := client.SetHardwareAddr(tc.preMAC)
				if err != nil {
					t.Fatal(err)
				}
				if got := client.HardwareAddr(); got != tc.preMAC {
					t.Fatalf("HardwareAddr=%x, want %x", got, tc.preMAC)
				}
				if got := client.GatewayHardwareAddr(); got != ethernet.BroadcastAddr() {
					t.Fatalf("GatewayHardwareAddr changed by SetHardwareAddr: %x", got)
				}
			}

			_, err := client.ResultDHCP()
			if err == nil || !strings.Contains(err.Error(), "not completed") {
				t.Fatalf("ResultDHCP before start: want not completed error, got %v", err)
			}
			err = client.StartDHCPv4Request(tc.request)
			if err != nil {
				t.Fatal(err)
			}
			shuttle(t, client, server, 1, nil) // DISCOVER and OFFER only.
			_, err = client.ResultDHCP()
			if err == nil || !strings.Contains(err.Error(), "not completed") {
				t.Fatalf("ResultDHCP mid-DORA: want not completed error, got %v", err)
			}
			shuttle(t, client, server, 8, func() bool { return client.dhcp.State().HasIP() })
			if !client.dhcp.State().HasIP() {
				t.Fatalf("DHCP did not complete, client state %s", client.dhcp.State())
			}

			res, err := client.ResultDHCP()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			} else if err != nil {
				t.Fatal(err)
			}
			checkDHCPResults(t, res, &tc.want)

			// Second call reuses DNSServers capacity and must not duplicate entries.
			res, err = client.ResultDHCP()
			if err != nil {
				t.Fatal(err)
			}
			checkDHCPResults(t, res, &tc.want)

			err = client.AssimilateDHCPResults(res)
			if err != nil {
				t.Fatal(err)
			}
			if got := client.Addr4(); got != tc.want.AssignedAddr4 {
				t.Errorf("Addr4 after assimilate=%v, want %v", got, tc.want.AssignedAddr4)
			}
		})
	}
}

func checkDHCPResults(t *testing.T, got, want *DHCPResults) {
	t.Helper()
	if !slices.Equal(got.DNSServers, want.DNSServers) {
		t.Errorf("DNSServers=%v, want %v", got.DNSServers, want.DNSServers)
	}
	if got.Router != want.Router {
		t.Errorf("Router=%v, want %v", got.Router, want.Router)
	}
	if got.AssignedAddr4 != want.AssignedAddr4 {
		t.Errorf("AssignedAddr4=%v, want %v", got.AssignedAddr4, want.AssignedAddr4)
	}
	if got.ServerAddr != want.ServerAddr {
		t.Errorf("ServerAddr=%v, want %v", got.ServerAddr, want.ServerAddr)
	}
	if got.BroadcastAddr != want.BroadcastAddr {
		t.Errorf("BroadcastAddr=%v, want %v", got.BroadcastAddr, want.BroadcastAddr)
	}
	if got.Gateway != want.Gateway {
		t.Errorf("Gateway=%v, want %v", got.Gateway, want.Gateway)
	}
	// Subnet is interface-style: assigned address with the network's prefix length.
	if got.Subnet.Masked() != want.Subnet || got.Subnet.Addr() != netip.AddrFrom4(want.AssignedAddr4) {
		t.Errorf("Subnet=%v, want network %v holding %v", got.Subnet, want.Subnet, want.AssignedAddr4)
	}
	if got.TLease != want.TLease || got.TRenewal != want.TRenewal || got.TRebind != want.TRebind {
		t.Errorf("lease/renew/rebind=%d/%d/%d, want %d/%d/%d", got.TLease, got.TRenewal, got.TRebind,
			want.TLease, want.TRenewal, want.TRebind)
	}
}

func TestStackAsyncAddrSetters(t *testing.T) {
	var (
		newAddr4 = [4]byte{10, 0, 0, 7}
		newAddr6 = [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 7} // 2001:db8::7
		newMAC   = [6]byte{0x02, 0, 0, 0, 0, 0x77}
		gwMAC    = [6]byte{1, 2, 3, 4, 5, 6}
	)
	for _, ipv6 := range []bool{false, true} {
		t.Run("ipv6="+map[bool]string{false: "off", true: "on"}[ipv6], func(t *testing.T) {
			peer := newTestStack(t, "peer-1", 1, dhcpTestMTU, 0, 0)
			cfg := StackConfig{
				Hostname:        "dut-2",
				RandSeed:        2,
				StaticAddress4:  [4]byte{10, 0, 0, 2},
				HardwareAddress: [6]byte{0xbe, 0xef, 0, 0, 0, 2},
				MTU:             dhcpTestMTU,
			}
			if ipv6 {
				cfg.IPv6Stack = DefaultStack6()
			}
			var s StackAsync
			err := s.Reset(cfg)
			if err != nil {
				t.Fatal(err)
			}

			// Gateway hardware address defaults to broadcast.
			if got := s.GatewayHardwareAddr(); got != ethernet.BroadcastAddr() {
				t.Fatalf("default GatewayHardwareAddr=%x, want broadcast", got)
			}
			s.SetGatewayHardwareAddr(gwMAC)
			if got := s.GatewayHardwareAddr(); got != gwMAC {
				t.Fatalf("GatewayHardwareAddr=%x, want %x", got, gwMAC)
			}

			// New IPv4 address must be answered over ARP.
			err = s.SetAddr4(newAddr4)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.Addr4(); got != newAddr4 {
				t.Fatalf("Addr4=%v, want %v", got, newAddr4)
			}
			if got := resolveMAC(t, peer, &s, newAddr4); got != cfg.HardwareAddress {
				t.Fatalf("ARP resolved %v to %x, want %x", newAddr4, got, cfg.HardwareAddress)
			}

			// New MAC must be answered over ARP for the same IPv4 address.
			for i := 0; i < 2; i++ {
				err = s.SetHardwareAddr(newMAC) // Repeat exercises ARP node re-registration.
				if err != nil {
					t.Fatalf("SetHardwareAddr call %d: %v", i, err)
				}
			}
			if got := s.HardwareAddr(); got != newMAC {
				t.Fatalf("HardwareAddr=%x, want %x", got, newMAC)
			}
			if got := s.GatewayHardwareAddr(); got != gwMAC {
				t.Fatalf("GatewayHardwareAddr changed by SetHardwareAddr: %x", got)
			}
			err = peer.DiscardResolveHardwareAddress6(netip.AddrFrom4(newAddr4))
			if err != nil {
				t.Fatal(err)
			}
			if got := resolveMAC(t, peer, &s, newAddr4); got != newMAC {
				t.Fatalf("ARP resolved %v to %x after SetHardwareAddr, want %x", newAddr4, got, newMAC)
			}

			// IPv6 address.
			err = s.SetAddr6(newAddr6)
			if !ipv6 {
				if err != lneto.ErrUnsupported {
					t.Fatalf("SetAddr6 without IPv6: want ErrUnsupported, got %v", err)
				}
				if got := s.Addr6(); got != ([16]byte{}) {
					t.Fatalf("Addr6 without IPv6=%x, want zero", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := s.Addr6(); got != newAddr6 {
				t.Fatalf("Addr6=%x, want %x", got, newAddr6)
			}
		})
	}
}

// resolveMAC has querier resolve addr over ARP against target.
func resolveMAC(t *testing.T, querier, target *StackAsync, addr [4]byte) [6]byte {
	t.Helper()
	ip := netip.AddrFrom4(addr)
	err := querier.StartResolveHardwareAddress6(ip)
	if err != nil {
		t.Fatal(err)
	}
	var hw [6]byte
	shuttle(t, querier, target, 4, func() bool {
		hw, err = querier.ResultResolveHardwareAddress6(ip)
		return err == nil
	})
	if err != nil {
		t.Fatal("ARP resolution failed:", err)
	}
	return hw
}
