package dhcpv4

import (
	"net/netip"
	"testing"
)

func testServerConfig(svAddr [4]byte) ServerConfig {
	return ServerConfig{
		ServerAddr: svAddr,
		Subnet:     netip.PrefixFrom(netip.AddrFrom4(svAddr), 24),
	}
}

// TestServerMultipleClients verifies the server can handle multiple clients
// going through the full DORA flow independently.
func TestServerMultipleClients(t *testing.T) {
	svAddr := [4]byte{192, 168, 1, 1}
	var sv Server
	sv.Configure(testServerConfig(svAddr))

	const nClients = 3
	var clients [nClients]Client
	var bufs [nClients][1024]byte

	for i := range clients {
		err := clients[i].BeginRequest(uint32(100+i), RequestConfig{
			ClientHardwareAddr: [6]byte{0, 0, 0, 0, 0, byte(i + 1)},
			Hostname:           "host",
			ClientID:           string([]byte{byte(i + 1)}),
		})
		if err != nil {
			t.Fatalf("client %d BeginRequest: %v", i, err)
		}
	}

	// Phase 1: All clients send DISCOVER.
	for i := range clients {
		n, err := clients[i].Encapsulate(bufs[i][:], -1, 0)
		if err != nil {
			t.Fatalf("client %d discover encapsulate: %v", i, err)
		}
		err = sv.Demux(bufs[i][:n], 0)
		if err != nil {
			t.Fatalf("client %d discover demux: %v", i, err)
		}
	}

	// Route server responses to the correct client by XID (map iteration is non-deterministic).
	clientByXID := make(map[uint32]int)
	for i := range clients {
		clientByXID[uint32(100+i)] = i
	}

	// Phase 2: Server sends all OFFERs, clients receive.
	var assignedAddrs [nClients][4]byte
	for range clients {
		var buf [1024]byte
		n, err := sv.Encapsulate(buf[:], -1, 0)
		if err != nil {
			t.Fatalf("offer encapsulate: %v", err)
		} else if n == 0 {
			t.Fatal("no offer from server")
		}
		frm, _ := NewFrame(buf[:n])
		ci := clientByXID[frm.XID()]
		assignedAddrs[ci] = *frm.YIAddr()
		err = clients[ci].Demux(buf[:n], 0)
		if err != nil {
			t.Fatalf("client %d offer demux: %v", ci, err)
		}
	}

	// Phase 3: All clients send REQUEST.
	for i := range clients {
		n, err := clients[i].Encapsulate(bufs[i][:], -1, 0)
		if err != nil {
			t.Fatalf("client %d request encapsulate: %v", i, err)
		} else if n == 0 {
			t.Fatalf("client %d: no request data", i)
		}
		err = sv.Demux(bufs[i][:n], 0)
		if err != nil {
			t.Fatalf("client %d request demux: %v", i, err)
		}
	}

	// Phase 4: Server sends all ACKs, clients receive.
	for range clients {
		var buf [1024]byte
		n, err := sv.Encapsulate(buf[:], -1, 0)
		if err != nil {
			t.Fatalf("ack encapsulate: %v", err)
		} else if n == 0 {
			t.Fatal("no ack from server")
		}
		frm, _ := NewFrame(buf[:n])
		ci := clientByXID[frm.XID()]
		err = clients[ci].Demux(buf[:n], 0)
		if err != nil {
			t.Fatalf("client %d ack demux: %v", ci, err)
		}
		if clients[ci].State() != StateBound {
			t.Errorf("client %d: want StateBound, got %s", ci, clients[ci].State())
		}
	}

	// All assigned addresses must be unique.
	for i := 0; i < nClients; i++ {
		for j := i + 1; j < nClients; j++ {
			if assignedAddrs[i] == assignedAddrs[j] {
				t.Errorf("clients %d and %d got same address %v", i, j, assignedAddrs[i])
			}
		}
	}
}

// TestServerSequentialAddressAllocation verifies that the server allocates
// addresses sequentially starting from serverAddr+1.
func TestServerSequentialAddressAllocation(t *testing.T) {
	svAddr := [4]byte{192, 168, 1, 1}
	var sv Server
	sv.Configure(testServerConfig(svAddr))

	// Build raw DISCOVER frames for two clients.
	for i := byte(0); i < 2; i++ {
		var buf [512]byte
		frm, _ := NewFrame(buf[:])
		frm.ClearHeader()
		frm.SetOp(OpRequest)
		frm.SetHardware(1, 6, 0)
		frm.SetXID(uint32(200 + i))
		frm.SetSecs(1)
		copy(frm.CHAddrAs6()[:], []byte{0, 0, 0, 0, 0, 10 + i})
		frm.SetMagicCookie(MagicCookie)
		opts := buf[OptionsOffset:]
		n := writeOption(opts, OptMessageType, byte(MsgDiscover))
		n += writeOption(opts[n:], OptClientIdentifier, 10+i)
		opts[n] = byte(OptEnd)
		n++

		err := sv.Demux(buf[:OptionsOffset+n], 0)
		if err != nil {
			t.Fatalf("discover %d: %v", i, err)
		}
	}

	// Encapsulate both OFFERs and verify addresses are in expected range.
	var seen [2][4]byte
	for i := byte(0); i < 2; i++ {
		var buf [512]byte
		n, err := sv.Encapsulate(buf[:], -1, 0)
		if err != nil {
			t.Fatalf("offer %d encapsulate: %v", i, err)
		} else if n == 0 {
			t.Fatalf("offer %d: no data", i)
		}
		frm, _ := NewFrame(buf[:n])
		seen[i] = *frm.YIAddr()
		if seen[i][0] != 192 || seen[i][1] != 168 || seen[i][2] != 1 {
			t.Errorf("offer %d: unexpected subnet in %v", i, seen[i])
		}
		if seen[i][3] != 2 && seen[i][3] != 3 {
			t.Errorf("offer %d: expected .2 or .3, got .%d", i, seen[i][3])
		}
	}
	if seen[0] == seen[1] {
		t.Errorf("both offers got same address %v", seen[0])
	}
}

// TestServerOfferContainsOptions verifies that server OFFER responses
// contain the expected DHCP options from the ServerConfig.
func TestServerOfferContainsOptions(t *testing.T) {
	svAddr := [4]byte{192, 168, 1, 1}
	gwAddr := [4]byte{192, 168, 1, 254}
	dnsAddr := [4]byte{8, 8, 8, 8}
	var sv Server
	sv.Configure(ServerConfig{
		ServerAddr:   svAddr,
		Gateway:      gwAddr,
		DNS:          dnsAddr,
		Subnet:       netip.PrefixFrom(netip.AddrFrom4(svAddr), 24),
		LeaseSeconds: 7200,
	})

	var cl Client
	err := cl.BeginRequest(500, RequestConfig{
		ClientHardwareAddr: [6]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe},
	})
	if err != nil {
		t.Fatal(err)
	}

	var buf [1024]byte
	n, err := cl.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = sv.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}

	n, err = sv.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	frm, _ := NewFrame(buf[:n])

	var gotServerID, gotRouter, gotSubnet, gotDNS [4]byte
	var gotLease, gotRenew, gotRebind uint32
	var foundServerID, foundRouter, foundSubnet, foundDNS, foundLease bool
	frm.ForEachOption(func(_ int, opt OptNum, data []byte) error {
		switch opt {
		case OptServerIdentification:
			if len(data) == 4 {
				foundServerID = true
				copy(gotServerID[:], data)
			}
		case OptRouter:
			if len(data) == 4 {
				foundRouter = true
				copy(gotRouter[:], data)
			}
		case OptSubnetMask:
			if len(data) == 4 {
				foundSubnet = true
				copy(gotSubnet[:], data)
			}
		case OptDNSServers:
			if len(data) == 4 {
				foundDNS = true
				copy(gotDNS[:], data)
			}
		case OptIPAddressLeaseTime:
			if len(data) == 4 {
				foundLease = true
				gotLease = maybeU32(data)
			}
		case OptRenewTimeValue:
			gotRenew = maybeU32(data)
		case OptRebindingTimeValue:
			gotRebind = maybeU32(data)
		}
		return nil
	})
	if !foundServerID || gotServerID != svAddr {
		t.Errorf("server ID: found=%v got=%v want=%v", foundServerID, gotServerID, svAddr)
	}
	if !foundRouter || gotRouter != gwAddr {
		t.Errorf("router: found=%v got=%v want=%v", foundRouter, gotRouter, gwAddr)
	}
	if !foundSubnet || gotSubnet != [4]byte{255, 255, 255, 0} {
		t.Errorf("subnet: found=%v got=%v want=255.255.255.0", foundSubnet, gotSubnet)
	}
	if !foundDNS || gotDNS != dnsAddr {
		t.Errorf("DNS: found=%v got=%v want=%v", foundDNS, gotDNS, dnsAddr)
	}
	if !foundLease || gotLease != 7200 {
		t.Errorf("lease: found=%v got=%v want=7200", foundLease, gotLease)
	}
	if gotRenew != 3600 {
		t.Errorf("renew T1: got %d want 3600", gotRenew)
	}
	if gotRebind != 6300 {
		t.Errorf("rebind T2: got %d want 6300", gotRebind)
	}
}

// TestServerEncapsulateNoPending verifies Encapsulate returns 0 bytes
// when there are no pending responses.
func TestServerEncapsulateNoPending(t *testing.T) {
	var sv Server
	sv.Configure(testServerConfig([4]byte{192, 168, 1, 1}))

	var buf [512]byte
	n, err := sv.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes from empty server, got %d", n)
	}
}

// TestServerConfigValidation verifies that Configure rejects invalid configurations.
func TestServerConfigValidation(t *testing.T) {
	var sv Server
	err := sv.Configure(ServerConfig{
		ServerAddr: [4]byte{192, 168, 1, 1},
	})
	if err == nil {
		t.Error("expected error for zero subnet")
	}
	err = sv.Configure(ServerConfig{
		ServerAddr: [4]byte{10, 0, 0, 1},
		Subnet:     netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 1, 0}), 24),
	})
	if err == nil {
		t.Error("expected error for server address outside subnet")
	}
}

// TestServerRediscover verifies that a client that was previously bound
// can send a fresh DISCOVER and get re-served.
func TestServerRediscover(t *testing.T) {
	svAddr := [4]byte{192, 168, 1, 1}
	var sv Server
	sv.Configure(testServerConfig(svAddr))

	// First DORA cycle.
	var cl Client
	cl.BeginRequest(1, RequestConfig{
		ClientHardwareAddr: [6]byte{1, 2, 3, 4, 5, 6},
		ClientID:           "rediscover-client",
	})
	var buf [1024]byte
	n, _ := cl.Encapsulate(buf[:], -1, 0)
	sv.Demux(buf[:n], 0)
	n, _ = sv.Encapsulate(buf[:], -1, 0)
	cl.Demux(buf[:n], 0)
	n, _ = cl.Encapsulate(buf[:], -1, 0)
	sv.Demux(buf[:n], 0)
	n, _ = sv.Encapsulate(buf[:], -1, 0)
	cl.Demux(buf[:n], 0)
	if cl.State() != StateBound {
		t.Fatalf("first DORA: want StateBound, got %s", cl.State())
	}

	// Client reboots and sends fresh DISCOVER.
	cl.Reset()
	cl.BeginRequest(2, RequestConfig{
		ClientHardwareAddr: [6]byte{1, 2, 3, 4, 5, 6},
		ClientID:           "rediscover-client",
	})
	n, _ = cl.Encapsulate(buf[:], -1, 0)
	err := sv.Demux(buf[:n], 0)
	if err != nil {
		t.Fatalf("rediscover demux: %v", err)
	}
	n, _ = sv.Encapsulate(buf[:], -1, 0)
	if n == 0 {
		t.Fatal("no offer after rediscover")
	}
	err = cl.Demux(buf[:n], 0)
	if err != nil {
		t.Fatalf("rediscover offer demux: %v", err)
	}
	// Complete the second DORA.
	n, _ = cl.Encapsulate(buf[:], -1, 0)
	sv.Demux(buf[:n], 0)
	n, _ = sv.Encapsulate(buf[:], -1, 0)
	cl.Demux(buf[:n], 0)
	if cl.State() != StateBound {
		t.Errorf("second DORA: want StateBound, got %s", cl.State())
	}
}