package xnet

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/tcp"
)

// TestSubnetTable_PatchEgressMAC_WhenGatewayMAC captures the bug where patchEgressMAC
// returns early when the Ethernet dst is a gateway MAC (not broadcast), so it never
// patches the destination to the passively-learned client MAC.
func TestSubnetTable_PatchEgressMAC_WhenGatewayMAC(t *testing.T) {
	clientIP := [4]byte{10, 0, 0, 1}
	clientMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}
	serverIP := [4]byte{10, 0, 0, 2}
	serverMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02}
	gatewayMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF} // separate from client

	var st subnetTable
	st.reset(4, 2)
	st.subnet = netip.MustParsePrefix("10.0.0.0/24")

	// Learn client MAC from a simulated ingress frame (client→server SYN).
	ingressFrame := makeMinimalIPv4Frame(serverMAC, clientMAC, clientIP, serverIP)
	st.learnFromIngressEthernet(ingressFrame)

	// Simulate egress SYN-ACK: stack uses gateway MAC as Ethernet dst (the bug).
	egressFrame := makeMinimalIPv4Frame(gatewayMAC, serverMAC, serverIP, clientIP)
	st.patchEgressMAC(egressFrame)

	gotDst := [6]byte(egressFrame[0:6])
	if gotDst != clientMAC {
		t.Errorf("patchEgressMAC did not fix Ethernet dst:\n  got  %x (gateway MAC)\n  want %x (client MAC)", gotDst, clientMAC)
	}
}

// TestStackAsync_ListenerSynAckAddressedToClient mirrors the ESP32 hotspot scenario:
// server's gateway is a router (not the client), so the SYN-ACK must use the
// passively-learned client MAC, not the router/gateway MAC.
func TestStackAsync_ListenerSynAckAddressedToClient(t *testing.T) {
	const mtu = ethernet.MaxMTU
	const svPort = 80

	clientMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}
	serverMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02}
	routerMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF} // third party — not client

	// Server: gateway = router (not client), but passively learns client MAC from SYN.
	var sv StackAsync
	err := sv.Reset(StackConfig{
		Hostname:          "Server1",
		RandSeed:          1234,
		StaticAddress:     netip.AddrFrom4([4]byte{10, 0, 0, 2}),
		MaxActiveTCPPorts: 1,
		HardwareAddress:   serverMAC,
		MTU:               mtu,
		PassivePeers:      2,
	})
	if err != nil {
		t.Fatal(err)
	}
	sv.SetGateway6(routerMAC)
	sv.SetSubnet(netip.MustParsePrefix("10.0.0.0/24"))

	pool, err := NewTCPPool(TCPPoolConfig{
		PoolSize:           1,
		QueueSize:          4,
		TxBufSize:          mtu,
		RxBufSize:          mtu,
		EstablishedTimeout: 10e9,
		ClosingTimeout:     10e9,
	})
	if err != nil {
		t.Fatal(err)
	}
	var listener tcp.Listener
	if err = listener.Reset(svPort, pool); err != nil {
		t.Fatal(err)
	}
	if err = sv.RegisterListener(&listener); err != nil {
		t.Fatal(err)
	}

	// Client: gateway = server MAC (direct L2 path, as in a hotspot WLAN).
	var client StackAsync
	err = client.Reset(StackConfig{
		Hostname:          "Client1",
		RandSeed:          5678,
		StaticAddress:     netip.AddrFrom4([4]byte{10, 0, 0, 1}),
		MaxActiveTCPPorts: 1,
		HardwareAddress:   clientMAC,
		MTU:               mtu,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.SetGateway6(serverMAC)

	var clConn tcp.Conn
	if err = clConn.Configure(tcp.ConnConfig{
		RxBuf: make([]byte, mtu), TxBuf: make([]byte, mtu),
		TxPacketQueueSize: 4,
	}); err != nil {
		t.Fatal(err)
	}
	if err = client.DialTCP(&clConn, 54321, netip.AddrPortFrom(sv.Addr(), svPort)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, mtu+ethernet.MaxOverheadSize)

	// Step 1: client egresses SYN.
	n, err := client.EgressEthernet(buf)
	if err != nil || n == 0 {
		t.Fatalf("client egress SYN: n=%d err=%v", n, err)
	}
	synDst := [6]byte(buf[0:6])
	if synDst != serverMAC {
		t.Fatalf("SYN Ethernet dst wrong: got %x, want server %x", synDst, serverMAC)
	}

	// Step 2: server ingresses SYN — passively learns client MAC.
	if err = sv.IngressEthernet(buf[:n]); err != nil {
		t.Fatalf("server ingress SYN: %v", err)
	}

	// Step 3: server egresses SYN-ACK — must be addressed to client, not router.
	clear(buf)
	n, err = sv.EgressEthernet(buf)
	if err != nil || n == 0 {
		t.Fatalf("server egress SYN-ACK: n=%d err=%v", n, err)
	}

	synackDst := [6]byte(buf[0:6])
	if synackDst != clientMAC {
		t.Errorf("SYN-ACK Ethernet dst wrong:\n  got  %x\n  want %x (client MAC)\n  note: %x is router MAC", synackDst, clientMAC, routerMAC)
	}
}

// makeMinimalIPv4Frame builds a 35-byte Ethernet+IPv4 frame (no payload, 1 padding byte).
// This is the minimum size that passes both learnFromIngressEthernet (>34) and patchEgressMAC (>=34) checks.
func makeMinimalIPv4Frame(dstMAC, srcMAC [6]byte, srcIP, dstIP [4]byte) []byte {
	frame := make([]byte, 35)
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], uint16(ethernet.TypeIPv4))
	frame[14] = 0x45 // IPv4, IHL=5
	frame[22] = 64   // TTL
	copy(frame[26:30], srcIP[:])
	copy(frame[30:34], dstIP[:])
	return frame
}
