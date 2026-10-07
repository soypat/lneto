package xnet

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

// TestStackAsync_ResetMatchesFresh verifies a stack reset with a configuration
// puts the same frames on the wire as a fresh stack with that configuration,
// whatever configuration it had and traffic it carried before. State that
// survives Reset shows up as a difference in the frames.
func TestStackAsync_ResetMatchesFresh(t *testing.T) {
	small := resetTestConfig(576, 1, 1, 0, 1)
	big := resetTestConfig(ethernet.MaxMTU, 4, 4, 3, 4)
	for _, tc := range []struct {
		name          string
		before, after StackConfig
	}{
		{name: "same-small", before: small, after: small},
		{name: "same-big", before: big, after: big},
		{name: "shrink", before: big, after: small},
		{name: "grow", before: small, after: big},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fresh StackAsync
			if err := fresh.Reset(tc.after); err != nil {
				t.Fatal(err)
			}
			want := resetTestTraffic(t, &fresh, true)

			var reused StackAsync
			if err := reused.Reset(tc.before); err != nil {
				t.Fatal(err)
			}
			resetTestTraffic(t, &reused, false) // Leaves connections, a ping and an ARP query open.
			if err := reused.Reset(tc.after); err != nil {
				t.Fatal(err)
			}
			got := resetTestTraffic(t, &reused, true)
			for _, frames := range [][][]byte{got, want} {
				for _, frm := range frames {
					ignoreEchoSeq(frm)
				}
			}
			for i := range max(len(got), len(want)) {
				if i >= len(got) || i >= len(want) || !bytes.Equal(got[i], want[i]) {
					t.Fatalf("frame %d of %d differs from a fresh stack's (%d frames):\n got=%x\nwant=%x", i, len(got), len(want), at(got, i), at(want, i))
				}
			}
		})
	}
}

// ignoreEchoSeq zeroes the sequence number and checksum of an ICMP echo in an
// Ethernet/IPv4 frame. The sequence keeps counting across Reset; replies are
// matched by payload and address, so it carries no state that matters.
func ignoreEchoSeq(frm []byte) {
	const icmp = 14 + 20
	if len(frm) >= icmp+8 && frm[12] == 0x08 && frm[13] == 0x00 && frm[14] == 0x45 && frm[23] == 1 {
		frm[icmp+2], frm[icmp+3] = 0, 0 // Checksum.
		frm[icmp+6], frm[icmp+7] = 0, 0 // Sequence number.
	}
}

func at(frames [][]byte, i int) []byte {
	if i < len(frames) {
		return frames[i]
	}
	return nil
}

func resetTestConfig(mtu, tcpPorts, udpPorts uint16, passivePeers, icmpQueue int) StackConfig {
	return StackConfig{
		Hostname:          "dut-1",
		RandSeed:          1,
		StaticAddress4:    [4]byte{10, 0, 0, 1},
		HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, 1},
		MTU:               mtu,
		MaxActiveTCPPorts: tcpPorts,
		MaxActiveUDPPorts: udpPorts,
		PassivePeers:      passivePeers,
		ICMPQueueLimit:    icmpQueue,
		Nanotime:          func() int64 { return 1 },
	}
}

// resetTestTraffic resolves, pings, and exchanges TCP and UDP data between s
// and a fresh peer at 10.0.0.2, returning every frame both sent in order.
// With finish false it sets a subnet, leaves the connections open, a ping in
// flight and an ARP query pending, and the peer uses another hardware address,
// so entries that survive Reset send frames to the wrong one.
func resetTestTraffic(t *testing.T, s *StackAsync, finish bool) (frames [][]byte) {
	peer := newTestStackClock(t, "peer-2", 2, uint16(s.MTU()), 1, 1, func() int64 { return 1 })
	if !finish {
		if err := peer.SetHardwareAddr([6]byte{0xde, 0xad, 0, 0, 0, 2}); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, ethernet.MaxFrameLength)
	pump := func() {
		for range 64 {
			moved := false
			for _, dir := range [2][2]*StackAsync{{s, peer}, {peer, s}} {
				n, err := dir[0].EgressEthernet(buf)
				if err != nil {
					t.Fatal("egress:", err)
				} else if n == 0 {
					continue
				}
				frames = append(frames, bytes.Clone(buf[:n]))
				dir[1].IngressEthernet(buf[:n])
				moved = true
			}
			if !moved {
				return
			}
		}
		t.Fatal("traffic did not settle")
	}
	peerAddr := netip.AddrFrom4(peer.Addr4())
	if !finish {
		s.SetSubnet4(s.Addr4(), 24) // As after DHCP; enables learning passive peers.
	}
	if err := s.StartResolveHardwareAddress6(peerAddr); err != nil {
		t.Fatal(err)
	}
	pump()
	if _, err := s.ResultResolveHardwareAddress6(peerAddr); err != nil {
		t.Fatal("ARP:", err)
	}
	s.SetGatewayHardwareAddr(peer.HardwareAddr())
	peer.SetGatewayHardwareAddr(s.HardwareAddr())

	for _, st := range []*StackAsync{s, peer} {
		if err := st.EnableICMP(true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.icmp.PingStart(peer.Addr4(), []byte("pingdata"), 16); err != nil {
		t.Fatal(err)
	}

	var c1, c2 tcp.Conn
	for _, c := range []*tcp.Conn{&c1, &c2} {
		*c = *newTestTCPConn(t, 256, 4)
	}
	if err := peer.ListenTCP4(&c2, 80); err != nil {
		t.Fatal(err)
	}
	if err := s.DialTCP(&c1, 1337, netip.AddrPortFrom(peerAddr, 80)); err != nil {
		t.Fatal(err)
	}
	pump()
	if _, err := c1.Write([]byte("tcp payload")); err != nil {
		t.Fatal(err)
	}
	pump()

	var u1, u2 udp.Conn
	for _, u := range []*udp.Conn{&u1, &u2} {
		err := u.Configure(udp.ConnConfig{RxBuf: make([]byte, 256), TxBuf: make([]byte, 256), RxQueueSize: 2, TxQueueSize: 2, RWBackoff: backoffYield, MTU: uint16(s.MTU())})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DialUDP(&u1, 5000, netip.AddrPortFrom(peerAddr, 5001)); err != nil {
		t.Fatal(err)
	}
	if err := peer.DialUDP(&u2, 5001, netip.AddrPortFrom(netip.AddrFrom4(s.Addr4()), 5000)); err != nil {
		t.Fatal(err)
	}
	if _, err := u1.Write([]byte("udp payload")); err != nil {
		t.Fatal(err)
	}
	pump()
	if !finish {
		// Best effort: a small configuration may have no room left for these.
		s.icmp.PingStart(peer.Addr4(), []byte("pingdata"), 16)
		s.StartResolveHardwareAddress6(netip.AddrFrom4([4]byte{10, 0, 0, 9}))
		return frames
	}
	if err := c1.Close(); err != nil {
		t.Fatal(err)
	}
	pump()
	return frames
}

// TestStackAsync_ResetClearsSubnet verifies Reset forgets a subnet set with
// SetSubnet4: a destination in it is then sent to the gateway instead of being
// resolved on the link.
func TestStackAsync_ResetClearsSubnet(t *testing.T) {
	cfg := resetTestConfig(576, 1, 1, 0, 1)
	var s StackAsync
	if err := s.Reset(cfg); err != nil {
		t.Fatal(err)
	}
	s.SetSubnet4(s.Addr4(), 24)
	if err := s.Reset(cfg); err != nil {
		t.Fatal(err)
	}
	router := [6]byte{0x02, 0, 0, 0, 0, 0xfe}
	s.SetGatewayHardwareAddr(router)
	var u udp.Conn
	err := u.Configure(udp.ConnConfig{RxBuf: make([]byte, 64), TxBuf: make([]byte, 64), RxQueueSize: 1, TxQueueSize: 1, RWBackoff: backoffYield, MTU: uint16(s.MTU())})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DialUDP(&u, 5000, netip.MustParseAddrPort("10.0.0.2:5001")); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, ethernet.MaxFrameLength)
	n, err := s.EgressEthernet(buf)
	if err != nil {
		t.Fatal(err)
	}
	efrm, err := ethernet.NewFrame(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if efrm.EtherTypeOrSize() != ethernet.TypeIPv4 || *efrm.DestinationHardwareAddr() != router {
		t.Fatalf("first frame %s to %x, want IPv4 to the gateway %x", efrm.EtherTypeOrSize(), *efrm.DestinationHardwareAddr(), router)
	}
}

// TestStack6_ResetForgetsNeighborQueries verifies a neighbor query left
// unsent by a dial is dropped by Reset6 instead of being sent afterwards, and
// that no pending resolve keeps pointing into the old connection.
func TestStack6_ResetForgetsNeighborQueries(t *testing.T) {
	cfg, _ := stack6PairConfigs(1, 1, 2)
	s := DefaultStack6()
	if err := s.Reset6(&cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableICMP6(true); err != nil {
		t.Fatal(err)
	}
	unknown := [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 9} // 2001:db8::9, never answers.
	if err := s.DialUDP6(newUDPConn6(t), 5000, unknown, 5001); err != nil {
		t.Fatal(err)
	}
	if err := s.Reset6(&cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableICMP6(true); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, ethernet.MaxMTU)
	if n, err := s.EgressIPv6(buf); err != nil || n != 0 {
		t.Errorf("EgressIPv6 after Reset6 = %d, %v; want nothing sent", n, err)
	}
	for _, p := range s.(*stack6).ndpPending {
		if p.macBuf != nil {
			t.Fatalf("pending resolve for %x survived Reset6", p.addr)
		}
	}
}
