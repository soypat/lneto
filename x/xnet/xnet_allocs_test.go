package xnet

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/dns/mdns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

// FuzzStackIngressAllocs feeds arbitrary frames to a stack with IPv4, IPv6,
// ICMP, TCP, UDP and mDNS active. Handling a frame and sending what it provokes must not
// allocate, whatever the frame holds. The seeds are the frames a peer sends it
// in ordinary traffic.
func FuzzStackIngressAllocs(f *testing.F) {
	if internal.HeapAllocDebugging {
		f.Skip("debugheaplog logs heap statistics, which allocates")
	}
	_, seeds := newAllocTestStack(f, true)
	for _, frame := range seeds {
		f.Add(frame)
	}
	f.Fuzz(func(t *testing.T, frame []byte) {
		frame = bytes.Clone(frame)
		fixCRCs(frame)
		// AllocsPerRun makes one unmeasured warm-up call before the measured
		// one. Give each call its own fresh stack and copy of the frame, so the
		// measured call is the first frame a stack handles and a first-use
		// allocation is counted rather than absorbed by the warm-up.
		measure := func() float64 {
			type run struct {
				s             *StackAsync
				frame, egress []byte
			}
			var runs [2]run
			for i := range runs {
				s, _ := newAllocTestStack(t, false)
				runs[i] = run{s: s, frame: bytes.Clone(frame), egress: make([]byte, s.MTU()+ethernet.MaxOverheadSize)}
			}
			i := 0
			return testing.AllocsPerRun(1, func() {
				r := &runs[i]
				i++
				r.s.IngressEthernet(r.frame)
				r.s.EgressEthernet(r.egress)
			})
		}
		// The count is process-wide and the fuzzing engine allocates concurrently.
		// An allocation by the stack recurs on every fresh stack, so fail only if
		// it shows in each of three measurements.
		allocs := measure()
		for i := 0; i < 2 && allocs != 0; i++ {
			allocs = min(allocs, measure())
		}
		if allocs != 0 {
			t.Fatalf("handling the frame allocated %v times: %x", allocs, frame)
		}
	})
}

// newAllocTestStack returns a stack at 10.0.0.1 and 2001:db8::1 with ICMP
// enabled, a TCP
// listener on port 80, a UDP connection on port 5000 and an mDNS client with a
// service and a resolve in progress, after exchanging ordinary traffic with a
// peer at 10.0.0.2. With record set it also returns the frames the peer sent.
func newAllocTestStack(t testing.TB, record bool) (s *StackAsync, fromPeer [][]byte) {
	t.Helper()
	const mtu = 1500
	mcast := []byte{224, 0, 0, 251}
	svc := mdns.Service{Name: dns.MustNewName("dut._http._tcp.local"), Host: dns.MustNewName("dut.local"), Addr: []byte{10, 0, 0, 1}, Port: 80}
	peerSvc := mdns.Service{Name: dns.MustNewName("peer._http._tcp.local"), Host: dns.MustNewName("peer.local"), Addr: []byte{10, 0, 0, 2}, Port: 80}
	var stacks [2]*StackAsync
	var clients [2]*mdns.Client
	for i, services := range [][]mdns.Service{{svc}, {peerSvc}} {
		id := byte(i + 1)
		st := new(StackAsync)
		err := st.Reset(StackConfig{
			Hostname:          "alloc-" + string('0'+id),
			RandSeed:          int64(id),
			StaticAddress4:    [4]byte{10, 0, 0, id},
			StaticAddress6:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: id},
			IPv6Stack:         DefaultStack6(),
			HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, id},
			MTU:               mtu,
			MaxActiveTCPPorts: 1,
			MaxActiveUDPPorts: 2,
			ICMPQueueLimit:    4,
			AcceptMulticast:   true,
			Nanotime:          func() int64 { return 1 },
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.EnableICMP(true); err != nil {
			t.Fatal(err)
		}
		clients[i] = new(mdns.Client)
		err = clients[i].Configure(mdns.ClientConfig{LocalPort: mdns.Port, Services: services, MulticastAddr: mcast})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.RegisterUDP4(clients[i], [4]byte(mcast), mdns.Port); err != nil {
			t.Fatal(err)
		}
		stacks[i] = st
	}
	s, peer := stacks[0], stacks[1]
	s.SetGatewayHardwareAddr(peer.HardwareAddr())
	peer.SetGatewayHardwareAddr(s.HardwareAddr())

	buf := make([]byte, mtu+ethernet.MaxOverheadSize)
	pump := func() {
		for range 32 {
			moved := false
			for _, dir := range [2][2]*StackAsync{{s, peer}, {peer, s}} {
				n, err := dir[0].EgressEthernet(buf)
				if err != nil {
					t.Fatal("egress:", err)
				} else if n == 0 {
					continue
				}
				if record && dir[0] == peer {
					fromPeer = append(fromPeer, bytes.Clone(buf[:n]))
				}
				dir[1].IngressEthernet(buf[:n])
				moved = true
			}
			if !moved {
				return
			}
		}
		t.Fatal("traffic did not settle")
	}
	addr1, addr2 := netip.AddrFrom4(s.Addr4()), netip.AddrFrom4(peer.Addr4())
	if err := peer.StartResolveHardwareAddress6(addr1); err != nil {
		t.Fatal(err)
	}
	pump()
	if _, err := peer.icmp.PingStart(s.Addr4(), []byte("ping"), 32); err != nil {
		t.Fatal(err)
	}
	pump()

	c1, c2 := newTestTCPConn(t, 512, 4), newTestTCPConn(t, 512, 4)
	if err := s.ListenTCP4(c1, 80); err != nil {
		t.Fatal(err)
	}
	if err := peer.DialTCP(c2, 1337, netip.AddrPortFrom(addr1, 80)); err != nil {
		t.Fatal(err)
	}
	pump()
	if c1.State() != tcp.StateEstablished {
		t.Fatal("TCP not established:", c1.State())
	}
	if _, err := c2.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	pump()

	var u1, u2 udp.Conn
	for _, u := range []*udp.Conn{&u1, &u2} {
		err := u.Configure(udp.ConnConfig{RxBuf: make([]byte, 512), TxBuf: make([]byte, 512), RxQueueSize: 2, TxQueueSize: 2, RWBackoff: backoffYield, MTU: mtu})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DialUDP(&u1, 5000, netip.AddrPortFrom(addr2, 5001)); err != nil {
		t.Fatal(err)
	}
	if err := peer.DialUDP(&u2, 5001, netip.AddrPortFrom(addr1, 5000)); err != nil {
		t.Fatal(err)
	}
	if _, err := u2.Write([]byte("datagram")); err != nil {
		t.Fatal(err)
	}
	pump()

	for i, name := range []dns.Name{peerSvc.Name, svc.Name} {
		err := clients[i].StartResolve(mdns.ResolveConfig{
			Questions:          []dns.Question{{Name: name, Type: dns.TypeSRV, Class: dns.ClassINET}},
			MaxResponseAnswers: 4,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	pump()
	if record && len(fromPeer) == 0 {
		t.Fatal("peer sent nothing")
	}
	// Leave a resolve running, so responses are parsed rather than ignored.
	err := clients[0].StartResolve(mdns.ResolveConfig{
		Questions:          []dns.Question{{Name: peerSvc.Name, Type: dns.TypeSRV, Class: dns.ClassINET}},
		MaxResponseAnswers: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, fromPeer
}

// fixCRCs recomputes the IPv4 and TCP checksums of an Ethernet frame and
// clears the UDP checksum, which IPv4 treats as absent, so mutated frames are
// not all dropped for a bad checksum.
func fixCRCs(frame []byte) {
	if fixIPTCPCRCs(frame) {
		return
	}
	efrm, err := ethernet.NewFrame(frame)
	if err != nil || efrm.EtherTypeOrSize() != ethernet.TypeIPv4 {
		return
	}
	ifrm, err := ipv4.NewFrame(efrm.Payload())
	if err != nil || ifrm.Protocol() != lneto.IPProtoUDP {
		return
	}
	var vld lneto.Validator
	if ifrm.ValidateSize(&vld); vld.HasError() {
		return
	}
	ufrm, err := udp.NewFrame(ifrm.Payload())
	if err == nil {
		ufrm.SetCRC(0)
	}
}
