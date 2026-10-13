package xnet

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	randv2 "math/rand/v2"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dhcp/dhcpv4"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/dns/mdns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/ipv4/icmpv4"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

const (
	logExchange = false

	synack = tcp.FlagSYN | tcp.FlagACK
	pshack = tcp.FlagPSH | tcp.FlagACK
	finack = tcp.FlagFIN | tcp.FlagACK
)

func TestTCPConn_ReadBlocksUntilDataAvailable(t *testing.T) {
	const seed = 5678
	const MTU = ethernet.MaxMTU
	const svPort = 8080
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := testerFrom(t, MTU)

	// Drive svconn.Read from a single background goroutine whose backoff is
	// controlled by the scheduler. This lets the test thread know deterministically
	// when Read has parked waiting for data, instead of sleeping and hoping it blocked.
	tsched := ltesto.NewSched(t)
	tgoro := tsched.Goro()
	err := svconn.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, MTU),
		TxBuf:             make([]byte, MTU),
		TxPacketQueueSize: 4,
		RWBackoff:         tgoro.Yield,
	})
	if err != nil {
		t.Fatal(err)
	}

	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)

	// Verify no data buffered initially.
	if svconn.BufferedInput() != 0 {
		t.Fatal("expected no buffered input on server conn")
	}

	sendData := []byte("blocking test data")
	var readN int
	var readBuf [64]byte

	// Start a goroutine to read from svconn - this should block since no data available.
	go func() {
		n, err := svconn.Read(readBuf[:])
		readN = n
		tgoro.FinishWithErr(err)
	}()

	// AwaitGoroYield blocks until Read parks in backoff: deterministic proof that
	// Read found no data available and is waiting.
	tsched.AwaitGoroYield()
	if readN != 0 {
		t.Fatal("Read returned before data was available")
	}

	// Write data on client side.
	_, err = clconn.Write(sendData)
	if err != nil {
		t.Fatal(err)
	}

	// Perform packet exchange to deliver data.
	tst.bufmu.Lock()
	buf := tst.buf[:cap(tst.buf)]
	n, err := client.EgressEthernet(buf)
	if err != nil {
		tst.bufmu.Unlock()
		t.Fatal(err)
	}
	if n == 0 {
		tst.bufmu.Unlock()
		t.Fatal("expected data packet from client")
	}
	err = sv.IngressEthernet(buf[:n])
	tst.bufmu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	// Release Read; the data is now available so it returns instead of backing off again.
	tsched.YieldToGoro()
	readErr := <-tsched.Done()
	if readErr != nil {
		t.Fatalf("Read returned error: %v", readErr)
	}
	if readN != len(sendData) {
		t.Fatalf("expected to read %d bytes, got %d", len(sendData), readN)
	}
	if !bytes.Equal(readBuf[:readN], sendData) {
		t.Fatalf("read data mismatch: got %q, want %q", readBuf[:readN], sendData)
	}
}

func TestStackAsyncTCP_multipacket(t *testing.T) {
	const seed = 1234
	const MTU = 512
	const svPort = 8080
	const maxPktLen = 30
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := testerFrom(t, MTU)
	rng := rand.New(rand.NewSource(seed))
	client2, sv2, clconn2, svconn2 := newTCPStacks(t, seed, MTU)

	for _, clientCloses := range []bool{true, false} {
		testClose := func() {
			t.Helper()
			if clientCloses {
				tst.TestTCPClose(client, sv, clconn, svconn)
			} else {
				tst.TestTCPClose(sv, client, svconn, clconn)
			}
		}
		tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)
		testClose()
		var buf [MTU]byte
		for range 20 {
			payloadSize := rng.Intn(maxPktLen) + 1
			tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)
			// npkt := rng.Intn(maxNPkt-1) + 2
			a, _ := rng.Read(buf[:payloadSize])
			tst.TestTCPEstablishedSingleData(sv, client, svconn, clconn, buf[:a])
			a, _ = rng.Read(buf[:payloadSize])
			tst.TestTCPEstablishedSingleData(sv, client, svconn, clconn, buf[:a])
			// for ipkt := 0; ipkt < npkt; ipkt++ {
			// 	a, _ := rng.Read(buf[:payloadSize])
			// 	tst.TestTCPEstablishedSingleData(sv, client, svconn, clconn, buf[:a])
			// }
			testClose()
			if t.Failed() {
				t.Error("multi failed")
				t.FailNow()
			}
		}
	}
	_, _, _, _ = client2, sv2, clconn2, svconn2

}

func TestStackAsyncTCP_singlepacket(t *testing.T) {
	const seed = 1234
	const MTU = ethernet.MaxMTU
	const svPort = 80
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := testerFrom(t, MTU)

	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)
	sendData := []byte("hello")
	tst.TestTCPEstablishedSingleData(client, sv, clconn, svconn, sendData)
	tst.TestTCPClose(client, sv, clconn, svconn)

	// Switch handles around, now server will be client and they will be registered to
	// a different stack.
	svconn, clconn = clconn, svconn
	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1234)
	sendData = []byte("olleh")
	tst.TestTCPEstablishedSingleData(client, sv, clconn, svconn, sendData)
	tst.TestTCPClose(client, sv, clconn, svconn)
}

type tcpExpectExchange struct {
	SourceIdx int
	WantFlags tcp.Flags
	WantData  []byte
}

// TestTCPConn_BufferNotClearedOnPassiveClose tests that data remains readable after
// the TCP connection is closed by the remote peer. This is a regression test
// for a bug where the receive buffer was cleared when the connection transitioned
// to CLOSED state, causing data loss.
//
// The sequence is:
//  1. Server sends DATA then initiates close (FIN)
//  2. Client receives data, enters CLOSE_WAIT
//  3. Client sends ACK, then FIN+ACK (enters LAST_ACK)
//  4. Server sends final ACK
//  5. Client receives ACK in LAST_ACK -> state becomes CLOSED
//  6. At this point, client.Read() should still return the buffered data
//
// The bug was that reset() cleared bufRx when state became CLOSED.
func TestTCPConn_BufferNotClearedOnPassiveClose(t *testing.T) {
	const seed = 9999
	const MTU = ethernet.MaxMTU
	const svPort = 8080
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := testerFrom(t, MTU)

	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)

	// Server writes data to be sent.
	sendData := []byte("this data should survive close handshake")
	_, err := svconn.Write(sendData)
	if err != nil {
		t.Fatal("server write:", err)
	}

	// Server sends DATA packet to client.
	tst.bufmu.Lock()
	buf := tst.buf[:cap(tst.buf)]
	n, err := sv.EgressEthernet(buf)
	if err != nil {
		tst.bufmu.Unlock()
		t.Fatal("server encapsulate data:", err)
	}
	if n == 0 {
		tst.bufmu.Unlock()
		t.Fatal("expected data packet from server")
	}
	err = client.IngressEthernet(buf[:n])
	tst.bufmu.Unlock()
	if err != nil {
		t.Fatal("client demux data:", err)
	}

	// Verify client buffered the data.
	if clconn.BufferedInput() != len(sendData) {
		t.Fatalf("client did not buffer data: got %d, want %d", clconn.BufferedInput(), len(sendData))
	}

	// Client sends ACK for data.
	tst.bufmu.Lock()
	buf = tst.buf[:cap(tst.buf)]
	n, err = client.EgressEthernet(buf)
	if err != nil {
		tst.bufmu.Unlock()
		t.Fatal("client encapsulate ACK:", err)
	}
	if n > 0 {
		err = sv.IngressEthernet(buf[:n])
		if err != nil {
			tst.bufmu.Unlock()
			t.Fatal("server demux ACK:", err)
		}
	}
	tst.bufmu.Unlock()

	// Server initiates close.
	err = svconn.Close()
	if err != nil {
		t.Fatal("server close:", err)
	}

	// Server sends FIN (enters FIN_WAIT_1).
	tst.bufmu.Lock()
	buf = tst.buf[:cap(tst.buf)]
	n, err = sv.EgressEthernet(buf)
	if err != nil {
		tst.bufmu.Unlock()
		t.Fatal("server encapsulate FIN:", err)
	}
	if n == 0 {
		tst.bufmu.Unlock()
		t.Fatal("expected FIN packet from server")
	}
	err = client.IngressEthernet(buf[:n])
	tst.bufmu.Unlock()
	if err != nil {
		t.Fatal("client demux FIN:", err)
	}

	if svconn.State() != tcp.StateFinWait1 {
		t.Fatalf("expected server in FIN_WAIT_1, got %s", svconn.State())
	}
	if clconn.State() != tcp.StateCloseWait {
		t.Fatalf("expected client in CLOSE_WAIT, got %s", clconn.State())
	}

	// Client sends ACK for FIN.
	tst.bufmu.Lock()
	buf = tst.buf[:cap(tst.buf)]
	n, err = client.EgressEthernet(buf)
	if err != nil {
		tst.bufmu.Unlock()
		t.Fatal("client encapsulate ACK:", err)
	}
	if n > 0 {
		err = sv.IngressEthernet(buf[:n])
		if err != nil {
			tst.bufmu.Unlock()
			t.Fatal("server demux ACK:", err)
		}
	}
	tst.bufmu.Unlock()

	if svconn.State() != tcp.StateFinWait2 {
		t.Fatalf("expected server in FIN_WAIT_2, got %s", svconn.State())
	}

	// Client initiates its close.
	err = clconn.Close()
	if err != nil {
		t.Fatal("client close:", err)
	}

	// Client sends FIN (enters LAST_ACK).
	tst.bufmu.Lock()
	buf = tst.buf[:cap(tst.buf)]
	n, err = client.EgressEthernet(buf)
	if err != nil {
		tst.bufmu.Unlock()
		t.Fatal("client encapsulate FIN:", err)
	}
	if n == 0 {
		tst.bufmu.Unlock()
		t.Fatal("expected FIN packet from client")
	}
	err = sv.IngressEthernet(buf[:n])
	tst.bufmu.Unlock()
	if err != nil {
		t.Fatal("server demux client FIN:", err)
	}

	if clconn.State() != tcp.StateLastAck {
		t.Fatalf("expected client in LAST_ACK, got %s", clconn.State())
	}
	if svconn.State() != tcp.StateTimeWait {
		t.Fatalf("expected server in TIME_WAIT, got %s", svconn.State())
	}

	// Server sends final ACK.
	tst.bufmu.Lock()
	buf = tst.buf[:cap(tst.buf)]
	n, err = sv.EgressEthernet(buf)
	if err != nil {
		tst.bufmu.Unlock()
		t.Fatal("server encapsulate final ACK:", err)
	}
	if n == 0 {
		tst.bufmu.Unlock()
		t.Fatal("expected final ACK from server")
	}
	err = client.IngressEthernet(buf[:n])
	tst.bufmu.Unlock()
	if err != nil {
		t.Fatal("client demux final ACK:", err)
	}

	// Client should now be CLOSED.
	if clconn.State() != tcp.StateClosed {
		t.Fatalf("expected client in CLOSED, got %s", clconn.State())
	}

	// THE BUG: At this point, the data should still be readable, but the
	// buffer was cleared by reset() when state transitioned to CLOSED.
	//
	// This test will FAIL until the bug is fixed.
	readBuf := make([]byte, MTU)
	n, err = clconn.Read(readBuf)
	if err != nil && n == 0 {
		t.Fatalf("BUG: Could not read buffered data after connection closed: %v\n"+
			"Expected to read %d bytes of data that was received before the connection closed.\n"+
			"The receive buffer was incorrectly cleared when the connection transitioned to CLOSED state.",
			err, len(sendData))
	}
	if n != len(sendData) {
		t.Fatalf("read wrong amount: got %d, want %d", n, len(sendData))
	}
	if !bytes.Equal(readBuf[:n], sendData) {
		t.Fatalf("read wrong data: got %q, want %q", readBuf[:n], sendData)
	}
}

func TestStackAsync_ICMPEchoChecksum(t *testing.T) {
	const MTU = ethernet.MaxMTU
	const MaxFrameLength = MTU + ethernet.MaxOverheadSize // Ethernet header+FCS+VLAN.
	stackAddr := [4]byte{192, 168, 1, 99}
	stackMAC := [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	routerAddr := [4]byte{192, 168, 1, 1}
	routerMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	var rawbuf [MaxFrameLength]byte
	stack := new(StackAsync)
	err := stack.Reset(StackConfig{
		Hostname:        "ICMPTest",
		RandSeed:        42,
		StaticAddress4:  stackAddr,
		HardwareAddress: stackMAC,
		MTU:             MTU,
		ICMPQueueLimit:  2,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = stack.EnableICMP(true)
	if err != nil {
		t.Error("enabling ICMP:", err)
	}
	gen := ltesto.PacketGen{
		SrcMAC:  routerMAC,
		DstMAC:  stackMAC,
		SrcIPv4: routerAddr,
		DstIPv4: stackAddr,
	}
	icmpPayload := []byte("abcdefghijklmnopqrstuvwxyz012345") // 32 bytes, typical ping payload.
	const (
		id  = 0x1234
		seq = 1
	)
	// Test 1: Valid ICMP echo request should be accepted.
	pkt := gen.AppendIPv4ICMPEcho(rawbuf[:0], ltesto.ICMPEchoConfig{
		Identifier:     id,
		SequenceNumber: seq,
		Payload:        icmpPayload,
	})
	err = stack.IngressEthernet(pkt)
	if err != nil {
		t.Fatalf("valid ICMP echo rejected: %v", err)
	}
	n, err := stack.EgressEthernet(rawbuf[:])
	if err != nil || n == 0 {
		t.Error("expected ICMP response:", n, err)
	}
	ifrm, err := icmpv4.NewFrame(rawbuf[14+20 : n])
	efrm := icmpv4.FrameEcho{Frame: ifrm}
	if err != nil {
		t.Fatal(err)
	} else if efrm.Identifier() != id || efrm.SequenceNumber() != seq || !internal.BytesEqual(icmpPayload, efrm.Data()) {
		t.Errorf("id want %d, got %d; seq want %d, got %d, payload want %q, got %q", id, efrm.Identifier(), seq, efrm.SequenceNumber(), icmpPayload, efrm.Data())
	}
	// Test 2: Valid ICMP with trailing FCS bytes (simulates real PIO hardware capture).
	// This is a regression test for the bug where recvicmp checksummed ifrm.RawData()
	// instead of ifrm.Payload(), causing the 4 trailing FCS bytes to corrupt the checksum.
	pkt = gen.AppendIPv4ICMPEcho(rawbuf[:0], ltesto.ICMPEchoConfig{
		Identifier:     0x1234,
		SequenceNumber: 2,
		Payload:        icmpPayload,
	})
	pkt = append(pkt, 0xDE, 0xAD, 0xBE, 0xEF) // Simulate Ethernet FCS.
	err = stack.IngressEthernet(pkt)
	if err != nil {
		t.Fatalf("valid ICMP with trailing FCS rejected: %v", err)
	}

	// Test 3: Corrupted ICMP checksum should be rejected.
	pkt = gen.AppendIPv4ICMPEcho(rawbuf[:0], ltesto.ICMPEchoConfig{
		Identifier:     0x1234,
		SequenceNumber: 3,
		Payload:        icmpPayload,
	})
	pkt[len(pkt)-1] ^= 0xFF // Flip bits in last payload byte to corrupt ICMP checksum.
	err = stack.IngressEthernet(pkt)
	if err == nil {
		t.Fatal("corrupted ICMP accepted, expected CRC error")
	}

	// Test 4: Corrupted ICMP with trailing FCS should also be rejected.
	pkt = gen.AppendIPv4ICMPEcho(rawbuf[:0], ltesto.ICMPEchoConfig{
		Identifier:     0x1234,
		SequenceNumber: 4,
		Payload:        icmpPayload,
	})
	pkt[len(pkt)-1] ^= 0xFF                   // Corrupt ICMP payload.
	pkt = append(pkt, 0xDE, 0xAD, 0xBE, 0xEF) // Simulate Ethernet FCS.
	err = stack.IngressEthernet(pkt)
	if err == nil {
		t.Fatal("corrupted ICMP with FCS accepted, expected CRC error")
	}

}

const (
	protoEthernet = "Ethernet"
	protoARP      = "ARP"
	protoIPv4     = "IPv4"
	protoTCP      = "TCP"
)

// TestEgressIP_TCPMSSAdvertisesMTU guards against advertising a Maximum Segment Size
// derived from the (oversized) egress buffer instead of the link MTU. See the
// EgressIP clip in StackAsync: without it the SYN advertises ~65479 rather than
// MTU-ipHdr-20.
func TestEgressIP_TCPMSSAdvertisesMTU(t *testing.T) {
	for _, mtu := range []int{1280, 9000} { // M29: IP-only (TUN) use is not bound by the 1500 byte Ethernet MTU.
		t.Run(strconv.Itoa(mtu), func(t *testing.T) {
			testEgressIPTCPMSS(t, mtu)
		})
	}
}

func testEgressIPTCPMSS(t *testing.T, mtu int) {
	wantMSS := uint16(mtu - 20 - 20) // -IPv4 header -TCP header.
	s1, s2, c1, _ := newTCPStacks(t, 4, mtu)

	raddr := s2.Addr4()
	err := s1.DialTCP4(c1, 12345, raddr, 80)
	if err != nil {
		t.Fatal(err)
	}

	// Emit the client SYN through the IP (TUN) egress path using a buffer far
	// larger than the MTU. The advertised MSS must reflect the MTU, not len(buf).
	buf := make([]byte, 65535)
	n, err := s1.EgressIP(buf)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("no SYN emitted")
	} else if n > mtu {
		t.Fatalf("emitted IP datagram %d exceeds MTU %d", n, mtu)
	}

	ifrm, err := ipv4.NewFrame(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	tfrm, err := tcp.NewFrame(ifrm.Payload())
	if err != nil {
		t.Fatal(err)
	}
	seg := tfrm.Segment(len(tfrm.Payload()))
	if !seg.Flags.HasAny(tcp.FlagSYN) {
		t.Fatalf("expected SYN, got flags %s", seg.Flags.String())
	}

	var op tcp.OptionCodec
	gotMSS := uint16(0)
	found := false
	err = op.ForEachOption(tfrm.Options(), func(kind tcp.OptionKind, data []byte) error {
		if kind == tcp.OptMaxSegmentSize && len(data) == 2 {
			gotMSS = uint16(data[0])<<8 | uint16(data[1])
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("no MSS option in SYN")
	}
	if gotMSS != wantMSS {
		t.Errorf("advertised MSS = %d, want %d (MTU %d - 40)", gotMSS, wantMSS, mtu)
	}
}

// TestEphemeralPortSequence checks no ephemeral port is reused before the whole
// 16384-port dynamic range has cycled, which is what keeps a redial off the
// teardown state (TIME-WAIT, NAT flow entries) of the conversation before it.
func TestEphemeralPortSequence(t *testing.T) {
	s := new(StackAsync)
	err := s.Reset(StackConfig{
		Hostname:          "eph",
		RandSeed:          42,
		StaticAddress4:    [4]byte{10, 0, 0, 50},
		MaxActiveTCPPorts: 1,
		HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, 50},
		MTU:               ethernet.MaxMTU,
		ICMPQueueLimit:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	const cycle = 16384
	var seen [cycle]bool
	for i := range cycle {
		port := s.ephemeralPort()
		if port < 49152 {
			t.Fatalf("port %d below dynamic range (RFC 6335)", port)
		}
		idx := port - 49152
		if seen[idx] {
			t.Fatalf("port %d reused after only %d allocations (want full %d cycle)", port, i, cycle)
		}
		seen[idx] = true
	}
	// The cycle is exhausted: the next allocation may legitimately reuse.
	if got := s.ephemeralPort(); got < 49152 {
		t.Fatalf("post-cycle port %d below dynamic range", got)
	}
}

// regression test for a panic
func TestEncapsIdxSurvivesReset(t *testing.T) {
	s, _ := newICMPStacks(t, 42, 1500)
	s.EnableICMP(true)
	s.StartDHCPv4Request([4]byte{})
	buf := make([]byte, 2048)
	s.EgressEthernet(buf)
	err := s.Reset(StackConfig{Hostname: "icmp-stack-1", RandSeed: 42, HardwareAddress: [6]byte{1}, MTU: 1500, ICMPQueueLimit: 4})
	if err != nil {
		t.Fatal(err)
	}
	s.StartDHCPv4Request([4]byte{})
	s.EgressEthernet(buf) // panic
}

// regression test for panic in subnetTable.reset.
func TestPassivePeersGrowOnReset(t *testing.T) {
	s, peer := newICMPStacks(t, 42, 1500) // PassivePeers=0 -> len(resolves4)=10
	s.Reset(StackConfig{Hostname: "icmp-stack-1", RandSeed: 42, StaticAddress4: [4]byte{10, 0, 0, 42},
		HardwareAddress: [6]byte{0xbe, 0xef, 0, 0, 0, 42}, MTU: 1500, ICMPQueueLimit: 4, PassivePeers: 16})
	s.EnableICMP(true)
	s.SetGatewayHardwareAddr(peer.HardwareAddr())
	s.icmp.PingStart(peer.Addr4(), []byte("x"), 32)
	s.EgressEthernet(make([]byte, 2048)) // index out of range [10] with length 10
}

// regression test for panic. [ethernet.Frame.ValidateSize] was not correctly
// taking 14 byte header size into account for size validation.
func TestEthernetLengthFieldPanic(t *testing.T) {
	s, _ := newICMPStacks(t, 42, 1500)
	efrm, _ := ethernet.NewFrame(make([]byte, 60))
	*efrm.DestinationHardwareAddr() = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	efrm.SetEtherType(60)
	s.IngressEthernet(efrm.RawData()) // slices frame[14:74]
}

func TestICMPMismatchedMTUPanic(t *testing.T) {
	const mtu = 576
	s := new(StackAsync)
	err := s.Reset(StackConfig{
		Hostname:        "icmp-oversized",
		RandSeed:        16,
		StaticAddress4:  [4]byte{10, 0, 0, 1},
		HardwareAddress: [6]byte{0xbe, 0xef, 0, 0, 0, 1},
		MTU:             mtu,
		ICMPQueueLimit:  16, // Response ring 16*64=1024 bytes > MTU.
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnableICMP(true); err != nil {
		t.Fatal(err)
	}
	gen := ltesto.PacketGen{
		SrcMAC:  [6]byte{0xbe, 0xef, 0, 0, 0, 2},
		DstMAC:  s.HardwareAddr(),
		SrcIPv4: [4]byte{10, 0, 0, 2},
		DstIPv4: s.Addr4(),
	}
	// Valid IPv4+ICMP echo request with 1000 data bytes, larger than MTU.
	pkt := gen.AppendIPv4ICMPEcho(nil, ltesto.ICMPEchoConfig{
		Identifier:     0x1234,
		SequenceNumber: 1,
		Payload:        make([]byte, 1000),
	})
	if err := s.IngressEthernet(pkt); err != nil {
		t.Fatal("echo request rejected, test does not exercise oversized reply:", err)
	}
	var buf [mtu + 14]byte
	n, _ := s.EgressEthernet(buf[:]) // Reply does not fit in MTU, must not panic.
	if n > len(buf) {
		t.Fatalf("egress wrote %d bytes, exceeding buffer of %d", n, len(buf))
	}
}

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
		StaticAddress4:    [4]byte{10, 0, 0, 2},
		MaxActiveTCPPorts: 1,
		HardwareAddress:   serverMAC,
		MTU:               mtu,
		PassivePeers:      2,
	})
	if err != nil {
		t.Fatal(err)
	}
	sv.SetGatewayHardwareAddr(routerMAC)
	sv.SetSubnet4(sv.Addr4(), 24)

	pool, err := sv.NewTCPPool(TCPPoolConfig{
		PoolSize:           1,
		QueueSize:          4,
		TxBufSize:          mtu,
		RxBufSize:          mtu,
		EstablishedTimeout: 10e9,
		ClosingTimeout:     10e9,
		NewBackoff:         func() lneto.BackoffStrategy { return backoffYield },
	})
	if err != nil {
		t.Fatal(err)
	}
	var listener tcp.Listener
	if err = listener.Reset(svPort, pool); err != nil {
		t.Fatal(err)
	}
	if err = sv.RegisterListenerTCP(&listener); err != nil {
		t.Fatal(err)
	}

	// Client: gateway = server MAC (direct L2 path, as in a hotspot WLAN).
	var client StackAsync
	err = client.Reset(StackConfig{
		Hostname:          "Client1",
		RandSeed:          5678,
		StaticAddress4:    [4]byte{10, 0, 0, 1},
		MaxActiveTCPPorts: 1,
		HardwareAddress:   clientMAC,
		MTU:               mtu,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.SetGatewayHardwareAddr(serverMAC)

	var clConn tcp.Conn
	if err = clConn.Configure(tcp.ConnConfig{
		RxBuf: make([]byte, mtu), TxBuf: make([]byte, mtu),
		TxPacketQueueSize: 4,
		RWBackoff:         backoffYield,
	}); err != nil {
		t.Fatal(err)
	}
	if err = client.DialTCP(&clConn, 54321, netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)); err != nil {
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
		BroadcastAddr: netip.AddrFrom4(ipv4.BroadcastAddr()),
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

func BenchmarkARPExchange(b *testing.B) {
	const MTU = ethernet.MaxMTU
	const frameSize = ethernet.MaxFrameLength
	c1, c2 := new(StackAsync), new(StackAsync)
	queryAddr := netip.AddrFrom4([4]byte{192, 168, 1, 2})

	err := c1.Reset(StackConfig{
		Hostname:        "C1",
		RandSeed:        1,
		StaticAddress4:  [4]byte{192, 168, 1, 1},
		HardwareAddress: [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x00},
		MTU:             MTU,
	})
	if err != nil {
		b.Fatal(err)
	}
	err = c2.Reset(StackConfig{
		Hostname:        "C2",
		RandSeed:        2,
		StaticAddress4:  queryAddr.As4(),
		HardwareAddress: [6]byte{0xc0, 0xff, 0xee, 0xc0, 0xff, 0xee},
		MTU:             MTU,
	})
	if err != nil {
		b.Fatal(err)
	}
	// Set gateways so ethernet frames are properly addressed.
	c1.SetGatewayHardwareAddr(c2.HardwareAddr())
	c2.SetGatewayHardwareAddr(c1.HardwareAddr())

	var buf [frameSize]byte

	b.ResetTimer()
	for b.Loop() {
		err = c1.StartResolveHardwareAddress6(queryAddr)
		if err != nil {
			b.Fatal(err)
		}
		n, err := c1.EgressEthernet(buf[:]) // Send Request.
		if err != nil {
			b.Fatal(err)
		} else if n == 0 {
			b.Fatal("expected send of data after first query")
		}
		err = c2.IngressEthernet(buf[:n]) // Receive request.
		if err != nil {
			b.Fatal(err)
		}
		n, err = c2.EgressEthernet(buf[:]) // Send response.
		if err != nil {
			b.Fatal(err)
		} else if n == 0 {
			b.Fatal("got no response to request")
		}
		err = c1.IngressEthernet(buf[:n]) // Receive response.
		if err != nil {
			b.Fatal(err)
		}
		_, err = c1.ResultResolveHardwareAddress6(queryAddr)
		if err != nil {
			b.Fatal("expected query result:", err)
		}
		// Discard query for next iteration.
		c1.DiscardResolveHardwareAddress6(queryAddr)
	}
}

func BenchmarkTCPHandshake(b *testing.B) {
	const MTU = ethernet.MaxMTU
	const frameSize = ethernet.MaxFrameLength
	const svPort = 8080
	client, sv := new(StackAsync), new(StackAsync)
	clconn, svconn := new(tcp.Conn), new(tcp.Conn)

	err := sv.Reset(StackConfig{
		Hostname:          "Server",
		RandSeed:          1,
		StaticAddress4:    [4]byte{10, 0, 0, 1},
		MaxActiveTCPPorts: 1,
		HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, 1},
		MTU:               MTU,
	})
	if err != nil {
		b.Fatal(err)
	}
	err = client.Reset(StackConfig{
		Hostname:          "Client",
		RandSeed:          2,
		StaticAddress4:    [4]byte{10, 0, 0, 2},
		MaxActiveTCPPorts: 1,
		HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, 2},
		MTU:               MTU,
	})
	if err != nil {
		b.Fatal(err)
	}
	sv.SetGatewayHardwareAddr(client.HardwareAddr())
	client.SetGatewayHardwareAddr(sv.HardwareAddr())

	buf := make([]byte, MTU*4)
	err = clconn.Configure(tcp.ConnConfig{
		RxBuf:             buf[:MTU],
		TxBuf:             buf[MTU : MTU*2],
		TxPacketQueueSize: 4,
		RWBackoff:         backoffYield,
	})
	if err != nil {
		b.Fatal(err)
	}
	err = svconn.Configure(tcp.ConnConfig{
		RxBuf:             buf[2*MTU : 3*MTU],
		TxBuf:             buf[3*MTU : 4*MTU],
		TxPacketQueueSize: 4,
		RWBackoff:         backoffYield,
	})
	if err != nil {
		b.Fatal(err)
	}

	var pktbuf [frameSize]byte

	b.ResetTimer()
	for b.Loop() {
		// Setup connections.
		err = sv.ListenTCP4(svconn, svPort)
		if err != nil {
			b.Fatal(err)
		}
		err = client.DialTCP(clconn, 1337, netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort))
		if err != nil {
			b.Fatal(err)
		}

		// SYN from client.
		n, err := client.EgressEthernet(pktbuf[:])
		if err != nil {
			b.Fatal(err)
		}
		err = sv.IngressEthernet(pktbuf[:n])
		if err != nil {
			b.Fatal(err)
		}

		// SYN-ACK from server.
		n, err = sv.EgressEthernet(pktbuf[:])
		if err != nil {
			b.Fatal(err)
		}
		err = client.IngressEthernet(pktbuf[:n])
		if err != nil {
			b.Fatal(err)
		}

		// ACK from client.
		n, err = client.EgressEthernet(pktbuf[:])
		if err != nil {
			b.Fatal(err)
		}
		err = sv.IngressEthernet(pktbuf[:n])
		if err != nil {
			b.Fatal(err)
		}

		// Abort connections for next iteration.
		clconn.Abort()
		svconn.Abort()
	}
}

func TestTCPListener_ConcurrentEcho(t *testing.T) {
	const (
		numClients  = 10
		serverPort  = 8080
		MTU         = 1500
		carrierSize = MTU + ethernet.MaxOverheadSize
		tcpBufSize  = MTU
		seed        = 1
	)

	// 1. Setup server stack with tcp.Listener.
	var serverStack StackAsync
	serverMAC := [6]byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}
	serverIP := netip.AddrFrom4([4]byte{10, 0, 0, 1})
	err := serverStack.Reset(StackConfig{
		Hostname:          "Server",
		RandSeed:          seed,
		StaticAddress4:    serverIP.As4(),
		MaxActiveTCPPorts: numClients,
		HardwareAddress:   serverMAC,
		MTU:               MTU,
	})
	if err != nil {
		t.Fatal(err)
	}

	tcpPool, err := serverStack.NewTCPPool(TCPPoolConfig{
		PoolSize:           numClients,
		QueueSize:          4,
		TxBufSize:          512,
		RxBufSize:          512,
		EstablishedTimeout: 5 * time.Second,
		ClosingTimeout:     5 * time.Second,
		NewBackoff:         func() lneto.BackoffStrategy { return backoffYield },
	})
	if err != nil {
		t.Fatal(err)
	}

	var listener tcp.Listener
	err = listener.Reset(serverPort, tcpPool)
	if err != nil {
		t.Fatal(err)
	}
	err = serverStack.RegisterListenerTCP(&listener)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Setup client stacks (one per client).
	clientStacks := make([]StackAsync, numClients)
	clientConns := make([]tcp.Conn, numClients)
	connBufs := make([]byte, numClients*tcpBufSize*2) // RX+TX buffer space for all clients

	for i := range clientStacks {
		clientMAC := [6]byte{0xaa, 0xbb, 0xcc, 0x00, 0x01, byte(i + 1)}
		clientIP := [4]byte{10, 0, 0, byte(i + 10)}
		err := clientStacks[i].Reset(StackConfig{
			Hostname:          fmt.Sprintf("Client%d", i),
			RandSeed:          int64(seed + i + 1),
			StaticAddress4:    clientIP,
			MaxActiveTCPPorts: 1,
			HardwareAddress:   clientMAC,
			MTU:               MTU,
		})
		if err != nil {
			t.Fatalf("client %d reset: %v", i, err)
		}
		// Client gateway points to server.
		clientStacks[i].SetGatewayHardwareAddr(serverMAC)

		// Configure client connection buffers.
		bufOff := i * tcpBufSize * 2
		err = clientConns[i].Configure(tcp.ConnConfig{
			RxBuf:             connBufs[bufOff : bufOff+tcpBufSize],
			TxBuf:             connBufs[bufOff+tcpBufSize : bufOff+2*tcpBufSize],
			TxPacketQueueSize: 4,
			RWBackoff:         backoffYield,
		})
		if err != nil {
			t.Fatalf("client %d conn configure: %v", i, err)
		}
	}

	// 3. Start "kernel" goroutine - routes packets between stacks.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go kernelLoop(ctx, &serverStack, clientStacks)

	// 4. Start server goroutine - accepts and echoes.
	go echoServer(ctx, &listener)

	// 5. Start client goroutines.
	var wg sync.WaitGroup
	clientSuccess := make([]bool, numClients)
	for i := range numClients {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			if runClient(t, ctx, clientID, &clientStacks[clientID], &clientConns[clientID],
				serverIP, serverPort) {
				clientSuccess[clientID] = true
			}
		}(i)
	}

	// 6. Wait for all clients to complete.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Check all clients succeeded.
		for i, ok := range clientSuccess {
			if !ok {
				t.Errorf("client %d did not complete successfully", i)
			}
		}
	case <-ctx.Done():
		t.Fatal("test timed out")
	}
	cancel()
}

func kernelLoop(ctx context.Context, server *StackAsync, clients []StackAsync) {
	const MTU = ethernet.MaxMTU
	const carrierDataSize = ethernet.MaxFrameLength
	buf := make([]byte, carrierDataSize)
	rng := rand.New(rand.NewSource(1)) // Seed 1 for deterministic but randomized order
	order := make([]int, len(clients))
	for i := range order {
		order[i] = i
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Process server outgoing -> route to appropriate client based on dest IP.
		if n, _ := server.EgressEthernet(buf); n > 0 {
			routePacketToClient(buf[:n], clients)
		}

		// Process each client outgoing in randomized order.
		rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		for _, idx := range order {
			if n, _ := clients[idx].EgressEthernet(buf); n > 0 {
				server.IngressEthernet(buf[:n]) // All clients talk to server.
			}
		}

		runtime.Gosched() // Yield to other goroutines.
	}
}

func routePacketToClient(pkt []byte, clients []StackAsync) {
	// Extract destination IP from IPv4 header (offset 16-19 in IP header, after 14 byte Ethernet header).
	if len(pkt) < 20+ethernet.MaxOverheadSize { //  20 min IP header
		return
	}
	dstIP := [4]byte{pkt[30], pkt[31], pkt[32], pkt[33]}

	for i := range clients {
		if clients[i].Addr4() == dstIP {
			clients[i].IngressEthernet(pkt)
			return
		}
	}
}

func echoServer(ctx context.Context, listener *tcp.Listener) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if listener.NumberOfReadyToAccept() == 0 {
			runtime.Gosched()
			continue
		}

		conn, err := listener.TryAccept()
		if err != nil {
			continue
		}

		// Handle connection in separate goroutine (like real example).
		go func(c tcp.ConnHandle) {
			var buf [512]byte
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				n, err := c.Read(buf[:])
				if err != nil {
					return
				}
				if n > 0 {
					_, err = c.Write(buf[:n])
					if err != nil {
						return
					}
				}
			}
		}(conn)
	}
}

func runClient(t *testing.T, ctx context.Context, id int, stack *StackAsync, conn *tcp.Conn,
	serverAddr netip.Addr, serverPort uint16) bool {
	// Dial server.
	clientPort := uint16(10000 + id)
	err := stack.DialTCP(conn, clientPort, netip.AddrPortFrom(serverAddr, serverPort))
	if err != nil {
		t.Errorf("client %d dial failed: %v", id, err)
		return false
	}

	for conn.State() != tcp.StateEstablished && ctx.Err() == nil {
		runtime.Gosched()
	}

	// Send test data.
	testData := fmt.Appendf(nil, "hello from client %d", id)
	_, err = conn.Write(testData)
	if err != nil {
		t.Errorf("client %d write failed: %v", id, err)
		return false
	}

	// Read echo response. conn.Read yields (backoffYield) until data arrives, and the
	// overall test timeout (ctx) backstops a hang.
	var buf [64]byte
	var totalRead int
	for totalRead < len(testData) && ctx.Err() == nil {
		n, err := conn.Read(buf[totalRead:])
		if err != nil {
			t.Errorf("client %d read failed: %v", id, err)
			return false
		}
		totalRead += n
	}

	// Verify echo.
	if !bytes.Equal(buf[:totalRead], testData) {
		t.Errorf("client %d: expected %q, got %q", id, testData, buf[:totalRead])
		return false
	}
	return true
}

func TestCloseTransmitsPending(t *testing.T) {
	const mtu = ipv4.MinimumMTU
	const tcpbufsize = mtu * 2
	const tcpDataPerPkt = mtu - 14 - 20 - 20 // Ethernet=14, IPv4=20, TCP=20
	const expectPkts = 2*tcpbufsize/tcpDataPerPkt + 1
	const queueSize = 5
	const port1, port2 = 10, 20
	tst := testerFrom(t, mtu)
	tst.buf = tst.buf[:mtu+14]
	s1, s2, c1, c2 := newTCPStacks(t, 0x1337_c0de, mtu)
	t.Run("sync", func(t *testing.T) {
		// testCloseTransmitsPending(tst, s1, s2, c1, c2, queueSize, tcpbufsize, tcpbufsize, tcpbufsize)
	})
	t.Run("async", func(t *testing.T) {
		testCloseTransmitsPending(tst, s1, s2, c1, c2, queueSize, tcpbufsize, tcpbufsize, 2*tcpbufsize)
	})

}

func testCloseTransmitsPending(tst *tester, s1, s2 *StackAsync, c1, c2 *tcp.Conn, queueSize, tx1Buf, rx2Buf, datalen int) {
	t := tst.t
	buf := tst.buf
	defer func() {
		c1.Abort()
		c2.Abort()
		// Ensure they are unregistered.
		s1.EgressIP(buf)
		s2.EgressIP(buf)
	}()
	// When the payload exceeds the Tx buffer, c1.Write must run in a background
	// goroutine that blocks until the driver drains the buffer. The scheduler turns
	// that blocking into a deterministic, sleep-free handoff: c1's backoff parks the
	// writer and the driver releases it after freeing buffer space.
	async := datalen > tx1Buf
	var tsched *ltesto.Sched
	var tgoro ltesto.SchedGoro
	c1Backoff := backoffYield
	if async {
		tsched = ltesto.NewSched(t)
		tgoro = tsched.Goro()
		c1Backoff = tgoro.Yield
	}
	err := c1.Configure(tcp.ConnConfig{
		RxBuf:             nil,
		TxBuf:             make([]byte, tx1Buf),
		TxPacketQueueSize: queueSize,
		RWBackoff:         c1Backoff,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = c2.InternalHandler().SetBuffers(nil, make([]byte, rx2Buf), queueSize)
	if err != nil {
		t.Fatal(err)
	}
	const (
		port1, port2 = 10, 20
	)
	tst.TestTCPSetupAndEstablish(s1, s2, c1, c2, port1, port2)
	if c1.FreeOutput() != tx1Buf {
		t.Fatalf("want %d free bytes, got %d", tx1Buf, c1.FreeOutput())
	}
	data := make([]byte, datalen)
	for i := range datalen {
		data[i] = byte(i)
	}
	if async {
		// Since data does not fit in TCP Tx buffer the test must be run asynchronously.
		go func() {
			n, werr := c1.Write(data)
			if werr == nil && n != len(data) {
				werr = fmt.Errorf("async write %d of %d bytes", n, len(data))
			}
			if werr == nil {
				werr = c1.Close()
			}
			tgoro.FinishWithErr(werr)
		}()
	} else {
		n, err := c1.Write(data)
		if err != nil || n != len(data) {
			t.Fatal(err, n)
		}
		err = c1.Close()
		if err != nil {
			t.Fatal(err)
		}
	}

	exchanges := -1
	exchanging := 1
	tcpData := 0
	totalRead := 0
	writerDone := false
	for exchanging > 0 || c1.State().TxDataOpen() {
		if async && !writerDone {
			// Block until the writer parks on a full Tx buffer (or finishes). Servicing
			// each park with exactly one pump round below keeps progress deterministic
			// without sleeping or guessing whether the writer will park again.
			done, werr := tsched.AwaitGoroYieldOrDone()
			if werr != nil {
				t.Error("async write/close:", werr)
			}
			if done {
				writerDone = true
			}
		}
		exchanges++
		exchanging = exchangeEthernetOnce(t, s1, s2, buf)
		frm, ok := getTCPFrame(buf[:exchanging])
		if ok {
			n := len(frm.Payload())
			tcpData += n
			if async && tcpData > 0 {
				ngot, err := c2.Read(buf[:n])
				if err != nil {
					t.Error(err)
				} else if ngot != n {
					t.Errorf("want %d data read c1->c2, got %d", n, ngot)
				} else if !internal.BytesEqual(buf[:n], data[totalRead:totalRead+n]) {
					t.Errorf("exch%d data rx mismatch, want:\n%q\ngot:\n%q\n", exchanges, data[totalRead:totalRead+n], buf[:n])
				}
				totalRead += ngot
				acks := exchangeEthernetOnce(t, s2, s1, buf) // Send ACK s1's way, freeing its Tx buffer.
				if acks == 0 {
					t.Error("no data sent back to s1")
				}
			}
		}
		if async && !writerDone {
			// The ACK above freed Tx buffer space; release the writer to fill it and re-park.
			tsched.YieldToGoro()
		}
	}
	if c1.BufferedUnsent() != 0 {
		t.Errorf("done %s: want no data left unsent got %d/%d", c1.State(), c1.BufferedUnsent(), len(data))
	}
	if tcpData != datalen {
		t.Errorf("done %s: want %d bytes sent, got %d", c1.State(), len(data), tcpData)
	}
	if t.Failed() {
		t.Logf("test params: txsz1=%d rxsz2=%d queuesize=%d data(sent/had)=%d/%d", tx1Buf, rx2Buf, queueSize, tcpData, datalen)
	}
	if totalRead < datalen {
		n, err := c2.Read(buf)
		if err != nil {
			t.Error(err)
		} else if !internal.BytesEqual(buf[:n], data[totalRead:]) {
			t.Errorf("expected last bytes equal: want:\n%q\ngot:\n%q\n", data[totalRead:], buf[:n])
		}
	}

}

// M21: aborting a connection while another goroutine drives the stack must not
// race on the connection ID. Only detectable with -race.
func TestStackAsyncAbortConcurrentWithEgress(t *testing.T) {
	const randseed = 0x1337_c0de
	cl := newTestStack(t, "s1", randseed, ethernet.MaxMTU, 1, 0)
	raddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 80)
	conn := newTestTCPConn(t, ethernet.MaxMTU, 4)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		var buf [ethernet.MaxMTU + ethernet.MaxOverheadSize]byte
		for {
			select {
			case <-stop:
				return
			default:
				cl.EgressEthernet(buf[:])
			}
		}
	}()
	for i := range 100 {
		if err := cl.DialTCP(conn, uint16(1000+i), raddr); err != nil {
			t.Error(err)
			break
		}
		conn.Abort()
	}
	close(stop)
	wg.Wait()
}

func TestTCPConn_SetDeadline_Established(t *testing.T) {
	const seed = 9999
	const MTU = ethernet.MaxMTU
	const svPort = 8080
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := testerFrom(t, MTU)

	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)

	if clconn.State() != tcp.StateEstablished {
		t.Fatalf("expected StateEstablished, got %s", clconn.State())
	}

	// SetDeadline should succeed on established connection.
	err := clconn.SetDeadline(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("SetDeadline on established conn failed: %v", err)
	}

	// Clear deadlines.
	err = clconn.SetDeadline(time.Time{})
	if err != nil {
		t.Fatalf("SetDeadline(zero) failed: %v", err)
	}
	_ = sv
}

func TestTCPConn_ReadDeadlineExceeded(t *testing.T) {
	const seed = 10001
	const MTU = ethernet.MaxMTU
	const svPort = 8080
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := testerFrom(t, MTU)

	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)

	// Set read deadline in the past.
	err := svconn.SetReadDeadline(time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}

	// Read should fail immediately with deadline exceeded.
	buf := make([]byte, 64)
	_, rerr := svconn.Read(buf)
	if rerr == nil {
		t.Fatal("Read with past deadline should fail")
	}
	if rerr != os.ErrDeadlineExceeded {
		t.Fatalf("expected os.ErrDeadlineExceeded, got %v", rerr)
	}
}

func TestTCPConn_WriteDeadlineExceeded(t *testing.T) {
	const seed = 10002
	const MTU = ethernet.MaxMTU
	const svPort = 8080
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := testerFrom(t, MTU)

	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)

	// Set write deadline in the past.
	err := clconn.SetWriteDeadline(time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}

	// Write should fail immediately with deadline exceeded.
	_, werr := clconn.Write([]byte("hello"))
	if werr == nil {
		t.Fatal("Write with past deadline should fail")
	}
	if werr != os.ErrDeadlineExceeded {
		t.Fatalf("expected os.ErrDeadlineExceeded, got %v", werr)
	}
}

func TestTCPConn_FlushEmptyNoop(t *testing.T) {
	const seed = 10003
	const MTU = ethernet.MaxMTU
	const svPort = 8080
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := testerFrom(t, MTU)

	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)

	// Flush with no unsent data should return nil immediately.
	err := clconn.Flush()
	if err != nil {
		t.Fatalf("Flush with no unsent data should succeed: %v", err)
	}
}

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
	for range rounds {
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
			for i := range 2 {
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

var (
	dnsTestServerAddr = netip.AddrFrom4([4]byte{8, 8, 8, 8})
	dnsTestServerMAC  = [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dnsTestClientAddr = netip.AddrFrom4([4]byte{10, 0, 0, 100})
	dnsTestClientMAC  = [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
)

func (rr dnsRR) resource(t *testing.T) dns.Resource {
	t.Helper()
	owner := dns.MustNewName(rr.owner)
	if rr.cname == "" {
		return dns.NewResource(owner, dns.TypeA, dns.ClassINET, 300, rr.addr.AsSlice())
	}
	target := dns.MustNewName(rr.cname)
	wire, err := target.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	return dns.NewResource(owner, dns.TypeCNAME, dns.ClassINET, 300, wire)
}

// cnameChain returns a zone where host is a CNAME-only answer followed by hops-1
// more CNAME-only answers, the last alias holding the A record addr.
// Resolving it one query per answer takes hops+1 queries.
func cnameChain(host string, hops int, addr string) map[string][]dnsRR {
	zone := make(map[string][]dnsRR, hops+1)
	owner := host
	for i := 1; i <= hops; i++ {
		alias := fmt.Sprintf("cdn%d.example.net", i)
		zone[owner] = []dnsRR{rrCNAME(owner, alias)}
		owner = alias
	}
	zone[owner] = []dnsRR{rrA(owner, addr)}
	return zone
}

// TestDNS_LookupIP resolves a host against a zone through the async API
// (StartLookupIP+ResultLookupIP, a single query) or the blocking API
// (DoLookupIP, which queries again for the canonical name of CNAME-only answers,
// at most maxCNAMEqueries times).
func TestDNS_LookupIP(t *testing.T) {
	const host = "www.example.com"
	tests := []struct {
		name        string
		blocking    bool
		zone        map[string][]dnsRR
		wantAddr    string // Empty when wantErr is set.
		wantErr     error
		wantQueries int
	}{
		{
			name:     "A",
			zone:     map[string][]dnsRR{host: {rrA(host, "93.184.216.34")}},
			wantAddr: "93.184.216.34", wantQueries: 1,
		},
		{
			name: "A blocking", blocking: true,
			zone:     map[string][]dnsRR{host: {rrA(host, "93.184.216.35")}},
			wantAddr: "93.184.216.35", wantQueries: 1,
		},
		{
			// CNAME RDATA must not be misinterpreted as an IP address.
			name:     "CNAME and A",
			zone:     map[string][]dnsRR{host: {rrCNAME(host, "cdn.example.net"), rrA("cdn.example.net", "192.0.2.200")}},
			wantAddr: "192.0.2.200", wantQueries: 1,
		},
		{
			// Async API does not requery.
			name:    "CNAME only",
			zone:    cnameChain(host, 1, "192.0.2.201"),
			wantErr: dns.ErrUnresolvedCNAME, wantQueries: 1,
		},
		{
			name: "CNAME only requery", blocking: true,
			zone:     cnameChain(host, 1, "192.0.2.202"),
			wantAddr: "192.0.2.202", wantQueries: 2,
		},
		{
			// Address arrives on the last query allowed.
			name: "CNAME chain at query limit", blocking: true,
			zone:     cnameChain(host, maxCNAMEqueries-1, "192.0.2.203"),
			wantAddr: "192.0.2.203", wantQueries: maxCNAMEqueries,
		},
		{
			// One hop more than the limit allows: gives up without exceeding it.
			name: "CNAME chain past query limit", blocking: true,
			zone:    cnameChain(host, maxCNAMEqueries, "192.0.2.204"),
			wantErr: dns.ErrUnresolvedCNAME, wantQueries: maxCNAMEqueries,
		},
	}
	// Shared client: each lookup must not see the previous one's result, so wantAddr is unique per case.
	client := newDNSTestClient(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := &dnsTestServer{t: t, client: client, zone: tc.zone}
			var addrs []netip.Addr
			var err error
			if tc.blocking {
				pump := func(uint) time.Duration {
					srv.respond()
					return lneto.BackoffFlagNop
				}
				var dst [4]netip.Addr
				var n int
				n, err = client.StackBlocking(pump).DoLookupIP(dst[:], dns.MustNewName(host), time.Second)
				addrs = dst[:n]
			} else {
				txid, serr := client.LookupIPStart(dns.MustNewName(host), dns.TypeA, 4)
				if serr != nil {
					t.Fatal("LookupIPStart failed:", serr)
				}
				if !srv.respond() {
					t.Fatal("expected DNS query packet from client")
				}
				var dst [4]netip.Addr
				n, state, rerr := client.LookupIPResult(txid, dst[:])
				if state.InProgress() {
					t.Fatal("DNS lookup not done after response")
				}
				if state, ok := client.LookupIPPop(txid); state.InProgress() || !ok {
					t.Fatalf("pop: state=%v ok=%v", state, ok)
				}
				addrs, err = dst[:n], rerr
			}
			if err != tc.wantErr {
				t.Fatalf("got err=%v, want %v", err, tc.wantErr)
			}
			if tc.wantAddr != "" && !slices.Contains(addrs, netip.MustParseAddr(tc.wantAddr)) {
				t.Errorf("expected address %s not found in result %v", tc.wantAddr, addrs)
			}
			if srv.queries != tc.wantQueries {
				t.Errorf("got %d queries, want %d", srv.queries, tc.wantQueries)
			}
		})
	}
}

// lookupTestResult polls lookup txid once and fails the test unless it is done.
func lookupTestResult(t *testing.T, client *StackAsync, txid uint16, dst []netip.Addr) ([]netip.Addr, error) {
	t.Helper()
	n, state, err := client.LookupIPResult(txid, dst)
	if state.InProgress() {
		t.Fatalf("lookup %#x not done", txid)
	}
	return dst[:n], err
}

func TestDNS_LookupIPConcurrent(t *testing.T) {
	const hostA, hostB = "a.example.com", "b.example.org"
	client := newDNSTestClient(t)
	srv := &dnsTestServer{t: t, client: client, zone: map[string][]dnsRR{
		hostA: {rrA(hostA, "192.0.2.1")},
		hostB: {rrA(hostB, "198.51.100.1")},
	}}
	txidA, err := client.LookupIPStart(dns.MustNewName(hostA), dns.TypeA, 4)
	if err != nil {
		t.Fatal(err)
	}
	txidB, err := client.LookupIPStart(dns.MustNewName(hostB), dns.TypeA, 4)
	if err != nil {
		t.Fatal(err)
	}
	if txidA == 0 || txidB == 0 || txidA == txidB {
		t.Fatalf("txids must be distinct and non-zero: %#x %#x", txidA, txidB)
	}
	if n, state, _ := client.LookupIPResult(txidA, make([]netip.Addr, 1)); !state.InProgress() || n != 0 {
		t.Fatal("lookup done before any response")
	}
	for i := range 2 {
		if !srv.respond() {
			t.Fatalf("expected query %d", i)
		}
	}
	var dst [4]netip.Addr
	addrs, err := lookupTestResult(t, client, txidA, dst[:])
	if err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("lookup A: %v %v", addrs, err)
	}
	addrs, err = lookupTestResult(t, client, txidB, dst[:])
	if err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("198.51.100.1") {
		t.Fatalf("lookup B: %v %v", addrs, err)
	}
	for _, txid := range []uint16{txidA, txidB} {
		if state, ok := client.LookupIPPop(txid); state.InProgress() || !ok {
			t.Fatalf("pop %#x: state=%v ok=%v", txid, state, ok)
		}
		if _, ok := client.LookupIPPop(txid); ok {
			t.Fatalf("second pop of %#x succeeded", txid)
		}
	}
}

func TestDNS_LookupIPManyAddresses(t *testing.T) {
	const host = "many.example.com"
	zone := map[string][]dnsRR{}
	var want []netip.Addr
	for i := 1; i <= 8; i++ {
		addr := fmt.Sprintf("192.0.2.%d", i)
		zone[host] = append(zone[host], rrA(host, addr))
		want = append(want, netip.MustParseAddr(addr))
	}
	client := newDNSTestClient(t)
	srv := &dnsTestServer{t: t, client: client, zone: zone}
	txid, err := client.LookupIPStart(dns.MustNewName(host), dns.TypeA, 8)
	if err != nil {
		t.Fatal(err)
	}
	srv.respond()
	var dst [8]netip.Addr
	addrs, err := lookupTestResult(t, client, txid, dst[:])
	if err != nil || !slices.Equal(addrs, want) {
		t.Fatalf("got %v err=%v, want %v", addrs, err, want)
	}
}

func TestDNS_LookupIPFollowCNAME(t *testing.T) {
	const host = "www.example.com"
	client := newDNSTestClient(t)
	srv := &dnsTestServer{t: t, client: client, zone: cnameChain(host, 1, "192.0.2.77")}
	txid, err := client.LookupIPStart(dns.MustNewName(host), dns.TypeA, 4)
	if err != nil {
		t.Fatal(err)
	}
	srv.respond()
	var dst [4]netip.Addr
	if _, err = lookupTestResult(t, client, txid, dst[:]); err != dns.ErrUnresolvedCNAME {
		t.Fatalf("got err=%v, want %v", err, dns.ErrUnresolvedCNAME)
	}
	hopTxid, err := client.LookupIPFollowCNAME(txid)
	if err != nil {
		t.Fatal("follow CNAME:", err)
	} else if hopTxid == 0 || hopTxid == txid {
		t.Fatalf("hop txid %#x must differ from %#x and be non-zero", hopTxid, txid)
	}
	if _, ok := client.LookupIPPop(txid); ok {
		t.Fatal("old txid still active after following CNAME")
	}
	if n, state, _ := client.LookupIPResult(hopTxid, dst[:]); !state.InProgress() || n != 0 {
		t.Fatal("hop done before its response")
	}
	srv.respond()
	addrs, err := lookupTestResult(t, client, hopTxid, dst[:])
	if err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("192.0.2.77") {
		t.Fatalf("got %v err=%v", addrs, err)
	}
	if srv.queries != 2 {
		t.Fatalf("got %d queries, want 2", srv.queries)
	}
}

func TestDNS_LookupIPExhausted(t *testing.T) {
	client := newDNSTestClient(t) // Default of 2 concurrent lookups.
	var txids []uint16
	for i := range 2 {
		txid, err := client.LookupIPStart(dns.MustNewName(fmt.Sprintf("h%d.example.com", i)), dns.TypeA, 4)
		if err != nil {
			t.Fatal(err)
		}
		txids = append(txids, txid)
	}
	if _, err := client.LookupIPStart(dns.MustNewName("h2.example.com"), dns.TypeA, 4); !errors.Is(err, lneto.ErrExhausted) {
		t.Fatalf("got err=%v, want ErrExhausted", err)
	}
	if state, ok := client.LookupIPPop(txids[0]); state != dns.CQueryPending || !ok {
		t.Fatalf("pop pending: state=%v ok=%v", state, ok)
	}
	if _, err := client.LookupIPStart(dns.MustNewName("h2.example.com"), dns.TypeA, 4); err != nil {
		t.Fatal("start after pop:", err)
	}
}

// egressDNSTestPort sends the client's next pending query to nowhere and returns its source port.
func egressDNSTestPort(t *testing.T, client *StackAsync) uint16 {
	t.Helper()
	var buf [ethernet.MaxFrameLength]byte
	n, err := client.EgressEthernet(buf[:])
	if err != nil || n == 0 {
		t.Fatalf("no query egressed: n=%d err=%v", n, err)
	}
	_, port, err := extractDNSTxIDAndPort(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestDNS_LookupIPPort(t *testing.T) {
	client := newDNSTestClient(t)
	txidA, err := client.LookupIPStart(dns.MustNewName("a.example.com"), dns.TypeA, 4)
	if err != nil {
		t.Fatal(err)
	}
	portA := egressDNSTestPort(t, client)
	txidB, err := client.LookupIPStart(dns.MustNewName("b.example.com"), dns.TypeA, 4)
	if err != nil {
		t.Fatal(err)
	}
	portB := egressDNSTestPort(t, client)
	if portA != portB {
		t.Fatalf("concurrent lookups use ports %d and %d, want shared port", portA, portB)
	}
	client.LookupIPPop(txidA)
	client.LookupIPPop(txidB)
	if _, err = client.LookupIPStart(dns.MustNewName("c.example.com"), dns.TypeA, 4); err != nil {
		t.Fatal(err)
	}
	if portC := egressDNSTestPort(t, client); portC == portA {
		t.Fatalf("idle client kept port %d for a new lookup", portC)
	}
}

// extractDNSTxIDAndPort extracts the DNS transaction ID and source port from an Ethernet+IP+UDP+DNS packet.
func extractDNSTxIDAndPort(pkt []byte) (txid uint16, srcPort uint16, err error) {
	const ethHdrLen = 14
	if len(pkt) < ethHdrLen+20+8+dns.SizeHeader {
		return 0, 0, errBaseLenDNS
	}

	// Parse ethernet to find IP header length.
	ethHdr, err := ethernet.NewFrame(pkt)
	if err != nil {
		return 0, 0, err
	}
	etherType := ethHdr.EtherTypeOrSize()
	if etherType != ethernet.TypeIPv4 {
		return 0, 0, errInvalidEtherType
	}

	ipHdrLen := int(pkt[ethHdrLen]&0x0f) * 4
	udpStart := ethHdrLen + ipHdrLen
	dnsStart := udpStart + 8

	if len(pkt) < dnsStart+dns.SizeHeader {
		return 0, 0, errBaseLenDNS
	}

	// Extract UDP source port.
	udpFrame, err := udp.NewFrame(pkt[udpStart:])
	if err != nil {
		return 0, 0, err
	}
	srcPort = udpFrame.SourcePort()

	dnsFrame, err := dns.NewFrame(pkt[dnsStart:])
	if err != nil {
		return 0, 0, err
	}
	return dnsFrame.TxID(), srcPort, nil
}

// extractDNSPayload returns the DNS message of an Ethernet+IPv4+UDP+DNS packet
// already validated by extractDNSTxIDAndPort.
func extractDNSPayload(pkt []byte) []byte {
	const ethHdrLen = 14
	ipHdrLen := int(pkt[ethHdrLen]&0x0f) * 4
	return pkt[ethHdrLen+ipHdrLen+8:]
}

// buildDNSMsgResponsePacket wraps a DNS response message into a complete
// Ethernet+IP+UDP packet with valid checksums.
func buildDNSMsgResponsePacket(t *testing.T, txid uint16, dstPort uint16, msg dns.Message,
	srcIP netip.Addr, srcMAC [6]byte, dstIP netip.Addr, dstMAC [6]byte, buf []byte) ([]byte, error) {
	t.Helper()

	// Response flags: QR=1 (response), RD=1 (recursion desired), RA=1 (recursion available).
	responseFlags := dns.HeaderFlags(1<<15 | 1<<8 | 1<<7)

	var dnsBuf [512]byte
	dnsPayload, err := msg.AppendTo(dnsBuf[:0], txid, responseFlags)
	if err != nil {
		return nil, err
	}

	// Build packet: Ethernet + IP + UDP + DNS.
	const ethHdrLen = 14
	const ipHdrLen = 20
	const udpHdrLen = 8

	totalLen := ethHdrLen + ipHdrLen + udpHdrLen + len(dnsPayload)
	if len(buf) < totalLen {
		return nil, errBaseLenDNS
	}
	pkt := buf[:totalLen]

	// Ethernet header.
	ethFrame, err := ethernet.NewFrame(pkt)
	if err != nil {
		return nil, err
	}
	*ethFrame.DestinationHardwareAddr() = dstMAC
	*ethFrame.SourceHardwareAddr() = srcMAC
	ethFrame.SetEtherType(ethernet.TypeIPv4)

	// IP header using ipv4.Frame for correct CRC calculation.
	ipStart := ethHdrLen
	ifrm, err := ipv4.NewFrame(pkt[ipStart:])
	if err != nil {
		return nil, err
	}
	ifrm.SetVersionAndIHL(4, 5) // Version 4, IHL 5 (20 bytes)
	ifrm.SetTotalLength(uint16(ipHdrLen + udpHdrLen + len(dnsPayload)))
	ifrm.SetID(0)
	ifrm.SetFlags(0)
	ifrm.SetTTL(64)
	ifrm.SetProtocol(lneto.IPProtoUDP)
	*ifrm.SourceAddr() = srcIP.As4()
	*ifrm.DestinationAddr() = dstIP.As4()
	// Zero the CRC field so its value does not add to the final result.
	ifrm.SetCRC(0)
	crcValue := ifrm.CalculateHeaderCRC()
	ifrm.SetCRC(crcValue)

	// UDP header.
	udpStart := ipStart + ipHdrLen
	udpFrame, err := udp.NewFrame(pkt[udpStart:])
	if err != nil {
		return nil, err
	}
	udpFrame.SetSourcePort(dns.ServerPort)
	udpFrame.SetDestinationPort(dstPort)
	udpLen := udpHdrLen + len(dnsPayload)
	udpFrame.SetLength(uint16(udpLen))

	// Copy DNS payload before calculating checksum.
	dnsStart := udpStart + udpHdrLen
	copy(pkt[dnsStart:], dnsPayload)

	// Calculate UDP checksum using pseudo header.
	var crc lneto.CRC791
	ifrm.CRCWriteUDPPseudo(&crc, uint16(udpLen))
	// Zero the CRC field so its value does not add to the final result.
	udpFrame.SetCRC(0)
	crcValue = crc.PayloadSum16(udpFrame.RawData())
	udpFrame.SetCRC(crcValue)

	return pkt, nil
}

var errBaseLenDNS = func() error {
	_, err := dns.NewFrame(nil)
	return err
}()

var errInvalidEtherType = errors.New("invalid ethernet type")

func FuzzStackPacketHTTP(f *testing.F) {
	const MTU = ethernet.MaxMTU
	const seed = 1
	var buf [ethernet.MaxFrameLength]byte
	s1, s2, c1, c2 := newTCPStacks(f, seed, MTU)
	var hdr httpraw.HeaderV1
	err := s1.ListenTCP4(c1, 80)
	if err != nil {
		f.Fatal(err)
	}
	err = s2.DialTCP(c2, 1337, netip.AddrPortFrom(netip.AddrFrom4(s1.Addr4()), c1.LocalPort()))
	if err != nil {
		f.Fatal(err)
	}
	hdr.SetMethod("GET")
	hdr.SetProtocol("HTTP/1.1")
	hdr.SetRequestTarget("/")
	data := hdr.AppendHeaders(nil)

	pktnum := 0
	written := false
	closed := false
	for {
		n1, err := s1.EgressEthernet(buf[:])
		if err != nil {
			f.Fatal(err)
		}
		if n1 > 0 {
			err = s2.IngressEthernet(buf[:n1])
			if err != nil {
				f.Fatal(err)
			}
			f.Add(pktnum, buf[:n1])
			pktnum++
			if !written && c2.State() >= tcp.StateEstablished {
				_, err = c2.Write(data)
				if err != nil {
					f.Fatal(err)
				}
				written = true
			}
		}
		n2, err := s2.EgressEthernet(buf[:])
		if n2 > 0 {
			pktnum++
			err = s1.IngressEthernet(buf[:n2])
			if err != nil {
				f.Fatal(err)
			}
			f.Add(pktnum, buf[:n2])
		}
		if n1 == 0 && n2 == 0 {
			if !closed {
				c2.Close()
				closed = true
				continue
			}
			break // No more data to send
		}
	}

	f.Fuzz(func(t *testing.T, pktnum int, a []byte) {
		var buf [ethernet.MaxFrameLength]byte
		s1, s2, c1, c2 := newTCPStacks(t, seed, MTU)
		err = s1.EnableICMP(true)
		if err != nil {
			t.Fatal(err)
		}
		err = s2.EnableICMP(true)
		if err != nil {
			t.Fatal(err)
		}
		err := s1.ListenTCP4(c1, 80)
		if err != nil {
			t.Fatal(err)
		}
		err = s2.DialTCP(c2, 1337, netip.AddrPortFrom(netip.AddrFrom4(s1.Addr4()), c1.LocalPort()))
		if err != nil {
			t.Fatal(err)
		}
		pkt := 0
		written := false
		closed := false
		const maxpkts = 100
		for {
			n1, err := s1.EgressEthernet(buf[:])
			if err != nil {
				t.Fatal(err)
			}
			if n1 > 0 {
				if pkt == pktnum {
					n1 = copy(buf[:], a)
					fixIPTCPCRCs(buf[:n1])
				}
				s2.IngressEthernet(buf[:n1])
				pkt++
				if !written && c2.State() >= tcp.StateEstablished {
					c2.Write(data)
					written = true
				}
			}
			n2, err := s2.EgressEthernet(buf[:])
			if n2 > 0 {
				if pkt == pktnum {
					n2 = copy(buf[:], a)
					fixIPTCPCRCs(buf[:n2])
				}
				pkt++
				s1.IngressEthernet(buf[:n2])
			}
			if n1 == 0 && n2 == 0 {
				if !closed {
					if c1.BufferedInput() > 0 {
						var hdr httpraw.HeaderV1
						n, _ := c1.Read(buf[:])
						hdr.ReadFromBytes(buf[:n])
						hdr.TryParse(false)
					}
					c2.Close()
					closed = true
					continue
				}
				break // No more data to send
			}
			if pkt > maxpkts {
				panic("infinite retransmission loop")
			}
		}
	})
}

// fixIPTCPCRCs corrects CRCs of IP and TCP headers so that
// fuzzed packets are not discarded 99.9999% of the time.
func fixIPTCPCRCs(pkt []byte) (fixable bool) {
	efrm, err := ethernet.NewFrame(pkt)
	if err != nil || efrm.EtherTypeOrSize() != ethernet.TypeIPv4 {
		return false
	}
	ifrm, err := ipv4.NewFrame(efrm.Payload())
	if err != nil {
		return false
	}
	v, ihl := ifrm.VersionAndIHL()
	tl := ifrm.TotalLength()
	if v != 4 || ihl < 5 || tl < uint16(ihl)*4 || int(tl) > len(efrm.Payload()) {
		return false // Invalid frame
	}
	var crc lneto.CRC791
	ifrm.SetCRC(0)
	ifrm.CRCWriteHeader(&crc)
	ifrm.SetCRC(crc.Sum16())
	if ifrm.Protocol() != lneto.IPProtoTCP {
		return false
	}
	IPpayload := ifrm.Payload()
	tfrm, err := tcp.NewFrame(IPpayload)
	if err != nil {
		return false
	}
	crc.Reset()
	ifrm.CRCWriteTCPPseudo(&crc)
	// Zero the CRC field so its value does not add to the final result.
	tfrm.SetCRC(0)
	crcValue := crc.PayloadSum16(IPpayload)
	tfrm.SetCRC(crcValue)
	return true
}

func FuzzStackSeeded(f *testing.F) {
	f.Add(int64(1), int64(2))
	// Numbers below taken from ANU QRNG https://qrng.anu.edu.au/random-hex/
	f.Add(int64(0x5b38810084b73b78), int64(0xfbc7243ac2c4a84))
	f.Add(int64(0x78b75e43c6fb1336), int64(0x09f9c425438dd42a))
	f.Add(int64(0xf63789e3a0750ed), int64(0xd4d3df265f09358))
	f.Add(int64(0x9649343892132dc), int64(0xfd5be085171f904))

	// Set to the values of the fuzz case that is crashing to enable verbose debugging logs.
	f.Fuzz(testStackSeeded)
}

// fuzz test printing facilities.
var (
	fzppr    CapturePrinter
	fzpmut   ltesto.PacketMut
	fzoutput = os.Stdout
)

func init() {
	fzppr.Configure(fzoutput, CapturePrinterConfig{
		NamespaceWidth: 3,
	})
}

const (
	printFuzz  = false
	printSeed1 = 676827762285163398
	printSeed2 = 1141027023543727980
)

// Debugging facility.
func TestStackSeeded(t *testing.T) {
	testStackSeeded(t, printSeed1, printSeed2)
}

func testStackSeeded(t *testing.T, seed1, seed2 int64) {
	if seed1 == 0 {
		seed1++
	}
	if seed2 == 0 {
		seed2++
	}
	verbose := printFuzz && printSeed1 == seed1 && printSeed2 == seed2
	const (
		actionUDP = iota
		actionTCP
		actionICMP
		actionARP
		actionLim
	)
	const maxActions = 32
	const maxConsecutivePackets = 6
	var actions [maxActions]struct {
		Action   int64
		Rand     int64
		Mutation [maxConsecutivePackets]struct {
			Seed1, Seed2       int64
			MutBits1, MutBits2 int64
			IsMut              int64
		}
	}
	// Fuzz tests are supposed to be predictable and repeatable.
	// We only generate the randomness in one place and in same order of
	// rng.Int64 calls. We cannot add new calls into the for loop but we
	// can add a new for loops when we need more fields filled in.
	// Be wary of invalidating the entire fuzz corpus we have.
	{
		rng := randv2.New(randv2.NewPCG(uint64(seed1), uint64(seed2)))
		for i := range actions {
			// DO NOT ADD CALLS TO rng API IN HERE! Read comment above.
			actions[i].Action = rng.Int64() % actionLim
			actions[i].Rand = rng.Int64()
			for k := range maxConsecutivePackets {
				mut := &actions[i].Mutation[k]
				mut.IsMut = rng.Int64()
				mut.Seed1 = rng.Int64()
				mut.Seed2 = rng.Int64()
				mut.MutBits1 = rng.Int64()
				mut.MutBits2 = rng.Int64()
			}
		}
	}

	const mtu = ethernet.MaxMTU
	const mfl = mtu + ethernet.MaxOverheadSize // frame length includes ethernet header
	var buf [mfl]byte
	var s1, s2 StackAsync
	v1, v2 := byte(seed1), byte(seed2)
	cfg1 := StackConfig{
		Hostname:          "s1",
		StaticAddress4:    [4]byte{1, 0, 0, v1},
		RandSeed:          seed1,
		MaxActiveTCPPorts: 1,
		MaxActiveUDPPorts: 1,
		ICMPQueueLimit:    1 + int(v1%4),
		MTU:               mtu,
		HardwareAddress:   [6]byte{0x1, 0, 0, 0, 0, v1},
		AcceptMulticast:   v1%2 == 0,
		PassivePeers:      int(v1 >> 6),
	}
	err := s1.Reset(cfg1)
	if err != nil {
		t.Fatal(err, cfg1)
	}
	cfg2 := StackConfig{
		Hostname:          "s2",
		StaticAddress4:    [4]byte{1, 0, 0, v2},
		RandSeed:          seed2,
		MaxActiveTCPPorts: 1,
		MaxActiveUDPPorts: 1,
		ICMPQueueLimit:    1 + int(v2%4),
		MTU:               mtu,
		HardwareAddress:   [6]byte{0x2, 0, 0, 0, 0, v2},
		AcceptMulticast:   v2%2 == 0,
		PassivePeers:      int(v2 >> 6),
	}
	err = s2.Reset(cfg2)
	if err != nil {
		t.Fatal(err, cfg2)
	}

	const (
		pingMinPayload = 8
		port1          = 8080
		port2          = 80
		bufsize        = 64
	)
	var udp1, udp2 udp.Conn
	var tcp1, tcp2 tcp.Conn
	err = tcp1.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, bufsize),
		TxBuf:             make([]byte, bufsize),
		TxPacketQueueSize: 1 + int(uint16(seed1)%10),
		RWBackoff:         backoffYield,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = tcp2.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, bufsize),
		TxBuf:             make([]byte, bufsize),
		TxPacketQueueSize: 1 + int(uint16(seed2)%10),
		RWBackoff:         backoffYield,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = udp1.Configure(udp.ConnConfig{
		RxBuf:       make([]byte, bufsize),
		TxBuf:       make([]byte, bufsize),
		RxQueueSize: int(1 + uint16(seed1>>32)%10),
		TxQueueSize: int(1 + uint16(seed1>>32)%10),
		RWBackoff:   backoffYield,
		MTU:         mtu,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = udp2.Configure(udp.ConnConfig{
		RxBuf:       make([]byte, bufsize),
		TxBuf:       make([]byte, bufsize),
		RxQueueSize: int(1 + uint16(seed2>>32)%10),
		TxQueueSize: int(1 + uint16(seed2>>32)%10),
		RWBackoff:   backoffYield,
		MTU:         mtu,
	})
	if err != nil {
		t.Fatal(err)
	}
	icmpEnabled := false
	udpOrder := 0
	betsAreOff := false // When a packet is mutated all bets on which error can be returned are off.
	for i, action := range actions {
		switch action.Action {
		case actionTCP:
			state1 := tcp1.State()
			state2 := tcp2.State()
			if state1 == 0 && state2 == 0 {
				if verbose {
					fmt.Fprintln(fzoutput, "TCP dial")
				}
				err = s1.DialTCP(&tcp1, port1, netip.AddrPortFrom(netip.AddrFrom4(s2.Addr4()), port2))
				if err != nil {
					t.Fatal(i, err)
				}
				err = s2.ListenTCP4(&tcp2, port2)
				if err != nil {
					t.Fatal(i, err)
				}
			} else if state1 == tcp.StateEstablished && state2 == tcp.StateEstablished {
				// For now just close after established.
				closeNum := 1 + action.Rand%2
				if verbose {
					fmt.Fprintln(fzoutput, "TCP close", closeNum)
				}
				switch closeNum {
				case 1:
					tcp1.Close()
				case 2:
					tcp2.Close()
				}
			}
		case actionUDP:
			// Ensure connections open.
			if !udp1.IsOpen() {
				if verbose {
					fmt.Fprintln(fzoutput, "UDP dial 1")
				}
				err = s1.DialUDP(&udp1, port1, netip.AddrPortFrom(netip.AddrFrom4(s2.Addr4()), port2))
				if err != nil {
					t.Fatal(i, err)
				}
			}
			if !udp2.IsOpen() {
				if verbose {
					fmt.Fprintln(fzoutput, "UDP dial 2")
				}
				err = s2.DialUDP(&udp2, port2, netip.AddrPortFrom(netip.AddrFrom4(s1.Addr4()), port1))
				if err != nil {
					t.Fatal(i, err)
				}
			}
			udpOrder++
			action := action.Rand % 8
			if verbose {
				fmt.Fprintln(fzoutput, "UDP action", action)
			}
			switch action {
			case 0:
				if udp1.FreeOutput() > 0 {
					udp1.Write([]byte{byte(udpOrder)})
				}
			case 1:
				if udp1.BufferedInput() > 0 {
					udp1.Read(buf[:])
				}
			case 2:
				if udp2.FreeOutput() > 0 {
					udp2.Write([]byte{byte(udpOrder)})
				}
			case 3:
				if udp2.BufferedInput() > 0 {
					udp2.Read(buf[:])
				}
			case 4:
				udp1.Close()
			case 5:
				udp2.Close()
			}
		case actionICMP:
			icmpaction := action.Rand % 2
			if verbose {
				fmt.Fprintln(fzoutput, "ICMP action", icmpaction, "enabled", icmpEnabled)
			}
			if !icmpEnabled {
				err = s1.EnableICMP(true)
				if err != nil {
					t.Fatal(i, err)
				}
				err = s2.EnableICMP(true)
				if err != nil {
					t.Fatal(i, err)
				}
				icmpEnabled = true
			}
			switch icmpaction {
			case 0:
				s1.icmp.Reset()
				_, err = s1.icmp.PingStart(s2.Addr4(), buf[:pingMinPayload], pingMinPayload+uint16(action.Rand)%pingMinPayload)
				if err != nil {
					t.Fatal(i, err)
				}
			case 1:
				s2.icmp.Reset()
				_, err = s2.icmp.PingStart(s1.Addr4(), buf[:pingMinPayload], pingMinPayload+uint16(action.Rand)%pingMinPayload)
				if err != nil {
					t.Fatal(i, err)
				}
			}

		case actionARP:
			action := action.Rand % 6
			if verbose {
				fmt.Fprintln(fzoutput, "ARP action", action)
			}
			switch action {
			case 0: // s1 queries s2 address.
				s1.StartResolveHardwareAddress6(netip.AddrFrom4(s2.Addr4()))
			case 1: // s2 queries s1 address.
				s2.StartResolveHardwareAddress6(netip.AddrFrom4(s1.Addr4()))
			case 2: // s1 checks query result for s2.
				s1.ResultResolveHardwareAddress6(netip.AddrFrom4(s2.Addr4()))
			case 3: // s2 checks query result for s1.
				s2.ResultResolveHardwareAddress6(netip.AddrFrom4(s1.Addr4()))
			case 4: // s1 discards pending query.
				s1.DiscardResolveHardwareAddress6(netip.AddrFrom4(s2.Addr4()))
			case 5: // s2 discards pending query.
				s2.DiscardResolveHardwareAddress6(netip.AddrFrom4(s1.Addr4()))
			}
		}
		// Exchange data while checking stack does not enter runaway infinite frame send loop.
		first, second := &s1, &s2
		if (action.Rand>>32)%2 == 0 {
			first, second = second, first
		}
		// TODO(soypat): add specialized packet mutation by detecting protocol and modifying specific packet fields.

		for k, mut := range action.Mutation {
			n, err := first.EgressEthernet(buf[:])
			if err != nil {
				t.Fatal(i, k, err)
			} else if n > 0 {
				if mut.IsMut&1 != 0 {
					if verbose {
						fmt.Fprintln(fzoutput, "mutate tx", first.Hostname())
					}
					fzpmut.MutateEthernet(buf[:n], mut.Seed1, mut.MutBits1)
					betsAreOff = true
				}
				if verbose {
					fzppr.PrintEthernet(first.Hostname(), buf[:n])
				}
				err = second.IngressEthernet(buf[:n])
				if err != nil && !betsAreOff && err != lneto.ErrPacketDrop && err != lneto.ErrExhausted {
					t.Fatal(i, k, err)
				} else if verbose && err != nil {
					fmt.Fprintln(fzoutput, "err rx", second.Hostname(), err.Error())
				}
			}
			n, err = second.EgressEthernet(buf[:])
			if err != nil {
				t.Fatal(i, k, err)
			} else if n > 0 {
				if mut.IsMut&1 != 0 {
					if verbose {
						fmt.Fprintln(fzoutput, "mutate tx", second.Hostname())
					}
					fzpmut.MutateEthernet(buf[:n], mut.Seed2, mut.MutBits2)
					betsAreOff = true
				}
				if verbose {
					fzppr.PrintEthernet(second.Hostname(), buf[:n])
				}
				err = first.IngressEthernet(buf[:n])
				if err != nil && !betsAreOff && err != lneto.ErrPacketDrop && err != lneto.ErrExhausted {
					t.Fatal(i, k, err)
				} else if verbose && err != nil {
					fmt.Fprintln(fzoutput, "err rx", first.Hostname(), err.Error())
				}
			}
		}
		// Drain any remaining packets (retransmits from mutation).
		// Hard ceiling prevents infinite send loops from passing silently.
		// Also send drained packet to other stack to also catch infinite feedback loops.
		const drainLimit = 8
		for d := range drainLimit {
			limit := d == drainLimit-1
			n, err := first.EgressEthernet(buf[:])
			if (err != nil || n > 0) && limit {
				fzppr.PrintEthernet(first.Hostname(), buf[:n])
				t.Fatal(i, "stuck in data/error loop:", err)
			} else if n > 0 {
				if verbose {
					fzppr.PrintEthernet(first.Hostname(), buf[:n])
				}
				second.IngressEthernet(buf[:n])
			}
			n, err = second.EgressEthernet(buf[:])
			if (err != nil || n > 0) && limit {
				fzppr.PrintEthernet("(2) ", buf[:n])
				t.Fatal(i, "stuck in data/error loop:", err)
			} else if n > 0 {
				if verbose {
					fzppr.PrintEthernet(second.Hostname(), buf[:n])
				}
				first.IngressEthernet(buf[:n])
			}
		}
	}
}

func TestStackAsync_ICMPEcho(t *testing.T) {
	tests := []struct {
		name    string
		pattern []byte
		size    uint16
	}{
		{"1 EchoRequestReply", []byte("icmp-test"), 56},
		{"2 ReplyToManualRequest", []byte("manual-echo"), 32},
	}
	sender, receiver := newICMPStacks(t, 42, 1500) // seed 42 is arbitrary, stacks get unique IPs
	if err := sender.EnableICMP(true); err != nil {
		t.Fatal(err)
	}
	if err := receiver.EnableICMP(true); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := sender.EgressEthernet(buf)
	if n > 0 || err != nil {
		t.Fatal("sender unexpected data sent or error", n, err)
	}
	n, err = receiver.EgressEthernet(buf)
	if n > 0 || err != nil {
		t.Fatal("receiver unexpected data sent or error", n, err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			sender.SetGatewayHardwareAddr(receiver.HardwareAddr())
			receiver.SetGatewayHardwareAddr(sender.HardwareAddr())

			key, err := sender.icmp.PingStart(receiver.Addr4(), tt.pattern, tt.size)
			if err != nil {
				t.Fatal(err)
			}
			echoSent := exchangeEthernetOnce(t, sender, receiver, buf)
			if echoSent == 0 {
				t.Error("ECHO not sent")
			}
			echoReplySent := exchangeEthernetOnce(t, receiver, sender, buf)
			if echoReplySent == 0 {
				t.Error("ECHOREPLY not sent")
			}
			n, err = sender.EgressEthernet(buf)
			if n > 0 || err != nil {
				t.Error("sender excess data sent or error", n, err)
			}
			n, err = receiver.EgressEthernet(buf)
			if n > 0 || err != nil {
				t.Error("receiver excess data sent or error", n, err)
			}

			completed, ok := sender.icmp.PingPop(key)
			if !ok {
				t.Fatal("ping key not found")
			}
			if !completed {
				t.Fatal("expected ping to complete")
			}
		})
	}
}

// newICMPStacks creates two test stacks with distinct static addresses and hardware addresses.
func newICMPStacks(t testing.TB, randSeed int64, mtu int) (*StackAsync, *StackAsync) {
	const icmpQueue = 4
	s1, s2 := new(StackAsync), new(StackAsync)

	// Use the seed to generate two adjacent IPs (10.0.0.x) and MACs.
	base := byte(randSeed & 0x7F) // keep in safe range 0..127
	addr1 := [4]byte{10, 0, 0, base}
	addr2 := [4]byte{10, 0, 0, base + 1}
	mac1 := [6]byte{0xbe, 0xef, 0, 0, 0, base}
	mac2 := [6]byte{0xbe, 0xef, 0, 0, 0, base + 1}

	if err := s1.Reset(StackConfig{
		Hostname:        "icmp-stack-1",
		RandSeed:        randSeed,
		StaticAddress4:  addr1,
		HardwareAddress: mac1,
		MTU:             uint16(mtu),
		ICMPQueueLimit:  icmpQueue,
	}); err != nil {
		t.Fatal(err)
	}

	if err := s2.Reset(StackConfig{
		Hostname:        "icmp-stack-2",
		RandSeed:        ^randSeed,
		StaticAddress4:  addr2,
		HardwareAddress: mac2,
		MTU:             uint16(mtu),
		ICMPQueueLimit:  icmpQueue,
	}); err != nil {
		t.Fatal(err)
	}

	return s1, s2
}

func TestStackAsyncListener_SingleConnection(t *testing.T) {
	const seed int64 = 1234
	const MTU = ethernet.MaxMTU
	const carrierSize = MTU + ethernet.MaxOverheadSize
	const svPort = 80
	const clPort = 1337

	// Create two stacks.
	client, sv := new(StackAsync), new(StackAsync)
	err := client.Reset(StackConfig{
		Hostname:          "Client",
		RandSeed:          seed,
		StaticAddress4:    [4]byte{10, 0, 0, 1},
		MaxActiveTCPPorts: 1,
		HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, 1},
		MTU:               MTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = sv.Reset(StackConfig{
		Hostname:          "Server",
		RandSeed:          ^seed,
		StaticAddress4:    [4]byte{10, 0, 0, 2},
		MaxActiveTCPPorts: 1, // Note: We use listener, not direct TCP conn registration.
		HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, 2},
		MTU:               MTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.SetGatewayHardwareAddr(sv.HardwareAddr())
	sv.SetGatewayHardwareAddr(client.HardwareAddr())

	// Create client connection.
	var clConn tcp.Conn
	err = clConn.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, MTU),
		TxBuf:             make([]byte, MTU),
		TxPacketQueueSize: 4,
		RWBackoff:         backoffYield,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create pool and listener for server.
	pool, err := newTCPPool(&TCPPoolConfig{
		key:                [16]byte{1},
		PoolSize:           1,
		QueueSize:          4,
		TxBufSize:          MTU,
		RxBufSize:          MTU,
		EstablishedTimeout: 10e9,
		ClosingTimeout:     10e9,
		NewBackoff:         func() lneto.BackoffStrategy { return backoffYield },
	})
	if err != nil {
		t.Fatal(err)
	}

	var listener tcp.Listener
	err = listener.Reset(svPort, pool)
	if err != nil {
		t.Fatal(err)
	}
	err = sv.RegisterListenerTCP(&listener)
	if err != nil {
		t.Fatal(err)
	}

	// Client dials server.
	err = client.DialTCP(&clConn, clPort, netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort))
	if err != nil {
		t.Fatal(err)
	}

	tst := testerFrom(t, MTU)

	// Complete TCP handshake.
	tst.TestTCPHandshake(client, sv)

	// After handshake, TryAccept should work.
	if listener.NumberOfReadyToAccept() != 1 {
		t.Fatalf("after handshake: expected 1 ready, got %d", listener.NumberOfReadyToAccept())
	}
	pinned, err := listener.TryAccept()
	if err != nil {
		t.Fatalf("TryAccept: %v", err)
	}
	svConn := pinned.Conn()
	if listener.NumberOfReadyToAccept() != 0 {
		t.Fatalf("after accept: expected 0 ready, got %d", listener.NumberOfReadyToAccept())
	}

	// Verify both connections are established.
	if clConn.State() != tcp.StateEstablished {
		t.Fatalf("client: expected StateEstablished, got %s", clConn.State())
	}
	if svConn.State() != tcp.StateEstablished {
		t.Fatalf("server: expected StateEstablished, got %s", svConn.State())
	}

	// Test data exchange: client -> server.
	sendData := []byte("hello from client")
	tst.TestTCPEstablishedSingleData(client, sv, &clConn, svConn, sendData)

	// Test data exchange: server -> client.
	replyData := []byte("hello from server")
	tst.TestTCPEstablishedSingleData(sv, client, svConn, &clConn, replyData)

	// Test close (client-initiated).
	tst.TestTCPClose(client, sv, &clConn, svConn)
}

func TestStackAsyncListener_MultiSequentialConn(t *testing.T) {
	const seed int64 = 1234
	const MTU = ethernet.MaxMTU
	const carrierSize = MTU + ethernet.MaxOverheadSize
	const svPort = 80
	const clPort = 1337
	const poolsize = 10
	const bufsize = 128
	// Create two stacks.
	sv := new(StackAsync)
	err := sv.Reset(StackConfig{
		Hostname:          "Server",
		RandSeed:          ^seed,
		StaticAddress4:    [4]byte{10, 0, 0, 2},
		MaxActiveTCPPorts: 1, // Note: We use listener, not direct TCP conn registration.
		HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, 2},
		MTU:               MTU,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create pool and listener for server.
	pool, err := sv.NewTCPPool(TCPPoolConfig{
		PoolSize:           poolsize,
		QueueSize:          4,
		TxBufSize:          bufsize,
		RxBufSize:          bufsize,
		EstablishedTimeout: 10e9,
		ClosingTimeout:     10e9,
		NewBackoff:         func() lneto.BackoffStrategy { return backoffYield },
	})
	if err != nil {
		t.Fatal(err)
	}

	var listener tcp.Listener
	err = listener.Reset(svPort, pool)
	if err != nil {
		t.Fatal(err)
	}
	err = sv.RegisterListenerTCP(&listener)
	if err != nil {
		t.Fatal(err)
	}
	caddr := netip.AddrFrom4([4]byte{10, 0, 0, 1})
	chw := [6]byte{0xbe, 0xef, 0, 0, 0, 1}
	sv.SetGatewayHardwareAddr(chw)
	tst := testerFrom(t, MTU)
	doRequest := func(caddrp netip.AddrPort, data []byte) {
		var client StackAsync
		err := client.Reset(StackConfig{
			Hostname:          "Client",
			RandSeed:          seed,
			StaticAddress4:    caddrp.Addr().As4(),
			MaxActiveTCPPorts: 1,
			HardwareAddress:   chw,
			MTU:               MTU,
		})
		if err != nil {
			panic(err)
		}
		client.SetGatewayHardwareAddr(sv.HardwareAddr())
		// Create client connection.
		var clConn tcp.Conn
		err = clConn.Configure(tcp.ConnConfig{
			RxBuf:             make([]byte, bufsize),
			TxBuf:             make([]byte, bufsize),
			TxPacketQueueSize: 4,
			RWBackoff:         backoffYield,
		})
		if err != nil {
			t.Fatal(err)
		}
		// Client dials server.
		err = client.DialTCP(&clConn, caddrp.Port(), netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort))
		if err != nil {
			t.Fatal(err)
		}
		// Complete TCP handshake.
		tst.TestTCPHandshake(&client, sv)
		// After handshake, TryAccept should work.
		if listener.NumberOfReadyToAccept() != 1 {
			t.Fatalf("after handshake: expected 1 ready, got %d", listener.NumberOfReadyToAccept())
		}
		pinned, err := listener.TryAccept()
		svconn := pinned.Conn()
		if err != nil {
			t.Fatal(err)
		} else if svconn.RemotePort() != clConn.LocalPort() ||
			[4]byte(svconn.RemoteAddr()) != client.Addr4() {
			t.Fatal("race condition to listener acquisition")
		}
		// Verify both connections are established.
		if clConn.State() != tcp.StateEstablished {
			t.Fatalf("client: expected StateEstablished, got %s", clConn.State())
		}
		if len(data) > 0 {
			tst.TestTCPEstablishedSingleData(&client, sv, &clConn, svconn, data)
		}
		tst.TestTCPClose(&client, sv, &clConn, svconn)
	}

	for range 1000 {
		caddr := caddr.Next()
		doRequest(netip.AddrPortFrom(caddr, uint16(sv.Prand32())), []byte("HTTP 1.0\r\n"))
	}
}

func TestListener_Close(t *testing.T) {
	const svPort uint16 = 80

	pool, err := newTCPPool(&TCPPoolConfig{
		key:                [16]byte{1},
		PoolSize:           1,
		QueueSize:          4,
		TxBufSize:          512,
		RxBufSize:          512,
		EstablishedTimeout: 10e9,
		ClosingTimeout:     10e9,
		NewBackoff:         func() lneto.BackoffStrategy { return backoffYield },
	})
	if err != nil {
		t.Fatal(err)
	}

	var listener tcp.Listener
	err = listener.Reset(svPort, pool)
	if err != nil {
		t.Fatal(err)
	}
	if listener.LocalPort() != svPort {
		t.Fatalf("expected port %d, got %d", svPort, listener.LocalPort())
	}

	err = listener.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if listener.LocalPort() != 0 {
		t.Fatalf("port should be 0 after Close, got %d", listener.LocalPort())
	}

	// Double close should return net.ErrClosed.
	err = listener.Close()
	if err == nil {
		t.Fatal("double Close should return error")
	}
}

func TestListener_ResetAfterClose(t *testing.T) {
	const svPort uint16 = 80

	pool, err := newTCPPool(&TCPPoolConfig{
		key:                [16]byte{1},
		PoolSize:           1,
		QueueSize:          4,
		TxBufSize:          512,
		RxBufSize:          512,
		EstablishedTimeout: 10e9,
		ClosingTimeout:     10e9,
		NewBackoff:         func() lneto.BackoffStrategy { return backoffYield },
	})
	if err != nil {
		t.Fatal(err)
	}

	var listener tcp.Listener
	err = listener.Reset(svPort, pool)
	if err != nil {
		t.Fatal(err)
	}

	err = listener.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Should be able to Reset after Close.
	err = listener.Reset(svPort, pool)
	if err != nil {
		t.Fatalf("Reset after Close failed: %v", err)
	}
	if listener.LocalPort() != svPort {
		t.Fatalf("expected port %d after re-Reset, got %d", svPort, listener.LocalPort())
	}
}

func setIfZero[T comparable](a *T, v T) {
	var z T
	if *a == z {
		*a = v
	}
}

// newTestListener returns a listener on port backed by a pool built from cfg.
// Zero RandSeed, QueueSize, buffer sizes, timeouts and NewBackoff take test defaults.
// The listener is registered on stack when stack is non-nil.
func newTestListener(t testing.TB, stack *StackAsync, port uint16, cfg TCPPoolConfig) *tcp.Listener {
	t.Helper()
	setIfZero(&cfg.QueueSize, 4)
	setIfZero(&cfg.TxBufSize, ethernet.MaxMTU)
	setIfZero(&cfg.RxBufSize, ethernet.MaxMTU)
	setIfZero(&cfg.EstablishedTimeout, 10*time.Second)
	setIfZero(&cfg.ClosingTimeout, 10*time.Second)
	if cfg.NewBackoff == nil {
		cfg.NewBackoff = newBackoffYield
	}
	pool, err := stack.NewTCPPool(cfg)
	if err != nil {
		t.Fatal(err)
	}
	listener := new(tcp.Listener)
	if err = listener.Reset(port, pool); err != nil {
		t.Fatal(err)
	}
	if stack != nil {
		if err = stack.RegisterListenerTCP(listener); err != nil {
			t.Fatal(err)
		}
	}
	return listener
}

// M20: closing a listener must not kill connections it already accepted.
func TestListener_CloseKeepsAcceptedConns(t *testing.T) {
	const svPort = 80
	const mtu = ethernet.MaxMTU
	const lim = 8
	tst := testerFrom(t, mtu)
	sv := newTestStack(t, "sv1", 1, mtu, 1, 0)
	cl := newTestStack(t, "cl2", 2, mtu, 1, 0)
	sv.SetGatewayHardwareAddr(cl.HardwareAddr())
	cl.SetGatewayHardwareAddr(sv.HardwareAddr())
	listener := newTestListener(t, sv, svPort, TCPPoolConfig{PoolSize: 1})

	clconn := newTestTCPConn(t, mtu, 4)
	if err := cl.DialTCP(clconn, 1337, netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)); err != nil {
		t.Fatal(err)
	}
	tst.ensureQuiesce(cl, sv, lim)
	accepted, err := listener.TryAccept()
	if err != nil {
		t.Fatal("TryAccept:", err)
	}

	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}

	// Inbound: client data reaches accepted conn.
	if _, err = clconn.Write([]byte("in")); err != nil {
		t.Fatal(err)
	}
	tst.ensureQuiesce(cl, sv, lim)
	if got := accepted.Conn().BufferedInput(); got != 2 {
		t.Errorf("accepted conn got %d inbound bytes after listener Close, want 2", got)
	}
	// Outbound: accepted conn data reaches client.
	if _, err = accepted.Write([]byte("out")); err != nil {
		t.Fatal("accepted write after listener Close:", err)
	}
	tst.ensureQuiesce(cl, sv, lim)
	if got := clconn.BufferedInput(); got != 3 {
		t.Errorf("client got %d bytes from accepted conn after listener Close, want 3", got)
	}
	if n := listener.NumberOfActiveAccepted(); n != 1 {
		t.Errorf("closed listener reports %d active accepted, want 1", n)
	}
	// Abort forcibly ends accepted conns.
	listener.Abort()
	if n := listener.NumberOfActiveAccepted(); n != 0 {
		t.Errorf("aborted listener reports %d active accepted, want 0", n)
	}
	if _, err = accepted.Write([]byte("x")); err == nil {
		t.Error("accepted write succeeded after listener Abort")
	}
}

// M4: a client that sends data and half-closes before the server calls Accept
// must still be accepted, and its data must be readable before EOF.
func TestListener_AcceptHalfClosedBeforeAccept(t *testing.T) {
	const svPort = 80
	const mtu = ethernet.MaxMTU
	const lim = 8
	const msg = "upload"
	tst := testerFrom(t, mtu)
	sv := newTestStack(t, "sv1", 1, mtu, 1, 0)
	cl := newTestStack(t, "cl2", 2, mtu, 1, 0)
	sv.SetGatewayHardwareAddr(cl.HardwareAddr())
	cl.SetGatewayHardwareAddr(sv.HardwareAddr())
	listener := newTestListener(t, sv, svPort, TCPPoolConfig{PoolSize: 1})

	clconn := newTestTCPConn(t, mtu, 4)
	if err := cl.DialTCP(clconn, 1337, netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)); err != nil {
		t.Fatal(err)
	}
	tst.ensureQuiesce(cl, sv, lim)
	// Client uploads and half-closes before server accepts.
	if _, err := clconn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	if err := clconn.Close(); err != nil {
		t.Fatal(err)
	}
	tst.ensureQuiesce(cl, sv, lim)
	if clconn.State() != tcp.StateFinWait2 {
		t.Fatalf("client state %s, want %s", clconn.State(), tcp.StateFinWait2)
	}

	accepted, err := listener.TryAccept()
	if err != nil {
		t.Fatal("TryAccept of conn half-closed before Accept:", err)
	}
	if accepted.State() != tcp.StateCloseWait {
		t.Errorf("accepted state %s, want %s", accepted.State(), tcp.StateCloseWait)
	}
	var buf [32]byte
	n, err := accepted.Read(buf[:])
	if err != nil {
		t.Fatal("read accepted:", err)
	} else if string(buf[:n]) != msg {
		t.Errorf("accepted read %q, want %q", buf[:n], msg)
	}
	if _, err = accepted.Read(buf[:]); err != io.EOF {
		t.Errorf("read after drained half-closed conn: got %v, want io.EOF", err)
	}
	// Server can still reply over the half-closed connection.
	if _, err = accepted.Write([]byte("ok")); err != nil {
		t.Fatal("write to half-closed conn:", err)
	}
	tst.ensureQuiesce(cl, sv, lim)
	if got := clconn.BufferedInput(); got != 2 {
		t.Errorf("client got %d bytes after half-close, want 2", got)
	}
}

// Resetting a listener must hand the conns it still holds back to their pool,
// else each Reset leaks pool slots until the listener refuses every client.
func TestListener_ResetReleasesPoolConns(t *testing.T) {
	const svPort = 80
	const mtu = ethernet.MaxMTU
	const lim = 8
	tests := []struct {
		name     string
		accept   bool // conn was accepted before Reset, else still pending acceptance.
		closeFst bool // listener closed before Reset.
	}{
		{name: "accepted, closed", accept: true, closeFst: true},
		{name: "accepted, open", accept: true},
		{name: "pending, open"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tst := testerFrom(t, mtu)
			sv := newTestStack(t, "sv1", 1, mtu, 1, 0)
			pool, err := sv.NewTCPPool(TCPPoolConfig{
				PoolSize:           1,
				QueueSize:          4,
				TxBufSize:          mtu,
				RxBufSize:          mtu,
				EstablishedTimeout: 10 * time.Second,
				ClosingTimeout:     10 * time.Second,
				NewBackoff:         newBackoffYield,
			})
			if err != nil {
				t.Fatal(err)
			}
			var listener tcp.Listener
			if err = listener.Reset(svPort, pool); err != nil {
				t.Fatal(err)
			} else if err = sv.RegisterListenerTCP(&listener); err != nil {
				t.Fatal(err)
			}
			connect := func(cl *StackAsync) {
				t.Helper()
				sv.SetGatewayHardwareAddr(cl.HardwareAddr())
				cl.SetGatewayHardwareAddr(sv.HardwareAddr())
				clconn := newTestTCPConn(t, mtu, 4)
				err := cl.DialTCP(clconn, 1337, netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort))
				if err != nil {
					t.Fatal(err)
				}
				tst.ensureQuiesce(cl, sv, lim)
			}

			connect(newTestStack(t, "cl2", 2, mtu, 1, 0))
			if tt.accept {
				if _, err = listener.TryAccept(); err != nil {
					t.Fatal("TryAccept:", err)
				}
			}
			if tt.closeFst {
				if err = listener.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err = listener.Reset(svPort, pool); err != nil {
				t.Fatal("Reset:", err)
			} else if err = sv.RegisterListenerTCP(&listener); err != nil {
				t.Fatal("RegisterListenerTCP after Reset:", err)
			}

			// Pool holds a single conn: a new client is only served if Reset released it.
			connect(newTestStack(t, "cl3", 3, mtu, 1, 0))
			if _, err = listener.TryAccept(); err != nil {
				t.Errorf("TryAccept of new client after Reset: %v (pool slot leaked)", err)
			}
		})
	}
}

func TestMDNS_QueryResponse(t *testing.T) {
	const MTU = ethernet.MaxMTU
	svcName := dns.MustNewName("My Web._http._tcp.local")
	hostName := dns.MustNewName("mydevice.local")
	svcType := dns.MustNewName("_http._tcp.local")
	svc := mdns.Service{
		Name: svcName,
		Host: hostName,
		Addr: []byte{192, 168, 1, 50},
		Port: 80,
	}

	responderAddr := [4]byte{192, 168, 1, 50}
	responderMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}
	querierAddr := [4]byte{192, 168, 1, 100}
	querierMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02}
	mcastAddr := [4]byte{224, 0, 0, 251}

	// Setup responder stack with mDNS service.
	responderStack := new(StackAsync)
	err := responderStack.Reset(StackConfig{
		Hostname:          "responder",
		RandSeed:          1234,
		StaticAddress4:    responderAddr,
		HardwareAddress:   responderMAC,
		MTU:               MTU,
		MaxActiveUDPPorts: 1,
		AcceptMulticast:   true,
	})
	if err != nil {
		t.Fatal("responder reset:", err)
	}
	responderStack.SetGatewayHardwareAddr(querierMAC)

	var responderClient mdns.Client
	err = responderClient.Configure(mdns.ClientConfig{
		LocalPort:     mdns.Port,
		Services:      []mdns.Service{svc},
		MulticastAddr: mcastAddr[:],
	})
	if err != nil {
		t.Fatal("responder configure:", err)
	}
	err = responderStack.RegisterUDP4(&responderClient, mcastAddr, mdns.Port)
	if err != nil {
		t.Fatal("responder register:", err)
	}

	// Setup querier stack.
	querierStack := new(StackAsync)
	err = querierStack.Reset(StackConfig{
		Hostname:          "querier",
		RandSeed:          5678,
		StaticAddress4:    querierAddr,
		HardwareAddress:   querierMAC,
		MTU:               MTU,
		MaxActiveUDPPorts: 1,
		AcceptMulticast:   true,
	})
	if err != nil {
		t.Fatal("querier reset:", err)
	}
	querierStack.SetGatewayHardwareAddr(responderMAC)

	var querierClient mdns.Client
	err = querierClient.Configure(mdns.ClientConfig{
		LocalPort:     mdns.Port,
		MulticastAddr: mcastAddr[:],
	})
	if err != nil {
		t.Fatal("querier configure:", err)
	}
	err = querierClient.StartResolve(mdns.ResolveConfig{
		Questions: []dns.Question{{
			Name:  svcType,
			Type:  dns.TypePTR,
			Class: dns.ClassINET,
		}},
		MaxResponseAnswers: 4,
	})
	if err != nil {
		t.Fatal("start resolve:", err)
	}
	err = querierStack.RegisterUDP4(&querierClient, mcastAddr, mdns.Port)
	if err != nil {
		t.Fatal("querier register:", err)
	}

	const carrierDataSize = MTU + ethernet.MaxOverheadSize
	var buf [carrierDataSize]byte

	// Querier encapsulates query through full stack (Ethernet+IP+UDP+mDNS).
	n, err := querierStack.EgressEthernet(buf[:])
	if err != nil || n == 0 {
		t.Fatal("querier encapsulate:", err, n)
	}

	// Verify mDNS query wire format at DNS layer.
	const ethHdrLen = 14
	ipIHL := int(buf[ethHdrLen]&0x0f) * 4
	dnsStart := ethHdrLen + ipIHL + 8
	dnsFrame, err := dns.NewFrame(buf[dnsStart:n])
	if err != nil {
		t.Fatal("parse query dns frame:", err)
	}
	if dnsFrame.TxID() != 0 {
		t.Errorf("mDNS query txid=%d, want 0", dnsFrame.TxID())
	}
	if dnsFrame.Flags() != 0 {
		t.Errorf("mDNS query flags=%d, want 0", dnsFrame.Flags())
	}

	// Responder demuxes the query (multicast MAC+IP accepted via AcceptMulticast).
	err = responderStack.IngressEthernet(buf[:n])
	if err != nil {
		t.Fatal("responder demux:", err)
	}

	// Responder encapsulates response.
	n, err = responderStack.EgressEthernet(buf[:])
	if err != nil || n == 0 {
		t.Fatal("responder encapsulate:", err, n)
	}

	// Verify response DNS flags.
	ipIHL = int(buf[ethHdrLen]&0x0f) * 4
	dnsStart = ethHdrLen + ipIHL + 8
	dnsFrame, err = dns.NewFrame(buf[dnsStart:n])
	if err != nil {
		t.Fatal("parse response dns frame:", err)
	}
	flags := dnsFrame.Flags()
	if !flags.IsResponse() {
		t.Error("mDNS response missing QR bit")
	}
	if !flags.IsAuthorativeAnswer() {
		t.Error("mDNS response missing AA bit")
	}
	if dnsFrame.ANCount() == 0 {
		t.Fatal("mDNS response has 0 answers")
	}

	// Querier demuxes response.
	err = querierStack.IngressEthernet(buf[:n])
	if err != nil {
		t.Fatal("querier demux:", err)
	}

	// Read answers.
	var answers [4]dns.Resource
	nans, done, err := querierClient.AnswersCopyTo(answers[:])
	if err != nil {
		t.Fatal("answers:", err)
	}
	if !done {
		t.Fatal("expected done")
	}
	if nans == 0 {
		t.Fatal("got 0 answers")
	}

	// Verify PTR answer points to our service instance name.
	ptrData := answers[0].RawData()
	var ptrTarget dns.Name
	_, err = ptrTarget.Decode(ptrData, 0)
	if err != nil {
		t.Fatal("decode PTR target:", err)
	}
	if !dns.NamesEqual(ptrTarget, svcName) {
		t.Errorf("PTR target=%q, want %q", ptrTarget.String(), svcName.String())
	}
}

func TestMDNS_SRVThroughStack(t *testing.T) {
	const MTU = ethernet.MaxMTU
	svcName := dns.MustNewName("My Web._http._tcp.local")
	hostName := dns.MustNewName("mydevice.local")
	svc := mdns.Service{
		Name: svcName,
		Host: hostName,
		Addr: []byte{192, 168, 1, 50},
		Port: 80,
	}
	mcastAddr := []byte{224, 0, 0, 251}

	responderMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x01}
	querierMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x02}

	// Create responder.
	responderStack, _ := newMDNSStack(t, "responder", 1111,
		netip.AddrFrom4([4]byte{192, 168, 1, 50}), responderMAC, querierMAC,
		mdns.ClientConfig{LocalPort: mdns.Port, Services: []mdns.Service{svc}, MulticastAddr: mcastAddr},
	)

	// Create querier.
	querierStack, querierClient := newMDNSStack(t, "querier", 2222,
		netip.AddrFrom4([4]byte{192, 168, 1, 100}), querierMAC, responderMAC,
		mdns.ClientConfig{LocalPort: mdns.Port, MulticastAddr: mcastAddr},
	)
	err := querierClient.StartResolve(mdns.ResolveConfig{
		Questions: []dns.Question{{
			Name:  svcName,
			Type:  dns.TypeSRV,
			Class: dns.ClassINET,
		}},
		MaxResponseAnswers: 4,
	})
	if err != nil {
		t.Fatal("start resolve:", err)
	}

	// Full round-trip through both stacks.
	var buf [MTU + ethernet.MaxOverheadSize]byte
	mdnsQueryRespond(t, querierStack, responderStack, buf[:])

	var answers [4]dns.Resource
	nans, done, err := querierClient.AnswersCopyTo(answers[:])
	if err != nil || !done {
		t.Fatal("expected done:", err)
	}
	if nans < 2 {
		t.Fatalf("expected at least 2 answers (SRV+A), got %d", nans)
	}

	// Verify SRV port.
	srvData := answers[0].RawData()
	if len(srvData) < 6 {
		t.Fatalf("SRV data too short: %d", len(srvData))
	}
	gotPort := binary.BigEndian.Uint16(srvData[4:6])
	if gotPort != svc.Port {
		t.Errorf("SRV port=%d, want %d", gotPort, svc.Port)
	}

	// Verify A record.
	aData := answers[1].RawData()
	if [4]byte(aData) != [4]byte(svc.Addr) {
		t.Errorf("A record addr=%v, want %v", aData, svc.Addr)
	}
}

// newMDNSStack creates a StackAsync with an mDNS client registered on its UDP ports.
func newMDNSStack(t *testing.T, hostname string, seed int64,
	addr netip.Addr, mac, gatewayMAC [6]byte,
	mdnsCfg mdns.ClientConfig,
) (*StackAsync, *mdns.Client) {
	t.Helper()
	const MTU = ethernet.MaxMTU
	stack := new(StackAsync)
	err := stack.Reset(StackConfig{
		Hostname:          hostname,
		RandSeed:          seed,
		StaticAddress4:    addr.As4(),
		HardwareAddress:   mac,
		MTU:               MTU,
		MaxActiveUDPPorts: 1,
		AcceptMulticast:   true,
	})
	if err != nil {
		t.Fatal(hostname, "reset:", err)
	}
	stack.SetGatewayHardwareAddr(gatewayMAC)

	var client mdns.Client
	err = client.Configure(mdnsCfg)
	if err != nil {
		t.Fatal(hostname, "mdns configure:", err)
	}

	var remote [4]byte
	copy(remote[:], mdnsCfg.MulticastAddr)
	err = stack.RegisterUDP4(&client, remote, mdns.Port)
	if err != nil {
		t.Fatal(hostname, "register udp:", err)
	}
	return stack, &client
}

// mdnsQueryRespond performs a full Ethernet+IP+UDP+mDNS query→response cycle
// between two stacks with AcceptMulticast enabled.
func mdnsQueryRespond(t *testing.T, querier, responder *StackAsync, buf []byte) {
	t.Helper()

	// Querier encapsulates query.
	n, err := querier.EgressEthernet(buf)
	if err != nil || n == 0 {
		t.Fatal("querier encapsulate:", err, n)
	}

	// Responder demuxes multicast query directly.
	err = responder.IngressEthernet(buf[:n])
	if err != nil {
		t.Fatal("responder demux:", err)
	}

	// Responder encapsulates response.
	n, err = responder.EgressEthernet(buf)
	if err != nil || n == 0 {
		t.Fatal("responder encapsulate:", err, n)
	}

	// Querier demuxes multicast response.
	err = querier.IngressEthernet(buf[:n])
	if err != nil {
		t.Fatal("querier demux:", err)
	}
}

func TestMDNS_RealWorldQueries(t *testing.T) {
	const MTU = ethernet.MaxMTU

	responderMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}
	querierMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02}

	responderIP := netip.AddrFrom4([4]byte{192, 168, 50, 81})
	querierIP := netip.AddrFrom4([4]byte{192, 168, 50, 213})

	mcastAddr := mdns.IPv4MulticastAddr()

	// Service hosted by responder.
	hostName := dns.MustNewName("server.local")
	svc := mdns.Service{
		Name: hostName,
		Host: hostName,
		Addr: []byte{192, 168, 50, 81},
		Port: 80,
	}

	responderStack, _ := newMDNSStack(t, "responder", 1,
		responderIP, responderMAC, querierMAC,
		mdns.ClientConfig{
			LocalPort:     mdns.Port,
			Services:      []mdns.Service{svc},
			MulticastAddr: mcastAddr[:],
		},
	)

	pkts := []struct {
		name    string
		qname   string
		qtype   dns.Type
		unicast bool // QU bit
	}{
		// Frame 1: QM multicast A server.local
		{"QM_A_server", "server.local", dns.TypeA, false},

		// Frame 2: QU unicast AAAA random.local
		{"QU_AAAA_random", "rds-th-TH010-e6614864d3511735.local", dns.TypeAAAA, true},

		// Frame 3: QU unicast A random.local
		{"QU_A_random", "rds-th-TH010-e6614864d3511735.local", dns.TypeA, true},
	}

	var buf [MTU + ethernet.MaxOverheadSize]byte
	checkNoData := func(msg string) {
		t.Helper()
		n, err := responderStack.EgressEthernet(buf[:])
		if err != nil {
			t.Fatal(err)
		} else if n != 0 {
			t.Errorf(" %s: expected no data sent: %d", msg, n)
		}
	}
	checkNoData("before transaction")
	var msg dns.Message
	for _, q := range pkts {
		msg.Reset()
		msg.AddQuestions([]dns.Question{
			{
				Name:  dns.MustNewName(q.qname),
				Type:  q.qtype,
				Class: withQU(q.unicast),
			},
		})
		efrm, _ := ethernet.NewFrame(buf[:])
		*efrm.DestinationHardwareAddr(), _ = ethernet.MulticastAddrFrom4(mdns.IPv4MulticastAddr())
		*efrm.SourceHardwareAddr() = querierMAC
		efrm.SetEtherType(ethernet.TypeIPv4)

		ifrm, _ := ipv4.NewFrame(efrm.Payload())
		ifrm.SetVersionAndIHL(4, 5) // No options. IHL=5, IPLEN=4*IHL=20
		ifrm.SetToS(ipv4.NewToS(0, 0))
		ifrm.SetTotalLength(20 + 8 + msg.Len())
		ifrm.SetID(1337)
		ifrm.SetFlags(ipv4.FlagDontFragment)
		ifrm.SetTTL(64)
		ifrm.SetProtocol(lneto.IPProtoUDP)

		*ifrm.SourceAddr() = querierIP.As4()
		*ifrm.DestinationAddr() = mdns.IPv4MulticastAddr()

		ifrm.SetCRC(0) // Zero CRC before calculating CRC, as custom with lneto.
		ifrm.SetCRC(ifrm.CalculateHeaderCRC())

		ufrm, _ := udp.NewFrame(ifrm.Payload())
		ufrm.SetSourcePort(mdns.Port)
		ufrm.SetDestinationPort(mdns.Port)
		ufrm.SetLength(8 + msg.Len())

		mdnsPayload, _ := msg.AppendTo(ufrm.Payload()[:0], 0, 0)
		if len(mdnsPayload) != int(msg.Len()) {
			t.Fatal("unreachable")
		}
		var crc lneto.CRC791
		ufrm.SetCRC(0)
		ifrm.CRCWriteUDPPseudo(&crc, ufrm.Length())
		got := crc.PayloadSum16(ifrm.Payload())
		ufrm.SetCRC(got)
		err := responderStack.IngressEthernet(buf[:14+20+8+msg.Len()])
		if err != nil {
			t.Fatal(err)
		}
	}
	n, err := responderStack.EgressEthernet(buf[:])
	if err != nil {
		t.Fatal(err)
	} else if n < 14+20+8+dns.SizeHeader {
		t.Error("expected response", n)
	}
	n, err = responderStack.EgressEthernet(buf[:])
	if err != nil {
		t.Fatal(err)
	} else if n != 0 {
		t.Error("expected single response")
	}
}

func withQU(unicast bool) dns.Class {
	if !unicast {
		return dns.ClassINET
	}
	return dns.ClassINET | (1 << 15) // QU bit
}

// TestMDNS_QDCountAlloc checks an incoming mDNS query with an attacker controlled
// QDCOUNT does not cause a heap allocation sized by QDCOUNT.
func TestMDNS_QDCountAlloc(t *testing.T) {
	const MTU = ethernet.MaxMTU
	svcName := dns.MustNewName("My Web._http._tcp.local")
	svc := mdns.Service{
		Name: svcName,
		Host: dns.MustNewName("mydevice.local"),
		Addr: []byte{192, 168, 1, 50},
		Port: 80,
	}
	mcastAddr := []byte{224, 0, 0, 251}
	responderMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x01}
	querierMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x02}
	responderStack, _ := newMDNSStack(t, "responder", 1111,
		netip.AddrFrom4([4]byte{192, 168, 1, 50}), responderMAC, querierMAC,
		mdns.ClientConfig{LocalPort: mdns.Port, Services: []mdns.Service{svc}, MulticastAddr: mcastAddr},
	)
	querierStack, querierClient := newMDNSStack(t, "querier", 2222,
		netip.AddrFrom4([4]byte{192, 168, 1, 66}), querierMAC, responderMAC,
		mdns.ClientConfig{LocalPort: mdns.Port, MulticastAddr: mcastAddr},
	)
	err := querierClient.StartResolve(mdns.ResolveConfig{
		Questions:          []dns.Question{{Name: svcName, Type: dns.TypeSRV, Class: dns.ClassINET}},
		MaxResponseAnswers: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	var buf [MTU + ethernet.MaxOverheadSize]byte
	n, err := querierStack.EgressEthernet(buf[:])
	if err != nil || n == 0 {
		t.Fatal("querier encapsulate:", err, n)
	}
	pkt := buf[:n]
	ifrm, err := ipv4.NewFrame(pkt[14:])
	if err != nil {
		t.Fatal(err)
	}
	ufrm, err := udp.NewFrame(ifrm.Payload())
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(ufrm.Payload()[4:], 0xffff) // QDCOUNT, only 1 question present.
	var crc lneto.CRC791
	ifrm.CRCWriteUDPPseudo(&crc, ufrm.Length())
	ufrm.SetCRC(0)
	ufrm.SetCRC(lneto.NeverZeroSum(crc.PayloadSum16(ifrm.Payload())))
	allocs := testing.AllocsPerRun(10, func() {
		responderStack.IngressEthernet(pkt) // Error irrelevant, must not allocate.
	})
	if allocs > 0 {
		t.Errorf("mDNS query with QDCOUNT=0xffff allocated %v times per packet", allocs)
	}
}

const (
	testUDPBufSize   = 2048
	testUDPQueueSize = 4
)

// newUDPTestPair creates a server/client StackAsync pair for UDP tests with
// static addresses and each stack's gateway pointing at the peer.
func newUDPTestPair(t testing.TB, seed int64) (s1, s2 *StackAsync) {
	t.Helper()
	s1, s2 = new(StackAsync), new(StackAsync)
	if err := s1.Reset(StackConfig{
		Hostname:          "UDP-1",
		RandSeed:          seed,
		StaticAddress4:    [4]byte{10, 1, 0, 1},
		HardwareAddress:   [6]byte{0xaa, 0xbb, 0, 0, 0, 1},
		MTU:               ethernet.MaxMTU,
		MaxActiveUDPPorts: 4,
	}); err != nil {
		t.Fatal("sv Reset:", err)
	}
	if err := s2.Reset(StackConfig{
		Hostname:          "UDP-2",
		RandSeed:          ^seed,
		StaticAddress4:    [4]byte{10, 1, 0, 2},
		HardwareAddress:   [6]byte{0xaa, 0xbb, 0, 0, 0, 2},
		MTU:               ethernet.MaxMTU,
		MaxActiveUDPPorts: 4,
	}); err != nil {
		t.Fatal("cl Reset:", err)
	}
	s1.SetGatewayHardwareAddr(s2.HardwareAddr())
	s2.SetGatewayHardwareAddr(s1.HardwareAddr())
	return s1, s2
}

// TestStackAsyncRegisterListenerUDP_ReceiveData registers a udp.PacketConn as
// a listener and verifies that a datagram from a dialed client is delivered
// with the correct payload and sender address.
func TestStackAsyncRegisterListenerUDP_ReceiveData(t *testing.T) {
	const (
		svPort = 9000
		clPort = 9001
	)
	sv, cl := newUDPTestPair(t, 1234)
	buf := make([]byte, ethernet.MaxMTU+ethernet.MaxOverheadSize)

	var pc udp.PacketConn
	if err := pc.Configure(udp.PacketConnConfig{
		RxBuf: make([]byte, testUDPBufSize), TxBuf: make([]byte, testUDPBufSize),
		RxQueueSize: testUDPQueueSize, TxQueueSize: testUDPQueueSize,
		RWBackoff: backoffYield,
	}); err != nil {
		t.Fatal("pc Configure:", err)
	}
	if err := pc.Open(netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)); err != nil {
		t.Fatal("pc.Open:", err)
	}
	if err := sv.RegisterListenerUDP(&pc); err != nil {
		t.Fatal("RegisterListenerUDP:", err)
	}

	var conn udp.Conn
	if err := conn.Configure(udp.ConnConfig{
		RxBuf: make([]byte, testUDPBufSize), TxBuf: make([]byte, testUDPBufSize),
		RxQueueSize: testUDPQueueSize, TxQueueSize: testUDPQueueSize,
		RWBackoff: backoffYield,
		MTU:       uint16(sv.MTU()),
	}); err != nil {
		t.Fatal("conn Configure:", err)
	}
	if err := cl.DialUDP4(&conn, clPort, sv.Addr4(), svPort); err != nil {
		t.Fatal("DialUDP4:", err)
	}

	want := []byte("hello listener")
	if _, err := conn.Write(want); err != nil {
		t.Fatal("Write:", err)
	}
	if exchangeEthernetOnce(t, cl, sv, buf) == 0 {
		t.Fatal("no packet sent by client")
	}

	pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var rbuf [testUDPBufSize]byte
	n, senderAddr, err := pc.ReadFrom(rbuf[:])
	if err != nil {
		t.Fatal("ReadFrom:", err)
	}
	if !bytes.Equal(rbuf[:n], want) {
		t.Errorf("data: got %q, want %q", rbuf[:n], want)
	}
	wantSender := netip.AddrPortFrom(netip.AddrFrom4(cl.Addr4()), clPort)
	if senderAddr != wantSender {
		t.Errorf("sender addr: got %v, want %v", senderAddr, wantSender)
	}
}

// TestStackAsyncRegisterListenerUDP_ReplyToClient registers a PacketConn, receives
// a datagram, then calls WriteTo to send a reply back to the sender and verifies
// the client's udp.Conn reads it.
func TestStackAsyncRegisterListenerUDP_ReplyToClient(t *testing.T) {
	const (
		svPort = 9002
		clPort = 9003
	)
	sv, cl := newUDPTestPair(t, 5678)
	buf := make([]byte, ethernet.MaxMTU+ethernet.MaxOverheadSize)

	var pc udp.PacketConn
	if err := pc.Configure(udp.PacketConnConfig{
		RxBuf: make([]byte, testUDPBufSize), TxBuf: make([]byte, testUDPBufSize),
		RxQueueSize: testUDPQueueSize, TxQueueSize: testUDPQueueSize,
		RWBackoff: backoffYield,
	}); err != nil {
		t.Fatal("pc Configure:", err)
	}
	if err := pc.Open(netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)); err != nil {
		t.Fatal("pc.Open:", err)
	}
	if err := sv.RegisterListenerUDP(&pc); err != nil {
		t.Fatal("RegisterListenerUDP:", err)
	}

	var conn udp.Conn
	if err := conn.Configure(udp.ConnConfig{
		RxBuf: make([]byte, testUDPBufSize), TxBuf: make([]byte, testUDPBufSize),
		RxQueueSize: testUDPQueueSize, TxQueueSize: testUDPQueueSize,
		RWBackoff: backoffYield,
		MTU:       uint16(sv.MTU()),
	}); err != nil {
		t.Fatal("conn Configure:", err)
	}
	if err := cl.DialUDP4(&conn, clPort, sv.Addr4(), svPort); err != nil {
		t.Fatal("DialUDP4:", err)
	}

	// Client → Server
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal("Write:", err)
	}
	exchangeEthernetOnce(t, cl, sv, buf)

	pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var rbuf [testUDPBufSize]byte
	_, senderAddr, err := pc.ReadFrom(rbuf[:])
	if err != nil {
		t.Fatal("ReadFrom:", err)
	}

	// Server → Client
	reply := []byte("pong")
	pc.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := pc.WriteTo(reply, senderAddr); err != nil {
		t.Fatal("WriteTo:", err)
	}
	if exchangeEthernetOnce(t, sv, cl, buf) == 0 {
		t.Fatal("no reply packet from server")
	}

	var rbuf2 [testUDPBufSize]byte
	n, err := conn.Read(rbuf2[:])
	if err != nil {
		t.Fatal("conn.Read:", err)
	}
	if !bytes.Equal(rbuf2[:n], reply) {
		t.Errorf("reply data: got %q, want %q", rbuf2[:n], reply)
	}
}

// TestStackAsyncRegisterListenerUDP_MultiSource verifies that a single PacketConn
// registered via RegisterListenerUDP (no MAC filter) receives datagrams from two
// distinct clients and ReadFrom returns the correct sender address for each.
func TestStackAsyncRegisterListenerUDP_MultiSource(t *testing.T) {
	const (
		svPort = 9004
		clPort = 9005
	)
	buf := make([]byte, ethernet.MaxMTU+ethernet.MaxOverheadSize)

	sv := new(StackAsync)
	if err := sv.Reset(StackConfig{
		Hostname:          "UDPSvMS",
		RandSeed:          999,
		StaticAddress4:    [4]byte{10, 1, 0, 1},
		HardwareAddress:   [6]byte{0xaa, 0xbb, 0, 0, 0, 1},
		MTU:               ethernet.MaxMTU,
		MaxActiveUDPPorts: 1,
	}); err != nil {
		t.Fatal("sv Reset:", err)
	}

	cl1 := new(StackAsync)
	cl1Addr := [4]byte{10, 1, 0, 2}
	if err := cl1.Reset(StackConfig{
		Hostname:          "UDPCl1",
		RandSeed:          111,
		StaticAddress4:    cl1Addr,
		HardwareAddress:   [6]byte{0xaa, 0xbb, 0, 0, 0, 2},
		MTU:               ethernet.MaxMTU,
		MaxActiveUDPPorts: 1,
	}); err != nil {
		t.Fatal("cl1 Reset:", err)
	}

	cl2 := new(StackAsync)
	cl2Addr := [4]byte{10, 1, 0, 3}
	if err := cl2.Reset(StackConfig{
		Hostname:          "UDPCl2",
		RandSeed:          222,
		StaticAddress4:    cl2Addr,
		HardwareAddress:   [6]byte{0xaa, 0xbb, 0, 0, 0, 3},
		MTU:               ethernet.MaxMTU,
		MaxActiveUDPPorts: 1,
	}); err != nil {
		t.Fatal("cl2 Reset:", err)
	}

	cl1.SetGatewayHardwareAddr(sv.HardwareAddr())
	cl2.SetGatewayHardwareAddr(sv.HardwareAddr())

	var pc udp.PacketConn
	if err := pc.Configure(udp.PacketConnConfig{
		RxBuf: make([]byte, testUDPBufSize), TxBuf: make([]byte, testUDPBufSize),
		RxQueueSize: testUDPQueueSize, TxQueueSize: testUDPQueueSize,
		RWBackoff: backoffYield,
	}); err != nil {
		t.Fatal("pc Configure:", err)
	}
	if err := pc.Open(netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)); err != nil {
		t.Fatal("pc.Open:", err)
	}
	if err := sv.RegisterListenerUDP(&pc); err != nil {
		t.Fatal("RegisterListenerUDP:", err)
	}

	// Client 1 dials and sends.
	var conn1 udp.Conn
	if err := conn1.Configure(udp.ConnConfig{
		RxBuf: make([]byte, testUDPBufSize), TxBuf: make([]byte, testUDPBufSize),
		RxQueueSize: testUDPQueueSize, TxQueueSize: testUDPQueueSize,
		RWBackoff: backoffYield,
		MTU:       uint16(sv.MTU()),
	}); err != nil {
		t.Fatal("conn1 Configure:", err)
	}
	if err := cl1.DialUDP4(&conn1, clPort, sv.Addr4(), svPort); err != nil {
		t.Fatal("cl1 DialUDP4:", err)
	}
	msg1 := []byte("from-client-1")
	if _, err := conn1.Write(msg1); err != nil {
		t.Fatal("conn1 Write:", err)
	}
	exchangeEthernetOnce(t, cl1, sv, buf)

	// Client 2 dials and sends.
	var conn2 udp.Conn
	if err := conn2.Configure(udp.ConnConfig{
		RxBuf: make([]byte, testUDPBufSize), TxBuf: make([]byte, testUDPBufSize),
		RxQueueSize: testUDPQueueSize, TxQueueSize: testUDPQueueSize,
		RWBackoff: backoffYield,
		MTU:       uint16(sv.MTU()),
	}); err != nil {
		t.Fatal("conn2 Configure:", err)
	}
	if err := cl2.DialUDP4(&conn2, clPort, sv.Addr4(), svPort); err != nil {
		t.Fatal("cl2 DialUDP4:", err)
	}
	msg2 := []byte("from-client-2")
	if _, err := conn2.Write(msg2); err != nil {
		t.Fatal("conn2 Write:", err)
	}
	exchangeEthernetOnce(t, cl2, sv, buf)

	// Server reads both datagrams.
	pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	type recv struct {
		data []byte
		from netip.AddrPort
	}
	var got [2]recv
	var rbuf [testUDPBufSize]byte
	for i := range 2 {
		n, addr, err := pc.ReadFrom(rbuf[:])
		if err != nil {
			t.Fatalf("ReadFrom[%d]: %v", i, err)
		}
		got[i] = recv{data: bytes.Clone(rbuf[:n]), from: addr}
	}

	wantFrom1 := netip.AddrPortFrom(netip.AddrFrom4(cl1Addr), clPort)
	wantFrom2 := netip.AddrPortFrom(netip.AddrFrom4(cl2Addr), clPort)

	// Datagrams may arrive in either order.
	if got[0].from == wantFrom1 {
		if !bytes.Equal(got[0].data, msg1) {
			t.Errorf("[0] data: got %q, want %q", got[0].data, msg1)
		}
		if got[1].from != wantFrom2 || !bytes.Equal(got[1].data, msg2) {
			t.Errorf("[1]: got addr=%v data=%q, want addr=%v data=%q", got[1].from, got[1].data, wantFrom2, msg2)
		}
	} else {
		if got[0].from != wantFrom2 || !bytes.Equal(got[0].data, msg2) {
			t.Errorf("[0]: got addr=%v data=%q, want addr=%v data=%q", got[0].from, got[0].data, wantFrom2, msg2)
		}
		if got[1].from != wantFrom1 || !bytes.Equal(got[1].data, msg1) {
			t.Errorf("[1]: got addr=%v data=%q, want addr=%v data=%q", got[1].from, got[1].data, wantFrom1, msg1)
		}
	}
}
