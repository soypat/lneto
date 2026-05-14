package xnet

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/udp"
)

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
