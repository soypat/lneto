package internet

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/soypat/lneto/tcp"
)

func TestNodeTCPListener_SingleConnection(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var clientStack, serverStack StackIP
	var clientConn, serverConn tcp.Conn
	var listener NodeTCPListener
	pool := newMockTCPPool(1, 3, 2048)

	// Use existing setup but replace server's conn registration with listener.
	setupClientServer(t, rng, &clientStack, &serverStack, &clientConn, &serverConn)
	serverConn.Abort()
	serverPort := uint16(80)
	if err := listener.Reset(serverPort, pool); err != nil {
		t.Fatal(err)
	}
	if err := serverStack.Register(&listener); err != nil {
		t.Fatal(err)
	}

	var buf [2048]byte

	// Client sends SYN, server receives via listener.
	expectExchange(t, &clientStack, &serverStack, buf[:])
	if listener.NumberOfReadyToAccept() != 1 {
		t.Fatalf("expected 1 ready, got %d", listener.NumberOfReadyToAccept())
	}
	acceptedConn, err := listener.TryAccept()
	if err != nil {
		t.Fatalf("TryAccept: %v", err)
	}
	if listener.NumberOfReadyToAccept() != 0 {
		t.Fatalf("expected 0 ready, got %d", listener.NumberOfReadyToAccept())
	}

	// Complete handshake (SYN already sent/received).
	testEstablishAfterSYN(t, &clientStack, &serverStack, &clientConn, acceptedConn)
}

func TestNodeTCPListener_AcceptAfterEstablished(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var client1Stack, serverStack StackIP
	var client1Conn, serverConn tcp.Conn
	var listener NodeTCPListener
	pool := newMockTCPPool(2, 3, 2048)

	// Setup server with listener.
	setupClientServer(t, rng, &client1Stack, &serverStack, &client1Conn, &serverConn)
	serverConn.Abort()
	serverPort := uint16(80)
	if err := listener.Reset(serverPort, pool); err != nil {
		t.Fatal(err)
	}
	if err := serverStack.Register(&listener); err != nil {
		t.Fatal(err)
	}

	var buf [2048]byte

	// Client1 sends SYN.
	expectExchange(t, &client1Stack, &serverStack, buf[:])
	accepted1, err := listener.TryAccept()
	if err != nil {
		t.Fatalf("TryAccept client1: %v", err)
	}

	// Complete handshake for client1 (SYN already sent/received).
	testEstablishAfterSYN(t, &client1Stack, &serverStack, &client1Conn, accepted1)

	// Setup second client and verify we can still accept.
	var client2Stack StackIP
	var client2Conn tcp.Conn
	setupClient(t, &client2Stack, &client2Conn, serverStack.Addr(), serverPort, 1338)

	// Client2 sends SYN.
	expectExchange(t, &client2Stack, &serverStack, buf[:])
	if listener.NumberOfReadyToAccept() != 1 {
		t.Fatalf("after client2 SYN: expected 1 ready, got %d", listener.NumberOfReadyToAccept())
	}

	accepted2, err := listener.TryAccept()
	if err != nil {
		t.Fatalf("TryAccept client2: %v", err)
	}

	// Complete handshake for client2 (SYN already sent/received).
	testEstablishAfterSYN(t, &client2Stack, &serverStack, &client2Conn, accepted2)
}

func TestNodeTCPListener_MultiConn(t *testing.T) {
	const numClients = 5
	rng := rand.New(rand.NewSource(1))
	var serverStack StackIP
	var serverConn tcp.Conn
	var listener NodeTCPListener
	pool := newMockTCPPool(numClients, 3, 2048)

	// Create slices for clients.
	clientStacks := make([]StackIP, numClients)
	clientConns := make([]tcp.Conn, numClients)
	acceptedConns := make([]*tcp.Conn, numClients)

	// Setup server with listener using setupClientServer for first client to get server configured.
	setupClientServer(t, rng, &clientStacks[0], &serverStack, &clientConns[0], &serverConn)
	serverConn.Abort()
	serverPort := uint16(80)
	if err := listener.Reset(serverPort, pool); err != nil {
		t.Fatal(err)
	}
	if err := serverStack.Register(&listener); err != nil {
		t.Fatal(err)
	}

	// Setup remaining clients.
	for i := 1; i < numClients; i++ {
		clientPort := uint16(1337 + i)
		setupClient(t, &clientStacks[i], &clientConns[i], serverStack.Addr(), serverPort, clientPort)
	}

	var buf [2048]byte

	// All clients send SYN.
	for i := 0; i < numClients; i++ {
		expectExchange(t, &clientStacks[i], &serverStack, buf[:])
	}
	if listener.NumberOfReadyToAccept() != numClients {
		t.Fatalf("after all SYNs: expected %d ready, got %d", numClients, listener.NumberOfReadyToAccept())
	}
	if pool.NumberOfAcquired() != numClients {
		t.Fatalf("pool should have %d acquired, got %d", numClients, pool.NumberOfAcquired())
	}

	// Accept all connections.
	for i := 0; i < numClients; i++ {
		var err error
		acceptedConns[i], err = listener.TryAccept()
		if err != nil {
			t.Fatalf("TryAccept client %d: %v", i, err)
		}
	}
	if listener.NumberOfReadyToAccept() != 0 {
		t.Fatalf("after all accepts: expected 0 ready, got %d", listener.NumberOfReadyToAccept())
	}

	// Complete handshakes for all clients.
	for i := 0; i < numClients; i++ {
		testEstablishAfterSYN(t, &clientStacks[i], &serverStack, &clientConns[i], acceptedConns[i])
	}

	// Verify all connections established.
	for i := 0; i < numClients; i++ {
		if clientConns[i].State() != tcp.StateEstablished {
			t.Errorf("client %d: expected StateEstablished, got %s", i, clientConns[i].State())
		}
		if acceptedConns[i].State() != tcp.StateEstablished {
			t.Errorf("accepted %d: expected StateEstablished, got %s", i, acceptedConns[i].State())
		}
	}

	// Test data exchange: client -> server.
	for i := 0; i < numClients; i++ {
		msg := []byte("hello from client " + string('0'+byte(i)))
		n, err := clientConns[i].Write(msg)
		if err != nil {
			t.Fatalf("client %d write: %v", i, err)
		}
		if n != len(msg) {
			t.Fatalf("client %d write: wrote %d, expected %d", i, n, len(msg))
		}
	}

	// Exchange data packets from all clients to server.
	for i := 0; i < numClients; i++ {
		expectExchange(t, &clientStacks[i], &serverStack, buf[:])
	}

	// Read data on server side and verify.
	for i := 0; i < numClients; i++ {
		expected := "hello from client " + string('0'+byte(i))
		var readBuf [64]byte
		n, err := acceptedConns[i].Read(readBuf[:])
		if err != nil {
			t.Fatalf("server read %d: %v", i, err)
		}
		if string(readBuf[:n]) != expected {
			t.Errorf("server read %d: got %q, expected %q", i, string(readBuf[:n]), expected)
		}
	}

	// Test data exchange: server -> client.
	for i := 0; i < numClients; i++ {
		msg := []byte("reply to client " + string('0'+byte(i)))
		n, err := acceptedConns[i].Write(msg)
		if err != nil {
			t.Fatalf("server %d write: %v", i, err)
		}
		if n != len(msg) {
			t.Fatalf("server %d write: wrote %d, expected %d", i, n, len(msg))
		}
	}

	// Exchange data packets from server to all clients.
	for i := 0; i < numClients; i++ {
		expectExchange(t, &serverStack, &clientStacks[i], buf[:])
	}

	// Read responses on client side and verify.
	for i := 0; i < numClients; i++ {
		expected := "reply to client " + string('0'+byte(i))
		var readBuf [64]byte
		n, err := clientConns[i].Read(readBuf[:])
		if err != nil {
			t.Fatalf("client read %d: %v", i, err)
		}
		if string(readBuf[:n]) != expected {
			t.Errorf("client read %d: got %q, expected %q", i, string(readBuf[:n]), expected)
		}
	}

	// Close connections, alternating between client-initiated and server-initiated.
	for i := 0; i < numClients; i++ {
		var initiator, responder *StackIP
		var initiatorConn, responderConn *tcp.Conn
		if i%2 == 0 {
			// Client initiates close.
			initiator, responder = &clientStacks[i], &serverStack
			initiatorConn, responderConn = &clientConns[i], acceptedConns[i]
		} else {
			// Server initiates close.
			initiator, responder = &serverStack, &clientStacks[i]
			initiatorConn, responderConn = acceptedConns[i], &clientConns[i]
		}

		// Initiator sends FIN.
		if err := initiatorConn.Close(); err != nil {
			t.Fatalf("conn %d close: %v", i, err)
		}
		expectExchange(t, initiator, responder, buf[:]) // FIN
		if initiatorConn.State() != tcp.StateFinWait1 {
			t.Errorf("conn %d initiator: expected StateFinWait1, got %s", i, initiatorConn.State())
		}
		if responderConn.State() != tcp.StateCloseWait {
			t.Errorf("conn %d responder: expected StateCloseWait, got %s", i, responderConn.State())
		}

		// Responder sends ACK (may be combined with FIN if responder also closes).
		expectExchange(t, responder, initiator, buf[:]) // ACK
		if initiatorConn.State() != tcp.StateFinWait2 {
			t.Errorf("conn %d initiator: expected StateFinWait2, got %s", i, initiatorConn.State())
		}

		// Responder closes and sends FIN.
		if err := responderConn.Close(); err != nil {
			t.Fatalf("conn %d responder close: %v", i, err)
		}
		expectExchange(t, responder, initiator, buf[:]) // FIN
		if responderConn.State() != tcp.StateLastAck {
			t.Errorf("conn %d responder: expected StateLastAck, got %s", i, responderConn.State())
		}
		if initiatorConn.State() != tcp.StateTimeWait {
			t.Errorf("conn %d initiator: expected StateTimeWait, got %s", i, initiatorConn.State())
		}

		// Initiator sends final ACK.
		expectExchange(t, initiator, responder, buf[:]) // ACK
		if responderConn.State() != tcp.StateClosed {
			t.Errorf("conn %d responder: expected StateClosed, got %s", i, responderConn.State())
		}
	}
}

func setupClient(t *testing.T, client *StackIP, conn *tcp.Conn, serverAddr netip.Addr, serverPort, clientPort uint16) {
	t.Helper()
	bufsize := 2048
	clientIP := netip.AddrFrom4([4]byte{192, 168, 1, byte(clientPort % 256)})
	client.Reset(clientIP, 1)
	err := conn.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, bufsize),
		TxBuf:             make([]byte, bufsize),
		TxPacketQueueSize: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverAddrPort := netip.AddrPortFrom(serverAddr, serverPort)
	err = conn.OpenActive(clientPort, serverAddrPort, 100)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Register(conn)
	if err != nil {
		t.Fatal(err)
	}
}

// testEstablishAfterSYN completes the TCP handshake after SYN has already been sent and received.
// Use this when testing listeners where the SYN was already processed.
func testEstablishAfterSYN(t *testing.T, client, server *StackIP, connClient, connServer *tcp.Conn) {
	t.Helper()
	var buf [2048]byte
	// Server sends SYN-ACK.
	expectExchange(t, server, client, buf[:])
	if connClient.State() != tcp.StateEstablished {
		t.Errorf("after SYN-ACK: want client StateEstablished, got %s", connClient.State())
	}
	if connServer.State() != tcp.StateSynRcvd {
		t.Errorf("after SYN-ACK: want server StateSynRcvd, got %s", connServer.State())
	}
	// Client sends ACK.
	expectExchange(t, client, server, buf[:])
	if connClient.State() != tcp.StateEstablished {
		t.Errorf("after ACK: want client StateEstablished, got %s", connClient.State())
	}
	if connServer.State() != tcp.StateEstablished {
		t.Errorf("after ACK: want server StateEstablished, got %s", connServer.State())
	}
	if t.Failed() {
		t.FailNow()
	}
}

// mockTCPPool implements tcpPool for testing.
type mockTCPPool struct {
	naqcuired int
	conns     []tcp.Conn
	acquired  []bool
	nextISS   tcp.Value
}

func newMockTCPPool(n, queuesize, bufsize int) *mockTCPPool {
	pool := &mockTCPPool{
		acquired: make([]bool, n),
		conns:    make([]tcp.Conn, n),
	}
	for i := range pool.conns {
		err := pool.conns[i].Configure(tcp.ConnConfig{
			RxBuf:             make([]byte, bufsize),
			TxBuf:             make([]byte, bufsize),
			TxPacketQueueSize: queuesize,
		})
		if err != nil {
			panic(err)
		}
	}
	return pool
}

func (p *mockTCPPool) GetTCP() (*tcp.Conn, tcp.Value) {
	for i := range p.conns {
		if !p.acquired[i] {
			p.acquired[i] = true
			p.nextISS += 1000
			p.naqcuired++
			return &p.conns[i], p.nextISS
		}
	}
	return nil, 0
}

func (p *mockTCPPool) PutTCP(conn *tcp.Conn) {
	for i := range p.conns {
		if &p.conns[i] == conn {
			p.conns[i].Abort()
			p.acquired[i] = false
			p.naqcuired--
			return
		}
	}
	panic("conn does not belong to this pool")
}

func (p *mockTCPPool) NumberOfAcquired() int {
	return p.naqcuired
}
