package internet

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/soypat/lneto/tcp"
)

func TestListener_SingleConnection(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var clientStack, serverStack StackIP
	var clientConn, serverConn tcp.Conn
	var listener tcp.Listener

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

	// Complete full handshake before TryAccept (TryAccept only works for ESTABLISHED).
	// Client sends SYN.
	expectExchange(t, &clientStack, &serverStack, buf[:])
	if listener.NumberOfReadyToAccept() != 0 {
		t.Fatalf("after SYN: expected 0 ready (not established yet), got %d", listener.NumberOfReadyToAccept())
	}
	// Server sends SYN-ACK.
	expectExchange(t, &serverStack, &clientStack, buf[:])
	if listener.NumberOfReadyToAccept() != 0 {
		t.Fatalf("after SYN: expected 0 ready (not established yet), got %d", listener.NumberOfReadyToAccept())
	}
	// Client sends ACK.
	expectExchange(t, &clientStack, &serverStack, buf[:])

	// Now connection is ESTABLISHED, TryAccept should work.
	if listener.NumberOfReadyToAccept() != 1 {
		t.Fatalf("after handshake: expected 1 ready, got %d", listener.NumberOfReadyToAccept())
	}
	acceptedConn, err := listener.TryAccept()
	if err != nil {
		t.Fatalf("TryAccept: %v", err)
	}
	if listener.NumberOfReadyToAccept() != 0 {
		t.Fatalf("after accept: expected 0 ready, got %d", listener.NumberOfReadyToAccept())
	}
	if acceptedConn.State() != tcp.StateEstablished {
		t.Fatalf("accepted conn: expected StateEstablished, got %s", acceptedConn.State())
	}
	if clientConn.State() != tcp.StateEstablished {
		t.Fatalf("client conn: expected StateEstablished, got %s", clientConn.State())
	}
}

func TestListener_AcceptAfterEstablished(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var client1Stack, serverStack StackIP
	var client1Conn, serverConn tcp.Conn
	var listener tcp.Listener
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

	// Complete full handshake for client1.
	expectExchange(t, &client1Stack, &serverStack, buf[:]) // SYN
	expectExchange(t, &serverStack, &client1Stack, buf[:]) // SYN-ACK
	expectExchange(t, &client1Stack, &serverStack, buf[:]) // ACK

	// Now TryAccept client1.
	if listener.NumberOfReadyToAccept() != 1 {
		t.Fatalf("after client1 handshake: expected 1 ready, got %d", listener.NumberOfReadyToAccept())
	}
	accepted1, err := listener.TryAccept()
	if err != nil {
		t.Fatalf("TryAccept client1: %v", err)
	} else if listener.NumberOfReadyToAccept() != 0 {
		t.Fatalf("after accepting conn: expected 0 ready, got %d", listener.NumberOfReadyToAccept())
	}
	if accepted1.State() != tcp.StateEstablished {
		t.Fatalf("accepted1: expected StateEstablished, got %s", accepted1.State())
	}

	// Setup second client and verify we can still accept.
	var client2Stack StackIP
	var client2Conn tcp.Conn
	setupClient(t, &client2Stack, &client2Conn, serverStack.Addr(), serverPort, 1338)

	// Complete full handshake for client2.
	expectExchange(t, &client2Stack, &serverStack, buf[:]) // SYN
	expectExchange(t, &serverStack, &client2Stack, buf[:]) // SYN-ACK
	expectExchange(t, &client2Stack, &serverStack, buf[:]) // ACK

	// Now TryAccept client2.
	if listener.NumberOfReadyToAccept() != 1 {
		t.Fatalf("after client2 handshake: expected 1 ready, got %d", listener.NumberOfReadyToAccept())
	}
	accepted2, err := listener.TryAccept()
	if err != nil {
		t.Fatalf("TryAccept client2: %v", err)
	} else if listener.NumberOfReadyToAccept() != 0 {
		t.Fatalf("after client2 accept: expected 0 ready, got %d", listener.NumberOfReadyToAccept())
	}
	if accepted2.State() != tcp.StateEstablished {
		t.Fatalf("accepted2: expected StateEstablished, got %s", accepted2.State())
	}
}

func TestListener_MultiConn(t *testing.T) {
	const numClients = 5
	rng := rand.New(rand.NewSource(1))
	var serverStack StackIP
	var serverConn tcp.Conn
	var listener tcp.Listener
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

	// Complete full handshakes for all clients.
	for i := 0; i < numClients; i++ {
		expectExchange(t, &clientStacks[i], &serverStack, buf[:]) // SYN
		expectExchange(t, &serverStack, &clientStacks[i], buf[:]) // SYN-ACK
		expectExchange(t, &clientStacks[i], &serverStack, buf[:]) // ACK
	}
	if listener.NumberOfReadyToAccept() != numClients {
		t.Fatalf("after all handshakes: expected %d ready, got %d", numClients, listener.NumberOfReadyToAccept())
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
		var closer, responder *StackIP
		var closerConn, responderConn *tcp.Conn
		var serverClosed bool
		whoCloses := "client"
		whoResponds := "server"
		expectStates := func(ctx string, wantCloserState, wantResponderState tcp.State) {
			t.Helper()
			if closerConn.State() != wantCloserState {
				t.Errorf("%s: %s closer want %s, got %s", ctx, whoCloses, wantCloserState, closerConn.State())
			}
			if responderConn.State() != wantResponderState {
				t.Errorf("%s: %s respon want %s, got %s", ctx, whoResponds, wantResponderState, responderConn.State())
			}
		}
		if i%2 == 0 {
			// Client initiates close.
			closer, responder = &clientStacks[i], &serverStack
			closerConn, responderConn = &clientConns[i], acceptedConns[i]
		} else {
			// Server initiates close.
			serverClosed = true
			whoCloses, whoResponds = whoResponds, whoCloses
			closer, responder = &serverStack, &clientStacks[i]
			closerConn, responderConn = acceptedConns[i], &clientConns[i]
		}
		_ = serverClosed // Used for context in debugging.

		// Closer calls Close(), FIN not sent yet.
		if err := closerConn.Close(); err != nil {
			t.Fatalf("conn %d close: %v", i, err)
		}
		expectStates("after-close()", tcp.StateEstablished, tcp.StateEstablished)

		// Closer sends FIN -> responder receives, goes to CLOSE-WAIT.
		expectExchange(t, closer, responder, buf[:])
		expectStates("after-FIN", tcp.StateFinWait1, tcp.StateCloseWait)

		// Responder sends ACK -> closer goes to FIN-WAIT-2.
		expectExchange(t, responder, closer, buf[:])
		expectStates("after-ACK", tcp.StateFinWait2, tcp.StateCloseWait)

		// Responder closes and sends FIN -> closer goes to TIME-WAIT.
		if err := responderConn.Close(); err != nil {
			t.Fatalf("conn %d responder close: %v", i, err)
		}
		expectExchange(t, responder, closer, buf[:])
		expectStates("after-resp-FIN", tcp.StateTimeWait, tcp.StateLastAck)

		// Closer sends final ACK -> responder goes to CLOSED.
		expectExchange(t, closer, responder, buf[:])
		expectStates("after-final-ACK", tcp.StateTimeWait, tcp.StateClosed)
	}
}

// tryExchange attempts an exchange but doesn't fail if no data to send.
func tryExchange(t *testing.T, from, to *StackIP, buf []byte) {
	t.Helper()
	n, err := from.Encapsulate(buf, -1, 0)
	if err != nil || n == 0 {
		return // No data to send.
	}
	_ = to.Demux(buf[:n], 0) // Ignore errors during close.
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
