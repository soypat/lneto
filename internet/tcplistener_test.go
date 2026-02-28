package internet

import (
	"encoding/binary"
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
	acceptedConn, _, err := listener.TryAccept()
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
	accepted1, _, err := listener.TryAccept()
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
	accepted2, _, err := listener.TryAccept()
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
		acceptedConns[i], _, err = listener.TryAccept()
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

func TestListener_RSTOnPoolExhaustion(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var client1Stack, client2Stack, serverStack StackIP
	var client1Conn, client2Conn, serverConn tcp.Conn
	var listener tcp.Listener

	pool := newMockTCPPool(1, 3, 2048) // Pool size 1: will exhaust after first connection.

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

	// Complete full handshake for client1, exhausting the pool.
	expectExchange(t, &client1Stack, &serverStack, buf[:]) // SYN
	expectExchange(t, &serverStack, &client1Stack, buf[:]) // SYN-ACK
	expectExchange(t, &client1Stack, &serverStack, buf[:]) // ACK
	if pool.NumberOfAcquired() != 1 {
		t.Fatalf("pool should have 1 acquired, got %d", pool.NumberOfAcquired())
	}

	// Setup client2 and send its SYN — pool is full, server should queue RST.
	const client2Port = uint16(1338)
	setupClient(t, &client2Stack, &client2Conn, serverStack.Addr(), serverPort, client2Port)

	// Client2 sends SYN.
	n, err := client2Stack.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal("client2 encapsulate:", err)
	} else if n == 0 {
		t.Fatal("client2 produced no SYN")
	}
	// Server receives SYN — pool full, should return ErrPacketDrop but queue RST.
	err = serverStack.Demux(buf[:n], 0)
	if err == nil {
		t.Fatal("expected error from server demux of rejected SYN")
	}

	// Server encapsulates — should produce RST (no connection data pending).
	n, err = serverStack.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal("server encapsulate RST:", err)
	} else if n == 0 {
		t.Fatal("server produced no RST response")
	}

	// Parse the IPv4+TCP frame to verify RST fields.
	// IPv4 header is 20 bytes at offset 0, TCP starts at offset 20.
	tfrm, err := tcp.NewFrame(buf[20:n])
	if err != nil {
		t.Fatal("parse RST frame:", err)
	}
	_, flags := tfrm.OffsetAndFlags()
	wantFlags := tcp.FlagRST | tcp.FlagACK
	if flags != wantFlags {
		t.Errorf("RST flags: got %s, want %s", flags, wantFlags)
	}
	if tfrm.SourcePort() != serverPort {
		t.Errorf("RST source port: got %d, want %d", tfrm.SourcePort(), serverPort)
	}
	if tfrm.DestinationPort() != client2Port {
		t.Errorf("RST dest port: got %d, want %d", tfrm.DestinationPort(), client2Port)
	}
	if tfrm.Seq() != 0 {
		t.Errorf("RST SEQ: got %d, want 0", tfrm.Seq())
	}
	// ACK should be client2's ISS + 1 (SYN occupies 1 sequence number).
	// client2 was opened with ISS=100 (setupClient uses 100).
	gotACK := tfrm.Ack()
	if gotACK != 101 {
		t.Errorf("RST ACK: got %d, want %d (client ISS+1)", gotACK, 101)
	}
}

func TestListener_RSTOnStalePacket(t *testing.T) {
	// Test Scenario C: stale FIN,ACK to a port with a listener but no matching connection.
	// Test at Listener level directly to avoid StackIP CRC validation.
	var listener tcp.Listener
	pool := newMockTCPPool(1, 3, 2048)
	serverPort := uint16(80)
	if err := listener.Reset(serverPort, pool); err != nil {
		t.Fatal(err)
	}

	// Build a raw stale FIN,ACK targeting port 80 from an unknown source.
	// IP header (20 bytes) + TCP header (20 bytes).
	clientIP := [4]byte{10, 0, 0, 1}
	serverIP := [4]byte{10, 0, 0, 2}
	rawBuf := make([]byte, 256)
	rawBuf[0] = 0x45 // version=4, IHL=5
	rawBuf[9] = 6    // protocol=TCP
	copy(rawBuf[12:16], clientIP[:])
	copy(rawBuf[16:20], serverIP[:])
	// TCP header at offset 20.
	binary.BigEndian.PutUint16(rawBuf[20:], 1337)       // src port
	binary.BigEndian.PutUint16(rawBuf[22:], serverPort) // dst port
	binary.BigEndian.PutUint32(rawBuf[24:], 500)        // SEQ
	binary.BigEndian.PutUint32(rawBuf[28:], 200)        // ACK
	rawBuf[32] = 0x50                                   // offset=5
	rawBuf[33] = 0x11                                   // flags = FIN|ACK (0x01|0x10)

	// Demux directly on Listener — no matching connection, should queue RST.
	err := listener.Demux(rawBuf[:40], 20)
	if err == nil {
		t.Fatal("expected error from stale FIN,ACK demux")
	}

	// Encapsulate should produce RST.
	// Pre-fill IP version (StackIP normally does this before calling children).
	var outBuf [256]byte
	outBuf[0] = 0x45
	n, err := listener.Encapsulate(outBuf[:], 0, 20)
	if err != nil {
		t.Fatal("encapsulate RST:", err)
	} else if n == 0 {
		t.Fatal("no RST produced for stale packet")
	}

	tfrm, err := tcp.NewFrame(outBuf[20 : 20+n])
	if err != nil {
		t.Fatal("parse RST frame:", err)
	}
	_, flags := tfrm.OffsetAndFlags()
	if flags != tcp.FlagRST {
		t.Errorf("RST flags: got %s, want [RST]", flags)
	}
	if tfrm.Seq() != 200 {
		t.Errorf("RST SEQ: got %d, want 200 (stale packet's ACK)", tfrm.Seq())
	}
	if tfrm.SourcePort() != serverPort {
		t.Errorf("RST source port: got %d, want %d", tfrm.SourcePort(), serverPort)
	}
	if tfrm.DestinationPort() != 1337 {
		t.Errorf("RST dest port: got %d, want 1337", tfrm.DestinationPort())
	}
}

func TestStackPorts_RSTOnUnknownPort(t *testing.T) {
	// Test Scenario A: SYN to a port with no listener (e.g. HTTPS port 443).
	// Test at StackPorts level directly to avoid StackIP CRC validation.
	var sp StackPorts
	var listener tcp.Listener
	pool := newMockTCPPool(1, 3, 2048)
	if err := sp.ResetTCP(4); err != nil {
		t.Fatal(err)
	}
	if err := listener.Reset(80, pool); err != nil {
		t.Fatal(err)
	}
	if err := sp.Register(&listener); err != nil {
		t.Fatal(err)
	}

	// Build a SYN to port 443 (no listener).
	// StackPorts.Demux expects carrier data starting at IP header with TCP at offset.
	clientIP := [4]byte{10, 0, 0, 1}
	serverIP := [4]byte{10, 0, 0, 2}
	rawBuf := make([]byte, 256)
	rawBuf[0] = 0x45 // version=4, IHL=5
	rawBuf[9] = 6    // protocol=TCP
	copy(rawBuf[12:16], clientIP[:])
	copy(rawBuf[16:20], serverIP[:])
	// TCP header at offset 20.
	binary.BigEndian.PutUint16(rawBuf[20:], 5000) // src port
	binary.BigEndian.PutUint16(rawBuf[22:], 443)  // dst port (no listener!)
	binary.BigEndian.PutUint32(rawBuf[24:], 700)  // SEQ = 700
	binary.BigEndian.PutUint32(rawBuf[28:], 0)    // ACK = 0
	rawBuf[32] = 0x50                             // offset=5
	rawBuf[33] = 0x02                             // flags = SYN

	err := sp.Demux(rawBuf[:40], 20)
	if err == nil {
		t.Fatal("expected error for SYN to unknown port")
	}

	// Pre-fill IP version (StackIP normally does this before calling children).
	var outBuf [256]byte
	outBuf[0] = 0x45
	n, err := sp.Encapsulate(outBuf[:], 0, 20)
	if err != nil {
		t.Fatal("encapsulate RST:", err)
	} else if n == 0 {
		t.Fatal("no RST produced for SYN to unknown port")
	}

	tfrm, err := tcp.NewFrame(outBuf[20 : 20+n])
	if err != nil {
		t.Fatal("parse RST frame:", err)
	}
	_, flags := tfrm.OffsetAndFlags()
	wantFlags := tcp.FlagRST | tcp.FlagACK
	if flags != wantFlags {
		t.Errorf("RST flags: got %s, want %s", flags, wantFlags)
	}
	if tfrm.SourcePort() != 443 {
		t.Errorf("RST source port: got %d, want 443", tfrm.SourcePort())
	}
	if tfrm.DestinationPort() != 5000 {
		t.Errorf("RST dest port: got %d, want 5000", tfrm.DestinationPort())
	}
	if tfrm.Seq() != 0 {
		t.Errorf("RST SEQ: got %d, want 0", tfrm.Seq())
	}
	if tfrm.Ack() != 701 {
		t.Errorf("RST ACK: got %d, want 701 (SEG.SEQ+1)", tfrm.Ack())
	}
}

func TestListener_ECN_SYN(t *testing.T) {
	// Test that Listener.Demux accepts SYN+ECE+CWR (ECN negotiation per RFC 3168).
	// Currently fails: strict flags != FlagSYN check rejects ECN SYNs.
	var listener tcp.Listener
	pool := newMockTCPPool(1, 3, 2048)
	serverPort := uint16(80)
	if err := listener.Reset(serverPort, pool); err != nil {
		t.Fatal(err)
	}

	// Build SYN+ECE+CWR packet targeting port 80.
	clientIP := [4]byte{10, 0, 0, 1}
	serverIP := [4]byte{10, 0, 0, 2}
	rawBuf := make([]byte, 256)
	rawBuf[0] = 0x45 // version=4, IHL=5
	rawBuf[9] = 6    // protocol=TCP
	copy(rawBuf[12:16], clientIP[:])
	copy(rawBuf[16:20], serverIP[:])
	// TCP header at offset 20.
	binary.BigEndian.PutUint16(rawBuf[20:], 5000) // src port
	binary.BigEndian.PutUint16(rawBuf[22:], serverPort)
	binary.BigEndian.PutUint32(rawBuf[24:], 300)               // SEQ
	binary.BigEndian.PutUint32(rawBuf[28:], 0)                 // ACK
	rawBuf[32] = 0x50                                          // offset=5
	rawBuf[33] = byte(tcp.FlagSYN | tcp.FlagECE | tcp.FlagCWR) // SYN+ECE+CWR

	// Should be accepted (create connection), not dropped.
	err := listener.Demux(rawBuf[:40], 20)
	if err != nil {
		t.Errorf("SYN+ECE+CWR was rejected: %v (want accepted as valid SYN)", err)
	}
}

func TestStackPorts_ECN_SYN_RST(t *testing.T) {
	// Test that StackPorts queues RST for SYN+ECE+CWR to an unknown port.
	// Currently fails: strict flags == flagSYN check doesn't recognize ECN SYN.
	var sp StackPorts
	var listener tcp.Listener
	pool := newMockTCPPool(1, 3, 2048)
	if err := sp.ResetTCP(4); err != nil {
		t.Fatal(err)
	}
	if err := listener.Reset(80, pool); err != nil {
		t.Fatal(err)
	}
	if err := sp.Register(&listener); err != nil {
		t.Fatal(err)
	}

	// Build SYN+ECE+CWR to port 443 (no listener).
	clientIP := [4]byte{10, 0, 0, 1}
	serverIP := [4]byte{10, 0, 0, 2}
	rawBuf := make([]byte, 256)
	rawBuf[0] = 0x45
	rawBuf[9] = 6
	copy(rawBuf[12:16], clientIP[:])
	copy(rawBuf[16:20], serverIP[:])
	binary.BigEndian.PutUint16(rawBuf[20:], 5000) // src port
	binary.BigEndian.PutUint16(rawBuf[22:], 443)  // dst port (no listener)
	binary.BigEndian.PutUint32(rawBuf[24:], 700)  // SEQ
	binary.BigEndian.PutUint32(rawBuf[28:], 0)    // ACK
	rawBuf[32] = 0x50
	rawBuf[33] = byte(tcp.FlagSYN | tcp.FlagECE | tcp.FlagCWR)

	err := sp.Demux(rawBuf[:40], 20)
	if err == nil {
		t.Fatal("expected error for SYN to unknown port")
	}

	// Should have queued RST (same as bare SYN to unknown port).
	var outBuf [256]byte
	outBuf[0] = 0x45
	n, err := sp.Encapsulate(outBuf[:], 0, 20)
	if err != nil {
		t.Fatal("encapsulate RST:", err)
	} else if n == 0 {
		t.Error("no RST produced for SYN+ECE+CWR to unknown port (want RST,ACK)")
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

func (p *mockTCPPool) GetTCP() (*tcp.Conn, any, tcp.Value) {
	for i := range p.conns {
		if !p.acquired[i] {
			p.acquired[i] = true
			p.nextISS += 1000
			p.naqcuired++
			return &p.conns[i], nil, p.nextISS
		}
	}
	return nil, nil, 0
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
