package internet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
)

func TestBasicStack(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var sbCl, sbSv StackIPv4
	var connCl, connSv tcp.Conn
	setupClientServer(t, rng, &sbCl, &sbSv, &connCl, &connSv)
	var buf [2048]byte
	nextToSend := &sbCl
	nextToRecv := &sbSv
	exchangeAndExpectStates := func(clState, svState tcp.State) {
		t.Helper()
		expectExchange(t, nextToSend, nextToRecv, buf[:])
		gotCl := connCl.State()
		gotSv := connSv.State()
		if gotCl != clState {
			t.Errorf("want client state %s, got %s", clState, gotCl)
		}
		if gotSv != svState {
			t.Errorf("want server state %s, got %s", svState, gotSv)
		}
		nextToSend, nextToRecv = nextToRecv, nextToSend
	}
	exchangeAndExpectStates(tcp.StateSynSent, tcp.StateSynRcvd)         // Client sends over first SYN and server receives it.
	exchangeAndExpectStates(tcp.StateEstablished, tcp.StateSynRcvd)     // server sends back SYNACK, establishing connection on client side.
	exchangeAndExpectStates(tcp.StateEstablished, tcp.StateEstablished) // Client sends ACK, establishing connection in full.
}

func TestBasicStack2(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var sbCl, sbSv StackIPv4
	var connCl, connSv tcp.Conn
	setupClientServerEstablished(t, rng, &sbCl, &sbSv, &connCl, &connSv)

}

func expectExchange(t *testing.T, from, to lneto.StackNode, buf []byte) {
	t.Helper()
	n, err := from.Encapsulate(buf, 0, 0)
	if err != nil {
		t.Error("expectExchange:encapsulate:", err)
	} else if n == 0 {
		t.Error("expected data exchange")
		return
	}
	err = to.Demux(buf[:n], 0)
	if err != nil {
		t.Error("expectExchange:Recv:", err)
	}
}

func setupClientServerEstablished(t *testing.T, rng *rand.Rand, client, server *StackIPv4, connClient, connServer *tcp.Conn) {
	t.Helper()
	setupClientServer(t, rng, client, server, connClient, connServer)
	testClientServerEstablish(t, client, server, connClient, connServer)
}

func testClientServerEstablish(t *testing.T, client, server lneto.StackNode, connClient, connServer *tcp.Conn) {
	t.Helper()
	var buf [2048]byte
	nextToSend := client
	nextToRecv := server
	exchangeAndExpectStates := func(clState, svState tcp.State) {
		t.Helper()
		expectExchange(t, nextToSend, nextToRecv, buf[:])
		gotCl := connClient.State()
		gotSv := connServer.State()
		if gotCl != clState {
			t.Errorf("want client state %s, got %s", clState, gotCl)
		}
		if gotSv != svState {
			t.Errorf("want server state %s, got %s", svState, gotSv)
		}
		nextToSend, nextToRecv = nextToRecv, nextToSend
	}
	exchangeAndExpectStates(tcp.StateSynSent, tcp.StateSynRcvd)         // Client sends over first SYN and server receives it.
	exchangeAndExpectStates(tcp.StateEstablished, tcp.StateSynRcvd)     // server sends back SYNACK, establishing connection on client side.
	exchangeAndExpectStates(tcp.StateEstablished, tcp.StateEstablished) // Client sends ACK, establishing connection in full.
	if t.Failed() {
		t.Error("establishment failed")
		t.FailNow()
	}
}

func TestBasicStack6(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var sbCl, sbSv StackIPv6
	var connCl, connSv tcp.Conn
	setupClientServer6(t, rng, &sbCl, &sbSv, &connCl, &connSv)
	var buf [2048]byte
	nextToSend := &sbCl
	nextToRecv := &sbSv
	exchangeAndExpectStates := func(clState, svState tcp.State) {
		t.Helper()
		expectExchange(t, nextToSend, nextToRecv, buf[:])
		gotCl := connCl.State()
		gotSv := connSv.State()
		if gotCl != clState {
			t.Errorf("want client state %s, got %s", clState, gotCl)
		}
		if gotSv != svState {
			t.Errorf("want server state %s, got %s", svState, gotSv)
		}
		nextToSend, nextToRecv = nextToRecv, nextToSend
	}
	exchangeAndExpectStates(tcp.StateSynSent, tcp.StateSynRcvd)
	exchangeAndExpectStates(tcp.StateEstablished, tcp.StateSynRcvd)
	exchangeAndExpectStates(tcp.StateEstablished, tcp.StateEstablished)
}

func TestBasicStack6Established(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var sbCl, sbSv StackIPv6
	var connCl, connSv tcp.Conn
	setupClientServer6(t, rng, &sbCl, &sbSv, &connCl, &connSv)
	testClientServerEstablish(t, &sbCl, &sbSv, &connCl, &connSv)
}

func setupClientServer6(t *testing.T, rng *rand.Rand, client, server *StackIPv6, connClient, connServer *tcp.Conn) {
	t.Helper()
	_ = rng
	const maxNodes = 1
	bufsize := 2048
	svip6 := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) // 2001:db8::1
	clip6 := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}) // 2001:db8::2
	svip := netip.AddrPortFrom(svip6, 80)
	clip := netip.AddrPortFrom(clip6, 1337)
	if err := server.Reset(new(lneto.Validator), maxNodes); err != nil {
		t.Fatal(err)
	}
	if err := client.Reset(new(lneto.Validator), maxNodes); err != nil {
		t.Fatal(err)
	}
	server.SetAddr6(svip6.As16())
	client.SetAddr6(clip6.As16())
	err := connServer.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, bufsize),
		TxBuf:             make([]byte, bufsize),
		TxPacketQueueSize: 3,
		RWBackoff:         backoffYield,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = connClient.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, bufsize),
		TxBuf:             make([]byte, bufsize),
		TxPacketQueueSize: 3,
		RWBackoff:         backoffYield,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = connServer.OpenListen(svip.Port(), 200); err != nil {
		t.Fatal(err)
	}
	if err = connClient.OpenActive(clip.Port(), svip, 100); err != nil {
		t.Fatal(err)
	}
	if err = server.Register6(connServer); err != nil {
		t.Fatal(err)
	}
	if err = client.Register6(connClient); err != nil {
		t.Fatal(err)
	}
}

func setupClientServer(t *testing.T, rng *rand.Rand, client, server *StackIPv4, connClient, connServer *tcp.Conn) {
	const maxNodes = 1
	bufsize := 2048
	// Ensure buffer sizes are OK with reused buffers.
	svip := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 0}), 80)
	clip := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 1}), 1337)
	server.Reset(new(lneto.Validator), maxNodes)
	client.Reset(new(lneto.Validator), maxNodes)
	server.SetAddr4(svip.Addr().As4())
	client.SetAddr4(clip.Addr().As4())
	err := connServer.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, bufsize),
		TxBuf:             make([]byte, bufsize),
		TxPacketQueueSize: 3,
		Logger:            nil,
		RWBackoff:         backoffYield,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = connClient.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, bufsize),
		TxBuf:             make([]byte, bufsize),
		TxPacketQueueSize: 3,
		Logger:            nil,
		RWBackoff:         backoffYield,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = connServer.OpenListen(svip.Port(), 200)
	if err != nil {
		t.Fatal(err)
	}
	err = connClient.OpenActive(clip.Port(), svip, 100)
	if err != nil {
		t.Fatal(err)
	}

	err = server.Register4(connServer)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Register4(connClient)
	if err != nil {
		t.Fatal(err)
	}
}

func backoffYield(consecutiveBackoffs uint) time.Duration {
	return lneto.BackoffFlagGosched
}

// TestConn_ConcurrentCloseDoesNotDropWrite is a regression test for issue #82:
// when one goroutine has a Write in progress (blocked because the TX buffer is
// full) and another goroutine calls Close, the in-flight write data must not be
// silently dropped. With the atomic write-lock, Close waits for the in-progress
// write to finish queueing all of its data before tearing the connection down.
//
// The scenario is made deterministic by filling the TX buffer before any packets
// are exchanged: the writer blocks holding the write lock, Close is then issued
// (and must wait), and only afterwards is the packet pump started so the buffer
// can drain and the writer can run to completion.
func TestConn_ConcurrentCloseDoesNotDropWrite(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var sbCl, sbSv StackIPv4
	var connCl, connSv tcp.Conn
	setupClientServerEstablished(t, rng, &sbCl, &sbSv, &connCl, &connSv)

	// Payload several times larger than the 2048-byte TX buffer so the writer
	// must block waiting for the buffer to drain across many segments.
	payload := make([]byte, 4*2048)
	for i := range payload {
		payload[i] = byte(i)
	}

	// Watchdog: break any deadlock so a regression fails fast instead of hanging.
	watchdog := time.AfterFunc(10*time.Second, func() {
		t.Error("test timed out: Close likely blocked waiting on a stuck write")
		connCl.Abort()
		connSv.Abort()
	})
	defer watchdog.Stop()

	// Writer (G1): writes the whole payload. Blocks once the TX buffer fills.
	type writeResult struct {
		n   int
		err error
	}
	writeDone := make(chan writeResult, 1)
	go func() {
		n, err := connCl.Write(payload)
		writeDone <- writeResult{n, err}
	}()

	// Wait until the writer has filled the TX buffer and is blocked. At this
	// point it owns the write lock, reproducing "Write in progress".
	for connCl.FreeOutput() != 0 {
		runtime.Gosched()
	}

	// Close (G2): issued while the write is in progress. Must wait for the
	// writer to drain instead of dropping its data.
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- connCl.Close()
	}()

	// Reader: drains the server side until EOF, accumulating everything received.
	readDone := make(chan []byte, 1)
	go func() {
		got := make([]byte, 0, len(payload))
		rbuf := make([]byte, 1024)
		for {
			n, err := connSv.Read(rbuf)
			got = append(got, rbuf[:n]...)
			if err != nil {
				break
			}
		}
		readDone <- got
	}()

	// Packet pump: only now do we move packets between the two stacks, letting
	// the buffer drain so the blocked writer can finish.
	var stop atomic.Bool
	pumpStopped := make(chan struct{})
	go func() {
		defer close(pumpStopped)
		var buf [2048]byte
		for !stop.Load() {
			progressed := false
			if n, err := sbCl.Encapsulate(buf[:], 0, 0); err == nil && n > 0 {
				_ = sbSv.Demux(buf[:n], 0)
				progressed = true
			}
			if n, err := sbSv.Encapsulate(buf[:], 0, 0); err == nil && n > 0 {
				_ = sbCl.Demux(buf[:n], 0)
				progressed = true
			}
			if !progressed {
				runtime.Gosched()
			}
		}
	}()

	wr := <-writeDone
	if wr.err != nil {
		t.Errorf("issue #82: Write returned error %v; concurrent Close dropped in-flight data", wr.err)
	}
	if wr.n != len(payload) {
		t.Errorf("issue #82: Write wrote %d of %d bytes; concurrent Close truncated the write", wr.n, len(payload))
	}
	if err := <-closeDone; err != nil {
		t.Errorf("Close returned error: %v", err)
	}
	got := <-readDone
	stop.Store(true)
	<-pumpStopped

	if len(got) != len(payload) {
		t.Fatalf("server received %d of %d bytes; data was dropped by concurrent Close", len(got), len(payload))
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("server received corrupted data")
	}
}

// TestConn_ConcurrentWritesSerialize verifies that the atomic write-lock
// serializes concurrent Write calls on the same connection so their payloads are
// not interleaved on the wire, and that all bytes from both writers are delivered.
func TestConn_ConcurrentWritesSerialize(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	var sbCl, sbSv StackIPv4
	var connCl, connSv tcp.Conn
	setupClientServerEstablished(t, rng, &sbCl, &sbSv, &connCl, &connSv)

	const chunk = 1500
	a := bytes.Repeat([]byte{0xAA}, chunk)
	b := bytes.Repeat([]byte{0xBB}, chunk)

	watchdog := time.AfterFunc(10*time.Second, func() {
		t.Error("test timed out")
		connCl.Abort()
		connSv.Abort()
	})
	defer watchdog.Stop()

	var stop atomic.Bool
	pumpStopped := make(chan struct{})
	go func() {
		defer close(pumpStopped)
		var buf [2048]byte
		for !stop.Load() {
			progressed := false
			if n, err := sbCl.Encapsulate(buf[:], 0, 0); err == nil && n > 0 {
				_ = sbSv.Demux(buf[:n], 0)
				progressed = true
			}
			if n, err := sbSv.Encapsulate(buf[:], 0, 0); err == nil && n > 0 {
				_ = sbCl.Demux(buf[:n], 0)
				progressed = true
			}
			if !progressed {
				runtime.Gosched()
			}
		}
	}()

	writeErr := make(chan error, 2)
	writer := func(b []byte) {
		n, err := connCl.Write(b)
		if err == nil && n != len(b) {
			err = io.ErrShortWrite
		}
		writeErr <- err
	}
	go writer(a)
	go writer(b)

	got := make([]byte, 0, 2*chunk)
	rbuf := make([]byte, 1024)
	for len(got) < 2*chunk {
		n, err := connSv.Read(rbuf)
		got = append(got, rbuf[:n]...)
		if err != nil && !errors.Is(err, io.EOF) {
			break
		}
	}
	for range 2 {
		if err := <-writeErr; err != nil {
			t.Errorf("concurrent write failed: %v", err)
		}
	}
	stop.Store(true)
	<-pumpStopped

	if len(got) != 2*chunk {
		t.Fatalf("received %d bytes, want %d", len(got), 2*chunk)
	}
	// Serialized writes mean one chunk's bytes appear fully before the other's;
	// the boundary is a single transition, never interleaved.
	transitions := 0
	for i := 1; i < len(got); i++ {
		if got[i] != got[i-1] {
			transitions++
		}
	}
	if transitions != 1 {
		t.Fatalf("expected exactly one A/B boundary (serialized writes), got %d transitions", transitions)
	}
}

func TestListener_SingleConnection(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var clientStack, serverStack StackIPv4
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
	if err := serverStack.Register4(&listener); err != nil {
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
	var client1Stack, serverStack StackIPv4
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
	if err := serverStack.Register4(&listener); err != nil {
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
	var client2Stack StackIPv4
	var client2Conn tcp.Conn
	setupClient(t, &client2Stack, &client2Conn, netip.AddrFrom4(serverStack.Addr4()), serverPort, 1338)

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
	var serverStack StackIPv4
	var serverConn tcp.Conn
	var listener tcp.Listener
	pool := newMockTCPPool(numClients, 3, 2048)

	// Create slices for clients.
	clientStacks := make([]StackIPv4, numClients)
	clientConns := make([]tcp.Conn, numClients)
	acceptedConns := make([]tcp.ConnHandle, numClients)

	// Setup server with listener using setupClientServer for first client to get server configured.
	setupClientServer(t, rng, &clientStacks[0], &serverStack, &clientConns[0], &serverConn)
	serverConn.Abort()
	serverPort := uint16(80)
	if err := listener.Reset(serverPort, pool); err != nil {
		t.Fatal(err)
	}
	if err := serverStack.Register4(&listener); err != nil {
		t.Fatal(err)
	}

	// Setup remaining clients.
	for i := 1; i < numClients; i++ {
		clientPort := uint16(1337 + i)
		setupClient(t, &clientStacks[i], &clientConns[i], netip.AddrFrom4(serverStack.Addr4()), serverPort, clientPort)
	}

	var buf [2048]byte

	// Complete full handshakes for all clients.
	for i := range numClients {
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
	for i := range numClients {
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
	for i := range numClients {
		if clientConns[i].State() != tcp.StateEstablished {
			t.Errorf("client %d: expected StateEstablished, got %s", i, clientConns[i].State())
		}
		if acceptedConns[i].State() != tcp.StateEstablished {
			t.Errorf("accepted %d: expected StateEstablished, got %s", i, acceptedConns[i].State())
		}
	}

	// Test data exchange: client -> server.
	for i := range numClients {
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
	for i := range numClients {
		expectExchange(t, &clientStacks[i], &serverStack, buf[:])
	}

	// Read data on server side and verify.
	for i := range numClients {
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
	for i := range numClients {
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
	for i := range numClients {
		expectExchange(t, &serverStack, &clientStacks[i], buf[:])
	}

	// Read responses on client side and verify.
	for i := range numClients {
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
	for i := range numClients {
		var closer, responder *StackIPv4
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
			closerConn, responderConn = &clientConns[i], acceptedConns[i].Conn()
		} else {
			// Server initiates close.
			serverClosed = true
			whoCloses, whoResponds = whoResponds, whoCloses
			closer, responder = &serverStack, &clientStacks[i]
			closerConn, responderConn = acceptedConns[i].Conn(), &clientConns[i]
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
	var client1Stack, client2Stack, serverStack StackIPv4
	var client1Conn, client2Conn, serverConn tcp.Conn
	var listener tcp.Listener

	pool := newMockTCPPool(1, 3, 2048) // Pool size 1: will exhaust after first connection.

	setupClientServer(t, rng, &client1Stack, &serverStack, &client1Conn, &serverConn)
	serverConn.Abort()
	serverPort := uint16(80)
	if err := listener.Reset(serverPort, pool); err != nil {
		t.Fatal(err)
	}
	if err := serverStack.Register4(&listener); err != nil {
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
	setupClient(t, &client2Stack, &client2Conn, netip.AddrFrom4(serverStack.Addr4()), serverPort, client2Port)

	// Client2 sends SYN.
	n, err := client2Stack.Encapsulate(buf[:], 0, 0)
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
	n, err = serverStack.Encapsulate(buf[:], 0, 0)
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

func setupClient(t *testing.T, client *StackIPv4, conn *tcp.Conn, serverAddr netip.Addr, serverPort, clientPort uint16) {
	t.Helper()
	bufsize := 2048
	clientIP := netip.AddrFrom4([4]byte{192, 168, 1, byte(clientPort % 256)})
	client.Reset(new(lneto.Validator), 1)
	client.SetAddr4(clientIP.As4())
	err := conn.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, bufsize),
		TxBuf:             make([]byte, bufsize),
		TxPacketQueueSize: 3,
		RWBackoff:         backoffYield,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverAddrPort := netip.AddrPortFrom(serverAddr, serverPort)
	err = conn.OpenActive(clientPort, serverAddrPort, 100)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Register4(conn)
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
			RWBackoff:         backoffYield,
		})
		if err != nil {
			panic(err)
		}
	}
	return pool
}

func (p *mockTCPPool) GetTCP(laddr, raddr []byte, lport, rport uint16) (*tcp.Conn, any, tcp.Value) {
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

func (p *mockTCPPool) CheckTimeouts() {}

func (p *mockTCPPool) NumberOfAcquired() int {
	return p.naqcuired
}
