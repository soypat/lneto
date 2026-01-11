package xnet

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/soypat/lneto/tcp"
)

func TestTCPListener_ConcurrentEcho(t *testing.T) {
	const (
		numClients = 10
		serverPort = 8080
		MTU        = 1500
		seed       = 1
	)

	// 1. Setup server stack with tcp.Listener.
	var serverStack StackAsync
	serverMAC := [6]byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}
	serverIP := netip.AddrFrom4([4]byte{10, 0, 0, 1})
	err := serverStack.Reset(StackConfig{
		Hostname:        "Server",
		RandSeed:        seed,
		StaticAddress:   serverIP,
		MaxTCPConns:     numClients,
		HardwareAddress: serverMAC,
		MTU:             MTU,
	})
	if err != nil {
		t.Fatal(err)
	}

	tcpPool, err := NewTCPPool(TCPPoolConfig{
		PoolSize:           numClients,
		QueueSize:          4,
		TxBufSize:          512,
		RxBufSize:          512,
		EstablishedTimeout: 5 * time.Second,
		ClosingTimeout:     5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	var listener tcp.Listener
	err = listener.Reset(serverPort, tcpPool)
	if err != nil {
		t.Fatal(err)
	}
	err = serverStack.RegisterListener(&listener)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Setup client stacks (one per client).
	clientStacks := make([]StackAsync, numClients)
	clientConns := make([]tcp.Conn, numClients)
	connBufs := make([]byte, numClients*MTU*2) // RX+TX buffer space for all clients

	for i := range clientStacks {
		clientMAC := [6]byte{0xaa, 0xbb, 0xcc, 0x00, 0x01, byte(i + 1)}
		clientIP := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 10)})
		err := clientStacks[i].Reset(StackConfig{
			Hostname:        fmt.Sprintf("Client%d", i),
			RandSeed:        int64(seed + i + 1),
			StaticAddress:   clientIP,
			MaxTCPConns:     1,
			HardwareAddress: clientMAC,
			MTU:             MTU,
		})
		if err != nil {
			t.Fatalf("client %d reset: %v", i, err)
		}
		// Client gateway points to server.
		clientStacks[i].SetGateway6(serverMAC)

		// Configure client connection buffers.
		bufOff := i * MTU * 2
		err = clientConns[i].Configure(tcp.ConnConfig{
			RxBuf:             connBufs[bufOff : bufOff+MTU],
			TxBuf:             connBufs[bufOff+MTU : bufOff+2*MTU],
			TxPacketQueueSize: 4,
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
			if runClient(t, clientID, &clientStacks[clientID], &clientConns[clientID],
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
	const MTU = 1500
	buf := make([]byte, MTU)
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
		if n, _ := server.Encapsulate(buf, -1, 0); n > 0 {
			routePacketToClient(buf[:n], clients)
		}

		// Process each client outgoing in randomized order.
		rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		for _, idx := range order {
			if n, _ := clients[idx].Encapsulate(buf, -1, 0); n > 0 {
				server.Demux(buf[:n], 0) // All clients talk to server.
			}
		}

		runtime.Gosched() // Yield to other goroutines.
	}
}

func routePacketToClient(pkt []byte, clients []StackAsync) {
	// Extract destination IP from IPv4 header (offset 16-19 in IP header, after 14 byte Ethernet header).
	if len(pkt) < 34 { // 14 ethernet + 20 min IP header
		return
	}
	dstIP := netip.AddrFrom4([4]byte{pkt[30], pkt[31], pkt[32], pkt[33]})

	for i := range clients {
		if clients[i].Addr() == dstIP {
			clients[i].Demux(pkt, 0)
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
			time.Sleep(time.Millisecond)
			continue
		}

		conn, _, err := listener.TryAccept()
		if err != nil || conn == nil {
			continue
		}

		// Handle connection in separate goroutine (like real example).
		go func(c *tcp.Conn) {
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

func runClient(t *testing.T, id int, stack *StackAsync, conn *tcp.Conn,
	serverAddr netip.Addr, serverPort uint16) bool {
	// Dial server.
	clientPort := uint16(10000 + id)
	err := stack.DialTCP(conn, clientPort, netip.AddrPortFrom(serverAddr, serverPort))
	if err != nil {
		t.Errorf("client %d dial failed: %v", id, err)
		return false
	}

	// Wait for connection established (handshake via kernel loop).
	deadline := time.Now().Add(5 * time.Second)
	for conn.State() != tcp.StateEstablished {
		if time.Now().After(deadline) {
			t.Errorf("client %d: timeout waiting for established state, got %s", id, conn.State())
			return false
		}
		time.Sleep(time.Millisecond)
	}

	// Send test data.
	testData := []byte(fmt.Sprintf("hello from client %d", id))
	_, err = conn.Write(testData)
	if err != nil {
		t.Errorf("client %d write failed: %v", id, err)
		return false
	}

	// Read echo response.
	var buf [64]byte
	deadline = time.Now().Add(5 * time.Second)
	var totalRead int
	for totalRead < len(testData) {
		if time.Now().After(deadline) {
			t.Errorf("client %d: timeout waiting for echo response, got %d/%d bytes", id, totalRead, len(testData))
			return false
		}
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
