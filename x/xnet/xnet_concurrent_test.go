package xnet

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
)

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
		StaticAddress:     serverIP,
		MaxActiveTCPPorts: numClients,
		HardwareAddress:   serverMAC,
		MTU:               MTU,
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
	connBufs := make([]byte, numClients*tcpBufSize*2) // RX+TX buffer space for all clients

	for i := range clientStacks {
		clientMAC := [6]byte{0xaa, 0xbb, 0xcc, 0x00, 0x01, byte(i + 1)}
		clientIP := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 10)})
		err := clientStacks[i].Reset(StackConfig{
			Hostname:          fmt.Sprintf("Client%d", i),
			RandSeed:          int64(seed + i + 1),
			StaticAddress:     clientIP,
			MaxActiveTCPPorts: 1,
			HardwareAddress:   clientMAC,
			MTU:               MTU,
		})
		if err != nil {
			t.Fatalf("client %d reset: %v", i, err)
		}
		// Client gateway points to server.
		clientStacks[i].SetGateway6(serverMAC)

		// Configure client connection buffers.
		bufOff := i * tcpBufSize * 2
		err = clientConns[i].Configure(tcp.ConnConfig{
			RxBuf:             connBufs[bufOff : bufOff+tcpBufSize],
			TxBuf:             connBufs[bufOff+tcpBufSize : bufOff+2*tcpBufSize],
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
	dstIP := netip.AddrFrom4([4]byte{pkt[30], pkt[31], pkt[32], pkt[33]})

	for i := range clients {
		if clients[i].Addr() == dstIP {
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
		testCloseTransmitsPending(tst, s1, s2, c1, c2, queueSize, tcpbufsize, tcpbufsize, tcpbufsize)
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
		s1.ip.Encapsulate(buf, 14, 14)
		s2.ip.Encapsulate(buf, 14, 14)
	}()

	err := c1.Configure(tcp.ConnConfig{
		RxBuf:             nil,
		TxBuf:             make([]byte, tx1Buf),
		TxPacketQueueSize: queueSize,
		RWBackoff: func(consecutiveBackoffs int) (sleep time.Duration) {
			panic("sadasd")
			return lneto.BackoffFlagNop
		},
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
	deadline := time.Now().Add(time.Second)
	err = c1.SetDeadline(deadline)
	err2 := c2.SetDeadline(deadline)
	if err != nil || err2 != nil {
		t.Fatal(err)
	}

	async := datalen > tx1Buf
	if async {
		// Since data does not fit in TCP Tx buffer the test must be run asynchronously.
		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug - 99,
		}))
		c1.InternalHandler().SetLoggers(logger, logger)
		// c1.InternalHandler().SetLoggers(nil, nil)
		go func() {
			n, err := c1.Write(data)
			if err != nil {
				t.Error(err)
			} else if n != len(data) {
				t.Error("io.Writer faulty implementation")
			}
		}()
	} else {
		n, err := c1.Write(data)
		if err != nil || n != len(data) {
			t.Fatal(err, n)
		}
	}

	err = c1.Close()
	if err != nil {
		t.Fatal(err)
	}
	exchanges := -1
	exchanging := 1
	tcpData := 0
	totalRead := 0
	for exchanging > 0 {
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
					t.Errorf("want %d data read c1->c1, got %d", n, ngot)
				} else if !internal.BytesEqual(buf[:n], data[totalRead:totalRead+n]) {
					t.Errorf("exch%d data rx mismatch, want:\n%q\ngot:\n%q\n", exchanges, data[totalRead:totalRead+n], buf[:n])
				}
				totalRead += ngot
				runtime.Gosched()                            // Yield to let c1 write via goroutine.
				acks := exchangeEthernetOnce(t, s2, s1, buf) // Send ACK s1's way.
				if acks == 0 {
					t.Error("no data sent back to s1")
				}
			}
		}
	}
	if c1.BufferedUnsent() != 0 {
		t.Errorf("done %s: want no data left unsent got %d/%d", c1.State(), c1.BufferedUnsent(), len(data))
	}
	if tcpData != datalen {
		t.Errorf("done %s: want %d bytes sent, got %d", c1.State(), len(data), tcpData)
	}
	if t.Failed() {
		t.Logf("test params: data=%d txsz1=%d rxsz2=%d queuesize=%d tcpsent=%d", datalen, tx1Buf, rx2Buf, queueSize, tcpData)
	}

}
