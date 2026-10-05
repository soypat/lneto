package xnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internal/ltesto"
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
		StaticAddress4:    serverIP.As4(),
		MaxActiveTCPPorts: numClients,
		HardwareAddress:   serverMAC,
		MTU:               MTU,
	})
	if err != nil {
		t.Fatal(err)
	}

	tcpPool, err := NewTCPPool(TCPPoolConfig{
		RandSeed:           1,
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

		conn, _, err := listener.TryAccept()
		if err != nil {
			continue
		}

		// Handle connection in separate goroutine (like real example).
		go func(c tcp.ConnPinned) {
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

// M6: a failed dial must release its port-table entry. Otherwise MaxActiveTCPPorts
// failed dials leave the stack unable to open any TCP connection.
func TestStackGoFailedDialReleasesPort(t *testing.T) {
	const maxPorts = 2
	const randseed = 0x1337_c0de
	tests := []struct {
		name string
		// drain consumes client egress while dialing, so the SYN leaves the stack
		// and is lost on the wire. Otherwise the SYN never leaves the stack.
		drain bool
	}{
		{name: "SYN not sent", drain: false},
		{name: "SYN lost", drain: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := newTestStack(t, "s1", randseed, ethernet.MaxMTU, maxPorts, 0)
			sg := newTestStackGo(cl, 1, 5*time.Millisecond, 1)
			raddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 80)
			laddr := netip.AddrPortFrom(netip.AddrFrom4(cl.Addr4()), 0)
			stop := make(chan struct{})
			drained := make(chan struct{})
			go func() {
				defer close(drained)
				var buf [ethernet.MaxMTU + ethernet.MaxOverheadSize]byte
				for tt.drain {
					select {
					case <-stop:
						return
					default:
					}
					cl.EgressEthernet(buf[:])
					time.Sleep(time.Millisecond)
				}
			}()
			for i := range maxPorts + 1 {
				c, err := sg.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM, laddr, raddr)
				if err == nil {
					t.Fatalf("dial #%d to silent peer succeeded: %v", i, c)
				}
			}
			close(stop)
			<-drained

			err := cl.DialTCP(newTestTCPConn(t, 256, 3), 1234, raddr)
			if err != nil {
				t.Fatalf("DialTCP after %d failed dials: %v", maxPorts+1, err)
			}
		})
	}
}

// M18: SocketNetip must honor its context during the dial handshake.
func TestStackGoDialHonorsContext(t *testing.T) {
	const dialTimeout = 3 * time.Second
	cl := newTestStack(t, "s1", 1, ethernet.MaxMTU, 1, 0)
	sg := newTestStackGo(cl, 1, dialTimeout, 1)
	raddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 80)
	laddr := netip.AddrPortFrom(netip.AddrFrom4(cl.Addr4()), 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() {
		_, err := sg.SocketNetip(ctx, "tcp", syscall.AF_INET, sockSTREAM, laddr, raddr)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("dial with canceled context: got %v, want %v", err, context.Canceled)
		}
	case <-time.After(dialTimeout / 3):
		t.Fatal("dial with canceled context did not return")
	}
}

// M18: a SYN answered with RST is a refused connection: the dial must fail
// without sending further SYNs, regardless of the retry count.
func TestStackGoDialRefusedNoRedial(t *testing.T) {
	const svPort = 80
	const randseed = 1334
	const mtu = ethernet.MaxMTU
	sv := newTestStack(t, "sv1", randseed, mtu, 1, 0)
	cl := newTestStack(t, "cl2", randseed+1, mtu, 1, 0)
	sv.SetGatewayHardwareAddr(cl.HardwareAddr())
	cl.SetGatewayHardwareAddr(sv.HardwareAddr())
	// Listener with no free connections answers every SYN with RST.
	pool, err := NewTCPPool(TCPPoolConfig{
		PoolSize:           0,
		RandSeed:           randseed,
		EstablishedTimeout: time.Second,
		ClosingTimeout:     time.Second,
		NewBackoff:         func() lneto.BackoffStrategy { return backoffYield },
	})
	if err != nil {
		t.Fatal(err)
	}
	var l tcp.Listener
	if err := l.Reset(svPort, pool); err != nil {
		t.Fatal(err)
	}
	if err := sv.RegisterListenerTCP(&l); err != nil {
		t.Fatal(err)
	}

	sg := newTestStackGo(cl, 1, 200*time.Millisecond, 3)
	raddr := netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)
	laddr := netip.AddrPortFrom(netip.AddrFrom4(cl.Addr4()), 0)
	done := make(chan error, 1)
	go func() {
		_, err := sg.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM, laddr, raddr)
		done <- err
	}()
	var buf [ethernet.MaxMTU + ethernet.MaxOverheadSize]byte
	nsyn := 0
	for {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("dial to refusing peer succeeded")
			}
			if nsyn != 1 {
				t.Errorf("sent %d SYNs to a peer that refused the first, want 1", nsyn)
			}
			return
		case <-time.After(5 * time.Second):
			t.Fatal("dial did not return")
		default:
		}
		n, err := cl.EgressEthernet(buf[:])
		if err != nil {
			t.Fatal(err)
		} else if n > 0 {
			if frm, ok := getTCPFrame(buf[:n]); ok {
				if _, flags := frm.OffsetAndFlags(); flags == tcp.FlagSYN {
					nsyn++
				}
			}
			sv.IngressEthernet(buf[:n])
		}
		n, err = sv.EgressEthernet(buf[:])
		if err != nil {
			t.Fatal(err)
		} else if n > 0 {
			cl.IngressEthernet(buf[:n])
		}
		time.Sleep(time.Millisecond)
	}
}
