package xnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
)

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
	pool, err := NewTCPPool(TCPPoolConfig{
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
	svConn, _, err := listener.TryAccept()
	if err != nil {
		t.Fatalf("TryAccept: %v", err)
	}
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
	pool, err := NewTCPPool(TCPPoolConfig{
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
		svconn, _, err := listener.TryAccept()
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

	pool, err := NewTCPPool(TCPPoolConfig{
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

	pool, err := NewTCPPool(TCPPoolConfig{
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

// TestTCPRetransmitsLostSegment drops one data segment and requires bytes to arrive anyway.
// This in particular tests the RTO [tcp.Policy] since tcp
// package by itself will not trigger a retransmission unless dupacks are received.
func TestTCPRetransmitsLostSegment(t *testing.T) {
	const (
		MTU     = ethernet.MaxMTU
		svPort  = 80
		bufSize = 2 << 10
		want    = "this segment is lost in transit"
		// A quiet round means both sides are waiting on the network, which is
		// what a lost segment looks like: only then does the clock move, so the
		// RTO expires in a bounded number of rounds instead of in real time.
		quietStep = 100 * time.Millisecond
		maxRounds = 600
		// Headers total 54 bytes, so a larger frame carries payload. Dropping a
		// bare ACK would exercise the other direction's recovery instead.
		minDataFrame = 14 + 20 + 20 + 8
	)
	client, sv := new(StackAsync), new(StackAsync)
	if err := client.Reset(StackConfig{
		Hostname:          "rtx-client",
		RandSeed:          11,
		StaticAddress4:    [4]byte{10, 0, 0, 90},
		MaxActiveTCPPorts: 2,
		HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, 90},
		MTU:               MTU,
		ICMPQueueLimit:    2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := sv.Reset(StackConfig{
		Hostname:          "rtx-server",
		RandSeed:          ^int64(11),
		StaticAddress4:    [4]byte{10, 0, 0, 91},
		MaxActiveTCPPorts: 2,
		HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, 91},
		MTU:               MTU,
		ICMPQueueLimit:    2,
	}); err != nil {
		t.Fatal(err)
	}
	client.SetGatewayHardwareAddr(sv.HardwareAddr())
	sv.SetGatewayHardwareAddr(client.HardwareAddr())

	tsched := ltesto.NewSched(t)
	svGoro, clGoro := tsched.Goro(), tsched.Goro()

	// Simulated monotonic clock. Only the driver writes it, and only while every
	// scheduled goroutine is parked, so it needs no synchronization of its own.
	var now int64
	nanotime := func() int64 { return now }

	// Each side backs off into its own scheduler handle, so the driver can park
	// and resume the two independently.
	newPool := func(yield lneto.BackoffStrategy) TCPPoolConfig {
		return TCPPoolConfig{
			PoolSize: 2, QueueSize: 4,
			TxBufSize: bufSize, RxBufSize: bufSize,
			// Well past the simulated time this test spends, so the pool never
			// reaps a connection out from under the retransmission.
			EstablishedTimeout: 120 * time.Second,
			ClosingTimeout:     120 * time.Second,
			NanoTime:           nanotime,
			NewBackoff:         func() lneto.BackoffStrategy { return yield },
			NewPolicy: func() tcp.Policy {
				timer := new(rto.Timer)
				if err := timer.Configure(nanotime); err != nil {
					t.Error(err)
				}
				return timer
			},
		}
	}
	svGo := sv.StackBlocking(svGoro.Yield).StackGo(StackGoConfig{
		ListenerPoolConfig: newPool(svGoro.Yield),
	})
	clGo := client.StackBlocking(clGoro.Yield).StackGo(StackGoConfig{
		ListenerPoolConfig: newPool(clGoro.Yield),
		TCPDialTimeout:     60 * time.Second,
		TCPDialRetries:     1,
	})
	svGo.blk._nanotime = nanotime
	clGo.blk._nanotime = nanotime

	lsAny, err := svGo.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM,
		netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort), netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	listener := lsAny.(net.Listener)
	defer listener.Close()

	// dropNext arms the driver to swallow the next server→client data frame. It
	// is handed between the server goroutine and the driver by the scheduler
	// handoff, which orders every access to it.
	var dropNext, dropped bool

	go func() {
		c, err := listener.Accept()
		if err != nil {
			svGoro.FinishWithErr(err)
			return
		}
		dropNext = true // The very next data frame is lost in transit.
		_, err = c.Write([]byte(want))
		c.Close() // Closing here is what makes #182's FIN-WAIT-1 retransmit matter.
		svGoro.FinishWithErr(err)
	}()

	raddr := netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)
	go func() {
		cAny, err := clGo.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM,
			netip.AddrPort{}, raddr)
		if err != nil {
			clGoro.FinishWithErr(err)
			return
		}
		conn := cAny.(net.Conn)
		got := make([]byte, 0, len(want))
		rb := make([]byte, 64)
		for len(got) < len(want) {
			n, err := conn.Read(rb)
			got = append(got, rb[:n]...)
			if err != nil {
				clGoro.FinishWithErr(fmt.Errorf("read %d/%d bytes: %w", len(got), len(want), err))
				return
			}
		}
		if string(got) != want {
			clGoro.FinishWithErr(fmt.Errorf("read %q, want %q", got, want))
			return
		}
		// Closed before finishing: a Yield after FinishWithErr would never be
		// serviced, since the driver stops resuming a goroutine it has reaped.
		conn.Close()
		clGoro.Finish()
	}()

	var buf [MTU + ethernet.MaxOverheadSize]byte
	// pump moves one frame each way, dropping the armed one. Only ever called
	// with both goroutines parked.
	// Ingress errors are not fatal here: once a segment is dropped the frames
	// behind it arrive past rcv.nxt and are rejected, which is precisely the
	// stall the retransmission has to break. Egress errors are real faults.
	pump := func() (moved bool) {
		n, err := client.EgressEthernet(buf[:])
		if err != nil {
			t.Fatal("client egress:", err)
		} else if n > 0 {
			sv.IngressEthernet(buf[:n])
			moved = true
		}
		n, err = sv.EgressEthernet(buf[:])
		if err != nil {
			t.Fatal("server egress:", err)
		} else if n > 0 {
			if dropNext && n > minDataFrame {
				dropNext, dropped = false, true
			} else {
				client.IngressEthernet(buf[:n])
			}
			moved = true
		}
		return moved
	}

	for round := 0; ; round++ {
		if round == maxRounds {
			t.Fatalf("no retransmission after %d rounds and %v of simulated time (dropped=%v): is a Policy installed?",
				maxRounds, time.Duration(now), dropped)
		}
		allFinished, err := tsched.AwaitAllParked()
		if err != nil {
			t.Fatalf("after losing one segment (dropped=%v): %v", dropped, err)
		}
		if allFinished {
			break
		}
		if !pump() {
			now += int64(quietStep) // Both sides idle: let the RTO age.
		}
		tsched.YieldToAllParked()
	}
	if !dropped {
		t.Fatal("no frame was dropped, so the test did not exercise retransmission")
	}
}
