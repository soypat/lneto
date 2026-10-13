package xnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
	"github.com/soypat/lneto/udp"
)

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
			// The clock moves only in the goroutine below, so dials to the silent
			// peer time out without waiting for wall time.
			var now atomic.Int64
			cl := newTestStackClock(t, "s1", randseed, ethernet.MaxMTU, maxPorts, 0, now.Load)
			sg := newTestStackGo(cl, 1, 5*time.Millisecond, 1)
			raddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 80)
			laddr := netip.AddrPortFrom(netip.AddrFrom4(cl.Addr4()), 0)
			stop := make(chan struct{})
			drained := make(chan struct{})
			go func() {
				defer close(drained)
				var buf [ethernet.MaxMTU + ethernet.MaxOverheadSize]byte
				for {
					select {
					case <-stop:
						return
					default:
					}
					if tt.drain {
						cl.EgressEthernet(buf[:])
					}
					now.Add(int64(time.Millisecond))
					runtime.Gosched()
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
	pool, err := sv.NewTCPPool(TCPPoolConfig{
		PoolSize:           0,
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
		runtime.Gosched()
	}
}

// M19: a dial without a deadline must return once the handshake completes, even
// if the peer closes the connection right after accepting it.
func TestStackGoDialPeerClosesAfterAccept(t *testing.T) {
	const seed = 4321
	const svPort = 22
	const mtu = ethernet.MaxMTU
	const lim = 8
	tst := testerFrom(t, mtu)
	client, sv, _, svconn := newTCPStacks(t, seed, mtu)
	if err := sv.ListenTCP4(svconn, svPort); err != nil {
		t.Fatal(err)
	}
	tsched := ltesto.NewSched(t)
	tgoro := tsched.Goro()
	sg := client.StackBlocking(tgoro.Yield).StackGo(StackGoConfig{
		ListenerPoolConfig: TCPPoolConfig{
			QueueSize:  4,
			TxBufSize:  mtu,
			RxBufSize:  mtu,
			NewBackoff: func() lneto.BackoffStrategy { return backoffYield },
		},
		TCPDialTimeout: time.Minute,
		TCPDialRetries: 1,
	})
	laddr := netip.AddrPortFrom(netip.AddrFrom4(client.Addr4()), 1234)
	raddr := netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)
	var dialed any
	go func() {
		c, err := sg.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM, laddr, raddr)
		dialed = c
		tgoro.FinishWithErr(err)
	}()
	checkDialed := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("dial failed after handshake completed: %v", err)
		} else if _, ok := dialed.(net.Conn); !ok {
			t.Fatalf("dial returned %T (%v), want net.Conn", dialed, dialed)
		}
	}

	// Handshake: run until the server is established, leaving the dialer parked.
	for i := 0; ; i++ {
		done, err := tsched.AwaitGoroYieldOrDone()
		if done {
			t.Fatalf("dial ended during handshake: %v", err)
		}
		tst.ensureQuiesce(client, sv, lim)
		if svconn.State() == tcp.StateEstablished {
			break
		} else if i > 64 {
			t.Fatal("handshake did not complete")
		}
		tsched.YieldToGoro()
	}
	// Dialer observes ESTABLISHED.
	tsched.YieldToGoro()
	done, err := tsched.AwaitGoroYieldOrDone()
	if done {
		checkDialed(err)
		return
	}
	// Peer closes before the dialer runs again.
	svconn.Close()
	tst.ensureQuiesce(client, sv, lim)
	for range 100 {
		tsched.YieldToGoro()
		done, err := tsched.AwaitGoroYieldOrDone()
		if done {
			checkDialed(err)
			return
		}
	}
	t.Fatal("dial hangs after peer closed the established connection")
}

// TestTCPListener_CloseUnblocksAccept covers the net.Listener wrapper's Accept
// poll loop being ended by a Close from another goroutine.
func TestTCPListener_CloseUnblocksAccept(t *testing.T) {
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

	var l tcplistener
	// Sleep rather than yield between polls so Accept is genuinely parked in the
	// loop when Close lands, instead of spinning a core for the whole test. The
	// first backoff signals that Accept has reached its poll loop.
	parked := make(chan struct{})
	l.sleep = func(consecutiveBackoffs uint) time.Duration {
		if consecutiveBackoffs == 0 {
			close(parked)
		}
		return time.Millisecond
	}
	l.localAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), svPort))
	err = l.l.Reset(svPort, pool)
	if err != nil {
		t.Fatal(err)
	}

	// No stack is driving this listener, so Accept can only ever block: nothing
	// will become ready and the sole way out is the Close below.
	accepted := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if c != nil {
			c.Close()
		}
		accepted <- err
	}()
	select {
	case <-parked:
	case err := <-accepted:
		t.Fatalf("Accept returned before polling: %v", err)
	case <-time.After(5 * time.Second):
		l.Close()
		t.Fatal("Accept did not reach its poll loop")
	}

	if err := l.Close(); err != nil {
		t.Fatal("Close while Accept is blocked:", err)
	}
	select {
	case err := <-accepted:
		if err != net.ErrClosed {
			t.Fatalf("blocked Accept: want net.ErrClosed, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return after Close")
	}

	// A later Accept reports the close rather than blocking again.
	if _, err := l.Accept(); err != net.ErrClosed {
		t.Fatalf("Accept after Close: want net.ErrClosed, got %v", err)
	}
	if err := l.Close(); err != net.ErrClosed {
		t.Fatalf("double Close: want net.ErrClosed, got %v", err)
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
	// Simulated monotonic clock. Only the driver writes it, and only while every
	// scheduled goroutine is parked, so it needs no synchronization of its own.
	var now int64
	nanotime := func() int64 { return now }

	client, sv := new(StackAsync), new(StackAsync)
	if err := client.Reset(StackConfig{
		Hostname:          "rtx-client",
		RandSeed:          11,
		StaticAddress4:    [4]byte{10, 0, 0, 90},
		MaxActiveTCPPorts: 2,
		HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, 90},
		MTU:               MTU,
		ICMPQueueLimit:    2,
		Nanotime:          nanotime,
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
		Nanotime:          nanotime,
	}); err != nil {
		t.Fatal(err)
	}
	client.SetGatewayHardwareAddr(sv.HardwareAddr())
	sv.SetGatewayHardwareAddr(client.HardwareAddr())

	tsched := ltesto.NewSched(t)
	svGoro, clGoro := tsched.Goro(), tsched.Goro()

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

// M2: a net.Conn returned by Accept must stop working once its connection ends,
// even after the listener pool hands the same slot to the next client.
func TestStackGoAcceptedConnStaleAfterReuse(t *testing.T) {
	const svPort = 80
	const seedRng = 0x1337_c0de
	const mtu = ethernet.MaxMTU
	const tcpPorts = 1
	sv := newTestStack(t, "s1", seedRng, mtu, tcpPorts, 0)
	cl1 := newTestStack(t, "s2", ^seedRng, mtu, tcpPorts, 0)
	cl2 := newTestStack(t, "s3", seedRng>>7, mtu, tcpPorts, 0)
	cl1.SetGatewayHardwareAddr(sv.HardwareAddr())
	cl2.SetGatewayHardwareAddr(sv.HardwareAddr())
	sg := newTestStackGo(sv, 1, time.Second, 1)
	svaddr := netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)
	sock, err := sg.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM, svaddr, netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	l := sock.(net.Listener)
	defer l.Close()
	tst := testerFrom(t, mtu)
	const lim = 8

	accept := func(cl *StackAsync, clconn *tcp.Conn) net.Conn {
		t.Helper()
		sv.SetGatewayHardwareAddr(cl.HardwareAddr())
		if err := cl.DialTCP(clconn, 1337, svaddr); err != nil {
			t.Fatal(err)
		}
		tst.ensureQuiesce(cl, sv, lim)
		if n := readyToAccept(t, l); n != 1 {
			t.Fatalf("client %v: %d ready to accept, want 1 (client state %s)", cl.Addr4(), n, clconn.State())
		}
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	c1 := newTestTCPConn(t, mtu, 4)
	stale := accept(cl1, c1)
	// First connection ends normally: client closes, then server closes.
	c1.Close()
	tst.ensureQuiesce(cl1, sv, lim)
	stale.Close()
	tst.ensureQuiesce(cl1, sv, lim)

	// Pool of 1: the second client is served by the slot the first one used.
	c2 := newTestTCPConn(t, mtu, 4)
	fresh := accept(cl2, c2)

	if n, err := stale.Write([]byte("stale")); err == nil {
		t.Errorf("Write on ended conn succeeded writing %d bytes into the next client's connection", n)
	}
	stale.Close()
	if _, err := fresh.Write([]byte("fresh")); err != nil {
		t.Fatalf("Close on ended conn closed the next client's connection: Write: %v", err)
	}
	tst.ensureQuiesce(cl2, sv, lim)
	var buf [32]byte
	n, err := c2.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	} else if string(buf[:n]) != "fresh" {
		t.Errorf("second client read %q, want %q", buf[:n], "fresh")
	}
}

// M8: half-open connections that never complete the handshake must time out and
// free their pool slot, else PoolSize unanswered SYNs disable the listener for good.
func TestStackGoListenerHalfOpenTimeout(t *testing.T) {
	const svPort = 80
	const poolSize = 2
	const mtu = ethernet.MaxMTU
	const lim = 8
	const estbTimeout = time.Second
	tst := testerFrom(t, mtu)
	var now atomic.Int64
	now.Store(int64(time.Hour))
	sv := newTestStackClock(t, "sv1", 1, mtu, 1, 0, now.Load) // Listener pool times out on stack clock.
	half := newTestStack(t, "half2", 2, mtu, poolSize, 0)     // Sends SYNs, never sees SYN-ACKs.
	cl := newTestStack(t, "cl3", 3, mtu, 1, 0)
	half.SetGatewayHardwareAddr(sv.HardwareAddr())
	cl.SetGatewayHardwareAddr(sv.HardwareAddr())
	sv.SetGatewayHardwareAddr(cl.HardwareAddr())
	sg := sv.StackBlocking(backoffYield).StackGo(StackGoConfig{
		ListenerPoolConfig: TCPPoolConfig{
			PoolSize:           poolSize,
			QueueSize:          4,
			TxBufSize:          mtu,
			RxBufSize:          mtu,
			EstablishedTimeout: estbTimeout,
			ClosingTimeout:     estbTimeout,
			NewBackoff:         func() lneto.BackoffStrategy { return backoffYield },
		},
	})
	svaddr := netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)
	sock, err := sg.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM, svaddr, netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	l := sock.(net.Listener)
	defer l.Close()

	drainServer := func() {
		for range lim {
			sv.EgressEthernet(tst.buf) // SYN-ACKs to half-open peers are lost.
		}
	}
	for i := range poolSize {
		if err := half.DialTCP(newTestTCPConn(t, mtu, 4), uint16(1000+i), svaddr); err != nil {
			t.Fatal(err)
		}
		if exchangeEthernetOnce(t, half, sv, tst.buf) == 0 {
			t.Fatal("no SYN from half-open peer")
		}
	}
	drainServer()
	now.Add(int64(2 * estbTimeout))
	drainServer()

	clconn := newTestTCPConn(t, mtu, 4)
	if err := cl.DialTCP(clconn, 1337, svaddr); err != nil {
		t.Fatal(err)
	}
	tst.ensureQuiesce(cl, sv, lim)
	if readyToAccept(t, l) != 1 {
		t.Fatalf("listener with %d timed-out half-open conns did not accept new client (client state %s)", poolSize, clconn.State())
	}
}

func TestStackGoTCPDialRetriesPendingControl(t *testing.T) {
	const seed = 5678
	const MTU = ethernet.MaxMTU
	const tcptimeout = time.Second
	const yield = 1 * time.Millisecond
	// closure to simulate time.
	var now time.Duration
	nanotime := func() int64 { return int64(now) }
	client, sv, _, _ := newTCPStacks(t, seed, MTU)
	client.mono.Config(nanotime)

	tsched := ltesto.NewSched(t)
	tgoro := tsched.Goro()
	sg := client.StackBlocking(tgoro.Yield).StackGo(StackGoConfig{
		ListenerPoolConfig: TCPPoolConfig{
			QueueSize: 4,
			TxBufSize: MTU,
			RxBufSize: MTU,
			NewBackoff: func() lneto.BackoffStrategy {
				return backoffYield
			},
		},
		TCPDialTimeout: tcptimeout,
		TCPDialRetries: 2,
	})

	t.Log("start")

	laddr := netip.AddrPortFrom(netip.AddrFrom4(client.Addr4()), 1234)
	raddr := netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), 22)
	go func() {
		_, err := sg.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM, laddr, raddr)
		tgoro.FinishWithErr(err)
	}()
	npacket := 0
	ntcppacket := 0
	var buf [ethernet.MaxMTU + ethernet.MaxOverheadSize]byte
	for !t.Failed() { // Tinygo does not implement failnow.
		tsched.AwaitGoroYield()
		n, err := client.EgressEthernet(buf[:])
		now += tcptimeout / 100
		if err != nil {
			t.Fatal(err)
		} else if n == 0 {
			t.Fatal("expected packet from socketnetip", npacket, ntcppacket)
		}
		npacket++
		frm, ok := getTCPFrame(buf[:])
		if !ok {
			tsched.YieldToGoro()
			continue
		}
		ntcppacket++
		_, flags := frm.OffsetAndFlags()
		if flags != tcp.FlagSYN {
			t.Fatal("expected SYN packet")
		}
		switch ntcppacket {
		case 1:
			now += 2 * tcptimeout
			tsched.YieldToGoro()
		case 2:
			now += 2 * tcptimeout
			tsched.YieldToGoro()
			select {
			case <-time.After(time.Second):
				t.Fatal("SocketNetip hanging")
			case err := <-tsched.Done():
				if err != errDeadlineExceed {
					t.Fatal("expected deadline exceeded", err)
				}
				return // Test success.
			}
		}
	}
}

// TestStackGoTCPDialSurvivesManyWaitIterations checks the dial wait ends on its
// deadline and not on an iteration count: the peer stays silent for several
// times the former maxIter while simulated time advances by a fraction of the
// timeout, and the dial must still establish once the handshake is serviced.
func TestStackGoTCPDialSurvivesManyWaitIterations(t *testing.T) {
	const seed = 91011
	const MTU = ethernet.MaxMTU
	const tcptimeout = time.Second
	const quietIters = 4000 // well past the former iteration cap
	// Simulated clock: the quiet phase below advances less than 5% of the dial
	// timeout, so a timeout error there can only come from iteration counting.
	var now time.Duration
	nanotime := func() int64 { return int64(now) }
	client, sv, _, svconn := newTCPStacks(t, seed, MTU)
	client.mono.Config(nanotime)

	err := sv.ListenTCP4(svconn, 22)
	if err != nil {
		t.Fatal(err)
	}
	tsched := ltesto.NewSched(t)
	tgoro := tsched.Goro()
	sg := client.StackBlocking(tgoro.Yield).StackGo(StackGoConfig{
		ListenerPoolConfig: TCPPoolConfig{
			QueueSize: 4,
			TxBufSize: MTU,
			RxBufSize: MTU,
			NewBackoff: func() lneto.BackoffStrategy {
				return backoffYield
			},
		},
		TCPDialTimeout: tcptimeout,
		TCPDialRetries: 1,
	})

	laddr := netip.AddrPortFrom(netip.AddrFrom4(client.Addr4()), 1234)
	raddr := netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), 22)
	go func() {
		_, err := sg.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM, laddr, raddr)
		tgoro.FinishWithErr(err)
	}()

	// Quiet phase: no packets serviced, so the dialer only spins.
	for i := range quietIters {
		done, err := tsched.AwaitGoroYieldOrDone()
		if done {
			t.Fatalf("dial gave up during quiet phase after %d iterations: %v", i, err)
		}
		now += tcptimeout / 100000
		tsched.YieldToGoro()
	}

	// Handshake phase: pump packets until the dial completes, bounded rounds so
	// a broken handshake fails loudly.
	var buf [ethernet.MaxMTU + ethernet.MaxOverheadSize]byte
	for range 64 {
		done, err := tsched.AwaitGoroYieldOrDone()
		if done {
			if err != nil {
				t.Fatalf("dial failed after handshake serviced: %v", err)
			}
			return // Established under deadline: test success.
		}
		n, err := client.EgressEthernet(buf[:])
		if err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			if err := sv.IngressEthernet(buf[:n]); err != nil {
				t.Fatal(err)
			}
		}
		n, err = sv.EgressEthernet(buf[:])
		if err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			if err := client.IngressEthernet(buf[:n]); err != nil {
				t.Fatal(err)
			}
		}
		now += tcptimeout / 100000
		tsched.YieldToGoro()
	}
	t.Fatal("dial did not establish within handshake rounds")
}

// M3: the address returned by ReadFrom must not change when a later datagram arrives
// from another sender, else replies to the first sender go to the second.
func TestStackGoUDPReadFromAddrNotAliased(t *testing.T) {
	const mtu = ethernet.MaxMTU
	const udpPorts = 1
	const seedRng = 0x1337_c0de
	const svPort, clPort = 9000, 9001
	sv := newTestStack(t, "s1", seedRng, mtu, 0, udpPorts)
	cl1 := newTestStack(t, "s2", ^seedRng, mtu, 0, udpPorts)
	cl2 := newTestStack(t, "s3", seedRng+1, mtu, 0, udpPorts)
	if cl1.Addr4() == cl2.Addr4() || cl1.Addr4() == sv.Addr4() || cl2.Addr4() == sv.Addr4() {
		t.Fatal("test stacks must have distinct addresses")
	}

	sg := newTestStackGo(sv, 1, time.Second, 1)
	svaddr := netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)
	sock, err := sg.SocketNetip(context.Background(), "udp", syscall.AF_INET, sockDGRAM, svaddr, netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	pc := sock.(net.PacketConn)
	defer pc.Close()

	var buf [ethernet.MaxMTU + ethernet.MaxOverheadSize]byte
	var rbuf [64]byte
	var froms []net.Addr
	for _, cl := range []*StackAsync{cl1, cl2} {
		cl.SetGatewayHardwareAddr(sv.HardwareAddr())
		var conn udp.Conn
		err := conn.Configure(udp.ConnConfig{
			RxBuf: make([]byte, testUDPBufSize), TxBuf: make([]byte, testUDPBufSize),
			RxQueueSize: testUDPQueueSize, TxQueueSize: testUDPQueueSize,
			RWBackoff: backoffYield,
			MTU:       uint16(sv.MTU()),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := cl.DialUDP(&conn, clPort, svaddr); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		if exchangeEthernetOnce(t, cl, sv, buf[:]) == 0 {
			t.Fatal("no datagram from client")
		}
		pc.SetReadDeadline(time.Now().Add(time.Second))
		_, from, err := pc.ReadFrom(rbuf[:])
		if err != nil {
			t.Fatal(err)
		}
		froms = append(froms, from)
	}
	want := []string{
		netip.AddrPortFrom(netip.AddrFrom4(cl1.Addr4()), clPort).String(),
		netip.AddrPortFrom(netip.AddrFrom4(cl2.Addr4()), clPort).String(),
	}
	for i, from := range froms {
		if from.String() != want[i] {
			t.Errorf("ReadFrom #%d address is now %s, want %s", i, from, want[i])
		}
	}
}

func newTestStackGo(s *StackAsync, poolSize uint16, timeouts time.Duration, dialRetries int) StackGo {
	return s.StackBlocking(backoffYield).StackGo(StackGoConfig{
		ListenerPoolConfig: TCPPoolConfig{
			PoolSize:           poolSize,
			QueueSize:          4,
			TxBufSize:          ethernet.MaxMTU,
			RxBufSize:          ethernet.MaxMTU,
			EstablishedTimeout: timeouts,
			ClosingTimeout:     timeouts,
			NewBackoff:         newBackoffYield,
		},
		TCPDialTimeout: timeouts,
		TCPDialRetries: dialRetries,
	})
}
