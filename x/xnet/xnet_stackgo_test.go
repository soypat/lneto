package xnet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

// newTestStack returns a stack at 10.0.0.<id> with MAC be:ef:00:00:00:<id>.
func newTestStack(t testing.TB, seed int64, id byte, tcpPorts, udpPorts uint16) *StackAsync {
	t.Helper()
	s := new(StackAsync)
	err := s.Reset(StackConfig{
		Hostname:          "Stack" + string('0'+id%10),
		RandSeed:          seed,
		StaticAddress4:    [4]byte{10, 0, 0, id},
		HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, id},
		MTU:               ethernet.MaxMTU,
		MaxActiveTCPPorts: tcpPorts,
		MaxActiveUDPPorts: udpPorts,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newTestStackGo(s *StackAsync, poolSize uint16, dialTimeout time.Duration, dialRetries int) StackGo {
	return s.StackBlocking(backoffYield).StackGo(StackGoConfig{
		ListenerPoolConfig: TCPPoolConfig{
			PoolSize:           poolSize,
			QueueSize:          4,
			TxBufSize:          ethernet.MaxMTU,
			RxBufSize:          ethernet.MaxMTU,
			EstablishedTimeout: 10 * time.Second,
			ClosingTimeout:     10 * time.Second,
			NewBackoff:         func() lneto.BackoffStrategy { return backoffYield },
		},
		TCPDialTimeout: dialTimeout,
		TCPDialRetries: dialRetries,
	})
}

func newTestTCPConn(t testing.TB) *tcp.Conn {
	t.Helper()
	conn := new(tcp.Conn)
	err := conn.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, ethernet.MaxMTU),
		TxBuf:             make([]byte, ethernet.MaxMTU),
		TxPacketQueueSize: 4,
		RWBackoff:         backoffYield,
	})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// pumpStacks exchanges Ethernet frames between a and b until neither has
// anything to send. Ingress errors are ignored: callers assert on resulting state.
func pumpStacks(t testing.TB, a, b *StackAsync) {
	t.Helper()
	var buf [ethernet.MaxMTU + ethernet.MaxOverheadSize]byte
	for range 64 {
		sent := false
		for _, p := range [2][2]*StackAsync{{a, b}, {b, a}} {
			n, err := p[0].EgressEthernet(buf[:])
			if err != nil {
				t.Fatal(err)
			} else if n > 0 {
				sent = true
				p[1].IngressEthernet(buf[:n])
			}
		}
		if !sent {
			return
		}
	}
	t.Fatal("stacks did not quiesce")
}

// readyToAccept reports the connections ready on a listener returned by [StackGo.SocketNetip].
func readyToAccept(t testing.TB, l net.Listener) int {
	t.Helper()
	ll, ok := l.(interface{ LnetoListener() *tcp.Listener })
	if !ok {
		t.Fatalf("listener %T does not expose LnetoListener", l)
	}
	return ll.LnetoListener().NumberOfReadyToAccept()
}

// M2: a net.Conn returned by Accept must stop working once its connection ends,
// even after the listener pool hands the same slot to the next client.
func TestStackGoAcceptedConnStaleAfterReuse(t *testing.T) {
	const svPort = 80
	sv := newTestStack(t, 1, 1, 1, 0)
	cl1 := newTestStack(t, 2, 2, 1, 0)
	cl2 := newTestStack(t, 3, 3, 1, 0)
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

	accept := func(cl *StackAsync, clconn *tcp.Conn) net.Conn {
		t.Helper()
		sv.SetGatewayHardwareAddr(cl.HardwareAddr())
		if err := cl.DialTCP(clconn, 1337, svaddr); err != nil {
			t.Fatal(err)
		}
		pumpStacks(t, cl, sv)
		if readyToAccept(t, l) != 1 {
			t.Fatalf("client %v not ready to accept (client state %s)", cl.Addr4(), clconn.State())
		}
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	c1 := newTestTCPConn(t)
	stale := accept(cl1, c1)
	// First connection ends normally: client closes, then server closes.
	c1.Close()
	pumpStacks(t, cl1, sv)
	stale.Close()
	pumpStacks(t, cl1, sv)

	// Pool of 1: the second client is served by the slot the first one used.
	c2 := newTestTCPConn(t)
	fresh := accept(cl2, c2)

	if n, err := stale.Write([]byte("stale")); err == nil {
		t.Errorf("Write on ended conn succeeded writing %d bytes into the next client's connection", n)
	}
	stale.Close()
	if _, err := fresh.Write([]byte("fresh")); err != nil {
		t.Fatalf("Close on ended conn closed the next client's connection: Write: %v", err)
	}
	pumpStacks(t, cl2, sv)
	var buf [32]byte
	n, err := c2.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	} else if string(buf[:n]) != "fresh" {
		t.Errorf("second client read %q, want %q", buf[:n], "fresh")
	}
}

// M3: the address returned by ReadFrom must not change when a later datagram arrives
// from another sender, else replies to the first sender go to the second.
func TestStackGoUDPReadFromAddrNotAliased(t *testing.T) {
	const svPort, clPort = 9000, 9001
	sv := newTestStack(t, 1, 1, 0, 1)
	cl1 := newTestStack(t, 2, 2, 0, 1)
	cl2 := newTestStack(t, 3, 3, 0, 1)
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

// M6: a failed dial must release its port-table entry. Otherwise MaxActiveTCPPorts
// failed dials leave the stack unable to open any TCP connection.
func TestStackGoFailedDialReleasesPort(t *testing.T) {
	const maxPorts = 2
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
			cl := newTestStack(t, 1, 1, maxPorts, 0)
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

			err := cl.DialTCP(newTestTCPConn(t), 1234, raddr)
			if err != nil {
				t.Fatalf("DialTCP after %d failed dials: %v", maxPorts+1, err)
			}
		})
	}
}

// M18: SocketNetip must honor its context during the dial handshake.
func TestStackGoDialHonorsContext(t *testing.T) {
	const dialTimeout = 3 * time.Second
	cl := newTestStack(t, 1, 1, 1, 0)
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
	sv := newTestStack(t, 1, 1, 1, 0)
	cl := newTestStack(t, 2, 2, 1, 0)
	sv.SetGatewayHardwareAddr(cl.HardwareAddr())
	cl.SetGatewayHardwareAddr(sv.HardwareAddr())
	// Listener with no free connections answers every SYN with RST.
	pool, err := NewTCPPool(TCPPoolConfig{
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
		time.Sleep(time.Millisecond)
	}
}

// M19: a dial without a deadline must return once the handshake completes, even
// if the peer closes the connection right after accepting it.
func TestStackGoDialPeerClosesAfterAccept(t *testing.T) {
	const seed = 4321
	const svPort = 22
	client, sv, _, svconn := newTCPStacks(t, seed, ethernet.MaxMTU)
	if err := sv.ListenTCP4(svconn, svPort); err != nil {
		t.Fatal(err)
	}
	tsched := ltesto.NewSched(t)
	tgoro := tsched.Goro()
	sg := client.StackBlocking(tgoro.Yield).StackGo(StackGoConfig{
		ListenerPoolConfig: TCPPoolConfig{
			QueueSize:  4,
			TxBufSize:  ethernet.MaxMTU,
			RxBufSize:  ethernet.MaxMTU,
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
		pumpStacks(t, client, sv)
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
	pumpStacks(t, client, sv)
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
