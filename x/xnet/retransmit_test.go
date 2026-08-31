package xnet

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
)

// TestTCPRetransmitsLostSegment drops exactly one data segment and requires the
// bytes to arrive anyway, which is what [TCPPoolConfig.NanoTime] already promises
// in its own documentation. Without a LossRecovery installed the loss is terminal.
func TestTCPRetransmitsLostSegment(t *testing.T) {
	const (
		MTU     = ethernet.MaxMTU
		svPort  = 80
		bufSize = 2 << 10
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

	pool := TCPPoolConfig{
		PoolSize: 2, QueueSize: 4,
		TxBufSize: bufSize, RxBufSize: bufSize,
		EstablishedTimeout: 30 * time.Second,
		ClosingTimeout:     30 * time.Second,
		NewBackoff:         func() lneto.BackoffStrategy { return backoffYield },
	}
	svGo := sv.StackBlocking(backoffYield).StackGo(StackGoConfig{ListenerPoolConfig: pool})
	clGo := client.StackBlocking(backoffYield).StackGo(StackGoConfig{
		ListenerPoolConfig: pool,
		TCPDialTimeout:     2 * time.Second,
		TCPDialRetries:     2,
	})

	lsAny, err := svGo.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM,
		netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort), netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	listener := lsAny.(net.Listener)
	defer listener.Close()

	// dropNext arms the pump to swallow the next server→client data frame.
	var dropNext, dropped atomic.Bool
	stopPump := make(chan struct{})
	defer close(stopPump)
	go func() {
		buf := make([]byte, MTU+ethernet.MaxOverheadSize)
		for {
			select {
			case <-stopPump:
				return
			default:
			}
			moved := false
			if n, err := client.EgressEthernet(buf); err == nil && n > 0 {
				sv.IngressEthernet(buf[:n])
				moved = true
			}
			if n, err := sv.EgressEthernet(buf); err == nil && n > 0 {
				// Drop only a data-carrying frame: headers total 54 bytes, so
				// anything larger has payload. Dropping a bare ACK would test the
				// other direction's recovery instead.
				if dropNext.Load() && n > 14+20+20+8 {
					dropNext.Store(false)
					dropped.Store(true)
				} else {
					client.IngressEthernet(buf[:n])
				}
				moved = true
			}
			if !moved {
				runtime.Gosched()
			}
		}
	}()

	served := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(30 * time.Second))
		dropNext.Store(true) // the very next data frame is lost
		_, err = c.Write([]byte("this segment is lost in transit"))
		served <- err
	}()

	raddr := netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), svPort)
	cAny, err := clGo.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM,
		netip.AddrPort{}, raddr)
	if err != nil {
		t.Fatal(err)
	}
	conn := cAny.(net.Conn)
	defer conn.Close()
	// Generous on purpose: the first RTO is one second (RFC 6298 §2.1) and may
	// back off once. What is under test is that recovery happens at all.
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	want := "this segment is lost in transit"
	got := make([]byte, 0, len(want))
	rb := make([]byte, 64)
	for len(got) < len(want) {
		n, err := conn.Read(rb)
		got = append(got, rb[:n]...)
		if err != nil {
			t.Fatalf("read %d/%d bytes after losing one segment (dropped=%v): %v (no retransmission timer?)",
				len(got), len(want), dropped.Load(), err)
		}
	}
	if string(got) != want {
		t.Fatalf("read %q, want %q", got, want)
	}
	if !dropped.Load() {
		t.Fatal("no frame was dropped, so the test did not exercise retransmission")
	}
	if err := <-served; err != nil {
		t.Fatalf("server side: %v", err)
	}
}
