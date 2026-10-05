package xnet

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
)

// M8: half-open connections that never complete the handshake must time out and
// free their pool slot, else PoolSize unanswered SYNs disable the listener for good.
func TestStackGoListenerHalfOpenTimeout(t *testing.T) {
	const svPort = 80
	const poolSize = 2
	const estbTimeout = time.Second
	var now atomic.Int64
	now.Store(int64(time.Hour))
	sv := newTestStack(t, 1, 1, 1, 0)
	half := newTestStack(t, 2, 2, poolSize, 0) // Sends SYNs, never sees SYN-ACKs.
	cl := newTestStack(t, 3, 3, 1, 0)
	half.SetGatewayHardwareAddr(sv.HardwareAddr())
	cl.SetGatewayHardwareAddr(sv.HardwareAddr())
	sv.SetGatewayHardwareAddr(cl.HardwareAddr())
	sg := sv.StackBlocking(backoffYield).StackGo(StackGoConfig{
		ListenerPoolConfig: TCPPoolConfig{
			PoolSize:           poolSize,
			QueueSize:          4,
			TxBufSize:          ethernet.MaxMTU,
			RxBufSize:          ethernet.MaxMTU,
			EstablishedTimeout: estbTimeout,
			ClosingTimeout:     estbTimeout,
			NanoTime:           now.Load,
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

	var buf [ethernet.MaxMTU + ethernet.MaxOverheadSize]byte
	drainServer := func() {
		for range 8 {
			sv.EgressEthernet(buf[:]) // SYN-ACKs to half-open peers are lost.
		}
	}
	for i := range poolSize {
		if err := half.DialTCP(newTestTCPConn(t), uint16(1000+i), svaddr); err != nil {
			t.Fatal(err)
		}
		if exchangeEthernetOnce(t, half, sv, buf[:]) == 0 {
			t.Fatal("no SYN from half-open peer")
		}
	}
	drainServer()
	now.Add(int64(2 * estbTimeout))
	drainServer()

	clconn := newTestTCPConn(t)
	if err := cl.DialTCP(clconn, 1337, svaddr); err != nil {
		t.Fatal(err)
	}
	pumpStacks(t, cl, sv)
	if readyToAccept(t, l) != 1 {
		t.Fatalf("listener with %d timed-out half-open conns did not accept new client (client state %s)", poolSize, clconn.State())
	}
}
