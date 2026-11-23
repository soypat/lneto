package xnet

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/tcp"
)

// TestStackGoDialReusesClosedConn checks a dial after the last dialed
// connection closed reuses it and its buffers, and that the old handle is stale.
func TestStackGoDialReusesClosedConn(t *testing.T) {
	const mtu = ethernet.MaxMTU
	client, sv, _, svconn := newTCPStacks(t, 4242, mtu)
	sg := newTestStackGo(client, 1, time.Second, 1)
	tst := testerFrom(t, mtu)
	laddr := netip.AddrPortFrom(netip.AddrFrom4(client.Addr4()), 0)
	raddr := netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), 22)

	dial := func() (net.Conn, *tcp.Conn) {
		t.Helper()
		if err := sv.ListenTCP4(svconn, 22); err != nil {
			t.Fatal(err)
		}
		type result struct {
			c   any
			err error
		}
		done := make(chan result, 1)
		go func() {
			c, err := sg.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM, laddr, raddr)
			done <- result{c, err}
		}()
		for {
			select {
			case r := <-done:
				if r.err != nil {
					t.Fatal("dial:", r.err)
				}
				c := r.c.(tcpconn)
				return c, c.LnetoConn()
			default:
				tst.ensureQuiesce(client, sv, 4)
			}
		}
	}
	// The server closes first so the client ends in CLOSED, not TIME-WAIT.
	closeBoth := func(c net.Conn, lc *tcp.Conn) {
		t.Helper()
		svconn.Close()
		tst.ensureQuiesce(client, sv, 16)
		c.Close()
		tst.ensureQuiesce(client, sv, 16)
		if !lc.State().IsClosed() || !svconn.State().IsClosed() {
			t.Fatalf("not closed: client %s server %s", lc.State(), svconn.State())
		}
	}

	c1, lc1 := dial()
	closeBoth(c1, lc1)
	c2, lc2 := dial()
	if lc2 != lc1 {
		t.Fatal("second dial did not reuse the closed connection")
	}
	if _, err := c1.Write([]byte("stale")); err == nil {
		t.Fatal("write on the first connection's handle succeeded")
	}
	if _, err := c2.Write([]byte("fresh")); err != nil {
		t.Fatal(err)
	}
	tst.ensureQuiesce(client, sv, 8)
	var buf [16]byte
	n, err := svconn.Read(buf[:])
	if err != nil || string(buf[:n]) != "fresh" {
		t.Fatalf("server read %q, %v", buf[:n], err)
	}
}

func TestDialPoolGetOpenConn(t *testing.T) {
	var p dialPool
	p.max = 1
	cfg := TCPPoolConfig{QueueSize: 4, TxBufSize: 512, RxBufSize: 512, NewBackoff: newBackoffYield}
	d1, err := p.get(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	// d1 is still dialing, so it must not be handed out again.
	d2, err := p.get(&cfg)
	if err != nil {
		t.Fatal(err)
	} else if d2 == d1 {
		t.Fatal("conn being dialed was reused")
	} else if len(p.conns) != 1 {
		t.Fatalf("pool kept %d conns, want 1", len(p.conns))
	}
	p.put(d1)
	if d3, _ := p.get(&cfg); d3 != d1 {
		t.Fatal("closed conn not reused")
	}
}
