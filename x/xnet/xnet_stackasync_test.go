package xnet

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/tcp"
)

// M40: the ISN of one connection must not predict the ISN of the next (RFC 6528).
func TestStackAsyncDialISNUnpredictable(t *testing.T) {
	const lookahead = 64
	cl := newTestStack(t, 1, 1, 2, 0)
	raddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 80)
	var buf [ethernet.MaxMTU + ethernet.MaxOverheadSize]byte
	var isn [2]tcp.Value
	for i := range isn {
		if err := cl.DialTCP(newTestTCPConn(t), uint16(1000+i), raddr); err != nil {
			t.Fatal(err)
		}
		n, err := cl.EgressEthernet(buf[:])
		if err != nil {
			t.Fatal(err)
		}
		frm, ok := getTCPFrame(buf[:n])
		if !ok {
			t.Fatal("no SYN emitted")
		}
		isn[i] = frm.Seq()
	}
	next := isn[0]
	for k := 1; k <= lookahead; k++ {
		next = internal.Prand32(next)
		if next == isn[1] {
			t.Fatalf("second ISN %d is xorshift step %d of first ISN %d", isn[1], k, isn[0])
		}
	}
}

// M21: aborting a connection while another goroutine drives the stack must not
// race on the connection ID. Only detectable with -race.
func TestStackAsyncAbortConcurrentWithEgress(t *testing.T) {
	cl := newTestStack(t, 1, 1, 1, 0)
	raddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 80)
	conn := newTestTCPConn(t)
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
