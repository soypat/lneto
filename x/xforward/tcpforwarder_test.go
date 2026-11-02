package xforward_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/x/xforward"
)

func newForwarder(t testing.TB, wake func()) *xforward.TCPForwarder {
	t.Helper()
	tf := new(xforward.TCPForwarder)
	start := time.Now()
	err := tf.Configure(xforward.TCPForwarderConfig{
		TCPHandlerConfig: testTCPConfig(func() int64 { return int64(time.Since(start)) }),
		Wake:             wake,
		RWBackoff:        testBackoff,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tf
}

// connectFwd returns a FlowConn for an established flow from p.
func connectFwd(t testing.TB, tf *xforward.TCPForwarder, p *tcpPeer) xforward.FlowConn {
	t.Helper()
	flow, isNew, err := tf.Demux(mustValidate(t, p.send()))
	if err != nil || !isNew {
		t.Fatalf("SYN: isNew=%v err=%v", isNew, err)
	}
	c, err := tf.Accept(flow, make([]byte, 4096), make([]byte, 4096))
	if err != nil {
		t.Fatal(err)
	}
	exchange(t, tf, p)
	return c
}

func TestFlowConnReadDeadline(t *testing.T) {
	tf := newForwarder(t, nil)
	c := connectFwd(t, tf, newPeer(t, "10.0.0.2:40000", "192.0.2.1:443", 4096))
	if err := c.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 16)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("got %v, want os.ErrDeadlineExceeded", err)
	}
}

func TestFlowConnUnblock(t *testing.T) {
	for _, tc := range []struct {
		name string
		stop func(*xforward.TCPForwarder, xforward.FlowConn)
		want error
	}{
		{name: "close", stop: func(_ *xforward.TCPForwarder, c xforward.FlowConn) { c.Close() }, want: io.EOF},
		{name: "abort", stop: func(tf *xforward.TCPForwarder, _ xforward.FlowConn) { tf.Abort() }, want: net.ErrClosed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tf := newForwarder(t, nil)
			c := connectFwd(t, tf, newPeer(t, "10.0.0.2:40000", "192.0.2.1:443", 4096))
			done := make(chan error, 1)
			go func() {
				_, err := c.Read(make([]byte, 16))
				done <- err
			}()
			time.Sleep(5 * time.Millisecond) // Let Read block.
			tc.stop(tf, c)
			select {
			case err := <-done:
				if !errors.Is(err, tc.want) {
					t.Fatalf("got %v, want %v", err, tc.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Read did not unblock")
			}
		})
	}
}

// TestTCPForwarderConcurrentFlows relays data both ways on several flows from
// concurrent FlowConn readers and writers. The network goroutine sleeps only on
// Wake, so a lost wakeup stalls the test.
func TestTCPForwarderConcurrentFlows(t *testing.T) {
	const nflows, size, bufSize = 4, 64 << 10, 4096
	wake := make(chan struct{}, 1)
	tf := newForwarder(t, func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	})
	peers := make([]*tcpPeer, nflows)
	up, down := make([][]byte, nflows), make([][]byte, nflows)
	for i := range peers {
		peers[i] = newPeer(t, fmt.Sprintf("10.0.0.2:%d", 40000+i), "192.0.2.1:80", bufSize)
		up[i], down[i] = pattern(size, byte(2*i)), pattern(size, byte(2*i+1))
	}
	conns := make(chan xforward.FlowConn, nflows)
	stop, downDone, netDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	gotDown := make([][]byte, nflows)
	allDown := downDone

	// Network goroutine: owns the peers, moves packets and plays the peers' application.
	go func() {
		defer close(netDone)
		var out [testMTU]byte
		var vld lneto.Validator
		buf := make([]byte, bufSize)
		sentUp := make([]int, nflows)
		for {
			moved := false
			complete := true
			for i, p := range peers {
				if n := min(size-sentUp[i], p.h.FreeOutput()); n > 0 && p.h.State().TxDataOpen() {
					p.h.Write(up[i][sentUp[i] : sentUp[i]+n])
					if sentUp[i] += n; sentUp[i] == size {
						p.h.Close()
					}
					moved = true
				}
				if n, _ := p.h.Read(buf); n > 0 {
					gotDown[i] = append(gotDown[i], buf[:n]...)
					moved = true
				}
				complete = complete && len(gotDown[i]) == size
				pkt := p.send()
				if pkt == nil {
					continue
				}
				moved = true
				vp, err := xforward.ValidatePacket(pkt, &vld)
				if err != nil {
					t.Error(err)
					return
				}
				flow, isNew, _ := tf.Demux(vp)
				if isNew {
					c, err := tf.Accept(flow, make([]byte, bufSize), make([]byte, bufSize))
					if err != nil {
						t.Error(err)
						return
					}
					conns <- c
				}
			}
			if complete && downDone != nil {
				close(downDone)
				downDone = nil
			}
			if n, _ := tf.Encapsulate(out[:], 0); n > 0 {
				vp, err := xforward.ValidatePacket(out[:n], &vld)
				i := int(vp.ID().Local.Port()) - 40000
				if err != nil || i < 0 || i >= nflows {
					t.Errorf("bad packet from forwarder: %v %v", err, vp.ID())
					return
				} else if err = peers[i].deliver(out[:n]); err != nil {
					t.Error(err)
					return
				}
				moved = true
			}
			if moved {
				continue
			}
			select {
			case <-stop:
				return
			case <-wake:
			}
		}
	}()

	var wg sync.WaitGroup
	accepted := make([]xforward.FlowConn, 0, nflows)
	for range nflows {
		var c xforward.FlowConn
		select {
		case c = <-conns:
		case <-time.After(10 * time.Second):
			t.Fatal("flow not accepted")
		}
		accepted = append(accepted, c)
		i := int(c.ID().Remote.Port()) - 40000
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := c.Write(down[i]); err != nil {
				t.Errorf("flow %d Write: %v", i, err)
			} else if err = c.CloseWrite(); err != nil {
				t.Errorf("flow %d CloseWrite: %v", i, err)
			}
		}()
		go func() {
			defer wg.Done()
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, up[i]) {
				t.Errorf("flow %d upstream: got %d bytes err=%v, want %d", i, len(got), err, size)
			}
		}()
	}
	wg.Wait()
	select {
	case <-allDown:
	case <-time.After(10 * time.Second):
		t.Fatal("peers did not receive all data")
	}
	for _, c := range accepted {
		c.Close()
	}
	close(stop)
	<-netDone
	for i := range gotDown {
		if !bytes.Equal(gotDown[i], down[i]) {
			t.Errorf("flow %d downstream mismatch: %d bytes", i, len(gotDown[i]))
		}
	}
}
