package xforward_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
	"github.com/soypat/lneto/x/xforward"
)

func TestTCPHandlerConfigure(t *testing.T) {
	var clock testClock
	for _, tc := range []struct {
		name string
		mod  func(*xforward.TCPHandlerConfig)
		want error
	}{
		{name: "valid"},
		{name: "no clock", mod: func(c *xforward.TCPHandlerConfig) { c.NanoTime = nil }, want: lneto.ErrMissingHALConfig},
		{name: "zero flows", mod: func(c *xforward.TCPHandlerConfig) { c.MaxFlows = 0 }, want: lneto.ErrInvalidConfig},
		{name: "too many flows", mod: func(c *xforward.TCPHandlerConfig) { c.MaxFlows = 1<<15 + 1 }, want: lneto.ErrInvalidConfig},
		{name: "pending above flows", mod: func(c *xforward.TCPHandlerConfig) { c.MaxPending = c.MaxFlows + 1 }, want: lneto.ErrInvalidConfig},
		{name: "zero queue", mod: func(c *xforward.TCPHandlerConfig) { c.TxPacketQueueSize = 0 }, want: lneto.ErrInvalidConfig},
		{name: "zero pending timeout", mod: func(c *xforward.TCPHandlerConfig) { c.PendingTimeout = 0 }, want: lneto.ErrInvalidConfig},
		{name: "zero key", mod: func(c *xforward.TCPHandlerConfig) { c.Key = [16]byte{} }, want: lneto.ErrInvalidConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testTCPConfig(clock.nanotime)
			if tc.mod != nil {
				tc.mod(&cfg)
			}
			var th xforward.TCPHandler
			if err := th.Configure(cfg); err != tc.want {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// optionMSS returns the MSS option of a TCP frame, 0 if absent.
func optionMSS(tfrm tcp.Frame) (mss uint16) {
	var codec tcp.OptionCodec
	codec.ForEachOption(tfrm.Options(), func(kind tcp.OptionKind, data []byte) error {
		if kind == tcp.OptMaxSegmentSize && len(data) == 2 {
			mss = binary.BigEndian.Uint16(data)
		}
		return nil
	})
	return mss
}

func TestTCPHandlerHandshake(t *testing.T) {
	for _, tc := range []struct {
		name      string
		peer, dst string
		wantMSS   uint16
	}{
		{name: "ipv4", peer: "10.0.0.2:40000", dst: "93.184.216.34:443", wantMSS: testMTU - 40},
		{name: "ipv6", peer: "[fd00::2]:40000", dst: "[2001:db8::1]:443", wantMSS: testMTU - 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTCPEnv(t, nil)
			p := newPeer(t, tc.peer, tc.dst, 4096)
			flow, isNew, err := env.demux(t, p.send())
			if err != nil || !isNew {
				t.Fatalf("SYN: isNew=%v err=%v", isNew, err)
			}
			if flow.ID.Local != p.dst || flow.ID.Remote != p.addr {
				t.Fatalf("flow ID %v", flow.ID)
			}
			if pkt := encap(t, &env.fwd); pkt != nil {
				t.Fatal("SYN-ACK sent before Accept")
			}
			if err = env.fwd.Accept(flow, make([]byte, 4096), make([]byte, 4096)); err != nil {
				t.Fatal(err)
			}
			synack := encap(t, &env.fwd)
			if synack == nil {
				t.Fatal("no SYN-ACK after Accept")
			}
			tfrm := tcpOf(t, synack)
			if _, flags := tfrm.OffsetAndFlags(); flags != tcp.FlagSYN|tcp.FlagACK {
				t.Errorf("flags %s, want SYN|ACK", flags)
			}
			if mss := optionMSS(tfrm); mss != tc.wantMSS {
				t.Errorf("MSS %d, want %d", mss, tc.wantMSS)
			}
			if err = p.deliver(synack); err != nil {
				t.Fatal(err)
			}
			exchange(t, &env.fwd, p)
			if st := p.h.State(); st != tcp.StateEstablished {
				t.Fatalf("peer state %s", st)
			}
			p.h.Write([]byte("ping"))
			exchange(t, &env.fwd, p)
			buf := make([]byte, 16)
			if n, err := env.fwd.Read(flow, buf); err != nil || string(buf[:n]) != "ping" {
				t.Fatalf("Read %q, %v", buf[:n], err)
			}
			if _, err = env.fwd.Write(flow, []byte("pong")); err != nil {
				t.Fatal(err)
			}
			exchange(t, &env.fwd, p)
			if n, _ := p.h.Read(buf); string(buf[:n]) != "pong" {
				t.Fatalf("peer read %q", buf[:n])
			}
		})
	}
}

func TestTCPHandlerReject(t *testing.T) {
	env := newTCPEnv(t, nil)
	p := newPeer(t, "10.0.0.2:40000", "192.0.2.1:443", 4096)
	flow, _, _ := env.demux(t, p.send())
	if err := env.fwd.Reject(flow); err != nil {
		t.Fatal(err)
	}
	rst := encap(t, &env.fwd)
	if rst == nil {
		t.Fatal("no RST after Reject")
	}
	tfrm := tcpOf(t, rst)
	if _, flags := tfrm.OffsetAndFlags(); flags != tcp.FlagRST|tcp.FlagACK || tfrm.Seq() != 0 || tfrm.Ack() != 1001 {
		t.Errorf("got %s seq=%d ack=%d, want RST|ACK seq=0 ack=1001", flags, tfrm.Seq(), tfrm.Ack())
	}
	if err := p.deliver(rst); err != nil {
		t.Fatal(err)
	}
	if st := p.h.State(); st != tcp.StateClosed {
		t.Errorf("peer state %s after refusal", st)
	}
	if err := env.fwd.Accept(flow, make([]byte, 4096), make([]byte, 4096)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept after Reject: got %v", err)
	}
	if pkt := encap(t, &env.fwd); pkt != nil {
		t.Error("unexpected packet after Reject")
	}
}

func TestTCPHandlerStraySegment(t *testing.T) {
	src, dst := netip.MustParseAddrPort("10.0.0.9:1234"), netip.MustParseAddrPort("192.0.2.1:80")
	for _, tc := range []struct {
		name      string
		seg       []byte
		wantFlags tcp.Flags // 0 means no reply.
		wantSeq   tcp.Value
		wantAck   tcp.Value
	}{
		{name: "ack", seg: tcpSeg(1234, 80, 5, 77, tcp.FlagACK, nil), wantFlags: tcp.FlagRST, wantSeq: 77},
		{name: "syn-ack", seg: tcpSeg(1234, 80, 5, 77, tcp.FlagSYN|tcp.FlagACK, nil), wantFlags: tcp.FlagRST, wantSeq: 77},
		{name: "data without ack", seg: tcpSeg(1234, 80, 5, 0, tcp.FlagPSH, []byte("abc")), wantFlags: tcp.FlagRST | tcp.FlagACK, wantAck: 8},
		{name: "fin", seg: tcpSeg(1234, 80, 5, 0, tcp.FlagFIN, nil), wantFlags: tcp.FlagRST | tcp.FlagACK, wantAck: 6},
		{name: "rst", seg: tcpSeg(1234, 80, 5, 0, tcp.FlagRST, nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTCPEnv(t, nil)
			_, isNew, err := env.demux(t, buildIP(src.Addr(), dst.Addr(), lneto.IPProtoTCP, tc.seg))
			if isNew || !errors.Is(err, lneto.ErrPacketDrop) {
				t.Fatalf("isNew=%v err=%v, want ErrPacketDrop", isNew, err)
			}
			pkt := encap(t, &env.fwd)
			if tc.wantFlags == 0 {
				if pkt != nil {
					t.Fatal("replied to RST")
				}
				return
			} else if pkt == nil {
				t.Fatal("no RST")
			}
			if id := mustValidate(t, pkt).ID(); id.Local != src || id.Remote != dst {
				t.Errorf("RST addressed %v", id)
			}
			tfrm := tcpOf(t, pkt)
			if _, flags := tfrm.OffsetAndFlags(); flags != tc.wantFlags || tfrm.Seq() != tc.wantSeq || tfrm.Ack() != tc.wantAck {
				t.Errorf("got %s seq=%d ack=%d, want %s seq=%d ack=%d", flags, tfrm.Seq(), tfrm.Ack(), tc.wantFlags, tc.wantSeq, tc.wantAck)
			}
		})
	}
}

func TestTCPHandlerHeldSYN(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, env *tcpEnv, p *tcpPeer, syn []byte, flow xforward.TCPFlow)
	}{
		{name: "retransmitted SYN while pending", run: func(t *testing.T, env *tcpEnv, p *tcpPeer, syn []byte, flow xforward.TCPFlow) {
			if _, isNew, err := env.demux(t, syn); isNew || !errors.Is(err, lneto.ErrPacketDrop) {
				t.Fatalf("isNew=%v err=%v", isNew, err)
			}
			if encap(t, &env.fwd) != nil {
				t.Fatal("replied to retransmitted SYN")
			}
		}},
		{name: "MaxPending drops without RST", run: func(t *testing.T, env *tcpEnv, p *tcpPeer, syn []byte, flow xforward.TCPFlow) {
			p2 := newPeer(t, "10.0.0.2:40001", "192.0.2.1:443", 4096)
			if _, isNew, err := env.demux(t, p2.send()); isNew || !errors.Is(err, lneto.ErrPacketDrop) {
				t.Fatalf("isNew=%v err=%v", isNew, err)
			}
			if encap(t, &env.fwd) != nil {
				t.Fatal("RST for SYN over MaxPending")
			}
		}},
		{name: "peer RST cancels", run: func(t *testing.T, env *tcpEnv, p *tcpPeer, syn []byte, flow xforward.TCPFlow) {
			rst := buildIP(p.addr.Addr(), p.dst.Addr(), lneto.IPProtoTCP, tcpSeg(p.addr.Port(), p.dst.Port(), 1001, 0, tcp.FlagRST, nil))
			env.demux(t, rst)
			if err := env.fwd.Accept(flow, make([]byte, 4096), make([]byte, 4096)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Accept: got %v, want net.ErrClosed", err)
			}
		}},
		{name: "PendingTimeout rejects", run: func(t *testing.T, env *tcpEnv, p *tcpPeer, syn []byte, flow xforward.TCPFlow) {
			if d := env.fwd.NextDeadline(); d != int64(time.Second) {
				t.Fatalf("NextDeadline %d, want %d", d, time.Second)
			}
			env.clock.now = int64(time.Second)
			rst := encap(t, &env.fwd)
			if rst == nil {
				t.Fatal("no RST on timeout")
			}
			if _, flags := tcpOf(t, rst).OffsetAndFlags(); flags != tcp.FlagRST|tcp.FlagACK {
				t.Errorf("flags %s", flags)
			}
			if err := env.fwd.Accept(flow, make([]byte, 4096), make([]byte, 4096)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Accept: got %v, want net.ErrClosed", err)
			}
		}},
		{name: "lost SYN-ACK resent on SYN retransmit", run: func(t *testing.T, env *tcpEnv, p *tcpPeer, syn []byte, flow xforward.TCPFlow) {
			if err := env.fwd.Accept(flow, make([]byte, 4096), make([]byte, 4096)); err != nil {
				t.Fatal(err)
			}
			lost := encap(t, &env.fwd)
			if _, isNew, err := env.demux(t, syn); isNew || err != nil {
				t.Fatalf("isNew=%v err=%v", isNew, err)
			}
			again := encap(t, &env.fwd)
			if again == nil || tcpOf(t, again).Seq() != tcpOf(t, lost).Seq() {
				t.Fatal("SYN-ACK not resent")
			}
			if err := p.deliver(again); err != nil {
				t.Fatal(err)
			}
			exchange(t, &env.fwd, p)
			if st := p.h.State(); st != tcp.StateEstablished {
				t.Fatalf("peer state %s", st)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTCPEnv(t, func(_ *tcpEnv, c *xforward.TCPHandlerConfig) { c.MaxPending = 1 })
			p := newPeer(t, "10.0.0.2:40000", "192.0.2.1:443", 4096)
			syn := p.send()
			flow, isNew, err := env.demux(t, syn)
			if err != nil || !isNew {
				t.Fatalf("SYN: isNew=%v err=%v", isNew, err)
			}
			tc.run(t, env, p, syn, flow)
		})
	}
}

func TestTCPHandlerTransfer(t *testing.T) {
	for _, tc := range []struct{ name, peer, dst string }{
		{name: "ipv4", peer: "10.0.0.2:40000", dst: "192.0.2.1:443"},
		{name: "ipv6", peer: "[fd00::2]:40000", dst: "[2001:db8::1]:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const size, bufSize = 64 << 10, 4096
			env := newTCPEnv(t, nil)
			p := newPeer(t, tc.peer, tc.dst, bufSize)
			flow := env.connect(t, p, make([]byte, bufSize), make([]byte, bufSize))
			up, down := pattern(size, 1), pattern(size, 2)
			var gotUp, gotDown []byte
			var sentUp, sentDown int
			buf := make([]byte, bufSize)
			for range 10_000 {
				if n := min(size-sentUp, p.h.FreeOutput()); n > 0 {
					p.h.Write(up[sentUp : sentUp+n])
					sentUp += n
				}
				n, err := env.fwd.Write(flow, down[sentDown:])
				if err != nil {
					t.Fatal(err)
				}
				sentDown += n
				exchange(t, &env.fwd, p)
				n, _ = env.fwd.Read(flow, buf)
				gotUp = append(gotUp, buf[:n]...)
				n, _ = p.h.Read(buf)
				gotDown = append(gotDown, buf[:n]...)
				if len(gotUp) == size && len(gotDown) == size {
					break
				}
			}
			if !bytes.Equal(gotUp, up) || !bytes.Equal(gotDown, down) {
				t.Fatalf("transfer mismatch: up %d/%d down %d/%d", len(gotUp), size, len(gotDown), size)
			}
			if rx, tx, err := env.fwd.Stats(flow); err != nil || rx == 0 || tx == 0 {
				t.Errorf("Stats rx=%d tx=%d err=%v", rx, tx, err)
			}
		})
	}
}

func TestTCPHandlerHalfCloseAndRelease(t *testing.T) {
	var released [][]byte
	env := newTCPEnv(t, func(_ *tcpEnv, c *xforward.TCPHandlerConfig) {
		c.MaxFlows, c.MaxPending = 1, 1
		c.ReleaseBuffers = func(rx, tx []byte) { released = append(released, rx, tx) }
	})
	p := newPeer(t, "10.0.0.2:40000", "192.0.2.1:443", 4096)
	rx, tx := make([]byte, 4096), make([]byte, 4096)
	flow := env.connect(t, p, rx, tx)
	if err := env.fwd.CloseWrite(flow); err != nil {
		t.Fatal(err)
	}
	exchange(t, &env.fwd, p)
	if st := p.h.State(); st != tcp.StateCloseWait {
		t.Fatalf("peer state %s after CloseWrite, want CloseWait", st)
	}
	p.h.Write([]byte("bye"))
	exchange(t, &env.fwd, p)
	buf := make([]byte, 16)
	if n, err := env.fwd.Read(flow, buf); err != nil || string(buf[:n]) != "bye" {
		t.Fatalf("Read after CloseWrite: %q, %v", buf[:n], err)
	}
	p.h.Close()
	exchange(t, &env.fwd, p)
	if _, err := env.fwd.Read(flow, buf); err != io.EOF {
		t.Fatalf("Read after peer FIN: got %v, want io.EOF", err)
	}
	if err := env.fwd.Release(flow); err != nil {
		t.Fatal(err)
	}
	if len(released) != 2 || &released[0][0] != &rx[0] || &released[1][0] != &tx[0] {
		t.Fatalf("ReleaseBuffers not given Accept's buffers: %d calls", len(released)/2)
	}
	if _, err := env.fwd.Read(flow, buf); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Read on reaped flow: got %v", err)
	}
	p2 := newPeer(t, "10.0.0.2:40001", "192.0.2.1:443", 4096)
	if _, isNew, err := env.demux(t, p2.send()); err != nil || !isNew {
		t.Fatalf("slot not reaped: isNew=%v err=%v", isNew, err)
	}
}

func TestTCPHandlerReleaseOpen(t *testing.T) {
	env := newTCPEnv(t, func(_ *tcpEnv, c *xforward.TCPHandlerConfig) { c.MaxFlows, c.MaxPending = 1, 1 })
	p := newPeer(t, "10.0.0.2:40000", "192.0.2.1:443", 4096)
	flow := env.connect(t, p, make([]byte, 4096), make([]byte, 4096))
	if err := env.fwd.Release(flow); err != nil {
		t.Fatal(err)
	}
	exchange(t, &env.fwd, p)
	if st := p.h.State(); st != tcp.StateCloseWait {
		t.Fatalf("peer state %s after Release", st)
	}
	p.h.Close()
	exchange(t, &env.fwd, p)
	p2 := newPeer(t, "10.0.0.2:40001", "192.0.2.1:443", 4096)
	if _, isNew, err := env.demux(t, p2.send()); err != nil || !isNew {
		t.Fatalf("closed flow not reaped: isNew=%v err=%v", isNew, err)
	}
}

func TestTCPHandlerCloseTimeout(t *testing.T) {
	env := newTCPEnv(t, func(_ *tcpEnv, c *xforward.TCPHandlerConfig) { c.MaxFlows, c.MaxPending = 1, 1 })
	p := newPeer(t, "10.0.0.2:40000", "192.0.2.1:443", 4096)
	flow := env.connect(t, p, make([]byte, 4096), make([]byte, 4096))
	if err := env.fwd.Release(flow); err != nil {
		t.Fatal(err)
	}
	encap(t, &env.fwd) // FIN lost; peer never answers.
	env.clock.now = int64(time.Second)
	encap(t, &env.fwd)
	p2 := newPeer(t, "10.0.0.2:40001", "192.0.2.1:443", 4096)
	if _, isNew, err := env.demux(t, p2.send()); err != nil || !isNew {
		t.Fatalf("flow not reaped after CloseTimeout: isNew=%v err=%v", isNew, err)
	}
}

func TestTCPHandlerRetransmit(t *testing.T) {
	env := newTCPEnv(t, func(env *tcpEnv, c *xforward.TCPHandlerConfig) {
		c.NewPolicy = func() tcp.Policy {
			timer := new(rto.Timer)
			if err := timer.Configure(env.clock.nanotime); err != nil {
				panic(err)
			}
			return timer
		}
	})
	p := newPeer(t, "10.0.0.2:40000", "192.0.2.1:443", 4096)
	flow := env.connect(t, p, make([]byte, 4096), make([]byte, 4096))
	if _, err := env.fwd.Write(flow, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if encap(t, &env.fwd) == nil {
		t.Fatal("no data segment")
	} // Lost.
	deadline := env.fwd.NextDeadline()
	if deadline == 0 {
		t.Fatal("no retransmission timer")
	}
	if encap(t, &env.fwd) != nil {
		t.Fatal("retransmitted before deadline")
	}
	env.clock.now = deadline
	pkt := encap(t, &env.fwd)
	if pkt == nil {
		t.Fatal("no retransmission at deadline")
	}
	if err := p.deliver(pkt); err != nil {
		t.Fatal(err)
	}
	exchange(t, &env.fwd, p)
	buf := make([]byte, 16)
	if n, _ := p.h.Read(buf); string(buf[:n]) != "data" {
		t.Fatalf("peer read %q", buf[:n])
	}
}

func TestTCPHandlerAbort(t *testing.T) {
	env := newTCPEnv(t, func(_ *tcpEnv, c *xforward.TCPHandlerConfig) { c.MaxFlows, c.MaxPending = 1, 1 })
	p := newPeer(t, "10.0.0.2:40000", "192.0.2.1:443", 4096)
	flow := env.connect(t, p, make([]byte, 4096), make([]byte, 4096))
	env.fwd.Abort()
	if _, err := env.fwd.Read(flow, make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Read after Abort: %v", err)
	}
	if encap(t, &env.fwd) != nil {
		t.Error("packet after Abort")
	}
	p2 := newPeer(t, "10.0.0.2:40001", "192.0.2.1:443", 4096)
	if _, isNew, err := env.demux(t, p2.send()); err != nil || !isNew {
		t.Fatalf("after Abort: isNew=%v err=%v", isNew, err)
	}
}
