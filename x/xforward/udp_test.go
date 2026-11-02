package xforward_test

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/x/xforward"
)

func newUDP(t testing.TB, maxFlows uint16, clock *testClock) *xforward.UDPHandler {
	t.Helper()
	uh := new(xforward.UDPHandler)
	err := uh.Configure(xforward.UDPHandlerConfig{MaxFlows: maxFlows, IdleTimeout: 10 * time.Second, NanoTime: clock.nanotime, Key: testKey})
	if err != nil {
		t.Fatal(err)
	}
	return uh
}

func TestUDPHandlerConfigure(t *testing.T) {
	var clock testClock
	for _, tc := range []struct {
		name string
		mod  func(*xforward.UDPHandlerConfig)
		want error
	}{
		{name: "valid"},
		{name: "no clock", mod: func(c *xforward.UDPHandlerConfig) { c.NanoTime = nil }, want: lneto.ErrMissingHALConfig},
		{name: "zero flows", mod: func(c *xforward.UDPHandlerConfig) { c.MaxFlows = 0 }, want: lneto.ErrInvalidConfig},
		{name: "too many flows", mod: func(c *xforward.UDPHandlerConfig) { c.MaxFlows = 1<<15 + 1 }, want: lneto.ErrInvalidConfig},
		{name: "zero idle", mod: func(c *xforward.UDPHandlerConfig) { c.IdleTimeout = 0 }, want: lneto.ErrInvalidConfig},
		{name: "zero key", mod: func(c *xforward.UDPHandlerConfig) { c.Key = [16]byte{} }, want: lneto.ErrInvalidConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := xforward.UDPHandlerConfig{MaxFlows: 4, IdleTimeout: time.Second, NanoTime: clock.nanotime, Key: testKey}
			if tc.mod != nil {
				tc.mod(&cfg)
			}
			var uh xforward.UDPHandler
			if err := uh.Configure(cfg); err != tc.want {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestUDPHandlerDemux(t *testing.T) {
	var clock testClock
	uh := newUDP(t, 2, &clock)
	a := udpPkt(t, "10.0.0.2:5000", "1.1.1.1:53", "q1")
	flow, payload, isNew, err := uh.Demux(a)
	if err != nil || !isNew || string(payload) != "q1" {
		t.Fatalf("first datagram: isNew=%v payload=%q err=%v", isNew, payload, err)
	}
	if want := netip.MustParseAddrPort("1.1.1.1:53"); flow.ID.Local != want {
		t.Errorf("Local %v, want %v", flow.ID.Local, want)
	}
	again, _, isNew, err := uh.Demux(a)
	if err != nil || isNew || again.Slot() != flow.Slot() {
		t.Fatalf("repeat datagram: isNew=%v slot=%d want %d err=%v", isNew, again.Slot(), flow.Slot(), err)
	}
	b, _, isNew, err := uh.Demux(udpPkt(t, "10.0.0.2:5000", "1.1.1.1:5353", "q2"))
	if err != nil || !isNew || b.Slot() == flow.Slot() {
		t.Fatalf("second flow: isNew=%v slot=%d err=%v", isNew, b.Slot(), err)
	}
	if _, _, _, err = uh.Demux(udpPkt(t, "10.0.0.3:5000", "1.1.1.1:53", "q3")); !errors.Is(err, lneto.ErrExhausted) {
		t.Fatalf("third flow: got %v, want ErrExhausted", err)
	}
	tcpPkt := mustValidate(t, buildIP(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("1.1.1.1"), lneto.IPProtoTCP, tcpSeg(5000, 53, 1, 0, 0, nil)))
	if _, _, _, err = uh.Demux(tcpPkt); err == nil {
		t.Fatal("TCP packet accepted by UDPHandler")
	}
}

func TestUDPHandlerEncapsulate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		peer, dst string
		offset    int
	}{
		{name: "ipv4", peer: "10.0.0.2:5000", dst: "1.1.1.1:53"},
		{name: "ipv6", peer: "[fd00::2]:5000", dst: "[2001:db8::1]:53"},
		{name: "ipv4 with link header", peer: "10.0.0.2:5000", dst: "1.1.1.1:53", offset: 14},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var clock testClock
			uh := newUDP(t, 2, &clock)
			flow, _, _, err := uh.Demux(udpPkt(t, tc.peer, tc.dst, "query"))
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, testMTU)
			n := copy(buf[tc.offset+flow.HeaderLen():], "answer")
			m, err := uh.Encapsulate(buf, tc.offset, flow, n)
			if err != nil {
				t.Fatal(err)
			}
			reply := mustValidate(t, buf[tc.offset:tc.offset+m])
			want := xforward.FlowID{Local: netip.MustParseAddrPort(tc.peer), Remote: netip.MustParseAddrPort(tc.dst)}
			if reply.ID() != want {
				t.Errorf("reply ID %v, want %v", reply.ID(), want)
			}
			if got := string(reply.RawData()[reply.TransportOffset()+8:]); got != "answer" {
				t.Errorf("reply payload %q", got)
			}
			if _, err = uh.Encapsulate(buf[:tc.offset+flow.HeaderLen()+n-1], tc.offset, flow, n); !errors.Is(err, lneto.ErrShortBuffer) {
				t.Errorf("short buffer: got %v", err)
			}
		})
	}
}

func TestUDPHandlerRemove(t *testing.T) {
	var clock testClock
	uh := newUDP(t, 1, &clock)
	flow, _, _, _ := uh.Demux(udpPkt(t, "10.0.0.2:5000", "1.1.1.1:53", "q"))
	if err := uh.Remove(flow); err != nil {
		t.Fatal(err)
	}
	if err := uh.Remove(flow); !errors.Is(err, net.ErrClosed) {
		t.Errorf("second Remove: got %v, want net.ErrClosed", err)
	}
	if _, err := uh.Encapsulate(make([]byte, testMTU), 0, flow, 0); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Encapsulate on removed flow: got %v, want net.ErrClosed", err)
	}
	if _, _, isNew, err := uh.Demux(udpPkt(t, "10.0.0.3:5000", "1.1.1.1:53", "q")); err != nil || !isNew {
		t.Fatalf("slot not freed: isNew=%v err=%v", isNew, err)
	}
}

func TestUDPHandlerExpiry(t *testing.T) {
	var clock testClock
	uh := newUDP(t, 2, &clock)
	a, _, _, _ := uh.Demux(udpPkt(t, "10.0.0.2:5000", "1.1.1.1:53", "a"))
	b, _, _, _ := uh.Demux(udpPkt(t, "10.0.0.3:5000", "1.1.1.1:53", "b"))
	clock.now = int64(5 * time.Second)
	if _, err := uh.Encapsulate(make([]byte, testMTU), 0, a, 0); err != nil { // Upstream traffic keeps a alive.
		t.Fatal(err)
	}
	clock.now = int64(11 * time.Second)
	if got, ok := uh.NextExpired(); !ok || got.ID != b.ID {
		t.Fatalf("NextExpired=%v,%v want %v", got.ID, ok, b.ID)
	}
	if got, ok := uh.NextExpired(); ok {
		t.Fatalf("refreshed flow expired: %v", got.ID)
	}
	clock.now = int64(16 * time.Second)
	if got, ok := uh.NextExpired(); !ok || got.ID != a.ID {
		t.Fatalf("NextExpired=%v,%v want %v", got.ID, ok, a.ID)
	}
	if _, err := uh.Encapsulate(make([]byte, testMTU), 0, b, 0); !errors.Is(err, net.ErrClosed) {
		t.Errorf("expired flow still usable: %v", err)
	}
}

func TestUDPHandlerAbort(t *testing.T) {
	var clock testClock
	uh := newUDP(t, 1, &clock)
	flow, _, _, _ := uh.Demux(udpPkt(t, "10.0.0.2:5000", "1.1.1.1:53", "q"))
	uh.Abort()
	if _, err := uh.Encapsulate(make([]byte, testMTU), 0, flow, 0); !errors.Is(err, net.ErrClosed) {
		t.Errorf("flow usable after Abort: %v", err)
	}
	if _, _, isNew, err := uh.Demux(udpPkt(t, "10.0.0.3:5000", "1.1.1.1:53", "q")); err != nil || !isNew {
		t.Fatalf("after Abort: isNew=%v err=%v", isNew, err)
	}
}

// FuzzUDPFlows checks flow table bookkeeping against a model. Each input byte is one
// operation on one of 16 tuples, so extending ops keeps existing corpus meaning.
func FuzzUDPFlows(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x80, 0x82, 10, 11, 0xc0, 0xc1, 0x40})
	f.Add([]byte{0, 16, 32, 48, 0x80, 1, 0x81, 0xc0, 0xc1})
	const maxFlows = 8
	pkts := make([]xforward.Packet, 16)
	for i := range pkts {
		pkts[i] = udpPkt(f, fmt.Sprintf("10.0.%d.2:%d", i, 1000+i), "1.1.1.1:53", "x")
	}
	buf := make([]byte, testMTU)
	f.Fuzz(func(t *testing.T, ops []byte) {
		var clock testClock
		uh := newUDP(t, maxFlows, &clock)
		var model [16]struct {
			flow xforward.UDPFlow
			live bool
		}
		nlive := 0
		for _, op := range ops {
			m := &model[op&15]
			switch op >> 6 {
			case 0, 1: // Datagram from tuple.
				flow, _, isNew, err := uh.Demux(pkts[op&15])
				switch {
				case m.live:
					if err != nil || isNew || flow.Slot() != m.flow.Slot() {
						t.Fatalf("live flow: isNew=%v slot=%d want %d err=%v", isNew, flow.Slot(), m.flow.Slot(), err)
					}
				case nlive == maxFlows:
					if !errors.Is(err, lneto.ErrExhausted) {
						t.Fatalf("full table: got %v", err)
					}
				default:
					if err != nil || !isNew {
						t.Fatalf("new flow: isNew=%v err=%v", isNew, err)
					}
					for i := range model {
						if model[i].live && model[i].flow.Slot() == flow.Slot() {
							t.Fatalf("slot %d handed out twice", flow.Slot())
						}
					}
					m.flow, m.live = flow, true
					nlive++
				}
			case 2: // Remove tuple's latest handle.
				if err := uh.Remove(m.flow); m.live != (err == nil) {
					t.Fatalf("Remove: live=%v err=%v", m.live, err)
				}
				if m.live {
					m.live = false
					nlive--
				}
			case 3: // Use tuple's latest handle.
				if _, err := uh.Encapsulate(buf, 0, m.flow, 0); m.live != (err == nil) {
					t.Fatalf("Encapsulate: live=%v err=%v", m.live, err)
				}
			}
		}
	})
}
