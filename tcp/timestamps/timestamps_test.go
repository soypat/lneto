package timestamps

import (
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
	"github.com/soypat/lneto/tcp/sack"
)

const mtu = ethernet.MaxMTU

// TestNegotiation verifies timestamps are used only when both sides offer the
// option, and that the SYN-ACK and final ACK carry it only then (RFC 7323
// §3.2).
func TestNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name           string
		client, server bool
	}{
		{"both", true, true},
		{"client-only", true, false},
		{"server-only", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var now int64
			client, server := newHandler(t), newHandler(t)
			cp, sp := newPolicy(t, &now, false, nil), newPolicy(t, &now, false, nil)
			if tc.client {
				client.SetPolicy(cp)
			}
			if tc.server {
				server.SetPolicy(sp)
			}
			handshake := establish(t, client, server)
			want := tc.client && tc.server
			if cp.Enabled() != want || sp.Enabled() != want {
				t.Errorf("enabled client=%v server=%v, want %v", cp.Enabled(), sp.Enabled(), want)
			}
			for i, wantTS := range []bool{tc.client, want, want} {
				if _, _, ok := timestampOf(t, handshake[i]); ok != wantTS {
					t.Errorf("handshake segment %d carries timestamps: %v, want %v", i, ok, wantTS)
				}
			}
			// TSval starts at the sender's ISS (RFC 7323 §7.1).
			for i, h := range []*tcp.Handler{client, server} {
				if tsval, _, ok := timestampOf(t, handshake[i]); ok && tsval != uint32(h.ISS()) {
					t.Errorf("handshake segment %d TSval %d, want the ISS %d", i, tsval, h.ISS())
				}
			}
		})
	}
}

// TestEcho verifies segments carry the sender's clock and echo TS.Recent, and
// that TS.Recent advances only for a segment at or below Last.ACK.sent: of two
// segments arriving before an ACK is sent, the first is echoed (RFC 7323 §4.3).
func TestEcho(t *testing.T) {
	var now int64
	client, server := newHandler(t), newHandler(t)
	cp, sp := newPolicy(t, &now, false, nil), newPolicy(t, &now, false, nil)
	client.SetPolicy(cp)
	server.SetPolicy(sp)
	handshake := establish(t, client, server)
	synackTSval, _, _ := timestampOf(t, handshake[1])

	now += 5 * int64(time.Millisecond)
	first := sendData(t, client, []byte("one"))
	now += 5 * int64(time.Millisecond)
	second := sendData(t, client, []byte("two"))
	tsval1, tsecr1, _ := timestampOf(t, first)
	tsval2, _, _ := timestampOf(t, second)
	if tsval2-tsval1 != 5 {
		t.Fatalf("TSval %d then %d, want 5 ms apart", tsval1, tsval2)
	}
	if tsecr1 != synackTSval {
		t.Fatalf("TSecr %d, want the SYN-ACK's TSval %d", tsecr1, synackTSval)
	}
	for _, pkt := range [][]byte{first, second} {
		if err := server.Recv(pkt); err != nil {
			t.Fatal(err)
		}
	}
	if _, tsecr, _ := timestampOf(t, send(t, server)); tsecr != tsval1 {
		t.Fatalf("ACK echoes %d, want the first segment's %d", tsecr, tsval1)
	}
}

// TestDropWithoutOption verifies that once timestamps are in use a segment
// without the option is dropped, while a RST without it is honoured (RFC 7323
// §3.2).
func TestDropWithoutOption(t *testing.T) {
	var now int64
	client, server := newHandler(t), newHandler(t)
	client.SetPolicy(newPolicy(t, &now, false, nil))
	server.SetPolicy(newPolicy(t, &now, false, nil))
	establish(t, client, server)
	seg := tcp.Segment{SEQ: server.ControlBlock().RecvNext(), ACK: server.ControlBlock().SendNext(), Flags: tcp.FlagACK, WND: mtu}
	if err := server.Recv(frameFor(t, client, server, seg, nil, []byte("data"))); err != nil {
		t.Fatal(err)
	}
	if server.BufferedInput() != 0 {
		t.Fatal("segment without timestamps was accepted")
	}
	seg.Flags = tcp.FlagRST | tcp.FlagACK
	server.Recv(frameFor(t, client, server, seg, nil, nil))
	if server.State() != tcp.StateClosed {
		t.Fatalf("RST without timestamps ignored: state %s", server.State())
	}
}

// TestPAWS verifies a segment with a timestamp older than TS.Recent is dropped
// and answered with an ACK when PAWS is on (RFC 7323 §5.3), and accepted when
// PAWS is off or TS.Recent has been idle past 24 days, which also replaces
// TS.Recent (§5.5). A RST with an old timestamp is honoured (§5.2).
func TestPAWS(t *testing.T) {
	for _, tc := range []struct {
		name       string
		paws       bool
		idle       time.Duration
		wantAccept bool
	}{
		{name: "drop", paws: true},
		{name: "off", wantAccept: true},
		{name: "recent-expired", paws: true, idle: pawsIdle + time.Second, wantAccept: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var now int64
			client, server := newHandler(t), newHandler(t)
			client.SetPolicy(newPolicy(t, &now, false, nil))
			sp := newPolicy(t, &now, tc.paws, nil)
			server.SetPolicy(sp)
			establish(t, client, server)
			now += int64(tc.idle)
			recent, _ := sp.Recent()
			seg := tcp.Segment{SEQ: server.ControlBlock().RecvNext(), ACK: server.ControlBlock().SendNext(), Flags: tcp.FlagACK, WND: mtu}
			if err := server.Recv(frameFor(t, client, server, seg, &[2]uint32{recent - 1, 1}, []byte("data"))); err != nil {
				t.Fatal(err)
			}
			if accepted := server.BufferedInput() != 0; accepted != tc.wantAccept {
				t.Fatalf("old timestamp accepted: %v, want %v", accepted, tc.wantAccept)
			}
			ack := send(t, server)
			if ack == nil || segmentOf(t, ack).ACK != server.ControlBlock().RecvNext() {
				t.Fatalf("no ACK of the receive state sent: %v", ack)
			}
			if got, _ := sp.Recent(); tc.idle > 0 && got != recent-1 {
				t.Fatalf("TS.Recent %d after expiry, want the accepted %d", got, recent-1)
			}
			seg = tcp.Segment{SEQ: server.ControlBlock().RecvNext(), Flags: tcp.FlagRST}
			server.Recv(frameFor(t, client, server, seg, &[2]uint32{recent - 100, 0}, nil))
			if server.State() != tcp.StateClosed {
				t.Fatalf("RST with an old timestamp ignored: state %s", server.State())
			}
		})
	}
}

// TestRTTFromRetransmission verifies a round-trip sample is taken from the
// echo of a retransmitted segment, which Karn's algorithm keeps the timer
// itself from sampling, and fed to the timer.
func TestRTTFromRetransmission(t *testing.T) {
	var now int64
	clock := func() int64 { return now }
	client, server := newHandler(t), newHandler(t)
	var timer rto.Timer
	if err := timer.Configure(clock); err != nil {
		t.Fatal(err)
	}
	cp := newPolicy(t, &now, false, &timer)
	client.SetPolicy(tcp.Policies{&timer, cp})
	server.SetPolicy(newPolicy(t, &now, false, nil))
	establish(t, client, server)

	sendData(t, client, []byte("lost"))
	now = timer.NextDeadline()
	resent := send(t, client)
	if resent == nil {
		t.Fatal("no retransmission after the RTO expired")
	}
	const rtt = 20 * time.Millisecond
	now += int64(rtt)
	if err := server.Recv(resent); err != nil {
		t.Fatal(err)
	}
	if err := client.Recv(send(t, server)); err != nil {
		t.Fatal(err)
	}
	if got, ok := cp.LastRTT(); !ok || got != rtt {
		t.Fatalf("LastRTT = %v (%v), want %v", got, ok, rtt)
	}
	if timer.SmoothedRTT() != rtt {
		t.Fatalf("timer SRTT = %v, want the timestamp sample %v", timer.SmoothedRTT(), rtt)
	}
}

// TestEchoOutOfRange verifies an echo of a timestamp not yet sent, or of one
// from before the connection started, yields no round-trip sample.
func TestEchoOutOfRange(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tsecr func(tsval, start uint32) uint32
	}{
		{name: "future", tsecr: func(tsval, _ uint32) uint32 { return tsval + 1000 }},
		{name: "before-start", tsecr: func(_, start uint32) uint32 { return start - 1000 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var now int64
			client, server := newHandler(t), newHandler(t)
			var timer rto.Timer
			if err := timer.Configure(func() int64 { return now }); err != nil {
				t.Fatal(err)
			}
			cp := newPolicy(t, &now, false, &timer)
			client.SetPolicy(cp)
			server.SetPolicy(newPolicy(t, &now, false, nil))
			establish(t, client, server)
			now += int64(time.Second)
			tsval, _, _ := timestampOf(t, sendData(t, client, []byte("data")))
			recent, _ := cp.Recent()
			seg := tcp.Segment{SEQ: client.ControlBlock().RecvNext(), ACK: client.ControlBlock().SendNext(), Flags: tcp.FlagACK, WND: mtu}
			echo := tc.tsecr(tsval, uint32(client.ISS()))
			if err := client.Recv(frameFor(t, server, client, seg, &[2]uint32{recent, echo}, nil)); err != nil {
				t.Fatal(err)
			}
			if rtt, ok := cp.LastRTT(); ok || timer.SmoothedRTT() != 0 {
				t.Fatalf("sample %v (%v), timer SRTT %v from echo %d", rtt, ok, timer.SmoothedRTT(), echo)
			}
		})
	}
}

// TestSYNAcceptedOnly verifies only a SYN the connection accepts in the
// handshake records the peer's offer and TS.Recent: neither a SYN-ACK the
// ControlBlock refuses nor a late duplicate SYN-ACK once established does.
func TestSYNAcceptedOnly(t *testing.T) {
	t.Run("refused-synack", func(t *testing.T) {
		var now int64
		client, server := newHandler(t), newHandler(t)
		cp := newPolicy(t, &now, false, nil)
		client.SetPolicy(cp) // The server does not offer timestamps.
		if err := server.OpenListen(80, 100); err != nil {
			t.Fatal(err)
		}
		if err := client.OpenActive(1234, 80, 300); err != nil {
			t.Fatal(err)
		}
		if err := server.Recv(send(t, client)); err != nil {
			t.Fatal(err)
		}
		synack := send(t, server)
		bogus := segmentOf(t, synack)
		bogus.Flags |= tcp.FlagFIN
		client.Recv(frameFor(t, server, client, bogus, &[2]uint32{1000, 1}, nil))
		if err := client.Recv(synack); err != nil {
			t.Fatal(err)
		}
		if _, _, ok := timestampOf(t, send(t, client)); ok || cp.Enabled() {
			t.Fatalf("timestamps used after a refused SYN-ACK offered them: final ACK %v, enabled %v", ok, cp.Enabled())
		}
	})
	t.Run("duplicate-synack", func(t *testing.T) {
		var now int64
		client, server := newHandler(t), newHandler(t)
		cp := newPolicy(t, &now, false, nil)
		client.SetPolicy(cp)
		server.SetPolicy(newPolicy(t, &now, false, nil))
		handshake := establish(t, client, server)
		now += int64(time.Second)
		if err := client.Recv(sendData(t, server, []byte("data"))); err != nil {
			t.Fatal(err)
		}
		recent, _ := cp.Recent()
		client.Recv(handshake[1])
		if got, _ := cp.Recent(); got != recent {
			t.Fatalf("duplicate SYN-ACK moved TS.Recent from %d to %d", recent, got)
		}
	})
}

// TestWithSACK verifies timestamps and SACK negotiate together and a duplicate
// ACK carries both options.
func TestWithSACK(t *testing.T) {
	var now int64
	client, server := newHandler(t), newHandler(t)
	cts, sts := newPolicy(t, &now, true, nil), newPolicy(t, &now, true, nil)
	var cs, ss sack.Policy
	client.SetPolicy(tcp.Policies{cts, &cs})
	server.SetPolicy(tcp.Policies{sts, &ss})
	establish(t, client, server)
	if !cts.Enabled() || !sts.Enabled() || !cs.Enabled() || !ss.Enabled() {
		t.Fatal("timestamps and SACK not both negotiated")
	}
	sendData(t, client, []byte("lost"))
	if err := server.Recv(sendData(t, client, []byte("held"))); err != nil {
		t.Fatal(err)
	}
	frm, _ := tcp.NewFrame(send(t, server))
	var kinds []tcp.OptionKind
	var codec tcp.OptionCodec
	codec.ForEachOption(frm.Options(), func(kind tcp.OptionKind, _ []byte) error {
		kinds = append(kinds, kind)
		return nil
	})
	if len(kinds) != 2 || kinds[0] != tcp.OptTimestamps || kinds[1] != tcp.OptSACK {
		t.Fatalf("duplicate ACK options %v, want timestamps then SACK", kinds)
	}
}

func TestLessThanWraps(t *testing.T) {
	if !lessThan(0xffff_fff0, 0x10) || lessThan(0x10, 0xffff_fff0) || lessThan(5, 5) {
		t.Fatal("timestamp comparison does not wrap modulo 2^32")
	}
}

// TestRTTEveryACK verifies every ACK of new data yields a sample (RFC 7323
// §4.1), fed to the timer with the gains scaled by the samples expected per
// flight, ceil(FlightSize / (2*SMSS)) with SMSS approximated by the MSS the
// server advertised (Appendix G).
func TestRTTEveryACK(t *testing.T) {
	var now int64
	// Room for four full segments in flight.
	newBigHandler := func() *tcp.Handler {
		h := new(tcp.Handler)
		if err := h.SetBuffers(make([]byte, 4*mtu), make([]byte, 4*mtu), 8); err != nil {
			t.Fatal(err)
		}
		return h
	}
	client, server := newBigHandler(), newBigHandler()
	var timer rto.Timer
	if err := timer.Configure(func() int64 { return now }); err != nil {
		t.Fatal(err)
	}
	cp := newPolicy(t, &now, false, &timer)
	client.SetPolicy(tcp.Policies{&timer, cp})
	server.SetPolicy(newPolicy(t, &now, false, nil))
	establish(t, client, server)

	// The largest payload a frame holds besides the 12 octets of the option.
	segSize := int(client.ControlBlock().SendMSS()) - 12
	var flight [4][]byte
	for i := range flight {
		flight[i] = sendData(t, client, make([]byte, segSize))
	}
	// Expected samples per flight of 4, 3, 2 and 1 segments in flight.
	perFlight := []float64{2, 2, 1, 1}
	var srtt, rttvar float64
	start := now
	for i, pkt := range flight {
		rtt := time.Duration(i+1) * 10 * time.Millisecond
		now = start + int64(rtt)
		if err := server.Recv(pkt); err != nil {
			t.Fatal(err)
		}
		if err := client.Recv(send(t, server)); err != nil {
			t.Fatal(err)
		}
		if got, _ := cp.LastRTT(); got != rtt {
			t.Fatalf("ACK %d: LastRTT = %v, want %v", i, got, rtt)
		}
		r := float64(rtt)
		if i == 0 {
			srtt, rttvar = r, r/2
		} else {
			alpha, beta := 1.0/8/perFlight[i], 1.0/4/perFlight[i]
			rttvar = (1-beta)*rttvar + beta*math.Abs(srtt-r)
			srtt = (1-alpha)*srtt + alpha*r
		}
	}
	if got := float64(timer.SmoothedRTT()); math.Abs(got-srtt) > float64(time.Microsecond) {
		t.Fatalf("timer SRTT = %v, want %v", timer.SmoothedRTT(), time.Duration(srtt))
	}
}

func newPolicy(t *testing.T, now *int64, paws bool, timer *rto.Timer) *Policy {
	t.Helper()
	p := new(Policy)
	if err := p.Configure(Config{Nanotime: func() int64 { return *now }, PAWS: paws, Timer: timer}); err != nil {
		t.Fatal(err)
	}
	return p
}

func newHandler(t *testing.T) *tcp.Handler {
	t.Helper()
	h := new(tcp.Handler)
	if err := h.SetBuffers(make([]byte, mtu), make([]byte, mtu), 8); err != nil {
		t.Fatal(err)
	}
	return h
}

// establish completes the three-way handshake and returns its segments.
func establish(t *testing.T, client, server *tcp.Handler) (handshake [3][]byte) {
	t.Helper()
	rng := rand.New(rand.NewSource(1))
	if err := server.OpenListen(uint16(rng.Uint32()), 100); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenActive(uint16(rng.Uint32()), server.LocalPort(), 300); err != nil {
		t.Fatal(err)
	}
	for i, h := range [][2]*tcp.Handler{{client, server}, {server, client}, {client, server}} {
		handshake[i] = send(t, h[0])
		if err := h[1].Recv(handshake[i]); err != nil {
			t.Fatal(err)
		}
	}
	if client.State() != tcp.StateEstablished || server.State() != tcp.StateEstablished {
		t.Fatalf("handshake: client %s, server %s", client.State(), server.State())
	}
	return handshake
}

// send returns a copy of the next frame h emits, or nil if it emits none.
func send(t *testing.T, h *tcp.Handler) []byte {
	t.Helper()
	var buf [mtu]byte
	n, err := h.Send(buf[:])
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		return nil
	}
	return append([]byte(nil), buf[:n]...)
}

func sendData(t *testing.T, h *tcp.Handler, data []byte) []byte {
	t.Helper()
	if _, err := h.Write(data); err != nil {
		t.Fatal(err)
	}
	return send(t, h)
}

func segmentOf(t *testing.T, pkt []byte) tcp.Segment {
	t.Helper()
	frm, err := tcp.NewFrame(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return frm.Segment(len(frm.Payload()))
}

func timestampOf(t *testing.T, pkt []byte) (tsval, tsecr uint32, ok bool) {
	t.Helper()
	frm, err := tcp.NewFrame(pkt)
	if err != nil {
		t.Fatal(err)
	}
	var p Policy
	return p.parse(frm.Options())
}

// frameFor builds a segment from src to dst carrying the timestamps ts, or no
// option if ts is nil.
func frameFor(t *testing.T, src, dst *tcp.Handler, seg tcp.Segment, ts *[2]uint32, payload []byte) []byte {
	t.Helper()
	pkt := make([]byte, 20+12+len(payload))
	frm, _ := tcp.NewFrame(pkt)
	seg.DATALEN = tcp.Size(len(payload))
	frm.SetSegment(seg, 5)
	frm.SetSourcePort(src.LocalPort())
	frm.SetDestinationPort(dst.LocalPort())
	if ts != nil {
		var data [optDataLen]byte
		put32(data[:4], ts[0])
		put32(data[4:], ts[1])
		var p Policy
		if !p.writeOption(frm, data[:]) {
			t.Fatal("option did not fit")
		}
	} else {
		pkt = pkt[:20+len(payload)]
	}
	copy(pkt[len(pkt)-len(payload):], payload)
	return pkt
}
