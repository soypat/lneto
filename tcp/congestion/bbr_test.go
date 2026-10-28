package congestion

import (
	"bytes"
	"cmp"
	"errors"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
)

// newBBR returns a controller with an SMSS of testMSS at SND.UNA 1000.
func newBBR(t *testing.T) *BBR {
	t.Helper()
	b := new(BBR)
	if err := b.Configure(BBRConfig{Nanotime: func() int64 { return 0 }}); err != nil {
		t.Fatal(err)
	}
	b.smss, b.una, b.nxt = testMSS, 1000, 1000
	return b
}

// roundTrip sends n segments of new data at now, acknowledges them all rtt
// later and returns that time.
func roundTrip(b *BBR, n int, rtt time.Duration, now int64) int64 {
	for range n {
		b.postTx(tcp.Segment{SEQ: b.nxt, DATALEN: testMSS, Flags: tcp.FlagACK}, b.una, now)
		b.nxt = tcp.Add(b.nxt, testMSS)
	}
	now += int64(rtt)
	b.postRx(b.nxt, b.nxt, false, false, now)
	return now
}

func TestBBR_Configure(t *testing.T) {
	if err := new(BBR).Configure(BBRConfig{}); !errors.Is(err, lneto.ErrMissingHALConfig) {
		t.Errorf("Configure without Nanotime = %v, want %v", err, lneto.ErrMissingHALConfig)
	}
	b := newBBR(t)
	if b.CongestionWindow() != 10*testMSS || b.State() != "Startup" || b.MaxBandwidth() != 0 || b.MinRTT() != 0 {
		t.Errorf("cwnd %d, state %s, max_bw %d, min_rtt %v; want %d, Startup, 0, 0",
			b.CongestionWindow(), b.State(), b.MaxBandwidth(), b.MinRTT(), 10*testMSS)
	}
}

// TestBBR_RoundTrip verifies a round trip is measured from a segment of new
// data to the ACK covering it, over the octets that ACKs delivered, and not
// for a resend (Karn) or a zero-window probe, whose ACK waits for the window.
func TestBBR_RoundTrip(t *testing.T) {
	const rtt = 50 * time.Millisecond
	for _, tc := range []struct {
		name    string
		resend  bool
		probing bool     // The segments are zero-window probes.
		acked   tcp.Size // Of the two segments sent.
		wantRTT time.Duration
		wantBw  uint64
	}{
		{name: "measured", acked: 2 * testMSS, wantRTT: rtt, wantBw: 2 * testMSS * 20},
		{name: "timed-segment-unacknowledged", acked: testMSS - 1},
		{name: "resend", resend: true, acked: 2 * testMSS},
		{name: "zero-window-probe", probing: true, acked: 2 * testMSS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBBR(t)
			b.probing = tc.probing
			una := b.una
			for range 2 {
				b.postTx(tcp.Segment{SEQ: b.nxt, DATALEN: testMSS, Flags: tcp.FlagACK}, una, 0)
				b.nxt = tcp.Add(b.nxt, testMSS)
			}
			if tc.resend {
				b.postTx(tcp.Segment{SEQ: una, DATALEN: testMSS, Flags: tcp.FlagACK}, una, 0)
			}
			b.postRx(tcp.Add(una, tc.acked), b.nxt, false, false, int64(rtt))
			if b.MinRTT() != tc.wantRTT || b.MaxBandwidth() != tc.wantBw {
				t.Errorf("min_rtt %v, max_bw %d; want %v, %d", b.MinRTT(), b.MaxBandwidth(), tc.wantRTT, tc.wantBw)
			}
		})
	}
}

// TestBBR_Phases verifies Startup ends after three rounds that grew max_bw by
// less than a quarter, Drain once the flight is down to the BDP, ProbeBW
// cycles its gains each min_rtt and only a min_rtt not measured for 5s starts
// ProbeRTT, which ends after 200ms with the window restored.
func TestBBR_Phases(t *testing.T) {
	const rtt = 100 * time.Millisecond
	b := newBBR(t)
	var now int64
	for _, n := range []int{10, 20, 40, 40, 40} {
		now = roundTrip(b, n, rtt, now)
	}
	if b.State() != "Startup" {
		t.Fatalf("state %s after two rounds without growth, want Startup", b.State())
	}
	start := b.nxt // The third round without growth leaves more than the BDP in flight.
	for range 81 {
		b.postTx(tcp.Segment{SEQ: b.nxt, DATALEN: testMSS, Flags: tcp.FlagACK}, b.una, now)
		b.nxt = tcp.Add(b.nxt, testMSS)
	}
	now += int64(rtt)
	b.postRx(tcp.Add(start, 40*testMSS), b.nxt, false, false, now)
	if b.State() != "Drain" || b.PacingRate() != 0.5*float32(b.MaxBandwidth()) {
		t.Fatalf("state %s, pacing rate %v after three rounds without growth; want Drain at half of %d", b.State(), b.PacingRate(), b.MaxBandwidth())
	}
	b.postRx(tcp.Add(start, 41*testMSS), b.nxt, false, false, now) // The flight is down to the BDP.
	gains := []float32{b.PacingRate() / float32(b.MaxBandwidth())}
	b.postRx(b.nxt, b.nxt, false, false, now)
	for range 2 {
		now = roundTrip(b, 40, rtt, now)
		gains = append(gains, b.PacingRate()/float32(b.MaxBandwidth()))
	}
	if b.State() != "ProbeBW" || !slices.Equal(gains, []float32{1.25, 0.9, 1}) {
		t.Fatalf("state %s, gains %v; want ProbeBW with 1.25, 0.9, 1", b.State(), gains)
	}
	cwnd := b.CongestionWindow()
	if bdp := tcp.Size(40 * testMSS); cwnd != 2*bdp {
		t.Fatalf("cwnd %d in ProbeBW, want twice the BDP %d", cwnd, bdp)
	}
	for range 51 { // 5.1s of round trips of min_rtt.
		if now = roundTrip(b, 40, rtt, now); b.State() != "ProbeBW" {
			t.Fatalf("state %s while min_rtt is measured again, want ProbeBW", b.State())
		}
	}
	now = roundTrip(b, 40, rtt, now+int64(bbrProbeRTTInterval))
	if b.State() != "ProbeRTT" || b.CongestionWindow() != cwnd/4 {
		t.Fatalf("state %s, cwnd %d after min_rtt went stale; want ProbeRTT at %d", b.State(), b.CongestionWindow(), cwnd/4)
	}
	now = roundTrip(b, 10, rtt, now) // The flight is down.
	now = roundTrip(b, 10, rtt, now)
	if b.State() != "ProbeRTT" {
		t.Fatalf("state %s within 200ms of the flight being down, want ProbeRTT", b.State())
	}
	roundTrip(b, 10, rtt, now+int64(bbrProbeRTTDuration))
	if b.State() != "ProbeBW" || b.CongestionWindow() != cwnd {
		t.Errorf("state %s, cwnd %d after ProbeRTT; want ProbeBW at %d", b.State(), b.CongestionWindow(), cwnd)
	}
}

// TestBBR_MinRTTRises verifies min_rtt takes a larger sample once it was not
// measured for 5s, and ProbeRTT a lower one again.
func TestBBR_MinRTTRises(t *testing.T) {
	const rtt = 100 * time.Millisecond
	b := newBBR(t)
	now := roundTrip(b, 10, rtt, int64(time.Hour))
	if b.State() != "Startup" {
		t.Fatalf("state %s after the first round trip, want Startup", b.State())
	}
	now = roundTrip(b, 10, 2*rtt, now+int64(bbrProbeRTTInterval))
	if b.MinRTT() != 2*rtt || b.State() != "ProbeRTT" {
		t.Fatalf("min_rtt %v, state %s after 5s, want %v and ProbeRTT", b.MinRTT(), b.State(), 2*rtt)
	}
	roundTrip(b, 4, 3*rtt/2, now)
	if b.MinRTT() != 3*rtt/2 {
		t.Errorf("min_rtt %v in ProbeRTT, want %v", b.MinRTT(), 3*rtt/2)
	}
}

// TestBBR_Cwnd verifies the window grows by the octets acknowledged up to
// twice the BDP, before the pipe is full only while below it, and is at least
// 4 segments.
func TestBBR_Cwnd(t *testing.T) {
	const bdp = 10 * testMSS
	for _, tc := range []struct {
		name     string
		bdp      tcp.Size
		cwnd     tcp.Size
		fullPipe bool
		want     tcp.Size
	}{
		{name: "startup-below-target", bdp: bdp, cwnd: 15 * testMSS, want: 16 * testMSS},
		{name: "startup-above-target", bdp: bdp, cwnd: 25 * testMSS, want: 25 * testMSS},
		{name: "full-pipe-capped", bdp: bdp, cwnd: 20 * testMSS, fullPipe: true, want: 20 * testMSS},
		{name: "full-pipe-above-target", bdp: bdp, cwnd: 25 * testMSS, fullPipe: true, want: 20 * testMSS},
		{name: "minimum-target", bdp: testMSS, cwnd: 10 * testMSS, fullPipe: true, want: 4 * testMSS},
		{name: "below-minimum", bdp: bdp, cwnd: 2 * testMSS, fullPipe: true, want: 4 * testMSS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBBR(t)
			b.minRTT = time.Second
			b.maxBw.update(bbrBwWindow, 0, uint64(tc.bdp))
			b.cwnd, b.fullBwReached = tc.cwnd, tc.fullPipe
			b.growCwnd(testMSS)
			if b.cwnd != tc.want {
				t.Errorf("cwnd %d, want %d", b.cwnd, tc.want)
			}
		})
	}
}

// TestBBR_MaxBwWindow verifies max_bw forgets a sample two ProbeBW cycles of
// rounds old, a round being one min_rtt.
func TestBBR_MaxBwWindow(t *testing.T) {
	const rtt = 100 * time.Millisecond
	for _, tc := range []struct {
		name    string
		spacing time.Duration // Between round trips.
		want    uint64
	}{
		{name: "aged-out", spacing: rtt, want: 10 * testMSS * 10},
		{name: "rounds-of-min-rtt", spacing: rtt / 2, want: 40 * testMSS * 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBBR(t)
			b.onRoundTrip(40*testMSS, 0, rtt, false, 0)
			for i := range int64(bbrBwWindow) + 1 {
				b.onRoundTrip(10*testMSS, 0, rtt, false, (i+1)*int64(tc.spacing))
			}
			if b.MaxBandwidth() != tc.want {
				t.Errorf("max_bw %d, want %d", b.MaxBandwidth(), tc.want)
			}
		})
	}
}

// TestBBR_Recovery verifies a fast retransmit the ControlBlock owes after
// three duplicate ACKs starts recovery without new data, a partial ACK resends SND.UNA unless it was
// resent, and the ACK of the data sent before ends it (RFC 6582 §3.2).
func TestBBR_Recovery(t *testing.T) {
	b := newBBR(t)
	recover := b.una + 10*testMSS
	for i := range 3 {
		b.postRx(b.una, recover, i == 2, true, 0)
	}
	if limit, _, rtx := b.preTx(b.una, recover, 0, false, false, 0); limit != 0 || rtx {
		t.Fatalf("limit %d, resend %v in recovery; want 0 and none", limit, rtx)
	}
	for i := range 3 { // SND.UNA and the two holes above it, as by tcp/sack.
		b.postTx(tcp.Segment{SEQ: b.una + tcp.Value(i*testMSS), DATALEN: testMSS, Flags: tcp.FlagACK}, b.una, 0)
	}
	b.postRx(b.una+testMSS, recover, false, false, 0)
	if _, _, rtx := b.preTx(b.una, recover, 0, false, false, 0); rtx {
		t.Fatalf("resend of SND.UNA %d, already resent", b.una)
	}
	b.postRx(b.una+2*testMSS, recover, false, false, 0)
	if _, from, rtx := b.preTx(b.una, recover, 0, false, false, 0); !rtx || from != b.una {
		t.Fatalf("no resend of SND.UNA %d after a partial ACK", b.una)
	}
	b.postRx(recover, recover, false, false, 0)
	if limit, _, rtx := b.preTx(b.una, recover, 0, false, false, 0); limit != b.CongestionWindow() || rtx {
		t.Errorf("limit %d, resend %v after recovery; want %d and none", limit, rtx, b.CongestionWindow())
	}
}

// TestBBR_TimeoutRecovery verifies a timeout starts recovery, discarding the
// round trip being measured.
func TestBBR_TimeoutRecovery(t *testing.T) {
	b := newBBR(t)
	nxt := b.una + 10*testMSS
	b.postTx(tcp.Segment{SEQ: b.una, DATALEN: testMSS, Flags: tcp.FlagACK}, b.una, 0)
	if limit, _, rtx := b.preTx(b.una, nxt, 1, true, false, 0); limit != 0 || !rtx || b.timing {
		t.Fatalf("limit %d, resend %v, timing %v after a timeout; want 0, a resend, none", limit, rtx, b.timing)
	}
	b.postRx(b.una+testMSS, nxt, false, false, 1)
	if _, _, rtx := b.preTx(b.una, nxt, 1, false, false, 0); !rtx || b.MinRTT() != 0 {
		t.Errorf("resend %v, min_rtt %v after a partial ACK; want a resend and none", rtx, b.MinRTT())
	}
}

// TestBBR_TransmitLimit verifies new data is limited to whole segments of the
// window left, in Drain, which cannot pace, of the BDP.
func TestBBR_TransmitLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state bbrState
		cwnd  tcp.Size
		want  tcp.Size // With 15 segments in flight.
	}{
		{name: "whole-segments", state: bbrProbeBW, cwnd: 22*testMSS + 50, want: 7 * testMSS},
		{name: "drain", state: bbrDrain, cwnd: 40 * testMSS, want: 5 * testMSS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBBR(t)
			b.state, b.cwnd, b.minRTT = tc.state, tc.cwnd, time.Second
			b.maxBw.update(bbrBwWindow, 0, 20*testMSS)
			if limit, _, _ := b.preTx(b.una, b.una+15*testMSS, 0, false, false, 0); limit != tc.want {
				t.Errorf("limit %d, want %d", limit, tc.want)
			}
		})
	}
}

// TestBBR_IdleRestart verifies a round trip measured after idle takes an
// expired min_rtt without ProbeRTT, which has no queue to drain, and that
// sending after idle ends a ProbeRTT that was due to end (§5.4.3).
func TestBBR_IdleRestart(t *testing.T) {
	const rtt = 100 * time.Millisecond
	b := newBBR(t)
	now := roundTrip(b, 10, rtt, 0) + int64(bbrProbeRTTInterval)
	b.preTx(b.una, b.nxt, 0, false, false, now)
	now = roundTrip(b, 10, 2*rtt, now)
	if b.State() == "ProbeRTT" || b.MinRTT() != 2*rtt {
		t.Fatalf("state %s, min_rtt %v after idle; want no ProbeRTT and %v", b.State(), b.MinRTT(), 2*rtt)
	}
	b.state, b.fullBwReached, b.cwnd, b.priorCwnd = bbrProbeRTT, true, 4*testMSS, 20*testMSS
	b.probeRTTDone, b.probeRTTDoneSet = now+1, true
	if b.preTx(b.una, b.nxt, 0, false, false, now); b.State() != "ProbeRTT" {
		t.Fatalf("state %s sending after idle before ProbeRTT is due to end, want ProbeRTT", b.State())
	}
	b.preTx(b.una, b.nxt, 0, false, false, now+1)
	if b.State() != "ProbeBW" || b.CongestionWindow() != 20*testMSS {
		t.Errorf("state %s, cwnd %d sending after idle past ProbeRTT; want ProbeBW, %d", b.State(), b.CongestionWindow(), 20*testMSS)
	}
}

// TestBBR_DrainEnd verifies Drain ends on an ACK leaving at most its window
// in flight, the BDP or at least 4 segments.
func TestBBR_DrainEnd(t *testing.T) {
	for _, tc := range []struct {
		name     string
		bdp      tcp.Size
		inflight tcp.Size
		want     string
	}{
		{name: "above-bdp", bdp: 40 * testMSS, inflight: 41 * testMSS, want: "Drain"},
		{name: "at-bdp", bdp: 40 * testMSS, inflight: 40 * testMSS, want: "ProbeBW"},
		{name: "small-bdp", bdp: testMSS, inflight: 4 * testMSS, want: "ProbeBW"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBBR(t)
			b.state, b.minRTT = bbrDrain, time.Second
			b.maxBw.update(bbrBwWindow, 0, uint64(tc.bdp))
			b.postRx(b.una+testMSS, b.una+testMSS+tcp.Value(tc.inflight), false, false, 1)
			if b.State() != tc.want {
				t.Errorf("state %s, want %s", b.State(), tc.want)
			}
		})
	}
}

// TestBBR_ZeroWindowProbe verifies zero-window probes timing out start no
// recovery, so the data goes out without a further timeout once the window
// reopens.
func TestBBR_ZeroWindowProbe(t *testing.T) {
	for _, tc := range []struct {
		name    string
		queued  int  // Data written after the peer's window closed.
		timeout bool // The last probe times out before the window reopens.
	}{
		{name: "last-probe-timed-out", queued: testMSS, timeout: true},
		{name: "window-reopens-first", queued: 6 * testMSS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := new(int64)
			client, server, bbr := bbrPair(t, clock)
			packet := make([]byte, connMTU)
			if _, err := client.Write(make([]byte, connBuf)); err != nil {
				t.Fatal("write:", err)
			}
			for i := 0; client.BufferedUnsent() > 0 && i < 1000; i++ {
				for relay(t, client, server, packet) != 0 {
					relay(t, server, client, packet)
				}
				*clock += int64(time.Millisecond)
			}
			if _, err := client.Write(make([]byte, tc.queued)); err != nil {
				t.Fatal("write:", err)
			}
			for i := range 3 {
				if n := sendOnly(t, client, packet); n != tcpHeaderLen+1 {
					t.Fatalf("sent %d octets, want a zero-window probe", n)
				}
				if i < 2 || tc.timeout {
					*clock = bbr.NextDeadline()
				}
			}
			expirations := bbr.Timer().Expirations()
			if _, err := server.Read(make([]byte, connBuf)); err != nil {
				t.Fatal(err)
			}
			for range 50 {
				for relay(t, server, client, packet) != 0 {
				}
				if relay(t, client, server, packet) == 0 {
					*clock += int64(10 * time.Millisecond)
				}
			}
			if tc.timeout {
				expirations++ // The last probe's, on the next transmit.
			}
			cb := client.ControlBlock()
			if cb.SendUNA() != cb.SendNext() || client.BufferedUnsent() != 0 || bbr.Timer().Expirations() != expirations {
				t.Errorf("%d octets unacknowledged, %d unsent, %d timeouts more than the probes'; want 0, 0, 0",
					tcp.Sizeof(cb.SendUNA(), cb.SendNext()), client.BufferedUnsent(), int(bbr.Timer().Expirations())-int(expirations))
			}
		})
	}
}

// bbrPair returns two established handlers with a BBR controller on the
// client, on clock, with an ISS half the sequence space away from zero.
func bbrPair(t *testing.T, clock *int64) (client, server *tcp.Handler, bbr *BBR) {
	t.Helper()
	bbr = new(BBR)
	if err := bbr.Configure(BBRConfig{Nanotime: func() int64 { return *clock }}); err != nil {
		t.Fatal(err)
	}
	client, server = new(tcp.Handler), new(tcp.Handler)
	for _, h := range []*tcp.Handler{client, server} {
		if err := h.SetBuffers(make([]byte, connBuf), make([]byte, connBuf), connBuf/testMSS); err != nil {
			t.Fatal(err)
		}
	}
	client.SetPolicy(bbr)
	if err := server.OpenListen(80, 0); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenActive(1234, 80, 1<<31+5); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, connMTU)
	for _, hop := range [][2]*tcp.Handler{{client, server}, {server, client}, {client, server}} {
		relay(t, hop[0], hop[1], packet)
	}
	if client.State() != tcp.StateEstablished || server.State() != tcp.StateEstablished {
		t.Fatalf("handshake failed: client=%s server=%s", client.State(), server.State())
	}
	return client, server, bbr
}

// TestBBR_Limit verifies new data is limited to the initial window of
// segments of the peer's MSS.
func TestBBR_Limit(t *testing.T) {
	client, _, bbr := bbrPair(t, new(int64))
	if _, err := client.Write(make([]byte, 20*testMSS)); err != nil {
		t.Fatal("write:", err)
	}
	packet := make([]byte, connMTU)
	sent := 0
	for n := sendOnly(t, client, packet); n != 0 && sent <= 20*testMSS; n = sendOnly(t, client, packet) {
		sent += n - tcpHeaderLen
	}
	if sent != 10*testMSS || bbr.CongestionWindow() != 10*testMSS {
		t.Errorf("sent %d octets, cwnd %d; want %d", sent, bbr.CongestionWindow(), 10*testMSS)
	}
}

// TestBBR_Timeout verifies the timer the controller runs resends SND.UNA at
// the deadline reported through tcp.Policies, and the round trip being
// measured is discarded.
func TestBBR_Timeout(t *testing.T) {
	clock := new(int64)
	client, server, bbr := bbrPair(t, clock)
	if _, err := client.Write(make([]byte, testMSS)); err != nil {
		t.Fatal("write:", err)
	}
	packet := make([]byte, connMTU)
	sendOnly(t, client, packet) // Lost.
	*clock = (tcp.Policies{bbr}).NextDeadline()
	if relay(t, client, server, packet) == 0 || bbr.Timer().Expirations() != 1 {
		t.Fatalf("timeouts %d, want a resend on the timeout", bbr.Timer().Expirations())
	}
	*clock += int64(time.Millisecond)
	relay(t, server, client, packet)
	if bbr.MinRTT() != 0 {
		t.Errorf("min_rtt %v from the ACK of a resend, want none", bbr.MinRTT())
	}
}

// path carries the client's segments to the server at rate octets per second
// and delay later, and the server's back after delay.
type path struct {
	rate, delay int64
	// From later on the delay is laterDelay, which may not be lower.
	later, laterDelay int64
	lost              []int // Indices of the client's segments dropped.
	busy              int64 // When the link is free.
	sent              int
	fwd, rev          []transit
}

type transit struct {
	at  int64
	pkt []byte
}

// run sends total octets from client to server over the path, moving clock
// from event to event, and returns what the server read.
func (p *path) run(t *testing.T, client, server *tcp.Handler, bbr *BBR, clock *int64, total int) []byte {
	t.Helper()
	data := make([]byte, total)
	for i := range data {
		data[i] = byte(i * 7)
	}
	packet, buf := make([]byte, connMTU), make([]byte, connBuf)
	var got []byte
	written := 0
	for range 1_000_000 {
		now, delay := *clock, p.delay
		if p.later != 0 && now >= p.later {
			delay = p.laterDelay
		}
		if written < total {
			n, _ := client.Write(data[written:min(total, written+2000)])
			written += n
		}
		for n := sendOnly(t, client, packet); n != 0; n = sendOnly(t, client, packet) {
			if p.sent++; p.sent > 10*total/testMSS {
				t.Fatalf("%d segments sent for %d octets", p.sent, total)
			}
			if slices.Contains(p.lost, p.sent-1) {
				continue
			}
			p.busy = max(p.busy, now) + int64(n)*int64(time.Second)/p.rate
			p.fwd = append(p.fwd, transit{at: p.busy + delay, pkt: slices.Clone(packet[:n])})
		}
		moved := false
		for len(p.fwd) > 0 && p.fwd[0].at <= now {
			server.Recv(p.fwd[0].pkt) // Rejects copies of segments it has.
			p.fwd, moved = p.fwd[1:], true
			n, _ := server.Read(buf)
			got = append(got, buf[:n]...)
			for m := sendOnly(t, server, packet); m != 0; m = sendOnly(t, server, packet) {
				p.rev = append(p.rev, transit{at: now + delay, pkt: slices.Clone(packet[:m])})
			}
		}
		for len(p.rev) > 0 && p.rev[0].at <= now {
			client.Recv(p.rev[0].pkt)
			p.rev, moved = p.rev[1:], true
		}
		if cb := client.ControlBlock(); len(got) == total && cb.SendUNA() == cb.SendNext() {
			return got
		} else if moved {
			continue
		}
		next := bbr.NextDeadline()
		for _, q := range [][]transit{p.fwd, p.rev} {
			if len(q) > 0 && (next == 0 || q[0].at < next) {
				next = q[0].at
			}
		}
		if next == 0 {
			t.Fatalf("stalled with %d of %d octets read", len(got), total)
		}
		*clock = max(next, now)
	}
	t.Fatalf("not done with %d of %d octets read", len(got), total)
	return nil
}

// TestBBR_Path verifies BBR estimates the rate and round trip of a bottleneck
// path, also after the delay rose, reaches ProbeBW and delivers the data
// intact without a timeout and with few resends, also after losses.
func TestBBR_Path(t *testing.T) {
	const ms = time.Millisecond
	for _, tc := range []struct {
		name          string
		rate          int64 // Octets per second, headers included; 100000 if zero.
		delay         time.Duration
		later, delay2 time.Duration // From later on the delay is delay2.
		total         int           // Octets; 100000 if zero.
		lost          []int
	}{
		{name: "lossless", delay: 10 * ms},
		{name: "one-loss", delay: 10 * ms, lost: []int{40}},
		{name: "consecutive-losses", delay: 10 * ms, lost: []int{40, 41, 42}},
		{name: "spread-losses", delay: 10 * ms, lost: []int{40, 200, 400, 600}},
		{name: "lan-losses", delay: 2 * ms, total: 150_000, lost: []int{50, 300, 301, 700}},
		{name: "delay-rises", rate: 50_000, delay: 5 * ms, later: time.Second, delay2: 50 * ms, total: 400_000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rate, total, delay := cmp.Or(tc.rate, 100_000), cmp.Or(tc.total, 100_000), cmp.Or(tc.delay2, tc.delay)
			clock := new(int64)
			client, server, bbr := bbrPair(t, clock)
			p := &path{rate: rate, delay: int64(tc.delay), later: int64(tc.later), laterDelay: int64(tc.delay2), lost: tc.lost}
			got := p.run(t, client, server, bbr, clock, total)
			want := make([]byte, total)
			for i := range want {
				want[i] = byte(i * 7)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("data corrupted")
			}
			goodput := float64(rate) * testMSS / (testMSS + tcpHeaderLen)
			bw, minRTT := float64(bbr.MaxBandwidth()), bbr.MinRTT()
			if bw < 0.95*goodput || bw > 1.05*goodput || minRTT < 2*delay || minRTT > 2*delay+3*ms ||
				bbr.State() != "ProbeBW" || bbr.Timer().Expirations() != 0 || p.sent > total/testMSS*5/4 {
				t.Errorf("max_bw %.0f, min_rtt %v, state %s, timeouts %d, %d segments; want within 5%% of %.0f, %v-%v, ProbeBW, 0, at most %d",
					bw, minRTT, bbr.State(), bbr.Timer().Expirations(), p.sent, goodput, 2*delay, 2*delay+3*ms, total/testMSS*5/4)
			}
		})
	}
}

// TestBBR_Reset verifies a reset after a transfer and a timeout starts the
// next connection afresh, also its timer.
func TestBBR_Reset(t *testing.T) {
	clock := new(int64)
	client, server, bbr := bbrPair(t, clock)
	p := &path{rate: 100_000, delay: int64(10 * time.Millisecond), lost: []int{100}}
	p.run(t, client, server, bbr, clock, 20_000)
	if bbr.State() == "Startup" || bbr.Timer().SmoothedRTT() == 0 {
		t.Fatalf("state %s, SRTT %v; test needs a measured connection", bbr.State(), bbr.Timer().SmoothedRTT())
	}
	bbr.Reset()
	if bbr.State() != "Startup" || bbr.CongestionWindow() != 10*defaultMSS || bbr.MinRTT() != 0 || bbr.MaxBandwidth() != 0 || bbr.Timer().SmoothedRTT() != 0 {
		t.Errorf("state %s, cwnd %d, min_rtt %v, max_bw %d, SRTT %v after Reset; want Startup, %d, 0, 0, 0",
			bbr.State(), bbr.CongestionWindow(), bbr.MinRTT(), bbr.MaxBandwidth(), bbr.Timer().SmoothedRTT(), 10*defaultMSS)
	}
}

func TestBBR_ZeroAlloc(t *testing.T) {
	if runtime.Compiler == "tinygo" {
		t.Skip("TinyGo's testing.AllocsPerRun does not count allocations")
	}
	clock := new(int64)
	client, server, _ := bbrPair(t, clock)
	data, packet := make([]byte, testMSS), make([]byte, connMTU)
	allocs := testing.AllocsPerRun(100, func() {
		*clock += int64(time.Millisecond)
		if _, err := client.Write(data); err != nil {
			t.Fatal("write:", err)
		}
		if relay(t, client, server, packet) == 0 {
			t.Fatal("no data segment produced")
		}
		if _, err := server.Read(data); err != nil {
			t.Fatal("read:", err)
		}
		relay(t, server, client, packet)
	})
	if allocs != 0 {
		t.Errorf("allocated %v times per exchange, want 0", allocs)
	}
}
