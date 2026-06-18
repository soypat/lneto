package congestion_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/congestion"
)

// Notes(MDr164):
//
// This file implements deterministic end-to-end congestion-control testing
// via two real tcp.Handlers that exchange data across an in-process emulated
// bottleneck link. The link models a finite bandwidth and a propagation delay,
// and the whole simulation is driven by a fake clock
// (the same clock injected into the congestion controllers), so runs are
// deterministic and independent of wall-clock time. The bottleneck is the
// emulated congestion: a controller that overshoots the bandwidth-delay product
// builds a standing queue (inflated RTT), while one that under-shoots leaves the
// pipe idle.
//
// Scope and a stack limitation worth recording: these tests emulate congestion
// through rate/delay limiting, not packet loss. lneto's ControlBlock accepts
// only in-order segments (it buffers no out-of-order data), recovers loss solely
// via duplicate-ACK fast retransmit with no RTO timer in the Handler, and the
// receiver aborts after maxChallengeRejects (8) consecutive out-of-order
// segments. A single mid-stream loss therefore forces go-back-N recovery that
// deadlocks as soon as the sender runs out of new data to elicit further dup
// ACKs. Robust loss-based recovery needs RTO support and/or out-of-order
// buffering at a higher layer; until then, end-to-end loss-recovery testing is
// out of scope here. CUBIC's loss response itself is covered at the controller
// level (see cubic_test.go: TestCUBICMultiplicativeDecrease, TestCUBICControlLoss).
//
// Potential follow-up: property/fuzz testing on top of this same harness.
// Rather than asserting throughput/estimate ranges for fixed scenarios,
// randomize the link parameters (rate, delay) with testing.F
// and assert invariants only — e.g. the congestion window never exceeds the
// advertised receive window, never drops to zero while data is in flight, BBR
// never collapses its window, the delivered byte stream always matches the sent
// stream, and Control performs no heap allocation. The emuLink/emuNet types are
// written so a fuzz target can construct them from fuzzed parameters unchanged.
// Adding lossy fuzzing depends on the RTO/out-of-order work noted above.

// emuPacket is a serialized TCP frame in transit across an [emuLink], tagged
// with the simulated time at which it is fully delivered to the receiver.
type emuPacket struct {
	data      []byte
	deliverAt time.Time
}

// emuLink is a one-way bottleneck link. Offered packets are serialized at rate
// bytes/sec, then delayed by a fixed propagation delay. When the bottleneck
// queue (the bytes already waiting to be serialized) would exceed queueCap the
// packet is tail-dropped, modelling congestive loss without injecting synthetic
// duplicate ACKs.
type emuLink struct {
	rate  float64       // bytes/sec; 0 means infinite bandwidth (no serialization).
	delay time.Duration // one-way propagation delay.

	inflight  []emuPacket // accepted packets ordered by deliverAt (monotonic).
	busyUntil time.Time   // time the serializer becomes free.
}

// offer submits a copy of data to the link at simulated time now. deliverAt is
// monotonically non-decreasing across calls made in non-decreasing now order, so
// inflight stays ordered.
func (l *emuLink) offer(data []byte, now time.Time) {
	start := now
	if l.busyUntil.After(start) {
		start = l.busyUntil // queue behind packets still being serialized.
	}
	var serialize time.Duration
	if l.rate > 0 {
		serialize = time.Duration(float64(len(data)) / l.rate * float64(time.Second))
	}
	finish := start.Add(serialize)
	l.busyUntil = finish
	cp := make([]byte, len(data))
	copy(cp, data)
	l.inflight = append(l.inflight, emuPacket{data: cp, deliverAt: finish.Add(l.delay)})
}

// due removes and returns every packet whose deliverAt is at or before now.
func (l *emuLink) due(now time.Time) [][]byte {
	var out [][]byte
	n := 0
	for _, p := range l.inflight {
		if p.deliverAt.After(now) {
			break
		}
		out = append(out, p.data)
		n++
	}
	l.inflight = l.inflight[n:]
	return out
}

// nextDeliver reports the earliest pending delivery time, if any.
func (l *emuLink) nextDeliver() (time.Time, bool) {
	if len(l.inflight) == 0 {
		return time.Time{}, false
	}
	return l.inflight[0].deliverAt, true
}

// emuParams configures an [emuNet].
type emuParams struct {
	rate    float64       // forward-path bottleneck bandwidth, bytes/sec.
	delay   time.Duration // one-way propagation delay applied to both paths.
	bufSize int           // per-handler tx/rx buffer size in bytes.
	packets int           // tx ring packet slots (must exceed segments in flight).
}

// emuNet runs a client→server bulk transfer across an emulated network: a
// rate-limited forward link carries data, an uncongested reverse link carries
// ACKs, and both share the propagation delay. The fake clock advances from
// event to event.
type emuNet struct {
	t      *testing.T
	clock  time.Time
	client *tcp.Handler
	server *tcp.Handler
	fwd    *emuLink // client → server (the bottleneck).
	rev    *emuLink // server → client (ACKs, uncongested).
	buf    []byte   // scratch frame buffer shared by Send/Recv/Read calls.

	// probe, if set, is sampled once per event step to record controller state
	// (e.g. the congestion window) over the life of the transfer.
	probe   func() tcp.Size
	samples []tcp.Size
}

func newEmuNet(t *testing.T, p emuParams) *emuNet {
	t.Helper()
	newHandler := func() *tcp.Handler {
		h := new(tcp.Handler)
		if err := h.SetBuffers(make([]byte, p.bufSize), make([]byte, p.bufSize), p.packets); err != nil {
			t.Fatalf("SetBuffers: %v", err)
		}
		return h
	}
	return &emuNet{
		t:      t,
		clock:  time.Unix(0, 0),
		client: newHandler(),
		server: newHandler(),
		fwd:    &emuLink{rate: p.rate, delay: p.delay},
		rev:    &emuLink{rate: 0, delay: p.delay}, // reverse path: infinite bandwidth.
		buf:    make([]byte, ethernet.MaxMTU),
	}
}

// now returns the simulated clock. It is installed as the controller's Now func
// so controller timing and link timing share one clock.
func (en *emuNet) now() time.Time { return en.clock }

// drain repeatedly pulls segments out of h and offers them to link until h has
// nothing more to send (it self-limits via the congestion/receive window).
func (en *emuNet) drain(h *tcp.Handler, link *emuLink) {
	for range 4096 {
		n, err := h.Send(en.buf)
		if err != nil {
			return // net.ErrClosed and friends: nothing more to send.
		}
		if n == 0 {
			return
		}
		link.offer(en.buf[:n], en.clock)
	}
	en.t.Fatal("drain: Send did not settle (possible send loop)")
}

// transfer streams payload from client to server and returns the bytes the
// server received, in order. The 3-way handshake is carried across the emulated
// links too, so RTT samples are realistic from the first round trip.
func (en *emuNet) transfer(payload []byte) (received []byte) {
	en.t.Helper()
	remaining := payload
	received = make([]byte, 0, len(payload))
	deadline := en.clock.Add(120 * time.Second) // simulated-time guard.

	for range 5_000_000 {
		// Feed application data once the connection can accept writes.
		if len(remaining) > 0 && en.client.State().TxDataOpen() {
			if free := en.client.FreeOutput(); free > 0 {
				w := min(free, len(remaining))
				n, err := en.client.Write(remaining[:w])
				if err != nil && !errors.Is(err, net.ErrClosed) {
					en.t.Fatalf("client write: %v", err)
				}
				remaining = remaining[n:]
			}
		}

		en.drain(en.client, en.fwd)
		en.drain(en.server, en.rev)

		if en.probe != nil {
			en.samples = append(en.samples, en.probe())
		}

		next, ok := earliestEvent(en.fwd, en.rev)
		if !ok {
			break // nothing left in flight: transfer complete.
		}
		if next.After(en.clock) {
			en.clock = next
		}
		if en.clock.After(deadline) {
			en.t.Fatal("transfer exceeded simulated-time deadline")
		}

		for _, pkt := range en.fwd.due(en.clock) {
			_ = en.server.Recv(pkt) // rejects under loss/reorder are normal (yield dup ACKs).
		}
		for _, pkt := range en.rev.due(en.clock) {
			_ = en.client.Recv(pkt)
		}

		// Drain the server's receive buffer so its advertised window stays open,
		// accumulating the delivered byte stream for the integrity check.
		for {
			n, err := en.server.Read(en.buf)
			if n > 0 {
				received = append(received, en.buf[:n]...)
			}
			if n == 0 || err != nil {
				break
			}
		}
		// Drain (and discard) anything the client receives besides ACKs.
		for {
			n, err := en.client.Read(en.buf)
			if n == 0 || err != nil {
				break
			}
		}

		if len(remaining) == 0 && en.client.BufferedUnsent() == 0 && len(received) == len(payload) {
			break
		}
	}
	return received
}

// earliestEvent returns the soonest pending delivery across both links.
func earliestEvent(a, b *emuLink) (time.Time, bool) {
	ta, oka := a.nextDeliver()
	tb, okb := b.nextDeliver()
	switch {
	case oka && okb:
		if ta.Before(tb) {
			return ta, true
		}
		return tb, true
	case oka:
		return ta, true
	case okb:
		return tb, true
	default:
		return time.Time{}, false
	}
}

// patternPayload returns n bytes of a deterministic, position-dependent pattern
// so the receiver can detect any byte-stream corruption or misordering.
func patternPayload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*131 + 7)
	}
	return b
}

func verifyStream(t *testing.T, want, got []byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("received %d of %d bytes", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("byte stream corrupted at offset %d: got %#x want %#x", i, got[i], want[i])
		}
	}
}

// TestEmuCUBICFillsBottleneck drives CUBIC across a bandwidth/delay-limited link
// and proves the controller is wired end-to-end through two real Handlers: with
// an initial slow-start threshold below the bandwidth-delay product, CUBIC
// leaves slow start, grows its window in congestion avoidance to fill the pipe,
// delivers the whole stream intact, and approaches — without exceeding — the
// link capacity.
func TestEmuCUBICFillsBottleneck(t *testing.T) {
	const (
		rate    = 1_000_000.0 // 1 MB/s bottleneck.
		delay   = 10 * time.Millisecond
		bufSize = 60_000
	)
	en := newEmuNet(t, emuParams{
		rate:    rate,
		delay:   delay,
		bufSize: bufSize,
		packets: 64,
	})

	var cubic congestion.CUBIC
	if err := cubic.Configure(congestion.CUBICConfig{
		InitialCwnd:     4, // start small so slow start is exercised...
		SlowStartThresh: 8, // ...then cross into congestion avoidance below the BDP.
		Now:             en.now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := en.client.SetCongestionControl(&cubic); err != nil {
		t.Fatal(err)
	}
	en.probe = cubic.CongestionWindow

	openPair(t, en.client, en.server)

	payload := patternPayload(256 * 1024)
	start := en.clock
	received := en.transfer(payload)
	elapsed := en.clock.Sub(start).Seconds()

	verifyStream(t, payload, received)

	if cubic.InSlowStart() {
		t.Errorf("CUBIC still in slow start after filling the pipe (cwnd=%d segments, ssthresh=%.0f)",
			cubic.CongestionWindow()/1460, cubic.SlowStartThresh())
	}
	if !sawWindowGrowth(en.samples) {
		t.Errorf("CUBIC congestion window never grew over the transfer")
	}
	throughput := float64(len(payload)) / elapsed
	if throughput > rate*1.1 {
		t.Errorf("throughput %.0f B/s exceeds link rate %.0f B/s", throughput, rate)
	}
	if throughput < rate*0.3 {
		t.Errorf("throughput %.0f B/s is under 30%% of link rate %.0f B/s (pipe under-filled)", throughput, rate)
	}
	t.Logf("CUBIC: cwnd=%d B (%d segs) ssthresh=%.0f throughput=%.0f B/s (%.0f%% of link)",
		cubic.CongestionWindow(), cubic.CongestionWindow()/1460, cubic.SlowStartThresh(),
		throughput, 100*throughput/rate)
}

// TestEmuBBRBandwidthEstimate drives BBR across a delay/rate-limited link. BBR
// should converge its delivery-rate estimate to the bottleneck bandwidth and
// its min_rtt to the propagation delay, while delivering the full stream intact.
func TestEmuBBRBandwidthEstimate(t *testing.T) {
	const (
		rate    = 1_000_000.0
		delay   = 10 * time.Millisecond
		propRTT = 2 * delay
		bufSize = 60_000
	)
	en := newEmuNet(t, emuParams{
		rate:    rate,
		delay:   delay,
		bufSize: bufSize,
		packets: 64,
	})

	var bbr congestion.BBR
	if err := bbr.Configure(congestion.BBRConfig{Now: en.now}); err != nil {
		t.Fatal(err)
	}
	if err := en.client.SetCongestionControl(&bbr); err != nil {
		t.Fatal(err)
	}

	openPair(t, en.client, en.server)

	payload := patternPayload(128 * 1024)
	received := en.transfer(payload)

	verifyStream(t, payload, received)

	bw := float64(bbr.BandwidthEstimate())
	if bw < rate*0.5 || bw > rate*1.2 {
		t.Errorf("BBR bandwidth estimate %.0f B/s not within [0.5,1.2]x link rate %.0f B/s", bw, rate)
	}
	if rtt := bbr.MinRTT(); rtt < propRTT || rtt > 2*propRTT+5*time.Millisecond {
		t.Errorf("BBR min_rtt %v not near propagation RTT %v", rtt, propRTT)
	}
	t.Logf("BBR: bw=%.0f B/s (%.0f%% of link) min_rtt=%v (prop RTT %v) cwnd=%d B",
		bw, 100*bw/rate, bbr.MinRTT(), propRTT, bbr.CongestionWindow())
}

// sawWindowGrowth reports whether the sampled congestion window ever increased
// between consecutive samples.
func sawWindowGrowth(samples []tcp.Size) bool {
	for i := 1; i < len(samples); i++ {
		if samples[i] > samples[i-1] {
			return true
		}
	}
	return false
}
