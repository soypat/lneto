package congestion_test

import (
	"errors"
	"net"
	"slices"
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
// Congestion is emulated both through rate/delay limiting and through packet
// loss (emuLink.lossAt). Loss recovery is driven by the RFC 6298 retransmission
// timer: the pump folds each Handler's RetransmitDeadline into its event
// schedule and calls CheckRetransmitTimeout, so an RTO fires even when the links
// are idle after a loss. With the timer in place a single loss is recovered
// go-back-N and the transfer completes.
//
// Remaining limitation: lneto's ControlBlock still accepts only in-order
// segments (no out-of-order buffering) and the receiver issues throttled
// challenge ACKs, aborting after maxChallengeRejects (8) consecutive
// out-of-order segments. Loss is therefore kept to a single early drop in a
// small window so the gap raises fewer than 8 out-of-order segments. Once
// out-of-order buffering and SACK land, larger and repeated loss patterns can be
// exercised.
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
// bytes/sec, then delayed by a fixed propagation delay. lossAt optionally drops
// a single packet to model an isolated loss.
type emuLink struct {
	rate  float64       // bytes/sec; 0 means infinite bandwidth (no serialization).
	delay time.Duration // one-way propagation delay.
	// lossAt drops the packets at these 1-based offered indices (nil = lossless).
	lossAt []int

	inflight  []emuPacket // accepted packets ordered by deliverAt (monotonic).
	busyUntil time.Time   // time the serializer becomes free.
	offered   int         // total packets offered, for the loss counter.
	dropped   int
}

// offer submits a copy of data to the link at simulated time now. deliverAt is
// monotonically non-decreasing across calls made in non-decreasing now order, so
// inflight stays ordered.
func (l *emuLink) offer(data []byte, now time.Time) {
	l.offered++
	if slices.Contains(l.lossAt, l.offered) {
		l.dropped++
		return
	}
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
	rate       float64       // forward-path bottleneck bandwidth, bytes/sec.
	delay      time.Duration // one-way propagation delay applied to both paths.
	lossAt     []int         // forward-path: drop packets at these offered indices (nil = lossless).
	bufSize    int           // per-handler tx/rx buffer size in bytes.
	packets    int           // tx ring packet slots (must exceed segments in flight).
	reasmSegs  int           // receiver out-of-order reassembly slots (0 = disabled).
	timestamps bool          // enable RFC 7323 TCP Timestamps on both ends.
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
	en := &emuNet{
		t:      t,
		clock:  time.Unix(0, 0),
		client: newHandler(),
		server: newHandler(),
		fwd:    &emuLink{rate: p.rate, delay: p.delay, lossAt: p.lossAt},
		rev:    &emuLink{rate: 0, delay: p.delay}, // reverse path: infinite bandwidth.
		buf:    make([]byte, ethernet.MaxMTU),
	}
	// Share the simulated clock with both handlers' RFC 6298 timers so RTO is
	// deterministic and aligned with the congestion controllers' clock.
	en.client.SetClock(en.now)
	en.server.SetClock(en.now)
	if p.reasmSegs > 0 {
		// Enable out-of-order reassembly on the receiver. Slots are sized for a
		// full-MTU segment payload.
		slab := make([]byte, p.reasmSegs*int(ethernet.MaxMTU))
		if err := en.server.SetReassemblyBuffer(slab, p.reasmSegs); err != nil {
			t.Fatalf("SetReassemblyBuffer: %v", err)
		}
	}
	if p.timestamps {
		if err := en.client.EnableTimestamps(true); err != nil {
			t.Fatalf("client EnableTimestamps: %v", err)
		}
		if err := en.server.EnableTimestamps(true); err != nil {
			t.Fatalf("server EnableTimestamps: %v", err)
		}
	}
	return en
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

		// The next event is the soonest of a packet delivery or a retransmission
		// timer firing. Folding the RFC 6298 timers in lets the clock jump to an
		// RTO when the links are idle (e.g. after a loss with no ACK feedback).
		next, ok := earliestEvent(en.fwd, en.rev)
		cd, crun := en.client.RetransmitDeadline()
		next, ok = earlierDeadline(next, ok, cd, crun)
		sd, srun := en.server.RetransmitDeadline()
		next, ok = earlierDeadline(next, ok, sd, srun)
		if !ok {
			break // nothing in flight and no timer pending: transfer complete.
		}
		if next.After(en.clock) {
			en.clock = next
		}
		if en.clock.After(deadline) {
			en.t.Fatal("transfer exceeded simulated-time deadline")
		}

		// Fire any expired retransmission timers; the rewound data is sent on the
		// next iteration's drain.
		en.client.CheckRetransmitTimeout()
		en.server.CheckRetransmitTimeout()

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

// earlierDeadline folds a candidate timer deadline (valid only when running)
// into the running earliest-event time.
func earlierDeadline(cur time.Time, haveCur bool, cand time.Time, running bool) (time.Time, bool) {
	if !running {
		return cur, haveCur
	}
	if !haveCur || cand.Before(cur) {
		return cand, true
	}
	return cur, true
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

// TestEmuTimestampsNegotiateAndMeasureRTT enables RFC 7323 Timestamps on both
// ends and runs a lossless transfer, verifying the option is negotiated and the
// smoothed RTT converges to the link's propagation round trip via per-ACK RTTM.
func TestEmuTimestampsNegotiateAndMeasureRTT(t *testing.T) {
	const (
		rate    = 1_000_000.0
		delay   = 10 * time.Millisecond
		propRTT = 2 * delay
		bufSize = 60_000
	)
	en := newEmuNet(t, emuParams{
		rate:       rate,
		delay:      delay,
		bufSize:    bufSize,
		packets:    64,
		timestamps: true,
	})

	var cubic congestion.CUBIC
	if err := cubic.Configure(congestion.CUBICConfig{Now: en.now}); err != nil {
		t.Fatal(err)
	}
	if err := en.client.SetCongestionControl(&cubic); err != nil {
		t.Fatal(err)
	}

	openPair(t, en.client, en.server)
	received := en.transfer(patternPayload(64 * 1024))
	verifyStream(t, patternPayload(64*1024), received)

	if !en.client.TimestampsEnabled() || !en.server.TimestampsEnabled() {
		t.Fatalf("timestamps not negotiated: client=%v server=%v",
			en.client.TimestampsEnabled(), en.server.TimestampsEnabled())
	}
	srtt := en.client.SmoothedRTT()
	if srtt <= 0 {
		t.Fatal("no RTT measured from timestamps")
	}
	if srtt < propRTT/2 || srtt > 3*propRTT {
		t.Errorf("SRTT %v not near propagation RTT %v", srtt, propRTT)
	}
	t.Logf("timestamps: negotiated; SRTT=%v (propagation RTT %v)", srtt, propRTT)
}

// TestEmuSACKRecoversMultipleLosses drops two segments in one window with SACK
// and reassembly enabled. The receiver advertises the byte ranges it buffered,
// and the sender retransmits only the two holes (skipping the SACKed data in
// between) rather than going back N. The test asserts SACK is negotiated and the
// full stream is delivered intact after exactly two drops.
func TestEmuSACKRecoversMultipleLosses(t *testing.T) {
	const (
		rate    = 1_000_000.0
		delay   = 10 * time.Millisecond
		bufSize = 32 * 1024
	)
	en := newEmuNet(t, emuParams{
		rate:       rate,
		delay:      delay,
		lossAt:     []int{4, 9}, // two holes in the same window.
		bufSize:    bufSize,
		packets:    64,
		reasmSegs:  32,
		timestamps: true,
	})
	en.client.EnableSACK(true)
	en.server.EnableSACK(true)

	var cubic congestion.CUBIC
	if err := cubic.Configure(congestion.CUBICConfig{InitialCwnd: 16, Now: en.now}); err != nil {
		t.Fatal(err)
	}
	if err := en.client.SetCongestionControl(&cubic); err != nil {
		t.Fatal(err)
	}

	payload := patternPayload(18 * 1024) // ~13 segments: one window with two gaps.
	openPair(t, en.client, en.server)
	received := en.transfer(payload)

	verifyStream(t, payload, received)
	if !en.client.SACKEnabled() || !en.server.SACKEnabled() {
		t.Fatalf("SACK not negotiated: client=%v server=%v",
			en.client.SACKEnabled(), en.server.SACKEnabled())
	}
	if en.fwd.dropped != 2 {
		t.Errorf("expected exactly 2 injected drops, got %d", en.fwd.dropped)
	}
	t.Logf("SACK recovery: delivered %d B intact after 2 losses in one window", len(received))
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

// sawWindowReduction reports whether the sampled congestion window ever
// decreased between consecutive samples.
func sawWindowReduction(samples []tcp.Size) bool {
	for i := 1; i < len(samples); i++ {
		if samples[i] < samples[i-1] {
			return true
		}
	}
	return false
}

// TestEmuRTORecoversLoss drives CUBIC across a link that drops a single early
// segment in a small window. With no out-of-order buffering yet, the receiver
// discards everything past the gap; recovery therefore relies on the RFC 6298
// retransmission timer (and/or fast retransmit) rewinding to snd.UNA. The test
// proves the loss is recovered end-to-end (full stream delivered intact), that
// exactly one drop occurred, and that the controller reacted to the loss.
func TestEmuRTORecoversLoss(t *testing.T) {
	const (
		rate    = 1_000_000.0
		delay   = 10 * time.Millisecond
		bufSize = 60_000
	)
	en := newEmuNet(t, emuParams{
		rate:    rate,
		delay:   delay,
		lossAt:  []int{5}, // an early forward segment, in a small window.
		bufSize: bufSize,
		packets: 64,
	})

	var cubic congestion.CUBIC
	if err := cubic.Configure(congestion.CUBICConfig{
		InitialCwnd:     4, // keep the window small so the gap raises < 8 out-of-order
		SlowStartThresh: 6, // segments, staying under the challenge-ACK abort threshold.
		Now:             en.now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := en.client.SetCongestionControl(&cubic); err != nil {
		t.Fatal(err)
	}
	en.probe = cubic.CongestionWindow

	openPair(t, en.client, en.server)

	payload := patternPayload(32 * 1024)
	received := en.transfer(payload)

	verifyStream(t, payload, received)
	if en.fwd.dropped != 1 {
		t.Errorf("expected exactly 1 injected drop, got %d", en.fwd.dropped)
	}
	if !sawWindowReduction(en.samples) {
		t.Error("CUBIC congestion window never decreased despite the loss")
	}
	t.Logf("RTO recovery: delivered %d B intact after 1 loss; final cwnd=%d B",
		len(received), cubic.CongestionWindow())
}

// TestEmuReassemblyRecoversManyFollowers drops a segment near the head of a
// window with more than eight segments queued behind it. Without out-of-order
// buffering the receiver would issue throttled challenge ACKs and abort after 8
// consecutive out-of-order segments; with reassembly enabled it buffers them,
// fast retransmit fills the single gap, and the buffered tail is delivered
// without go-back-N. The test asserts the full stream arrives intact after
// exactly one drop. The slab is sized larger than the receive buffer so any
// in-window out-of-order segment fits.
func TestEmuReassemblyRecoversManyFollowers(t *testing.T) {
	const (
		rate    = 1_000_000.0
		delay   = 10 * time.Millisecond
		bufSize = 32 * 1024
	)
	en := newEmuNet(t, emuParams{
		rate:      rate,
		delay:     delay,
		lossAt:    []int{3}, // 2nd data segment: ~11 segments follow the gap (> 8).
		bufSize:   bufSize,
		packets:   64,
		reasmSegs: 32, // slab (32*MTU) exceeds the receive buffer.
	})

	var cubic congestion.CUBIC
	if err := cubic.Configure(congestion.CUBICConfig{
		InitialCwnd: 16, // whole transfer fits one window: a single burst with one gap.
		Now:         en.now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := en.client.SetCongestionControl(&cubic); err != nil {
		t.Fatal(err)
	}

	payload := patternPayload(18 * 1024) // ~13 segments, < window and < slab.
	openPair(t, en.client, en.server)
	received := en.transfer(payload)

	verifyStream(t, payload, received)
	if en.fwd.dropped != 1 {
		t.Errorf("expected exactly 1 injected drop, got %d", en.fwd.dropped)
	}
	t.Logf("reassembly recovery: delivered %d B intact; one gap with >8 buffered followers",
		len(received))
}
