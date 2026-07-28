package congestion

import (
	"testing"
	"time"

	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
	"github.com/soypat/lneto/tcp/timestamps"
)

// This file is the proof that the seam composes: two policies written
// independently, in two packages, sharing the one retransmission timer a
// connection is allowed to have (RFC 6298 §5), driven together by a
// tcp.Composite.
//
// Without sharing they cannot be combined at all. Each embeds a timer of its own,
// and two timers on one connection retransmit on whichever estimate is the more
// pessimistic while each takes the outcome as its own decision.

// composed builds a composite of a shared timer, CUBIC and the timestamp
// extension, in the order the timer must come first.
func composed(t *testing.T) (*tcp.Composite, *rto.Timer, *CUBIC, *timestamps.Timestamps) {
	t.Helper()
	timer := new(rto.Timer)
	cubic := new(CUBIC)
	if err := cubic.Configure(CUBICConfig{MSS: 1000}); err != nil {
		t.Fatal(err)
	}
	ts := new(timestamps.Timestamps)
	cubic.SetTimer(timer)
	ts.SetTimer(timer)
	var c tcp.Composite
	for _, p := range []tcp.Policy{timer, cubic, ts} {
		if err := c.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	return &c, timer, cubic, ts
}

// composedPair establishes a connection with a composite of a shared timer, CUBIC
// and the timestamp extension on both sides. Both sides need the option or
// negotiation correctly fails, and no echo comes back to measure a round trip from.
// It returns the client's policies.
func composedPair(t *testing.T) (client, server *tcp.Handler, packet []byte, timer *rto.Timer, cubic *CUBIC, ts *timestamps.Timestamps) {
	t.Helper()
	clientComposite, timer, cubic, ts := composed(t)
	serverComposite, _, _, _ := composed(t)
	client, server = new(tcp.Handler), new(tcp.Handler)
	for _, h := range []*tcp.Handler{client, server} {
		if err := h.SetBuffers(make([]byte, connBuf), make([]byte, connBuf), 8); err != nil {
			t.Fatal(err)
		}
	}
	// A clock advancing a millisecond per read, so a round trip is measurable.
	var cnow, snow int64
	client.SetPolicy(clientComposite, func() int64 { cnow += int64(time.Millisecond); return cnow })
	server.SetPolicy(serverComposite, func() int64 { snow += int64(time.Millisecond); return snow })
	if err := server.OpenListen(80, 0); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenActive(1234, 80, 0); err != nil {
		t.Fatal(err)
	}
	packet = make([]byte, connMTU)
	relay(t, client, server, packet) // SYN
	relay(t, server, client, packet) // SYN-ACK
	relay(t, client, server, packet) // ACK
	if client.State() != tcp.StateEstablished || server.State() != tcp.StateEstablished {
		t.Fatalf("handshake failed: client=%s server=%s", client.State(), server.State())
	}
	return client, server, packet, timer, cubic, ts
}

// TestSharedTimer_DrivesRealConnection verifies the composed policies carry a
// connection end to end: the option is negotiated by one policy while the other
// throttles, and the timestamp-derived round-trip sample lands in the timer that
// both of them read.
func TestSharedTimer_DrivesRealConnection(t *testing.T) {
	client, server, packet, timer, cubic, ts := composedPair(t)

	if !ts.Enabled() {
		t.Fatal("the timestamp option was not negotiated through the composite")
	}
	// Carry data and let it be acknowledged, so an echo comes back.
	payload := make([]byte, 3000)
	for i := range payload {
		payload[i] = byte(i)
	}
	if _, err := client.Write(payload); err != nil {
		t.Fatal("write:", err)
	}
	for range 12 {
		if relay(t, client, server, packet) == 0 {
			break
		}
		relay(t, server, client, packet) // Acknowledgement carrying the echo.
	}
	got := make([]byte, len(payload))
	read := 0
	for read < len(payload) {
		n, err := server.Read(got[read:])
		if err != nil || n == 0 {
			break
		}
		read += n
	}
	if read == 0 {
		t.Fatal("no data crossed the composed connection")
	}

	// The sample the timestamp policy took must be in the shared timer, which is
	// what makes sharing worth doing: the controller's curve is evaluated against
	// an RTT it did not measure itself.
	if _, ok := ts.LastRTT(); !ok {
		t.Fatal("the timestamp policy never measured a round trip")
	}
	if timer.SmoothedRTT() == 0 {
		t.Error("the shared timer has no RTT estimate")
	}
	if cubic.SmoothedRTT() != int64(timer.SmoothedRTT()) {
		t.Errorf("CUBIC reads RTT %d but the shared timer holds %d", cubic.SmoothedRTT(), timer.SmoothedRTT())
	}
	if ts.SmoothedRTT() != int64(timer.SmoothedRTT()) {
		t.Errorf("the timestamp policy reads RTT %d but the shared timer holds %d", ts.SmoothedRTT(), timer.SmoothedRTT())
	}
}

// TestSharedTimer_OnlyOneTimerIsDriven verifies the policies do not drive a shared
// timer themselves. A timer driven by each of its readers as well as by the
// composite would observe every segment three times, sampling and rearming on
// repeats of the same event.
func TestSharedTimer_OnlyOneTimerIsDriven(t *testing.T) {
	timer := new(rto.Timer)
	cubic := new(CUBIC)
	if err := cubic.Configure(CUBICConfig{MSS: 1000}); err != nil {
		t.Fatal(err)
	}
	cubic.SetTimer(timer)
	ts := new(timestamps.Timestamps)
	ts.SetTimer(timer)

	// Neither policy may advance the shared timer's state on its own.
	seg := tcp.Segment{SEQ: 1000, ACK: 1, WND: 4096, Flags: tcp.FlagACK | tcp.FlagPSH, DATALEN: 500}
	cubic.PostTx(seg, 1000)
	if timer.Running() {
		t.Error("CUBIC armed a timer it does not drive")
	}
	ts.PostTx(seg, 1000)
	if timer.Running() {
		t.Error("the timestamp policy armed a timer it does not drive")
	}
	// Driving it directly, as a composite peer does, arms it exactly once.
	timer.PostTx(seg, 1000)
	if !timer.Running() {
		t.Fatal("the timer did not arm when driven")
	}
	// Neither policy reports a deadline of its own, so the composite's earliest
	// deadline is the timer's rather than three copies of it.
	if d := cubic.NextDeadline(); d != 0 {
		t.Errorf("CUBIC reports deadline %d for a timer it does not drive, want 0", d)
	}
	if d := ts.NextDeadline(); d != 0 {
		t.Errorf("the timestamp policy reports deadline %d for a timer it does not drive, want 0", d)
	}
}

// TestSharedTimer_TimeoutCollapsesWindow verifies CUBIC reacts to a timeout of a
// timer it does not drive. It cannot see the timer's directive in that
// arrangement, so the reaction is driven off the timer's expiry count; missing it
// would leave the window untouched through a timeout, which is the one signal
// congestion control must never ignore (RFC 9438 §4.8).
func TestSharedTimer_TimeoutCollapsesWindow(t *testing.T) {
	c, timer, cubic, _ := composed(t)
	const mss = 1000
	// Put data in flight so the timer has something to time out on.
	seg := tcp.Segment{SEQ: 1000, ACK: 1, WND: 4096, Flags: tcp.FlagACK | tcp.FlagPSH, DATALEN: mss}
	c.PostTx(seg, 0)
	if !timer.Running() {
		t.Fatal("the shared timer did not arm")
	}
	cwndBefore := cubic.WindowSegments()
	if cwndBefore <= 1 {
		t.Fatalf("congestion window starts at %v segments, too small for a collapse to be visible", cwndBefore)
	}

	// Transmit after the deadline: the timer expires, and the controller must see it.
	deadline := timer.NextDeadline()
	c.PreTx(tcp.TxIntent{Now: deadline + 1, UNA: 1000, NXT: 1000 + mss, InFlight: mss, MSS: mss, SendWindow: 4096})
	if timer.Expirations() != 1 {
		t.Fatalf("the shared timer recorded %d expirations, want 1", timer.Expirations())
	}
	if got := cubic.WindowSegments(); got >= cwndBefore {
		t.Errorf("congestion window is %v segments after a timeout, was %v: the timeout was ignored", got, cwndBefore)
	}
	if !cubic.InSlowStart() {
		t.Error("a timeout must return the controller to slow start")
	}
}

// TestSharedTimer_ResetLeavesSharingInPlace verifies reopening a connection does not
// unpick the arrangement. Reset is called on open, and a policy that dropped its
// shared timer there would silently fall back to a private one on the second
// connection, reintroducing the two-timer bug where it is hardest to notice.
func TestSharedTimer_ResetLeavesSharingInPlace(t *testing.T) {
	_, timer, cubic, ts := composed(t)
	// Give the shared timer an RTT estimate no private timer would have.
	timer.ObserveRTT(40 * time.Millisecond)
	want := int64(timer.SmoothedRTT())

	cubic.Reset()
	ts.Reset()
	if got := cubic.SmoothedRTT(); got != want {
		t.Errorf("after Reset CUBIC reads RTT %d, want the shared timer's %d", got, want)
	}
	if got := ts.SmoothedRTT(); got != want {
		t.Errorf("after Reset the timestamp policy reads RTT %d, want the shared timer's %d", got, want)
	}
	if timer.SmoothedRTT() == 0 {
		t.Error("a policy reset the shared timer, which belongs to whoever drives it")
	}
	// Still not driving it.
	if d := cubic.NextDeadline(); d != 0 {
		t.Errorf("CUBIC reports deadline %d after Reset, want 0", d)
	}
}

// TestSharedTimer_StandaloneStillOwnsATimer verifies the default is unchanged: a
// policy installed on its own still provides retransmission timing, so sharing is
// something you opt into rather than something you must arrange.
func TestSharedTimer_StandaloneStillOwnsATimer(t *testing.T) {
	cubic := new(CUBIC)
	if err := cubic.Configure(CUBICConfig{MSS: 1000}); err != nil {
		t.Fatal(err)
	}
	seg := tcp.Segment{SEQ: 1000, ACK: 1, WND: 4096, Flags: tcp.FlagACK | tcp.FlagPSH, DATALEN: 500}
	cubic.PostTx(seg, 1000)
	if cubic.NextDeadline() == 0 {
		t.Error("a standalone CUBIC must arm its own retransmission timer")
	}
	ts := new(timestamps.Timestamps)
	ts.PostTx(seg, 1000)
	if ts.NextDeadline() == 0 {
		t.Error("a standalone timestamp policy must arm its own retransmission timer")
	}
}

// TestSharedTimer_ZeroAlloc verifies composing policies with a shared timer
// allocates nothing on the datapath.
func TestSharedTimer_ZeroAlloc(t *testing.T) {
	c, _, _, _ := composed(t)
	var opts [16]byte
	seg := tcp.Segment{SEQ: 1000, ACK: 1, WND: 4096, Flags: tcp.FlagACK, DATALEN: 100}
	allocs := testing.AllocsPerRun(200, func() {
		c.PreRx(tcp.RxMeta{Segment: seg, Now: 1})
		c.PostRx(tcp.RxEvent{Segment: seg, Now: 1, Accepted: true})
		c.PreTx(tcp.TxIntent{Now: 1, MSS: 1000, SendWindow: 4096})
		c.WriteOptions(tcp.TxPlan{Now: 1}, opts[:])
		c.PostTx(seg, 1)
		c.NextDeadline()
	})
	if allocs != 0 {
		t.Errorf("composed policies allocated %v times per iteration, want 0", allocs)
	}
}
