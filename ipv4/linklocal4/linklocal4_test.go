package linklocal4

import (
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

var (
	ourHW   = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	otherHW = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
)

const frameOff = 14 // pretend there is an ethernet header before the ARP frame.

func newHandler(t *testing.T, clk *fakeClock) *Handler {
	t.Helper()
	var h Handler
	err := h.Reset(Config{
		HardwareAddr: ourHW,
		Now:          clk.now,
		Seed:         0xC0FFEE,
	})
	if err != nil {
		t.Fatal(err)
	}
	if h.State() != StateWaiting {
		t.Fatalf("expected StateWaiting after Reset, got %s", h.State())
	}
	return &h
}

// step advances the clock past any pending interval and runs one Encapsulate.
func step(t *testing.T, h *Handler, clk *fakeClock, buf []byte) (arp.Frame, int) {
	t.Helper()
	clk.advance(3 * time.Second) // larger than any RFC3927 probe/announce interval.
	n, err := h.Encapsulate(buf, -1, frameOff)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		return arp.Frame{}, 0
	}
	f, err := arp.NewFrame(buf[frameOff : frameOff+n])
	if err != nil {
		t.Fatalf("invalid arp produced: %v", err)
	}
	var vld lneto.Validator
	f.ValidateSize(&vld)
	if vld.HasError() {
		t.Fatalf("invalid arp size: %v", vld.ErrPop())
	}
	if f.Operation() != arp.OpRequest {
		t.Fatalf("link-local ARP must be a request, got %s", f.Operation())
	}
	// Ethernet destination must be broadcast.
	bc := ethernet.BroadcastAddr()
	for i := range 6 {
		if buf[i] != bc[i] {
			t.Fatalf("ethernet destination not broadcast: %x", buf[:6])
		}
	}
	return f, n
}

func TestClaim(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	h := newHandler(t, clk)
	buf := make([]byte, 64)

	cand := h.Candidate()
	if !ipv4.IsLinkLocal(cand) || cand[2] < 1 || cand[2] > 254 {
		t.Fatalf("candidate %v not a valid link-local address", cand)
	}

	var probes, announces int
	for i := 0; i < 10 && h.State() != StateBound; i++ {
		f, n := step(t, h, clk, buf)
		if n == 0 {
			continue
		}
		_, sproto := f.Sender4()
		_, tproto := f.Target4()
		shw, _ := f.Sender4()
		if *shw != ourHW {
			t.Fatalf("sender hardware address mismatch: %x", *shw)
		}
		if *tproto != cand {
			t.Fatalf("target proto must be candidate %v, got %v", cand, *tproto)
		}
		if *sproto == ([4]byte{}) {
			probes++
		} else if *sproto == cand {
			announces++
		} else {
			t.Fatalf("unexpected sender proto %v", *sproto)
		}
	}
	if h.State() != StateBound {
		t.Fatalf("expected StateBound, got %s", h.State())
	}
	if probes != probeNum {
		t.Errorf("expected %d probes, got %d", probeNum, probes)
	}
	if announces != announceNum {
		t.Errorf("expected %d announcements, got %d", announceNum, announces)
	}
	addr, ok := h.Addr()
	if !ok || addr != cand {
		t.Fatalf("Addr()=%v,%v want %v,true", addr, ok, cand)
	}
}

// makeARP builds an ARP IPv4 frame in buf for conflict-detection tests.
func makeARP(t *testing.T, buf []byte, op arp.Operation, senderHW [6]byte, senderProto, targetProto [4]byte) []byte {
	t.Helper()
	f, err := arp.NewFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	f.SetHardware(1, 6)
	f.SetProtocol(ethernet.TypeIPv4, 4)
	f.SetOperation(op)
	shw, sp := f.Sender4()
	*shw = senderHW
	*sp = senderProto
	thw, tp := f.Target4()
	*thw = [6]byte{}
	*tp = targetProto
	return buf[:arpIPv4Size]
}

func TestConflictDuringProbe(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	h := newHandler(t, clk)
	buf := make([]byte, 64)

	// Send the first probe.
	_, n := step(t, h, clk, buf)
	if n == 0 {
		t.Fatal("expected first probe")
	}
	cand := h.Candidate()

	// Another host replies/uses the candidate as its sender address: conflict.
	var arpbuf [64]byte
	frame := makeARP(t, arpbuf[:], arp.OpReply, otherHW, cand, [4]byte{169, 254, 1, 1})
	if err := h.Demux(frame, 0); err != nil {
		t.Fatal(err)
	}
	if h.Conflicts() != 1 {
		t.Fatalf("expected 1 conflict, got %d", h.Conflicts())
	}
	if h.Candidate() == cand {
		t.Fatal("expected a new candidate after conflict")
	}
	if h.State() != StateWaiting {
		t.Fatalf("expected restart in StateWaiting, got %s", h.State())
	}
}

func TestProbeConflictFromSimultaneousProbe(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	h := newHandler(t, clk)
	buf := make([]byte, 64)
	step(t, h, clk, buf) // first probe
	cand := h.Candidate()

	// Another host probes for the same candidate (zero sender proto, different HW).
	var arpbuf [64]byte
	frame := makeARP(t, arpbuf[:], arp.OpRequest, otherHW, [4]byte{}, cand)
	if err := h.Demux(frame, 0); err != nil {
		t.Fatal(err)
	}
	if h.Conflicts() != 1 || h.Candidate() == cand {
		t.Fatalf("simultaneous probe should cause conflict: conflicts=%d cand=%v", h.Conflicts(), h.Candidate())
	}
}

func driveToBound(t *testing.T, h *Handler, clk *fakeClock, buf []byte) {
	t.Helper()
	for i := 0; i < 10 && h.State() != StateBound; i++ {
		step(t, h, clk, buf)
	}
	if h.State() != StateBound {
		t.Fatalf("failed to reach StateBound, stuck at %s", h.State())
	}
}

func TestDefense(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	h := newHandler(t, clk)
	buf := make([]byte, 64)
	driveToBound(t, h, clk, buf)
	cand := h.Candidate()

	// A conflicting ARP from another host: handler should defend with one announcement.
	var arpbuf [64]byte
	frame := makeARP(t, arpbuf[:], arp.OpRequest, otherHW, cand, [4]byte{169, 254, 1, 1})
	if err := h.Demux(frame, 0); err != nil {
		t.Fatal(err)
	}
	n, err := h.Encapsulate(buf, -1, frameOff)
	if err != nil || n == 0 {
		t.Fatalf("expected defensive announcement, n=%d err=%v", n, err)
	}
	f, _ := arp.NewFrame(buf[frameOff : frameOff+n])
	_, sproto := f.Sender4()
	if *sproto != cand {
		t.Fatalf("defensive announcement must use candidate as sender, got %v", *sproto)
	}
	if h.State() != StateBound {
		t.Fatalf("should remain bound after a single defense, got %s", h.State())
	}
	// Subsequent Encapsulate yields nothing more.
	if n, _ := h.Encapsulate(buf, -1, frameOff); n != 0 {
		t.Fatal("expected only a single defensive announcement")
	}

	// A second conflict within defendInterval forces reconfiguration.
	clk.advance(defendInterval / 2)
	frame = makeARP(t, arpbuf[:], arp.OpReply, otherHW, cand, [4]byte{169, 254, 1, 1})
	if err := h.Demux(frame, 0); err != nil {
		t.Fatal(err)
	}
	if h.State() == StateBound {
		t.Fatal("expected reconfiguration after repeated conflict within defendInterval")
	}
	if h.Candidate() == cand {
		t.Fatal("expected new candidate after giving up address")
	}
}

func TestNoSelfConflict(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	h := newHandler(t, clk)
	buf := make([]byte, 64)
	driveToBound(t, h, clk, buf)
	cand := h.Candidate()

	// Our own announcement (same hardware address) must not be treated as a conflict.
	var arpbuf [64]byte
	frame := makeARP(t, arpbuf[:], arp.OpRequest, ourHW, cand, cand)
	if err := h.Demux(frame, 0); err != nil {
		t.Fatal(err)
	}
	if n, _ := h.Encapsulate(buf, -1, frameOff); n != 0 {
		t.Fatal("self-sent ARP must not trigger a defense")
	}
	if h.State() != StateBound {
		t.Fatalf("state changed on self ARP: %s", h.State())
	}
}

func TestFirstCandidate(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	want := [4]byte{169, 254, 42, 7}
	var h Handler
	err := h.Reset(Config{
		HardwareAddr:   ourHW,
		Now:            clk.now,
		Seed:           0xC0FFEE,
		FirstCandidate: want,
	})
	if err != nil {
		t.Fatal(err)
	}
	if h.Candidate() != want {
		t.Fatalf("expected FirstCandidate %v, got %v", want, h.Candidate())
	}
}

func TestRateLimit(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	h := newHandler(t, clk)
	buf := make([]byte, 64)
	var arpbuf [64]byte
	// Force more than maxConflicts conflicts during probing.
	for i := 0; i <= maxConflicts; i++ {
		step(t, h, clk, buf) // emit a probe for the current candidate.
		cand := h.Candidate()
		frame := makeARP(t, arpbuf[:], arp.OpReply, otherHW, cand, [4]byte{169, 254, 1, 1})
		if err := h.Demux(frame, 0); err != nil {
			t.Fatal(err)
		}
	}
	if h.State() != StateRateLimited {
		t.Fatalf("expected StateRateLimited after %d conflicts, got %s", h.Conflicts(), h.State())
	}
	// Before rateLimitInterval elapses no probe is emitted.
	if n, _ := h.Encapsulate(buf, -1, frameOff); n != 0 {
		t.Fatal("must not probe while rate limited")
	}
	// After the interval the machine resumes probing.
	clk.advance(rateLimitInterval + time.Second)
	if n, _ := h.Encapsulate(buf, -1, frameOff); n != 0 {
		t.Fatal("rate-limit recovery should reschedule, not emit immediately")
	}
	if h.State() != StateWaiting {
		t.Fatalf("expected StateWaiting after rate-limit recovery, got %s", h.State())
	}
}

func TestZeroAlloc(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	h := newHandler(t, clk)
	buf := make([]byte, 64)
	driveToBound(t, h, clk, buf)
	cand := h.Candidate()
	var arpbuf [64]byte
	frame := makeARP(t, arpbuf[:], arp.OpRequest, otherHW, cand, [4]byte{1, 2, 3, 4})

	if n := testing.AllocsPerRun(100, func() {
		_, _ = h.Encapsulate(buf, -1, frameOff)
	}); n != 0 {
		t.Errorf("Encapsulate allocated %g times, want 0", n)
	}
	if n := testing.AllocsPerRun(100, func() {
		_ = h.Demux(frame, 0)
	}); n != 0 {
		t.Errorf("Demux allocated %g times, want 0", n)
	}
}
