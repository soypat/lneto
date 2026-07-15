package rto

import (
	"testing"
	"time"
)

// newControl returns an initialized Control whose clock reads *now, so tests
// drive time deterministically by assigning to now.
func newControl(now *int64) Control {
	var r Control
	r.SetClock(func() int64 { return *now })
	r.Init()
	return r
}

func TestInitial(t *testing.T) {
	var r Control
	r.Init()
	if r.rto != Initial {
		t.Errorf("initial rto=%v, want %v", r.rto, Initial)
	}
	if r.CurrentRTO() != Initial {
		t.Errorf("CurrentRTO=%v, want %v", r.CurrentRTO(), Initial)
	}
	if r.haveRTT {
		t.Error("haveRTT should be false before first sample")
	}
}

// TestInertWithoutClock verifies time integration is opt-in: with no clock
// every timing method is a no-op and the timer never arms.
func TestInertWithoutClock(t *testing.T) {
	var r Control
	r.Init()
	r.StartSample(1000)
	r.ArmTimer()
	if r.Running() {
		t.Error("timer must not arm without an injected clock")
	}
	r.OnAckSample(1000, false)
	if r.Running() || r.haveRTT {
		t.Error("no RTT sample or timer without a clock")
	}
	if r.Expired() {
		t.Error("Expired must be false without a clock")
	}
}

// TestInitPreservesClock verifies Init keeps the injected clock so a connection
// can be reused across reopens without re-injecting time.
func TestInitPreservesClock(t *testing.T) {
	var now int64
	var r Control
	r.SetClock(func() int64 { return now })
	r.Init()
	if r.Clock() == nil {
		t.Fatal("clock lost after Init")
	}
	r.StartSample(1000)
	r.ArmTimer()
	if !r.Running() {
		t.Error("timer must arm once a clock is injected")
	}
}

func TestFirstSample(t *testing.T) {
	var r Control
	r.Init()
	const rtt = 400 * time.Millisecond
	r.UpdateRTT(rtt)
	// RFC 6298 §2.2: SRTT=R, RTTVAR=R/2, RTO=SRTT+4*RTTVAR.
	if r.srtt != rtt {
		t.Errorf("srtt=%v, want %v", r.srtt, rtt)
	}
	if r.rttvar != rtt/2 {
		t.Errorf("rttvar=%v, want %v", r.rttvar, rtt/2)
	}
	want := rtt + rttvarK*(rtt/2) // 400ms + 4*200ms = 1.2s
	if r.rto != want {
		t.Errorf("rto=%v, want %v", r.rto, want)
	}
	if r.SmoothedRTT() != rtt {
		t.Errorf("SmoothedRTT=%v, want %v", r.SmoothedRTT(), rtt)
	}
}

func TestSmoothing(t *testing.T) {
	var r Control
	r.Init()
	r.UpdateRTT(100 * time.Millisecond)
	srtt0, rttvar0 := r.srtt, r.rttvar
	r.UpdateRTT(120 * time.Millisecond)
	// SRTT must move toward the new, slightly larger sample but stay between them.
	if r.srtt <= srtt0 || r.srtt >= 120*time.Millisecond {
		t.Errorf("srtt=%v not smoothed between %v and 120ms", r.srtt, srtt0)
	}
	if r.rttvar == rttvar0 {
		t.Errorf("rttvar did not update from %v", rttvar0)
	}
	if r.rto != r.srtt+rttvarK*r.rttvar {
		t.Errorf("rto=%v != srtt+4*rttvar=%v", r.rto, r.srtt+rttvarK*r.rttvar)
	}
}

func TestMinClamp(t *testing.T) {
	var r Control
	r.Init()
	r.UpdateRTT(time.Millisecond) // tiny RTT → rto well below the floor.
	if got := r.CurrentRTO(); got != Min {
		t.Errorf("CurrentRTO=%v, want clamp to %v", got, Min)
	}
}

func TestSampleAndTimer(t *testing.T) {
	var now int64
	r := newControl(&now)
	r.StartSample(1000)
	r.ArmTimer()
	if !r.Running() {
		t.Fatal("timer should be running after ArmTimer")
	}
	// A second StartSample while one is pending is ignored (single sample).
	now = int64(time.Millisecond)
	r.StartSample(2000)
	if r.timedSeq != 1000 {
		t.Errorf("timedSeq=%d, want 1000 (second sample must be ignored)", r.timedSeq)
	}
	// ACK that covers the timed segment, with data still outstanding.
	now = int64(50 * time.Millisecond)
	r.OnAckSample(1500, false)
	if r.timing {
		t.Error("sample should be consumed by the covering ACK")
	}
	if r.srtt != 50*time.Millisecond {
		t.Errorf("srtt=%v, want 50ms from the sample", r.srtt)
	}
	if !r.Running() {
		t.Error("timer must restart while data remains outstanding")
	}
	if r.Deadline() != now+int64(r.CurrentRTO()) {
		t.Errorf("deadline=%v, want %v", r.Deadline(), now+int64(r.CurrentRTO()))
	}
}

func TestAllAckedStopsTimer(t *testing.T) {
	var now int64
	r := newControl(&now)
	r.StartSample(1000)
	r.ArmTimer()
	now = int64(20 * time.Millisecond)
	r.OnAckSample(1000, true)
	if r.Running() {
		t.Error("timer must stop when all data is acknowledged")
	}
}

// TestSeqWraparound verifies the ACK/timed-sequence comparison is modulo 2^32,
// so a sample completes correctly across the sequence-number wrap boundary.
func TestSeqWraparound(t *testing.T) {
	var now int64
	r := newControl(&now)
	const timed = uint32(0xffff_ff00)
	r.StartSample(timed)
	r.ArmTimer()
	// ACK of 0x40 is "after" 0xffffff00 modulo 2^32 → sample completes.
	now = int64(10 * time.Millisecond)
	r.OnAckSample(0x40, true)
	if r.timing {
		t.Error("wrapped ACK past timedSeq must complete the sample")
	}
	if !r.haveRTT {
		t.Error("RTT sample must be taken across the wrap boundary")
	}
}

func TestExpiryBackoff(t *testing.T) {
	var now int64
	r := newControl(&now)
	r.UpdateRTT(100 * time.Millisecond) // rto = 100 + 4*50 = 300ms.
	r.ArmTimer()
	rto0 := r.CurrentRTO()
	now = int64(rto0 - time.Millisecond)
	if r.Expired() {
		t.Error("timer must not expire before its deadline")
	}
	now = int64(rto0)
	if !r.Expired() {
		t.Error("timer must expire at its deadline")
	}
	timeoutAt := now
	r.OnTimeout()
	if r.CurrentRTO() != 2*rto0 {
		t.Errorf("rto after timeout=%v, want doubled %v", r.CurrentRTO(), 2*rto0)
	}
	if r.backoff != 1 {
		t.Errorf("backoff=%d, want 1", r.backoff)
	}
	if !r.Running() || r.Deadline() != timeoutAt+int64(2*rto0) {
		t.Errorf("timer must restart at the backed-off deadline")
	}
}

func TestBackoffCapAndMax(t *testing.T) {
	var now int64
	r := newControl(&now)
	for range 40 {
		r.ArmTimer()
		now = r.Deadline()
		r.OnTimeout()
	}
	if r.CurrentRTO() > Max {
		t.Errorf("rto=%v exceeds Max=%v", r.CurrentRTO(), Max)
	}
	if r.backoff > backoffMax {
		t.Errorf("backoff=%d exceeds cap %d", r.backoff, backoffMax)
	}
}

func TestKarnDiscardsRetransmittedSample(t *testing.T) {
	var now int64
	r := newControl(&now)
	r.StartSample(1000)
	r.OnRetransmit() // segment retransmitted: sample must be discarded.
	if r.timing {
		t.Error("retransmit must discard the outstanding RTT sample (Karn)")
	}
	// A later ACK covering the original seq must not produce a sample.
	now = int64(10 * time.Millisecond)
	r.OnAckSample(1000, true)
	if r.haveRTT {
		t.Error("no RTT sample should be taken from a retransmitted segment")
	}
}

func TestTimeoutPreservesNonBackoffAfterValidSample(t *testing.T) {
	var now int64
	r := newControl(&now)
	r.StartSample(1000)
	r.ArmTimer()
	now = int64(time.Second)
	r.OnTimeout() // backoff to 1.
	if r.backoff != 1 {
		t.Fatalf("backoff=%d, want 1", r.backoff)
	}
	// A subsequent valid sample resets backoff (RFC 6298 §5.7).
	now = int64(2 * time.Second)
	r.StartSample(2000)
	now = int64(2*time.Second + 30*time.Millisecond)
	r.OnAckSample(2000, true)
	if r.backoff != 0 {
		t.Errorf("backoff=%d, want 0 after a valid sample", r.backoff)
	}
}

// TestNoAllocs verifies the RFC 6298 estimator performs no heap allocations on
// its hot path: it is pure integer/time arithmetic over a fixed-size struct, so
// servicing the retransmission timer adds nothing to GC pressure.
func TestNoAllocs(t *testing.T) {
	var now int64
	r := newControl(&now)
	allocs := testing.AllocsPerRun(100, func() {
		r.StartSample(1000)
		r.ArmTimer()
		now = int64(10 * time.Millisecond)
		r.OnAckSample(1000, true)
		_ = r.CurrentRTO()
		now = int64(time.Second)
		_ = r.Expired()
		r.OnTimeout()
		r.OnRetransmit()
	})
	if allocs != 0 {
		t.Errorf("RTO estimator must not allocate, got %v allocs/op", allocs)
	}
}
