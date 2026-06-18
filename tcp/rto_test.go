package tcp

import (
	"testing"
	"time"
)

func TestRTOInitial(t *testing.T) {
	var r rtoControl
	r.init()
	if r.rto != rtoInitial {
		t.Errorf("initial rto=%v, want %v", r.rto, rtoInitial)
	}
	if r.currentRTO() != rtoInitial {
		t.Errorf("currentRTO=%v, want %v", r.currentRTO(), rtoInitial)
	}
	if r.haveRTT {
		t.Error("haveRTT should be false before first sample")
	}
}

func TestRTOFirstSample(t *testing.T) {
	var r rtoControl
	r.init()
	const rtt = 400 * time.Millisecond
	r.updateRTT(rtt)
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
}

func TestRTOSmoothing(t *testing.T) {
	var r rtoControl
	r.init()
	r.updateRTT(100 * time.Millisecond)
	srtt0, rttvar0 := r.srtt, r.rttvar
	r.updateRTT(120 * time.Millisecond)
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

func TestRTOMinClamp(t *testing.T) {
	var r rtoControl
	r.init()
	r.updateRTT(time.Millisecond) // tiny RTT → rto well below the floor.
	if got := r.currentRTO(); got != rtoMin {
		t.Errorf("currentRTO=%v, want clamp to %v", got, rtoMin)
	}
}

func TestRTOSampleAndTimer(t *testing.T) {
	var r rtoControl
	r.init()
	base := time.Unix(0, 0)
	r.startSample(1000, base)
	r.armTimer(base)
	if !r.running {
		t.Fatal("timer should be running after armTimer")
	}
	// A second startSample while one is pending is ignored (single sample).
	r.startSample(2000, base.Add(time.Millisecond))
	if r.timedSeq != 1000 {
		t.Errorf("timedSeq=%d, want 1000 (second sample must be ignored)", r.timedSeq)
	}
	// ACK that covers the timed segment, with data still outstanding.
	ackTime := base.Add(50 * time.Millisecond)
	r.onAckSample(1500, false, ackTime)
	if r.timing {
		t.Error("sample should be consumed by the covering ACK")
	}
	if r.srtt != 50*time.Millisecond {
		t.Errorf("srtt=%v, want 50ms from the sample", r.srtt)
	}
	if !r.running {
		t.Error("timer must restart while data remains outstanding")
	}
	if r.deadline != ackTime.Add(r.currentRTO()) {
		t.Errorf("deadline=%v, want %v", r.deadline, ackTime.Add(r.currentRTO()))
	}
}

func TestRTOAllAckedStopsTimer(t *testing.T) {
	var r rtoControl
	r.init()
	base := time.Unix(0, 0)
	r.startSample(1000, base)
	r.armTimer(base)
	r.onAckSample(1000, true, base.Add(20*time.Millisecond))
	if r.running {
		t.Error("timer must stop when all data is acknowledged")
	}
}

func TestRTOExpiryBackoff(t *testing.T) {
	var r rtoControl
	r.init()
	base := time.Unix(0, 0)
	r.updateRTT(100 * time.Millisecond) // rto = 100 + 4*50 = 300ms.
	r.armTimer(base)
	rto0 := r.currentRTO()
	if r.expired(base.Add(rto0 - time.Millisecond)) {
		t.Error("timer must not expire before its deadline")
	}
	if !r.expired(base.Add(rto0)) {
		t.Error("timer must expire at its deadline")
	}
	timeoutAt := base.Add(rto0)
	r.onTimeout(timeoutAt)
	if r.currentRTO() != 2*rto0 {
		t.Errorf("rto after timeout=%v, want doubled %v", r.currentRTO(), 2*rto0)
	}
	if r.backoff != 1 {
		t.Errorf("backoff=%d, want 1", r.backoff)
	}
	if !r.running || r.deadline != timeoutAt.Add(2*rto0) {
		t.Errorf("timer must restart at the backed-off deadline")
	}
}

func TestRTOBackoffCapAndMax(t *testing.T) {
	var r rtoControl
	r.init()
	now := time.Unix(0, 0)
	for range 40 {
		r.armTimer(now)
		now = r.deadline
		r.onTimeout(now)
	}
	if r.currentRTO() > rtoMax {
		t.Errorf("rto=%v exceeds rtoMax=%v", r.currentRTO(), rtoMax)
	}
	if r.backoff > rtoBackoffMax {
		t.Errorf("backoff=%d exceeds cap %d", r.backoff, rtoBackoffMax)
	}
}

func TestRTOKarnDiscardsRetransmittedSample(t *testing.T) {
	var r rtoControl
	r.init()
	base := time.Unix(0, 0)
	r.startSample(1000, base)
	r.onRetransmit() // segment retransmitted: sample must be discarded.
	if r.timing {
		t.Error("retransmit must discard the outstanding RTT sample (Karn)")
	}
	// A later ACK covering the original seq must not produce a sample.
	r.onAckSample(1000, true, base.Add(10*time.Millisecond))
	if r.haveRTT {
		t.Error("no RTT sample should be taken from a retransmitted segment")
	}
}

func TestRTOTimeoutPreservesNonBackoffAfterValidSample(t *testing.T) {
	var r rtoControl
	r.init()
	base := time.Unix(0, 0)
	r.startSample(1000, base)
	r.armTimer(base)
	r.onTimeout(base.Add(time.Second)) // backoff to 1.
	if r.backoff != 1 {
		t.Fatalf("backoff=%d, want 1", r.backoff)
	}
	// A subsequent valid sample resets backoff (RFC 6298 §5.7).
	r.startSample(2000, base.Add(2*time.Second))
	r.onAckSample(2000, true, base.Add(2*time.Second+30*time.Millisecond))
	if r.backoff != 0 {
		t.Errorf("backoff=%d, want 0 after a valid sample", r.backoff)
	}
}
