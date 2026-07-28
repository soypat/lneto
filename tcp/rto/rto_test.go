package rto

import (
	"testing"
	"time"

	"github.com/soypat/lneto/tcp"
)

const rtoMs = int64(time.Millisecond)

// dataSeg builds a data segment of datalen octets starting at seq.
func dataSeg(seq uint32, datalen int) tcp.Segment {
	return tcp.Segment{SEQ: tcp.Value(seq), DATALEN: tcp.Size(datalen), Flags: tcp.FlagPSH | tcp.FlagACK}
}

// ackSeg builds a bare ACK acknowledging up to ack.
func ackSeg(ack uint32) tcp.Segment {
	return tcp.Segment{ACK: tcp.Value(ack), Flags: tcp.FlagACK}
}

func newRTO() *Timer {
	var r Timer
	r.Reset()
	return &r
}

// rxAt builds the minimal tcp.RxMeta for driving PreRx directly.
func rxAt(seg tcp.Segment, now int64) tcp.RxMeta { return tcp.RxMeta{Segment: seg, Now: now} }

// acceptedAt builds the event for a segment the connection accepted, which is what
// drives the estimator. Timing state is only allowed to move for those.
func acceptedAt(seg tcp.Segment, now int64) tcp.RxEvent {
	return tcp.RxEvent{Segment: seg, Now: now, Accepted: true}
}

// txAt builds the minimal tcp.TxIntent for driving Timer.PreTx directly: the timer
// tracks the send sequence itself via PostTx and only reads the clock.
func txAt(now int64) tcp.TxIntent { return tcp.TxIntent{Now: now} }

func TestRTO_Reset(t *testing.T) {
	var r Timer
	r.Reset()
	if r.rto != rtoInitial {
		t.Errorf("initial rto=%v, want %v", r.rto, rtoInitial)
	}
	if r.CurrentRTO() != rtoInitial {
		t.Errorf("CurrentRTO=%v, want %v", r.CurrentRTO(), rtoInitial)
	}
	if r.haveRTT {
		t.Error("haveRTT should be false before first sample")
	}
	if r.Running() || r.NextDeadline() != 0 {
		t.Error("timer must be disarmed after Reset")
	}
}

// TestRTO_ArmOnSendSampleOnAck sends data, verifies the timer arms, then acks it
// and verifies an RTT sample is taken and the timer stops once all data is acked.
func TestRTO_ArmOnSendSampleOnAck(t *testing.T) {
	r := newRTO()
	const iss = uint32(1000)

	r.PostTx(dataSeg(iss, 100), 0)
	if !r.Running() {
		t.Fatal("timer must arm after sending data")
	}
	if r.NextDeadline() != int64(rtoInitial) {
		t.Errorf("deadline=%d, want %d", r.NextDeadline(), int64(rtoInitial))
	}

	// ACK arrives one RTT (40ms) later covering all sent data.
	if !r.PreRx(rxAt(ackSeg(iss+100), 40*rtoMs)).Keep {
		t.Error("PreRx must keep the segment")
	}
	r.PostRx(acceptedAt(ackSeg(iss+100), 40*rtoMs))
	if r.Running() {
		t.Error("timer must stop once all data is acknowledged")
	}
	if r.SmoothedRTT() != 40*time.Millisecond {
		t.Errorf("srtt=%v, want 40ms", r.SmoothedRTT())
	}
}

// TestRTO_RetransmitOnTimeout verifies PreTx directs a go-back-N retransmit once
// the deadline passes with data outstanding, and backs the RTO off.
func TestRTO_RetransmitOnTimeout(t *testing.T) {
	r := newRTO()
	const iss = uint32(1000)
	r.PostTx(dataSeg(iss, 100), 0)

	if r.PreTx(txAt(int64(rtoInitial) - 1)).Retransmit {
		t.Fatal("must not retransmit before the deadline")
	}
	dir := r.PreTx(tcp.TxIntent{Now: int64(rtoInitial), UNA: tcp.Value(iss), NXT: tcp.Value(iss + 100)})
	if !dir.Retransmit {
		t.Fatal("RTO must fire at the deadline with data outstanding")
	}
	if dir.RetransmitFrom != tcp.Value(iss) {
		t.Errorf("retransmit from %d, want snd.UNA=%d", dir.RetransmitFrom, iss)
	}
	if r.CurrentRTO() != 2*rtoInitial {
		t.Errorf("rto=%v after one backoff, want %v", r.CurrentRTO(), 2*rtoInitial)
	}
	// The connection resends from snd.UNA; PostTx sees a retransmission.
	r.PostTx(dataSeg(iss, 100), int64(rtoInitial))
	if r.timing {
		t.Error("retransmitted segment must not be RTT-sampled (Karn)")
	}
}

// TestRTO_KarnNoSampleOnRetransmittedAck verifies that after a retransmission the
// ACK does not produce an RTT sample (Karn's algorithm).
func TestRTO_KarnNoSampleOnRetransmittedAck(t *testing.T) {
	r := newRTO()
	const iss = uint32(1000)
	r.PostTx(dataSeg(iss, 100), 0)
	// Timeout and retransmit.
	r.PreTx(txAt(int64(rtoInitial)))
	r.PostTx(dataSeg(iss, 100), int64(rtoInitial))
	// ACK now arrives; no sample should be taken since timing was discarded.
	r.PostRx(acceptedAt(ackSeg(iss+100), int64(rtoInitial)+10*rtoMs))
	if r.haveRTT {
		t.Error("no RTT sample should exist after a retransmission (Karn)")
	}
}

// TestRTO_TimerRestartsWhilePartiallyAcked verifies the timer restarts (not
// stops) when an ACK advances UNA but data remains in flight (RFC 6298 §5.3).
func TestRTO_TimerRestartsWhilePartiallyAcked(t *testing.T) {
	r := newRTO()
	const iss = uint32(1000)
	r.PostTx(dataSeg(iss, 100), 0)
	r.PostTx(dataSeg(iss+100, 100), 0) // 200 octets outstanding, iss..iss+200.

	r.PostRx(acceptedAt(ackSeg(iss+100), 40*rtoMs)) // acks first 100 only.
	if !r.Running() {
		t.Fatal("timer must remain armed while data is still in flight")
	}
	if r.NextDeadline() != 40*rtoMs+int64(r.CurrentRTO()) {
		t.Errorf("deadline=%d, want %d", r.NextDeadline(), 40*rtoMs+int64(r.CurrentRTO()))
	}
}

// TestRTO_NoArmWithoutData verifies control-only segments neither arm the timer
// nor start an RTT sample.
func TestRTO_NoArmWithoutData(t *testing.T) {
	r := newRTO()
	r.PostTx(tcp.Segment{SEQ: 1000, Flags: tcp.FlagACK}, 0) // pure ACK, DATALEN==0.
	if r.Running() || r.timing {
		t.Error("pure control segment must not arm the timer or start a sample")
	}
}

// TestRTO_BackoffCollapsesOnValidSample verifies a valid RTT measurement
// collapses the exponential backoff counter (RFC 6298 §5.7).
func TestRTO_BackoffCollapsesOnValidSample(t *testing.T) {
	r := newRTO()
	const iss = uint32(1000)
	r.PostTx(dataSeg(iss, 100), 0)
	r.PreTx(txAt(int64(rtoInitial)))               // one timeout: backoff=1.
	r.PostTx(dataSeg(iss, 100), int64(rtoInitial)) // retransmit (no sample).
	if r.backoff != 1 {
		t.Fatalf("backoff=%d, want 1 after a timeout", r.backoff)
	}
	// New data sent and freshly sampled, then acked.
	r.PostTx(dataSeg(iss+100, 100), int64(rtoInitial)+rtoMs)
	r.PostRx(acceptedAt(ackSeg(iss+200), int64(rtoInitial)+30*rtoMs))
	if r.backoff != 0 {
		t.Errorf("backoff=%d, want 0 after a valid RTT sample", r.backoff)
	}
}

// TestRTO_Clamped verifies CurrentRTO is clamped to [rtoMin, rtoMax].
func TestRTO_Clamped(t *testing.T) {
	var r Timer
	r.Reset()
	r.rto = time.Nanosecond
	if got := r.CurrentRTO(); got != rtoMin {
		t.Errorf("CurrentRTO=%v, want floor %v", got, rtoMin)
	}
	r.rto = time.Hour
	if got := r.CurrentRTO(); got != rtoMax {
		t.Errorf("CurrentRTO=%v, want ceiling %v", got, rtoMax)
	}
}

// TestRTO_UpdateRTTFirstSample verifies the first-measurement initialization of
// SRTT/RTTVAR (RFC 6298 §2.2).
func TestRTO_UpdateRTTFirstSample(t *testing.T) {
	var r Timer
	r.Reset()
	r.updateRTT(100 * time.Millisecond)
	if r.srtt != 100*time.Millisecond {
		t.Errorf("srtt=%v, want 100ms", r.srtt)
	}
	if r.rttvar != 50*time.Millisecond {
		t.Errorf("rttvar=%v, want 50ms", r.rttvar)
	}
	// RTO = SRTT + K*RTTVAR = 100 + 4*50 = 300ms.
	if r.rto != 300*time.Millisecond {
		t.Errorf("rto=%v, want 300ms", r.rto)
	}
}

// TestRTO_ImplementsPolicy exercises Timer through the [tcp.Policy]
// interface: sending data arms a deadline and a full ACK disarms it.
func TestRTO_ImplementsPolicy(t *testing.T) {
	var lr tcp.Policy = newRTO()
	lr.Reset()
	lr.PostTx(dataSeg(1000, 100), 0)
	if lr.NextDeadline() == 0 {
		t.Error("expected an armed deadline after sending data")
	}
	if !lr.PreRx(rxAt(ackSeg(1100), 10*rtoMs)).Keep {
		t.Error("PreRx must keep")
	}
	lr.PostRx(acceptedAt(ackSeg(1100), 10*rtoMs))
	if lr.NextDeadline() != 0 {
		t.Error("expected disarmed timer after full ack")
	}
}

// TestRTO_IgnoresRejectedSegment verifies the estimator does not act on a segment
// the connection refused. PreRx runs before the state machine has judged the
// segment, so an acknowledgement for data never sent would otherwise collapse the
// backoff and take a bogus round-trip sample.
func TestRTO_IgnoresRejectedSegment(t *testing.T) {
	r := newRTO()
	const iss = uint32(1000)
	r.PostTx(dataSeg(iss, 100), 0)
	armed := r.NextDeadline()
	if armed == 0 {
		t.Fatal("timer must be armed after sending data")
	}

	// An acknowledgement far beyond anything sent, refused by the connection.
	bogus := ackSeg(iss + 100000)
	if !r.PreRx(rxAt(bogus, 40*rtoMs)).Keep {
		t.Error("PreRx must keep: dropping is not the estimator's business")
	}
	r.PostRx(tcp.RxEvent{Segment: bogus, Now: 40 * rtoMs, Accepted: false})

	if r.NextDeadline() != armed {
		t.Errorf("deadline moved to %d on a refused segment, want it left at %d",
			r.NextDeadline(), armed)
	}
	if r.SmoothedRTT() != 0 {
		t.Errorf("took an RTT sample of %v from a refused segment", r.SmoothedRTT())
	}
	if !r.Running() {
		t.Error("timer disarmed by a refused acknowledgement")
	}
}

// TestRTO_RetransmitsZeroWindowProbe verifies the timer takes over the periodic
// probing of a closed send window. A zero-window probe is a single octet the peer
// cannot accept, so it goes unacknowledged; the timer must keep resending it, with
// exponential backoff, which is the persist-timer behaviour of RFC 9293 §3.8.6.1.
// The tcp package relies on this and refuses to probe without a policy installed.
func TestRTO_RetransmitsZeroWindowProbe(t *testing.T) {
	r := newRTO()
	const iss = uint32(5000)
	probe := dataSeg(iss, 1) // The one-octet probe.
	r.PostTx(probe, 0)

	now := int64(rtoInitial)
	prevRTO := r.CurrentRTO()
	for attempt := 1; attempt <= 4; attempt++ {
		dir := r.PreTx(tcp.TxIntent{Now: now, UNA: tcp.Value(iss), NXT: tcp.Value(iss + 1)})
		if !dir.Retransmit {
			t.Fatalf("attempt %d: timer did not fire; the probe would never be resent", attempt)
		}
		if dir.RetransmitFrom != tcp.Value(iss) {
			t.Errorf("attempt %d: retransmit from %d, want the probe octet at %d",
				attempt, dir.RetransmitFrom, iss)
		}
		if got := r.CurrentRTO(); got <= prevRTO {
			t.Errorf("attempt %d: rto %v did not back off past %v", attempt, got, prevRTO)
		}
		prevRTO = r.CurrentRTO()
		// The peer still cannot accept the octet, so it stays unacknowledged.
		r.PostTx(probe, now)
		now += int64(prevRTO)
	}
}
