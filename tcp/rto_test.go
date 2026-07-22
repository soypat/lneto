package tcp

import (
	"testing"
	"time"
)

const rtoMs = int64(time.Millisecond)

// rtoDataSeg builds a data segment of datalen octets starting at seq.
func rtoDataSeg(seq uint32, datalen int) Segment {
	return Segment{SEQ: Value(seq), DATALEN: Size(datalen), Flags: FlagPSH | FlagACK}
}

// rtoAckSeg builds a bare ACK acknowledging up to ack.
func rtoAckSeg(ack uint32) Segment {
	return Segment{ACK: Value(ack), Flags: FlagACK}
}

func newRTO() *RTO {
	var r RTO
	r.Reset()
	return &r
}

func TestRTO_Reset(t *testing.T) {
	var r RTO
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

	r.PostTx(rtoDataSeg(iss, 100), 0)
	if !r.Running() {
		t.Fatal("timer must arm after sending data")
	}
	if r.NextDeadline() != int64(rtoInitial) {
		t.Errorf("deadline=%d, want %d", r.NextDeadline(), int64(rtoInitial))
	}

	// ACK arrives one RTT (40ms) later covering all sent data.
	dir := r.PreRx(rtoAckSeg(iss+100), 40*rtoMs)
	if !dir.Keep {
		t.Error("PreRx must keep the segment")
	}
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
	r.PostTx(rtoDataSeg(iss, 100), 0)

	if r.PreTx(int64(rtoInitial) - 1).RetransmitAll {
		t.Fatal("must not retransmit before the deadline")
	}
	dir := r.PreTx(int64(rtoInitial))
	if !dir.RetransmitAll {
		t.Fatal("RTO must fire at the deadline with data outstanding")
	}
	if r.CurrentRTO() != 2*rtoInitial {
		t.Errorf("rto=%v after one backoff, want %v", r.CurrentRTO(), 2*rtoInitial)
	}
	// The connection resends from snd.UNA; PostTx sees a retransmission.
	r.PostTx(rtoDataSeg(iss, 100), int64(rtoInitial))
	if r.timing {
		t.Error("retransmitted segment must not be RTT-sampled (Karn)")
	}
}

// TestRTO_KarnNoSampleOnRetransmittedAck verifies that after a retransmission the
// ACK does not produce an RTT sample (Karn's algorithm).
func TestRTO_KarnNoSampleOnRetransmittedAck(t *testing.T) {
	r := newRTO()
	const iss = uint32(1000)
	r.PostTx(rtoDataSeg(iss, 100), 0)
	// Timeout and retransmit.
	r.PreTx(int64(rtoInitial))
	r.PostTx(rtoDataSeg(iss, 100), int64(rtoInitial))
	// ACK now arrives; no sample should be taken since timing was discarded.
	r.PreRx(rtoAckSeg(iss+100), int64(rtoInitial)+10*rtoMs)
	if r.haveRTT {
		t.Error("no RTT sample should exist after a retransmission (Karn)")
	}
}

// TestRTO_TimerRestartsWhilePartiallyAcked verifies the timer restarts (not
// stops) when an ACK advances UNA but data remains in flight (RFC 6298 §5.3).
func TestRTO_TimerRestartsWhilePartiallyAcked(t *testing.T) {
	r := newRTO()
	const iss = uint32(1000)
	r.PostTx(rtoDataSeg(iss, 100), 0)
	r.PostTx(rtoDataSeg(iss+100, 100), 0) // 200 octets outstanding, iss..iss+200.

	dir := r.PreRx(rtoAckSeg(iss+100), 40*rtoMs) // acks first 100 only.
	if !r.Running() {
		t.Fatal("timer must remain armed while data is still in flight")
	}
	if r.NextDeadline() != 40*rtoMs+int64(r.CurrentRTO()) {
		t.Errorf("deadline=%d, want %d", r.NextDeadline(), 40*rtoMs+int64(r.CurrentRTO()))
	}
	if !dir.Keep {
		t.Error("PreRx must keep the segment")
	}
}

// TestRTO_NoArmWithoutData verifies control-only segments neither arm the timer
// nor start an RTT sample.
func TestRTO_NoArmWithoutData(t *testing.T) {
	r := newRTO()
	r.PostTx(Segment{SEQ: 1000, Flags: FlagACK}, 0) // pure ACK, DATALEN==0.
	if r.Running() || r.timing {
		t.Error("pure control segment must not arm the timer or start a sample")
	}
}

// TestRTO_BackoffCollapsesOnValidSample verifies a valid RTT measurement
// collapses the exponential backoff counter (RFC 6298 §5.7).
func TestRTO_BackoffCollapsesOnValidSample(t *testing.T) {
	r := newRTO()
	const iss = uint32(1000)
	r.PostTx(rtoDataSeg(iss, 100), 0)
	r.PreTx(int64(rtoInitial))                        // one timeout: backoff=1.
	r.PostTx(rtoDataSeg(iss, 100), int64(rtoInitial)) // retransmit (no sample).
	if r.backoff != 1 {
		t.Fatalf("backoff=%d, want 1 after a timeout", r.backoff)
	}
	// New data sent and freshly sampled, then acked.
	r.PostTx(rtoDataSeg(iss+100, 100), int64(rtoInitial)+rtoMs)
	r.PreRx(rtoAckSeg(iss+200), int64(rtoInitial)+30*rtoMs)
	if r.backoff != 0 {
		t.Errorf("backoff=%d, want 0 after a valid RTT sample", r.backoff)
	}
}

// TestRTO_Clamped verifies CurrentRTO is clamped to [rtoMin, rtoMax].
func TestRTO_Clamped(t *testing.T) {
	var r RTO
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
	var r RTO
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

// TestRTO_ImplementsLossRecovery exercises RTO through the [LossRecovery]
// interface: sending data arms a deadline and a full ACK disarms it.
func TestRTO_ImplementsLossRecovery(t *testing.T) {
	var lr LossRecovery = newRTO()
	lr.Reset()
	lr.PostTx(rtoDataSeg(1000, 100), 0)
	if lr.NextDeadline() == 0 {
		t.Error("expected an armed deadline after sending data")
	}
	if !lr.PreRx(rtoAckSeg(1100), 10*rtoMs).Keep {
		t.Error("PreRx must keep")
	}
	if lr.NextDeadline() != 0 {
		t.Error("expected disarmed timer after full ack")
	}
}
