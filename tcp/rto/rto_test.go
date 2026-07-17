package rto

import (
	"testing"
	"time"

	"github.com/soypat/lneto/tcp"
)

const ms = int64(time.Millisecond)

// dataSeg builds a data segment of datalen octets starting at seq.
func dataSeg(seq uint32, datalen int) tcp.Segment {
	return tcp.Segment{SEQ: tcp.Value(seq), DATALEN: tcp.Size(datalen), Flags: tcp.FlagPSH | tcp.FlagACK}
}

// ackSeg builds a bare ACK acknowledging up to ack.
func ackSeg(ack uint32) tcp.Segment {
	return tcp.Segment{ACK: tcp.Value(ack), Flags: tcp.FlagACK}
}

func newControl() *Control {
	var r Control
	r.Reset()
	return &r
}

func TestReset(t *testing.T) {
	var r Control
	r.Reset()
	if r.rto != Initial {
		t.Errorf("initial rto=%v, want %v", r.rto, Initial)
	}
	if r.CurrentRTO() != Initial {
		t.Errorf("CurrentRTO=%v, want %v", r.CurrentRTO(), Initial)
	}
	if r.haveRTT {
		t.Error("haveRTT should be false before first sample")
	}
	if r.Running() || r.NextDeadline() != 0 {
		t.Error("timer must be disarmed after Reset")
	}
}

// TestArmOnSendSampleOnAck sends data, verifies the timer arms, then acks it and
// verifies an RTT sample is taken and the timer stops once all data is acked.
func TestArmOnSendSampleOnAck(t *testing.T) {
	r := newControl()
	const iss = uint32(1000)

	r.PostTx(dataSeg(iss, 100), 0)
	if !r.Running() {
		t.Fatal("timer must arm after sending data")
	}
	if r.NextDeadline() != int64(Initial) {
		t.Errorf("deadline=%d, want %d", r.NextDeadline(), int64(Initial))
	}

	// ACK arrives one RTT (40ms) later covering all sent data.
	dir := r.PreRx(ackSeg(iss+100), 40*ms)
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

// TestRetransmitOnTimeout verifies PreTx directs a go-back-N retransmit once the
// deadline passes with data outstanding, and backs the RTO off.
func TestRetransmitOnTimeout(t *testing.T) {
	r := newControl()
	const iss = uint32(1000)
	r.PostTx(dataSeg(iss, 100), 0)

	if r.PreTx(int64(Initial) - 1).Retransmit {
		t.Fatal("must not retransmit before the deadline")
	}
	dir := r.PreTx(int64(Initial))
	if !dir.Retransmit {
		t.Fatal("RTO must fire at the deadline with data outstanding")
	}
	if r.CurrentRTO() != 2*Initial {
		t.Errorf("rto=%v after one backoff, want %v", r.CurrentRTO(), 2*Initial)
	}
	// The connection resends from snd.UNA; PostTx sees a retransmission.
	r.PostTx(dataSeg(iss, 100), int64(Initial))
	if r.timing {
		t.Error("retransmitted segment must not be RTT-sampled (Karn)")
	}
}

// TestKarnNoSampleOnRetransmittedAck verifies that after a retransmission the
// ACK does not produce an RTT sample (Karn's algorithm).
func TestKarnNoSampleOnRetransmittedAck(t *testing.T) {
	r := newControl()
	const iss = uint32(1000)
	r.PostTx(dataSeg(iss, 100), 0)
	// Timeout and retransmit.
	r.PreTx(int64(Initial))
	r.PostTx(dataSeg(iss, 100), int64(Initial))
	// ACK now arrives; no sample should be taken since timing was discarded.
	r.PreRx(ackSeg(iss+100), int64(Initial)+10*ms)
	if r.haveRTT {
		t.Error("no RTT sample should exist after a retransmission (Karn)")
	}
}

// TestTimerRestartsWhilePartiallyAcked verifies the timer restarts (not stops)
// when an ACK advances UNA but data remains in flight (RFC 6298 §5.3).
func TestTimerRestartsWhilePartiallyAcked(t *testing.T) {
	r := newControl()
	const iss = uint32(1000)
	r.PostTx(dataSeg(iss, 100), 0)
	r.PostTx(dataSeg(iss+100, 100), 0) // 200 octets outstanding, iss..iss+200.

	dir := r.PreRx(ackSeg(iss+100), 40*ms) // acks first 100 only.
	if !r.Running() {
		t.Fatal("timer must remain armed while data is still in flight")
	}
	if r.NextDeadline() != 40*ms+int64(r.CurrentRTO()) {
		t.Errorf("deadline=%d, want %d", r.NextDeadline(), 40*ms+int64(r.CurrentRTO()))
	}
	if !dir.Keep {
		t.Error("PreRx must keep the segment")
	}
}

// TestNoArmWithoutData verifies control-only segments neither arm the timer nor
// start an RTT sample.
func TestNoArmWithoutData(t *testing.T) {
	r := newControl()
	r.PostTx(tcp.Segment{SEQ: 1000, Flags: tcp.FlagACK}, 0) // pure ACK, DATALEN==0.
	if r.Running() || r.timing {
		t.Error("pure control segment must not arm the timer or start a sample")
	}
}

// TestBackoffCollapsesOnValidSample verifies a valid RTT measurement collapses
// the exponential backoff counter (RFC 6298 §5.7).
func TestBackoffCollapsesOnValidSample(t *testing.T) {
	r := newControl()
	const iss = uint32(1000)
	r.PostTx(dataSeg(iss, 100), 0)
	r.PreTx(int64(Initial))                     // one timeout: backoff=1.
	r.PostTx(dataSeg(iss, 100), int64(Initial)) // retransmit (no sample).
	if r.backoff != 1 {
		t.Fatalf("backoff=%d, want 1 after a timeout", r.backoff)
	}
	// New data sent and freshly sampled, then acked.
	r.PostTx(dataSeg(iss+100, 100), int64(Initial)+ms)
	r.PreRx(ackSeg(iss+200), int64(Initial)+30*ms)
	if r.backoff != 0 {
		t.Errorf("backoff=%d, want 0 after a valid RTT sample", r.backoff)
	}
}

// TestRTOClamped verifies CurrentRTO is clamped to [Min, Max].
func TestRTOClamped(t *testing.T) {
	var r Control
	r.Reset()
	r.rto = time.Nanosecond
	if got := r.CurrentRTO(); got != Min {
		t.Errorf("CurrentRTO=%v, want floor %v", got, Min)
	}
	r.rto = time.Hour
	if got := r.CurrentRTO(); got != Max {
		t.Errorf("CurrentRTO=%v, want ceiling %v", got, Max)
	}
}

// TestUpdateRTTFirstSample verifies the first-measurement initialization of
// SRTT/RTTVAR (RFC 6298 §2.2).
func TestUpdateRTTFirstSample(t *testing.T) {
	var r Control
	r.Reset()
	r.UpdateRTT(100 * time.Millisecond)
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

// TestImplementsLossRecovery is a compile-time-ish guard that Control satisfies
// the interface, exercised through the interface type.
func TestImplementsLossRecovery(t *testing.T) {
	var lr tcp.LossRecovery = newControl()
	lr.Reset()
	lr.PostTx(dataSeg(1000, 100), 0)
	if lr.NextDeadline() == 0 {
		t.Error("expected an armed deadline after sending data")
	}
	if !lr.PreRx(ackSeg(1100), 10*ms).Keep {
		t.Error("PreRx must keep")
	}
	if lr.NextDeadline() != 0 {
		t.Error("expected disarmed timer after full ack")
	}
}
