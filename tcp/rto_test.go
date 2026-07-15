package tcp

import (
	"testing"
	"time"

	"github.com/soypat/lneto/tcp/rto"
)

// TestControlBlockRTODisabledWithoutClock verifies time integration is opt-in:
// with no injected clock the retransmission timer never arms and
// CheckRetransmitTimeout is a no-op.
func TestControlBlockRTODisabledWithoutClock(t *testing.T) {
	var tcb ControlBlock
	const iss, irs = Value(1000), Value(500)
	tcb.HelperInitState(StateEstablished, iss, iss, 4096)
	tcb.HelperInitRcv(irs, irs, 4096)

	if err := tcb.Send(Segment{SEQ: iss, ACK: irs, DATALEN: 100, Flags: pshack, WND: 4096}); err != nil {
		t.Fatalf("send data: %v", err)
	}
	if tcb.rto.Running() {
		t.Fatal("timer must stay dormant when no clock is injected")
	}
	if tcb.CheckRetransmitTimeout() {
		t.Fatal("CheckRetransmitTimeout must be a no-op without a clock")
	}
}

// TestControlBlockRTOSampleAndStop drives a ControlBlock through a data send and
// its acknowledgment, verifying the retransmission timer is armed on send, an
// RTT sample is taken on the ACK, and the timer stops once all data is acked.
func TestControlBlockRTOSampleAndStop(t *testing.T) {
	var now int64
	var tcb ControlBlock
	tcb.SetClock(func() int64 { return now })
	const iss, irs = Value(1000), Value(500)
	tcb.HelperInitState(StateEstablished, iss, iss, 4096)
	tcb.HelperInitRcv(irs, irs, 4096)

	if err := tcb.Send(Segment{SEQ: iss, ACK: irs, DATALEN: 100, Flags: pshack, WND: 4096}); err != nil {
		t.Fatalf("send data: %v", err)
	}
	if !tcb.rto.Running() {
		t.Fatal("retransmission timer must be armed after sending data")
	}

	now = int64(40 * time.Millisecond) // ACK arrives one RTT later.
	if err := tcb.Recv(Segment{SEQ: irs, ACK: iss + 100, Flags: FlagACK, WND: 4096}); err != nil {
		t.Fatalf("recv ack: %v", err)
	}
	if tcb.rto.Running() {
		t.Error("timer must stop once all data is acknowledged")
	}
	if tcb.rto.SmoothedRTT() != 40*time.Millisecond {
		t.Errorf("srtt=%v, want 40ms RTT sample", tcb.rto.SmoothedRTT())
	}
}

// TestControlBlockRTORetransmit verifies that when no ACK arrives, the timer
// expires and rewinds snd.NXT to snd.UNA for go-back-N retransmission.
func TestControlBlockRTORetransmit(t *testing.T) {
	var now int64
	var tcb ControlBlock
	tcb.SetClock(func() int64 { return now })
	const iss, irs = Value(1000), Value(500)
	tcb.HelperInitState(StateEstablished, iss, iss, 4096)
	tcb.HelperInitRcv(irs, irs, 4096)

	if err := tcb.Send(Segment{SEQ: iss, ACK: irs, DATALEN: 100, Flags: pshack, WND: 4096}); err != nil {
		t.Fatalf("send data: %v", err)
	}
	if tcb.CheckRetransmitTimeout() {
		t.Fatal("timer must not fire before its deadline")
	}
	now = int64(rto.Initial) + int64(time.Millisecond)
	if !tcb.CheckRetransmitTimeout() {
		t.Fatal("RTO must fire after the deadline with data outstanding")
	}
	if tcb.snd.NXT != tcb.snd.UNA {
		t.Errorf("snd.NXT=%d not rewound to snd.UNA=%d", tcb.snd.NXT, tcb.snd.UNA)
	}
}
