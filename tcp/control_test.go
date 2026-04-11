package tcp

import (
	"testing"
)

// TestMaxInFlightData_Underflow verifies that MaxInFlightData never underflows
// when unacked data equals or exceeds the send window.
func TestMaxInFlightData_Underflow(t *testing.T) {
	const (
		iss       Value = 100
		remoteISS Value = 500
		localWND  Size  = 1024
	)
	setup := func(wnd Size, unacked Size) ControlBlock {
		var tcb ControlBlock
		// snd.UNA = iss, snd.NXT = iss + unacked
		tcb.HelperInitState(StateEstablished, iss, iss+Value(unacked), localWND)
		tcb.HelperInitRcv(remoteISS, remoteISS+1, wnd) // snd.WND = wnd
		// HelperInitState sets snd.UNA = iss; unacked = snd.NXT - snd.UNA = unacked.
		return tcb
	}

	// unacked == snd.WND: usable = 0, but code returns 0 - 1 = 2^32-1.
	t.Run("UnackedEqualsWindow", func(t *testing.T) {
		const wnd Size = 200
		tcb := setup(wnd, wnd) // unacked == wnd
		got := tcb.MaxInFlightData()
		if got != 0 {
			t.Errorf("MaxInFlightData() = %d; want 0 (unacked=%d == WND=%d, uint32 underflow via -1)",
				got, Sizeof(tcb.snd.UNA, tcb.snd.NXT), tcb.snd.WND)
		}
	})

	// unacked > snd.WND: window shrank; usable = 0, but code underflows.
	t.Run("UnackedExceedsWindow", func(t *testing.T) {
		const wnd Size = 100
		tcb := setup(wnd, 250) // unacked 250 > wnd 100
		got := tcb.MaxInFlightData()
		if got != 0 {
			t.Errorf("MaxInFlightData() = %d; want 0 (unacked=%d > WND=%d, must not underflow)",
				got, Sizeof(tcb.snd.UNA, tcb.snd.NXT), tcb.snd.WND)
		}
	})
}

// TestMaxInFlightData_BogusMinusOne verifies that MaxInFlightData returns
// snd.WND - unacked (RFC value), not snd.WND - unacked - 1.
func TestMaxInFlightData_BogusMinusOne(t *testing.T) {
	const (
		iss       Value = 100
		remoteISS Value = 500
		localWND  Size  = 1024
		wnd       Size  = 100
	)
	setup := func(unacked Size) ControlBlock {
		var tcb ControlBlock
		tcb.HelperInitState(StateEstablished, iss, iss+Value(unacked), localWND)
		tcb.HelperInitRcv(remoteISS, remoteISS+1, wnd)
		return tcb
	}

	// Zero unacked: RFC says wnd, code returns wnd-1.
	t.Run("ZeroUnacked_WantWND", func(t *testing.T) {
		tcb := setup(0)
		want := wnd
		got := tcb.MaxInFlightData()
		if got != want {
			t.Errorf("MaxInFlightData() = %d; want %d (RFC: WND - unacked, no bogus -1)", got, want)
		}
	})

	// unacked = 50: RFC says 50, code returns 49.
	t.Run("PartialUnacked_WantWNDMinusUnacked", func(t *testing.T) {
		tcb := setup(50)
		want := wnd - 50
		got := tcb.MaxInFlightData()
		if got != want {
			t.Errorf("MaxInFlightData() = %d; want %d (RFC: WND - unacked, no bogus -1)", got, want)
		}
	})
}

// TestRecvAcksUnsent_PreservesPendingFIN verifies that receiving a segment whose
// ACK field acknowledges unsent data does not clobber other pending flags (FIN).
func TestRecvAcksUnsent_PreservesPendingFIN(t *testing.T) {
	const (
		iss       Value = 100
		remoteISS Value = 500
		localWND  Size  = 2048
		remoteWND Size  = 2048
	)
	var tcb ControlBlock
	// 50 bytes in flight (snd.NXT = iss+50), snd.UNA = iss.
	tcb.HelperInitState(StateEstablished, iss, iss+50, localWND)
	tcb.HelperInitRcv(remoteISS, remoteISS+1, remoteWND)

	// Simulate a pending FIN+ACK that should not be clobbered.
	tcb.pending[0] = FlagFIN | FlagACK

	// Bogus ACK: seg.ACK > snd.NXT (acks data not yet sent).
	bogusACK := Segment{
		SEQ:   remoteISS + 1, // == rcv.NXT
		ACK:   iss + 51,      // > snd.NXT=iss+50 → acksUnsentData
		Flags: FlagACK,
		WND:   remoteWND,
	}

	err := tcb.Recv(bogusACK)
	if !IsDroppedErr(err) {
		t.Errorf("expected errDropSegment for ACK of unsent data, got: %v", err)
	}

	// FIN must be preserved (|= not =). Currently FAILS: pending[0] = FlagACK only.
	if !tcb.pending[0].HasAll(FlagFIN) {
		t.Errorf("FIN cleared from pending[0] by ACK-unsent handler: got %s, want FlagFIN|FlagACK",
			tcb.pending[0])
	}
}

// TestHandleRST_SynSent_GoesToClosed verifies that receiving RST in SYN-SENT
// transitions to CLOSED (not LISTEN), per RFC 9293 §3.10.7.2.
func TestHandleRST_SynSent_GoesToClosed(t *testing.T) {
	const (
		iss      Value = 1000
		localWND Size  = 2048
	)
	var tcb ControlBlock
	// Active open: SYN-SENT. rcv.NXT=0, rcv.WND=localWND (SYN not yet received).
	tcb.HelperInitState(StateSynSent, iss, iss+1, localWND)

	// RST with SEQ in receive window [rcv.NXT=0, 0+localWND=2048).
	rst := Segment{
		SEQ:   0, // in [0, localWND)
		Flags: FlagRST,
	}

	err := tcb.Recv(rst)
	if err == nil {
		t.Fatal("RST in SYN-SENT must return an error (connection reset)")
	}

	// RFC 9293 §3.10.7.2: "enter CLOSED state, delete TCB, and return."
	// Bug: code sets state to StateListen instead.
	if tcb.State() != StateClosed {
		t.Errorf("state = %s after RST in SYN-SENT; want CLOSED (RFC 9293 §3.10.7.2)", tcb.State())
	}
}

// TestRecvDuplicateACK_DoesNotShrinkWindow verifies that a duplicate ACK
// (ACK == snd.UNA) carrying a smaller window does not reduce snd.WND.
func TestRecvDuplicateACK_DoesNotShrinkWindow(t *testing.T) {
	const (
		iss       Value = 100
		remoteISS Value = 500
		localWND  Size  = 2048
		remoteWND Size  = 1000 // initial send window
	)
	var tcb ControlBlock
	tcb.HelperInitState(StateEstablished, iss, iss+10, localWND)
	tcb.HelperInitRcv(remoteISS, remoteISS+1, remoteWND) // snd.WND = 1000
	tcb.snd.UNA = iss + 10                               // all sent data acked

	// Duplicate ACK: ACK == snd.UNA (no new data acked), WND reduced to 100.
	dupACK := Segment{
		SEQ:   remoteISS + 1, // == rcv.NXT
		ACK:   iss + 10,      // == snd.UNA (duplicate)
		Flags: FlagACK,
		WND:   100, // smaller than current snd.WND=1000
	}

	err := tcb.Recv(dupACK)
	if err != nil {
		t.Fatalf("duplicate ACK must be silently accepted: %v", err)
	}

	// snd.WND must not shrink. Currently FAILS: snd.WND gets set to 100.
	if tcb.snd.WND != remoteWND {
		t.Errorf("snd.WND = %d after duplicate ACK; want %d (missing WL1/WL2 guard per RFC 9293 §3.10.7.4)",
			tcb.snd.WND, remoteWND)
	}
}

// TestPendingSegment_ChallengeACK_Idempotent verifies that calling PendingSegment
// does not consume the challengeAck flag, honouring its read-only contract.
func TestPendingSegment_ChallengeACK_Idempotent(t *testing.T) {
	var tcb ControlBlock
	tcb.HelperInitState(StateEstablished, 100, 101, 1024)
	tcb.HelperInitRcv(500, 501, 1024)
	tcb.triggerChallengeAckEmit()

	seg1, ok1 := tcb.PendingSegment(0)
	if !ok1 {
		t.Fatal("PendingSegment returned !ok when challengeAck=true")
	}

	// PendingSegment must not consume challengeAck (read-only contract).
	// Currently FAILS: challengeAck is set to false on the first call.
	if !tcb.pendingChallengeAck() {
		t.Error("PendingSegment cleared challengeAck flag; violates documented read-only contract")
	}

	// A second call (e.g., before the segment is actually transmitted) must still succeed.
	seg2, ok2 := tcb.PendingSegment(0)
	if !ok2 {
		t.Fatal("second PendingSegment call returned !ok; challengeAck was consumed on first call")
	}
	if seg1 != seg2 {
		t.Errorf("PendingSegment not idempotent:\n first=%+v\nsecond=%+v", seg1, seg2)
	}
}

// TestRcvSynRcvd_NoACKFlag_DoesNotCompleteHandshake verifies that a segment
// lacking the ACK flag cannot complete the 3-way handshake even if its ACK
// field value coincidentally matches snd.UNA+1.
func TestRcvSynRcvd_NoACKFlag_DoesNotCompleteHandshake(t *testing.T) {
	const (
		iss       Value = 1000
		remoteISS Value = 5000
		localWND  Size  = 2048
		remoteWND Size  = 2048
	)
	var tcb ControlBlock
	// SYN-RCVD: server received SYN, sent SYN-ACK. Waiting for client ACK.
	// snd.UNA=iss, snd.NXT=iss+1 (SYN-ACK consumed one seq).
	// rcv.NXT=remoteISS+1 (client SYN consumed one seq).
	tcb.HelperInitState(StateSynRcvd, iss, iss+1, localWND)
	tcb.HelperInitRcv(remoteISS, remoteISS+1, remoteWND)

	// Segment with NO ACK flag but ACK value == snd.UNA+1 (coincidentally correct).
	noACKSeg := Segment{
		SEQ:   remoteISS + 1, // == rcv.NXT
		ACK:   iss + 1,       // == snd.UNA+1 (right value, wrong flag)
		Flags: 0,             // ACK bit NOT set
		WND:   remoteWND,
	}

	tcb.Recv(noACKSeg) //nolint:errcheck // error value not the focus here

	// Handshake must not complete without the ACK flag.
	// Currently FAILS: state becomes ESTABLISHED because the flag check is commented out.
	if tcb.State() == StateEstablished {
		t.Errorf("3-way handshake completed without FlagACK in SYN-RCVD; " +
			"ACK flag validation is commented out (control_rcvhandlers.go:51-52)")
	}
}

// TestCloseWait_NoAutoFINBeforeUserClose verifies that entering CLOSE-WAIT after
// a remote FIN does not auto-queue a local FIN until the user calls Close().
func TestCloseWait_NoAutoFINBeforeUserClose(t *testing.T) {
	const (
		iss       Value = 100
		remoteISS Value = 500
		localWND  Size  = 2048
		remoteWND Size  = 2048
	)
	var tcb ControlBlock
	tcb.HelperInitState(StateEstablished, iss, iss+1, localWND)
	tcb.HelperInitRcv(remoteISS, remoteISS+1, remoteWND)

	// Remote sends FIN-ACK → we should enter CLOSE-WAIT.
	finAck := Segment{
		SEQ:   remoteISS + 1, // == rcv.NXT
		ACK:   iss + 1,       // == snd.NXT
		Flags: FlagFIN | FlagACK,
		WND:   remoteWND,
	}
	if err := tcb.Recv(finAck); err != nil {
		t.Fatalf("recv FIN-ACK: %v", err)
	}
	if tcb.State() != StateCloseWait {
		t.Fatalf("state = %s; want CLOSE-WAIT after receiving FIN", tcb.State())
	}

	// Retrieve and send the pending ACK for the FIN.
	pendSeg, ok := tcb.PendingSegment(0)
	if !ok {
		t.Fatal("no pending ACK after receiving FIN")
	}
	if err := tcb.Send(pendSeg); err != nil {
		t.Fatalf("send ACK in CLOSE-WAIT: %v", err)
	}
	if tcb.State() != StateCloseWait {
		t.Fatalf("state = %s after sending ACK; want CLOSE-WAIT (user has not called Close())", tcb.State())
	}

	// RFC 9293 §3.5: user may still send data in CLOSE-WAIT.
	// FIN must NOT be pending until the user calls Close().
	// Currently FAILS: Send(ACK) in CLOSE-WAIT auto-queues FINACK into pending[0].
	seg, hasPending := tcb.PendingSegment(0)
	if hasPending && seg.Flags.HasAny(FlagFIN) {
		t.Errorf("FIN auto-queued in CLOSE-WAIT before user calls Close(): pending flags=%s "+
			"(control.go:353-354 queues finack on any ACK sent in CLOSE-WAIT)", seg.Flags)
	}
}

func TestPendingSegment_RetransmitAfter3DupACKs(t *testing.T) {
	const (
		iss       Value = 100
		remoteISS Value = 500
		inFlight        = 10
		wnd       Size  = 1024
	)

	var tcb ControlBlock
	tcb.HelperInitState(StateEstablished, iss, iss+inFlight, wnd)
	tcb.HelperInitRcv(remoteISS, remoteISS+1, wnd)

	// Three duplicate ACKs against UNA must trigger retransmit state
	for i := 0; i < 3; i++ {
		dup := Segment{
			SEQ:   remoteISS + 1,
			ACK:   iss, // UNA (duplicate, no progress)
			Flags: FlagACK,
			WND:   wnd,
		}
		if !tcb.IncomingIsDupACK(dup.ACK) {
			t.Fatal("supposed duplicate ack segment not considered dupack")
		}
		if err := tcb.Recv(dup); err != nil {
			t.Fatalf("dup ACK %d: unexpected error: %v", i+1, err)
		}
	}

	if tcb.dupack != 3 {
		t.Fatalf("dupack = %d; want 3", tcb.dupack)
	}
	if !tcb.HasPendingRetransmit() {
		t.Fatal("expected HasPendingRetransmit() == true after 3 dupacks")
	}

	seg, ok := tcb.PendingSegment(4)
	if !ok {
		t.Fatal("PendingSegment(false) returned no segment; expected retransmit segment")
	}
	if seg.SEQ != tcb.snd.UNA {
		t.Fatalf("retransmit SEQ = %d; want UNA(%d)", seg.SEQ, tcb.snd.UNA)
	}
	if seg.ACK != tcb.rcv.NXT {
		t.Fatalf("retransmit ACK = %d; want RCV.NXT(%d)", seg.ACK, tcb.rcv.NXT)
	}
	if !seg.Flags.HasAny(FlagACK) {
		t.Errorf("retransmit segment must include ACK")
	}

	// Send retransmit, expect nRetransmit to be incremented and NXT not moved
	prevNXT := tcb.snd.NXT
	if err := tcb.Send(seg); err != nil {
		t.Fatalf("Send(retransmit) unexpected error: %v", err)
	}
	if tcb.nRetransmit != 1 {
		t.Fatalf("nRetransmit = %d; want 1", tcb.nRetransmit)
	}
	if tcb.snd.NXT != prevNXT {
		t.Fatalf("snd.NXT advanced on retransmit: got %d, want %d", tcb.snd.NXT, prevNXT)
	}
	if tcb.HasPendingRetransmit() {
		t.Fatal("expected retransmit reservation gone after retransmit send")
	}

	// Deliver cumulative ACK for all in-flight data => reset dupack + nRetransmit
	successACK := Segment{
		SEQ:   remoteISS + 1,
		ACK:   iss + inFlight,
		Flags: FlagACK,
		WND:   wnd,
	}
	if err := tcb.Recv(successACK); err != nil {
		t.Fatalf("successful ACK unexpected err: %v", err)
	}
	if tcb.dupack != 0 {
		t.Fatalf("dupack after progress = %d; want 0", tcb.dupack)
	}
	if tcb.nRetransmit != 0 {
		t.Fatalf("nRetransmit after progress = %d; want 0", tcb.nRetransmit)
	}
}

// TestACKLoop_MutualOutOfWindow verifies that two TCBs with diverged state
// (simulating post-mutation) don't enter an infinite challenge-ACK ping-pong.
// Each side sees the other's segment as out-of-window → challenge ACK → loop.
func TestACKLoop_MutualOutOfWindow(t *testing.T) {
	const wnd Size = 64

	// Setup: A.snd.NXT=101, B.rcv.NXT=5000 → A's segments are outside B's window.
	//        B.snd.NXT=501, A.rcv.NXT=8000 → B's segments are outside A's window.
	// Both will reject each other's challenge ACKs forever without a limit.
	var tcbA ControlBlock
	tcbA.HelperInitState(StateEstablished, 100, 101, wnd)
	tcbA.HelperInitRcv(8000, 8001, wnd) // A expects seq from B around 8001
	tcbA.snd.UNA = 101
	tcbA.snd.WND = wnd
	tcbA.snd.WL1 = 8001
	tcbA.snd.WL2 = 101

	var tcbB ControlBlock
	tcbB.HelperInitState(StateEstablished, 500, 501, wnd)
	tcbB.HelperInitRcv(5000, 5001, wnd) // B expects seq from A around 5001
	tcbB.snd.UNA = 501
	tcbB.snd.WND = wnd
	tcbB.snd.WL1 = 5001
	tcbB.snd.WL2 = 501

	// Kick off: A has a pending ACK (simulating normal data exchange trigger).
	tcbA.pending[0] = FlagACK

	const maxRounds = 50
	for round := 0; round < maxRounds; round++ {
		segA, okA := tcbA.PendingSegment(0)
		if okA {
			tcbA.Send(segA)
			// A sends seq=101, but B expects [5001, 5001+64) → out of window → challenge ACK
			tcbB.Recv(segA)
		}

		segB, okB := tcbB.PendingSegment(0)
		if okB {
			tcbB.Send(segB)
			// B sends seq=501, but A expects [8001, 8001+64) → out of window → challenge ACK
			tcbA.Recv(segB)
		}

		if !okA && !okB {
			return // Converged.
		}
	}
	t.Fatal("ACK ping-pong did not converge after", maxRounds, "rounds — infinite loop bug")
}
