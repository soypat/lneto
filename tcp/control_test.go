package tcp

import (
	"testing"

	"github.com/soypat/lneto/internal"
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

// TestRcvSynRcvd_SYN verifies a SYN in SYN-RCVD never consumes sequence space a
// second time. Found by lfuzzo: a SYN|ACK at rcv.NXT completed the handshake and
// advanced rcv.NXT past the client's first data octet, desynchronizing both
// ESTABLISHED ends permanently.
func TestRcvSynRcvd_SYN(t *testing.T) {
	t.Skip()
	const (
		iss       Value = 1000
		remoteISS Value = 5000
		window    Size  = 2048
	)
	newTCB := func() ControlBlock {
		var tcb ControlBlock
		tcb.HelperInitState(StateSynRcvd, iss, iss+1, window)
		tcb.HelperInitRcv(remoteISS, remoteISS+1, window)
		return tcb
	}

	t.Run("SYN past IRS", func(t *testing.T) {
		tcb := newTCB()
		synack := Segment{SEQ: remoteISS + 1, ACK: iss + 1, Flags: synack, WND: window}
		if err := tcb.Recv(synack); err == nil {
			t.Fatal("SYN|ACK past IRS accepted in SYN-RCVD")
		}
		if tcb.State() != StateSynRcvd {
			t.Fatalf("state = %s; want SYN-RCVD", tcb.State())
		}
		if tcb.RecvNext() != remoteISS+1 {
			t.Fatalf("rcv.NXT = %d; want %d", tcb.RecvNext(), remoteISS+1)
		}
		seg, ok := tcb.PendingSegment(0)
		if !ok || seg.Flags != FlagACK || seg.ACK != remoteISS+1 {
			t.Fatalf("pending = %v, %v; want challenge ACK of rcv.NXT=%d", seg, ok, remoteISS+1)
		}
		// The client's data must still complete the handshake and be accepted in order.
		data := Segment{SEQ: remoteISS + 1, ACK: iss + 1, Flags: FlagPSH | FlagACK, WND: window, DATALEN: 21}
		if err := tcb.Recv(data); err != nil {
			t.Fatal("data after challenged SYN rejected:", err)
		}
		if tcb.State() != StateEstablished || tcb.RecvNext() != remoteISS+1+21 {
			t.Fatalf("state = %s rcv.NXT = %d; want ESTABLISHED, %d", tcb.State(), tcb.RecvNext(), remoteISS+1+21)
		}
	})

	t.Run("SYN|ACK at IRS", func(t *testing.T) {
		// Simultaneous open: the peer's SYN|ACK repeats its SYN at IRS and acknowledges ours.
		tcb := newTCB()
		synack := Segment{SEQ: remoteISS, ACK: iss + 1, Flags: synack, WND: window}
		if err := tcb.Recv(synack); err != nil {
			t.Fatal("simultaneous open SYN|ACK rejected:", err)
		}
		if tcb.State() != StateEstablished {
			t.Fatalf("state = %s; want ESTABLISHED", tcb.State())
		}
		if tcb.RecvNext() != remoteISS+1 {
			t.Fatalf("rcv.NXT = %d; want %d: SYN consumed twice", tcb.RecvNext(), remoteISS+1)
		}
	})
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
	for i := range 3 {
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
	for range maxRounds {
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

const isnTick = 4096 // ns per ISN clock tick.

func isnByteKey(b byte) (sameByteKey [16]byte) {
	for i := range sameByteKey {
		sameByteKey[i] = b
	}
	return sameByteKey
}

// ISNs of a tuple advance with the clock: one per ~4µs tick, wrapping mod 2**32.
func TestISN_Clock(t *testing.T) {
	key := isnByteKey(1)
	laddr, raddr := []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}
	const t0 = 1e9
	isn0 := ISN(&key, t0, laddr, raddr, 1234, 80)
	for _, ticks := range []int64{0, 1, 1000, 250_000, 1 << 32, 1<<32 + 7} {
		got := ISN(&key, t0+ticks*isnTick, laddr, raddr, 1234, 80) - isn0
		if want := Value(ticks); got != want {
			t.Errorf("after %d ticks ISN advanced by %d, want %d", ticks, got, want)
		}
	}
}

// Every element of the tuple and the key select an unrelated ISN.
func TestISN_TupleAndKey(t *testing.T) {
	const now = 1e9
	key1 := isnByteKey(1)
	base := ISN(&key1, now, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}, 1234, 80)
	tests := []struct {
		name         string
		key          [16]byte
		laddr, raddr []byte
		lport, rport uint16
	}{
		{name: "key", key: isnByteKey(2), laddr: []byte{10, 0, 0, 1}, raddr: []byte{10, 0, 0, 2}, lport: 1234, rport: 80},
		{name: "laddr", key: key1, laddr: []byte{10, 0, 0, 3}, raddr: []byte{10, 0, 0, 2}, lport: 1234, rport: 80},
		{name: "raddr", key: key1, laddr: []byte{10, 0, 0, 1}, raddr: []byte{10, 0, 0, 3}, lport: 1234, rport: 80},
		{name: "lport", key: key1, laddr: []byte{10, 0, 0, 1}, raddr: []byte{10, 0, 0, 2}, lport: 1235, rport: 80},
		{name: "rport", key: key1, laddr: []byte{10, 0, 0, 1}, raddr: []byte{10, 0, 0, 2}, lport: 1234, rport: 81},
		{name: "swapped", key: key1, laddr: []byte{10, 0, 0, 2}, raddr: []byte{10, 0, 0, 1}, lport: 80, rport: 1234},
		{name: "ipv6", key: key1, laddr: append(make([]byte, 12), 10, 0, 0, 1), raddr: append(make([]byte, 12), 10, 0, 0, 2), lport: 1234, rport: 80},
	}
	for _, tt := range tests {
		got := ISN(&tt.key, now, tt.laddr, tt.raddr, tt.lport, tt.rport)
		if got == base {
			t.Errorf("%s: changing it did not change ISN %d", tt.name, got)
		}
		v := ISN(&tt.key, now, tt.laddr, tt.raddr, tt.lport, tt.rport)
		if v != ISN(&tt.key, now, tt.laddr, tt.raddr, tt.lport, tt.rport) {
			t.Errorf("%s: ISN not deterministic", tt.name)
		}
	}
}

func TestISNGenerator_NoAlloc(t *testing.T) {
	key := isnByteKey(1)
	laddr, raddr := make([]byte, 16), make([]byte, 16)
	allocs := testing.AllocsPerRun(100, func() {
		ISN(&key, 1e9, laddr, raddr, 1234, 80)
	})
	if allocs != 0 {
		t.Errorf("ISN allocates %v times per call", allocs)
	}
}

// Consecutive local ports, as a dialer allocates them, must not yield ISNs a
// constant distance apart, which would let one connection predict the next.
func TestISNGenerator_SequentialPortsUnpredictable(t *testing.T) {
	const now = 1e9
	key1 := isnByteKey(1)
	laddr, raddr := []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}
	prev := ISN(&key1, now, laddr, raddr, 49152, 80)
	var prevDelta Value
	distinct := 0
	for port := uint16(49153); port < 49152+64; port++ {
		isn := ISN(&key1, now, laddr, raddr, port, 80)
		delta := isn - prev
		if delta != prevDelta {
			distinct++
		}
		prev, prevDelta = isn, delta
	}
	if distinct < 60 {
		t.Errorf("only %d of 63 ISN deltas between sequential ports differ", distinct)
	}
}

func FuzzTCPControlBlock(f *testing.F) {
	const (
		mutopFlags = 1 << iota
		mutopSeq
		mutopAck
		mutopMaxBit
	)
	const mutopBits = mutopMaxBit - 1
	const (
		mutPacketBits = 4

		mutFlags = 1 << iota
	)
	const wnd = 1500
	var seed uint64
	editPkt := func(rngSeed, ops uint64, seg *Segment) {
		ops &= mutopBits
		if ops&mutopFlags != 0 {
			seg.Flags ^= Flags(seed & uint64(FlagACK|FlagFIN|FlagRST|FlagSYN))
		}
		if ops&mutopSeq != 0 {
			seg.SEQ = Value(int32(seg.SEQ) + int32(int8(uint8(rngSeed>>32))))
		}
		if ops&mutopAck != 0 {
			seg.ACK = Value(int32(seg.ACK) + int32(int8(uint8(rngSeed>>48))))
		}
	}
	f.Add(seed, uint64(mutopFlags))
	f.Fuzz(func(t *testing.T, seed, op uint64) {
		var tcb0, tcb1 ControlBlock
		iss0 := Value(seed)
		iss1 := Value(seed >> 32)
		err := tcb0.Open(iss0, wnd)
		if err != nil {
			t.Fatal(err)
		}
		synseg := ClientSynSegment(iss1, wnd)
		err = tcb1.Send(synseg)
		if err != nil {
			t.Fatal(err)
		}
		err = tcb0.Recv(synseg)
		if err != nil {
			t.Fatal(err)
		}
		sent := 0
		const maxpkts = 30
		pktEdits := internal.Prand64(seed)
		nextOp := internal.Prand64(op)
		for range maxpkts {
			nextOp = internal.Prand64(nextOp)
			seg0, ok := tcb0.PendingSegment(10)
			if ok {
				edit := pktEdits&1 != 0
				pktEdits >>= 1
				if edit {
					editPkt(seed, nextOp, &seg0)
				}
				err = tcb0.Send(seg0)
				if err == nil {
					sent++
					err = tcb1.Recv(seg0)
					if err != nil {
						t.Fatal("packet sent from TCB0 to TCB1 failed:\n", StringExchange(seg0, tcb0.State(), tcb1.State(), false))
					}
				}
			}
			nextOp = internal.Prand64(nextOp)
			seg1, ok := tcb1.PendingSegment(10)
			if ok {
				edit := pktEdits&1 != 0
				pktEdits >>= 1
				if edit {
					editPkt(seed, nextOp, &seg1)
				}
				err = tcb1.Send(seg1)
				if err == nil {
					sent++
					err = tcb0.Recv(seg1)
					if err != nil {
						t.Fatal("packet sent from TCB1 to TCB0 failed:\n", StringExchange(seg1, tcb0.State(), tcb1.State(), true))
					}
				}
			}
		}
		if sent == 0 {
			t.Fatal("no packets sent")
		}
	})
}

// Tests for the "seqs: bad calculation" panic bug caused by a retransmitted SYN
// being accepted on an ESTABLISHED connection.
//
// Bug 1: validateIncomingSegment skips SEQ checks for any SYN, even in synchronized states.
// Bug 2: rcvEstablished silently accepts bare SYN segments (no data, no FIN).
// Combined: SYN overwrites snd.WND with a small value while data is in flight, causing
// uint32 underflow in maxSend() → panic in PendingSegment.

// TestSYNOnEstablished_PanicRegression replicates the exact crash sequence from the bug report:
// a retransmitted SYN arrives on an ESTABLISHED connection with 1200 bytes in flight,
// clobbers snd.WND to 1025, and triggers "seqs: bad calculation" in PendingSegment.
// To trigger run with GOARCH=386
func TestSYNOnEstablished_PanicRegression(t *testing.T) {
	// Values from the bug report timeline.
	const (
		serverISS   Value = 155000
		clientISS   Value = 4189094524 // The SYN's sequence number from the log.
		serverWND   Size  = 1024
		clientWND   Size  = 1025 // The SYN's small window.
		payloadSent Size  = 1200 // HTTP response bytes in flight.
	)

	// Recv must reject the SYN on an ESTABLISHED connection.
	t.Run("Recv_rejects_SYN", func(t *testing.T) {
		var tcb ControlBlock
		tcb.HelperInitState(StateEstablished, serverISS, serverISS+1+Value(payloadSent), serverWND)
		tcb.HelperInitRcv(clientISS, clientISS+1, 65535)
		tcb.snd.UNA = serverISS + 1

		syn := Segment{
			SEQ:   clientISS,
			ACK:   0,
			Flags: FlagSYN,
			WND:   clientWND,
		}

		err := tcb.Recv(syn)
		if err == nil {
			t.Fatal("Recv accepted SYN on ESTABLISHED connection; expected error")
		}
		if tcb.State() != StateEstablished {
			t.Fatalf("state changed to %s; want ESTABLISHED", tcb.State())
		}
		if tcb.snd.WND == clientWND {
			t.Fatalf("snd.WND was clobbered to %d by the SYN segment", clientWND)
		}
	})

	// Directly simulate the corrupted state to trigger the panic in PendingSegment.
	// This is the actual crash path: inFlight=1200, snd.WND=1025 → maxSend() underflows.
	// On 32-bit targets int(underflowedUint32) wraps negative → panic.
	t.Run("PendingSegment_panic", func(t *testing.T) {
		var tcb ControlBlock
		tcb.HelperInitState(StateEstablished, serverISS, serverISS+1+Value(payloadSent), serverWND)
		tcb.HelperInitRcv(clientISS, clientISS+1, 65535)
		tcb.snd.UNA = serverISS + 1

		// Simulate what Recv does when the SYN is accepted (the bug):
		// snd.WND gets overwritten with the SYN's small window.
		tcb.snd.WND = clientWND // inFlight=1200 > snd.WND=1025 → underflow.

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("confirmed panic: %v", r)
			}
		}()
		tcb.PendingSegment(1) // Any payload > 0 triggers the panic.
	})
}

// TestSYNOnEstablished_SEQValidation verifies that SYN segments are subject to
// sequence number validation in synchronized states (Bug 1 from the report).
func TestSYNOnEstablished_SEQValidation(t *testing.T) {
	const (
		iss       Value = 100
		remoteISS Value = 5000
		window    Size  = 1000
	)
	var tcb ControlBlock
	tcb.HelperInitState(StateEstablished, iss, iss, window)
	tcb.HelperInitRcv(remoteISS, remoteISS, window)

	// SYN with SEQ outside the receive window should be rejected.
	outOfWindowSYN := Segment{
		SEQ:   remoteISS - 2000, // Way before rcv.NXT.
		Flags: FlagSYN,
		WND:   1025,
	}

	err := tcb.Recv(outOfWindowSYN)
	if err == nil {
		t.Fatal("SYN with out-of-window SEQ was accepted in ESTABLISHED state")
	}

	// SYN with SEQ inside the window but not equal to rcv.NXT should also be rejected
	// (we require sequential segments per SHLD-31).
	inWindowSYN := Segment{
		SEQ:   remoteISS + 1, // In window but not NXT.
		Flags: FlagSYN,
		WND:   1025,
	}

	err = tcb.Recv(inWindowSYN)
	if err == nil {
		t.Fatal("SYN with in-window non-NXT SEQ was accepted in ESTABLISHED state")
	}
}

// TestSYNOnEstablished_ChallengeACK verifies that per RFC 9293 §3.10.7.4,
// receiving a SYN on an ESTABLISHED connection results in a challenge ACK
// rather than silently accepting or resetting (Bug 2 from the report).
func TestSYNOnEstablished_ChallengeACK(t *testing.T) {
	const (
		issA   Value = 100
		issB   Value = 300
		window Size  = 1000
	)
	var tcb ControlBlock
	tcb.HelperInitState(StateEstablished, issA, issA, window)
	tcb.HelperInitRcv(issB, issB, window)

	// SYN at exact rcv.NXT (in-window).
	syn := Segment{
		SEQ:   issB,
		Flags: FlagSYN,
		WND:   512,
	}

	err := tcb.Recv(syn)
	// Must be rejected (either via validation or rcvEstablished).
	if err == nil {
		t.Fatal("SYN at rcv.NXT was accepted in ESTABLISHED state; expected rejection")
	}

	// Connection must stay ESTABLISHED.
	if tcb.State() != StateEstablished {
		t.Fatalf("state = %s; want ESTABLISHED", tcb.State())
	}

	// snd.WND must be preserved.
	if tcb.snd.WND == 512 {
		t.Fatal("snd.WND was overwritten by the SYN's window value")
	}

	// A challenge ACK should be pending.
	seg, ok := tcb.PendingSegment(0)
	if !ok {
		t.Fatal("no pending segment after SYN on ESTABLISHED; expected challenge ACK")
	}
	if seg.Flags != FlagACK {
		t.Errorf("pending flags = %s; want ACK (challenge ACK)", seg.Flags)
	}
	if seg.SEQ != issA {
		t.Errorf("challenge ACK SEQ = %d; want snd.NXT=%d", seg.SEQ, issA)
	}
	if seg.ACK != issB {
		t.Errorf("challenge ACK ACK = %d; want rcv.NXT=%d", seg.ACK, issB)
	}
}

// TestChallengeACK_CounterSaturates verifies the challenge ACK counter does not
// overflow. Found by lfuzzo: past 127 consecutive challenges the int8 counter
// wrapped to -128, which negation cannot make positive, so a challenge ACK
// stayed pending and was emitted on every Send forever.
func TestChallengeACK_CounterSaturates(t *testing.T) {
	const (
		issA   Value = 100
		issB   Value = 300
		window Size  = 1000
	)
	var tcb ControlBlock
	tcb.HelperInitState(StateEstablished, issA, issA, window)
	tcb.HelperInitRcv(issB, issB, window)
	syn := Segment{SEQ: issB, Flags: FlagSYN, WND: window}
	for i := range 300 {
		tcb.Recv(syn) //nolint:errcheck // SYN is always rejected with a challenge.
		ack, ok := tcb.PendingSegment(0)
		if !ok || ack.Flags != FlagACK {
			t.Fatalf("SYN %d: no challenge ACK pending", i)
		}
		if err := tcb.Send(ack); err != nil {
			t.Fatalf("SYN %d: sending challenge ACK: %v", i, err)
		}
		if seg, ok := tcb.PendingSegment(0); ok {
			t.Fatalf("SYN %d: segment %s still pending after challenge ACK sent", i, seg)
		}
	}
}

// TestSYNOnClosingStates verifies SYN rejection in other synchronized states
// beyond ESTABLISHED (FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT).
func TestSYNOnClosingStates(t *testing.T) {
	states := []State{StateFinWait1, StateFinWait2, StateCloseWait}
	for _, state := range states {
		t.Run(state.String(), func(t *testing.T) {
			const iss, remoteISS, window Size = 100, 300, 1000
			var tcb ControlBlock
			tcb.HelperInitState(state, Value(iss), Value(iss), window)
			tcb.HelperInitRcv(Value(remoteISS), Value(remoteISS), window)

			syn := Segment{
				SEQ:   Value(remoteISS),
				Flags: FlagSYN,
				WND:   512,
			}

			err := tcb.Recv(syn)
			if err == nil {
				t.Fatalf("SYN accepted in %s state; expected rejection", state)
			}
			if tcb.State() != state {
				t.Fatalf("state changed from %s to %s after SYN", state, tcb.State())
			}
		})
	}
}

// TestWindowReject_ChallengeACK verifies that per RFC 9293 §3.4,
// segments failing the receive window acceptability test generate a challenge ACK
// rather than being silently dropped.
func TestWindowReject_ChallengeACK(t *testing.T) {
	const (
		issA   Value = 1000
		issB   Value = 5000
		window Size  = 1024
	)

	// wantACK is the expected challenge ACK for all sub-tests.
	wantACK := Segment{SEQ: issA, ACK: issB + 512, Flags: FlagACK, WND: window}

	setup := func() ControlBlock {
		var tcb ControlBlock
		tcb.HelperInitState(StateEstablished, issA, issA, window)
		tcb.HelperInitRcv(issB, issB+512, window) // rcv.NXT advanced by 512 (data already received)
		return tcb
	}

	// errSeqNotInWindow: segment SEQ entirely before rcv.NXT (retransmission of acked data).
	t.Run("SeqNotInWindow", func(t *testing.T) {
		tcb := setup()
		retransmit := Segment{
			SEQ:     issB, // Before rcv.NXT (issB+512).
			ACK:     issA,
			Flags:   FlagACK,
			WND:     64240,
			DATALEN: 512, // Covers [issB, issB+512) — all already received.
		}
		err := tcb.Recv(retransmit)
		if err == nil {
			t.Fatal("expected rejection for retransmitted segment")
		}
		seg, ok := tcb.PendingSegment(0)
		if !ok {
			t.Fatal("no pending segment; expected challenge ACK")
		}
		if seg != wantACK {
			t.Errorf("challenge ACK:\n got=%+v\nwant=%+v", seg, wantACK)
		}
	})

	// errLastNotInWindow: segment starts in window but end is beyond window.
	t.Run("LastNotInWindow", func(t *testing.T) {
		tcb := setup()
		seg := Segment{
			SEQ:     issB + 512, // At rcv.NXT (in window).
			ACK:     issA,
			Flags:   FlagACK,
			WND:     64240,
			DATALEN: Size(window) + 100, // End extends beyond window.
		}
		err := tcb.Recv(seg)
		if err == nil {
			t.Fatal("expected rejection for segment extending past window")
		}
		got, ok := tcb.PendingSegment(0)
		if !ok {
			t.Fatal("no pending segment; expected challenge ACK")
		}
		if got != wantACK {
			t.Errorf("challenge ACK:\n got=%+v\nwant=%+v", got, wantACK)
		}
	})

	// errZeroWindow: data sent to zero-size receive window.
	t.Run("ZeroWindow", func(t *testing.T) {
		var tcb ControlBlock
		tcb.HelperInitState(StateEstablished, issA, issA, 0) // zero receive window
		tcb.HelperInitRcv(issB, issB+512, window)
		wantZW := Segment{SEQ: issA, ACK: issB + 512, Flags: FlagACK, WND: 0}
		seg := Segment{
			SEQ:     issB + 512, // At rcv.NXT.
			ACK:     issA,
			Flags:   FlagACK,
			WND:     64240,
			DATALEN: 100, // Data to zero window.
		}
		err := tcb.Recv(seg)
		if err == nil {
			t.Fatal("expected rejection for data on zero window")
		}
		got, ok := tcb.PendingSegment(0)
		if !ok {
			t.Fatal("no pending segment; expected challenge ACK")
		}
		if got != wantZW {
			t.Errorf("challenge ACK:\n got=%+v\nwant=%+v", got, wantZW)
		}
	})

	// errRequireSequential: segment in window but not at rcv.NXT (out-of-order).
	t.Run("RequireSequential", func(t *testing.T) {
		tcb := setup()
		seg := Segment{
			SEQ:     issB + 512 + 100, // In window but not at rcv.NXT.
			ACK:     issA,
			Flags:   FlagACK,
			WND:     64240,
			DATALEN: 50,
		}
		err := tcb.Recv(seg)
		if err == nil {
			t.Fatal("expected rejection for out-of-order segment")
		}
		got, ok := tcb.PendingSegment(0)
		if !ok {
			t.Fatal("no pending segment; expected challenge ACK")
		}
		if got != wantACK {
			t.Errorf("challenge ACK:\n got=%+v\nwant=%+v", got, wantACK)
		}
	})

	// RST segments failing window check must NOT generate a challenge ACK.
	t.Run("RST_NoACK", func(t *testing.T) {
		tcb := setup()
		rst := Segment{
			SEQ:   issB, // Before rcv.NXT, out of window.
			Flags: FlagRST,
		}
		err := tcb.Recv(rst)
		if err == nil {
			t.Fatal("expected rejection for out-of-window RST")
		}
		_, ok := tcb.PendingSegment(0)
		if ok {
			t.Fatal("RST rejection should not generate a challenge ACK")
		}
	})

	// Verify errWindowOverflow does NOT trigger challenge ACK.
	t.Run("WindowOverflow_NoACK", func(t *testing.T) {
		tcb := setup()
		seg := Segment{
			SEQ:   issB + 512,
			ACK:   issA,
			Flags: FlagACK,
			WND:   Size(maxWindow + 1), // beyond even the largest scaled window (RFC 7323).
		}
		err := tcb.Recv(seg)
		if err == nil {
			t.Fatal("expected rejection for window overflow")
		}
		_, ok := tcb.PendingSegment(0)
		if ok {
			t.Fatal("window overflow should not generate a challenge ACK")
		}
	})
}

// TestPendingSegment_ACKSuppressedWhenWindowFull replicates the root cause of the
// "reject in/out seg: seq not in snd/rcv.wnd" regression reported after eab43c4.
//
// When inFlight >= snd.WND (send window full) and the caller has buffered TX data
// (payloadLen > 0), PendingSegment suppresses ALL segments—including pending ACKs—
// because the maxPayload==0 guard only allows FIN/RST/SYN through.
//
// Before eab43c4, maxSend() underflowed to ~4 billion when inFlight > WND, so the
// guard on line 204 never triggered and ACKs always piggybacked on data segments.
// After the underflow fix, maxSend() correctly returns 0, but this exposes the
// latent bug: ACKs are starved when the send window is full and there's TX data.
//
// The deadlock chain in production:
//  1. Publisher keeps TX buffer non-empty (payloadLen > 0 always)
//  2. Send window fills → maxSend() returns 0
//  3. PendingSegment drops the pending ACK → remote never learns data was received
//  4. Remote retransmits with stale SEQ → "seq not in snd/rcv.wnd" rejection
//  5. (Before 3d0bc93: no challenge ACK → permanent deadlock → i/o timeout)
//
// The challenge ACK fix at 3d0bc93 masks this by allowing recovery, but the
// underlying ACK suppression still causes unnecessary retransmission delays.
func TestPendingSegment_ACKSuppressedWhenWindowFull(t *testing.T) {
	const (
		localISS     Value = 1000
		remoteISS    Value = 5000
		dataInFlight Size  = 500
		remoteWND    Size  = 500 // == dataInFlight, so inFlight >= WND → maxSend()=0
		localWND     Size  = 1024
	)

	setup := func() ControlBlock {
		var tcb ControlBlock
		// snd.NXT = localISS + 1 + dataInFlight (SYN consumed 1 seq, then 500 bytes sent)
		tcb.HelperInitState(StateEstablished, localISS, localISS+1+Value(dataInFlight), localWND)
		// snd.WND = remoteWND (500), so inFlight(500) >= WND(500) → maxSend()=0
		tcb.HelperInitRcv(remoteISS, remoteISS+1, remoteWND)
		tcb.snd.UNA = localISS + 1 // SYN acked, 500 bytes unacked
		return tcb
	}

	// Sanity check: maxSend() is actually 0 in our setup.
	t.Run("precondition_maxSend_zero", func(t *testing.T) {
		tcb := setup()
		if ms := tcb.snd.maxSend(); ms != 0 {
			t.Fatalf("maxSend()=%d; want 0 (test precondition broken)", ms)
		}
	})

	// Control: PendingSegment(0) correctly returns the ACK when no payload requested.
	t.Run("payloadLen_0_ACK_sent", func(t *testing.T) {
		tcb := setup()
		tcb.pending[0] |= FlagACK // Simulate pending ACK from receiving data.
		seg, ok := tcb.PendingSegment(0)
		if !ok {
			t.Fatal("PendingSegment(0) returned !ok; pending ACK should be sent when no payload requested")
		}
		if !seg.Flags.HasAll(FlagACK) {
			t.Errorf("segment flags = %s; want ACK", seg.Flags)
		}
	})

	// THE BUG: PendingSegment(>0) suppresses the ACK when window is full.
	// This is the exact scenario of a publisher with buffered TX data.
	t.Run("payloadLen_gt0_ACK_must_not_be_suppressed", func(t *testing.T) {
		tcb := setup()
		tcb.pending[0] |= FlagACK // Simulate pending ACK from receiving data.

		// Caller has 100 bytes buffered to send, but window is full.
		// PendingSegment should return the ACK with DATALEN=0 (no data, window full)
		// instead of returning false and dropping the ACK entirely.
		seg, ok := tcb.PendingSegment(100)
		if !ok {
			t.Fatal("PendingSegment(100) returned !ok; pending ACK was suppressed because " +
				"maxPayload==0 guard only allows FIN/RST/SYN, not ACK. " +
				"This causes the remote to never learn data was received, " +
				"leading to retransmissions and eventual 'seq not in snd/rcv.wnd' rejection")
		}
		if !seg.Flags.HasAll(FlagACK) {
			t.Errorf("segment flags = %s; want ACK", seg.Flags)
		}
		if seg.DATALEN != 0 {
			t.Errorf("segment DATALEN = %d; want 0 (window is full, no data should be sent)", seg.DATALEN)
		}
	})

	// Verify FIN is still allowed through when window is full (existing behavior).
	t.Run("payloadLen_gt0_FIN_allowed", func(t *testing.T) {
		tcb := setup()
		tcb.pending[0] |= FlagFIN | FlagACK
		_, ok := tcb.PendingSegment(100)
		if !ok {
			t.Fatal("PendingSegment suppressed FIN+ACK when window full; FIN must always go through")
		}
	})
}

// TestSYNPreestablished_StillAllowed ensures the fix doesn't break normal SYN
// processing in pre-established states (LISTEN, SYN-SENT, SYN-RCVD).
func TestSYNPreestablished_StillAllowed(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000

	t.Run("LISTEN", func(t *testing.T) {
		var tcb ControlBlock
		tcb.HelperInitState(StateListen, issA, issA, windowA)
		syn := Segment{SEQ: issB, Flags: FlagSYN, WND: windowB}
		err := tcb.Recv(syn)
		if err != nil {
			t.Fatalf("SYN rejected in LISTEN state: %v", err)
		}
		if tcb.State() != StateSynRcvd {
			t.Fatalf("state = %s; want SYN-RCVD", tcb.State())
		}
	})

	t.Run("SYN-SENT", func(t *testing.T) {
		var tcb ControlBlock
		tcb.HelperInitState(StateSynSent, issA, issA, windowA)
		// Simultaneous open: receive SYN from peer.
		syn := Segment{SEQ: issB, Flags: FlagSYN, WND: windowB}
		err := tcb.Recv(syn)
		if err != nil {
			t.Fatalf("SYN rejected in SYN-SENT state: %v", err)
		}
		if tcb.State() != StateSynRcvd {
			t.Fatalf("state = %s; want SYN-RCVD", tcb.State())
		}
	})
}

func TestRecvAckUpdatesUnaCorrectly(t *testing.T) {
	// Create a TCB in ESTABLISHED state with some data sent but not yet acknowledged.
	tcb := &ControlBlock{
		_state: StateEstablished,
		snd: sendSpace{
			UNA: 1000,  // oldest unacknowledged sequence number
			NXT: 2000,  // next sequence number to send (1000 bytes outstanding)
			ISS: 500,   // initial send sequence number (not critical here)
			WND: 65535, // large window to avoid window issues
		},
		rcv: recvSpace{
			NXT: 3000, // any value, not used in these tests
			WND: 65535,
		},
		// logger can be nil or a no-op for tests
	}

	// Helper to check that UNA stays at expected value after processing a segment.
	checkUna := func(want Value, msg string) {
		if got := tcb.snd.UNA; got != want {
			t.Errorf("%s: UNA = %d, want %d", msg, got, want)
		}
	}

	// 1. Send an old ACK (below current UNA) – should be silently accepted but not advance UNA.
	oldAckSeg := Segment{
		Flags: FlagACK,
		ACK:   500, // less than UNA=1000
		WND:   65535,
		SEQ:   3000, // any acceptable sequence (within rcv window)
	}
	err := tcb.Recv(oldAckSeg)
	if err != nil {
		t.Errorf("old ACK returned error: %v, want nil (silent accept)", err)
	}
	checkUna(1000, "after old ACK")

	// 2. Send an ACK for unsent data (beyond NXT) – should be rejected (error) and UNA unchanged.
	futureAckSeg := Segment{
		Flags: FlagACK,
		ACK:   2500, // > NXT=2000
		WND:   65535,
		SEQ:   3000,
	}
	err = tcb.Recv(futureAckSeg)
	if err == nil {
		t.Error("ACK for unsent data returned nil, want error")
	}
	checkUna(1000, "after future ACK")

	// 3. Send a valid ACK that acknowledges some, but not all, outstanding data.
	validAckSeg := Segment{
		Flags: FlagACK,
		ACK:   1500, // between UNA and NXT
		WND:   65535,
		SEQ:   3000,
	}
	err = tcb.Recv(validAckSeg)
	if err != nil {
		t.Errorf("valid ACK returned error: %v, want nil", err)
	}
	checkUna(1500, "after valid ACK")

	// 4. Send an ACK that acknowledges exactly all outstanding data (ACK == NXT).
	allAckSeg := Segment{
		Flags: FlagACK,
		ACK:   2000, // == NXT
		WND:   65535,
		SEQ:   3000,
	}
	err = tcb.Recv(allAckSeg)
	if err != nil {
		t.Errorf("ACK == NXT returned error: %v, want nil", err)
	}
	checkUna(2000, "after ACK == NXT")
}

// cbSending returns a control block in ESTABLISHED with iss..iss+sent already
// given to the network.
func cbSending(t *testing.T, iss Value, sent Size) *ControlBlock {
	t.Helper()
	var tcb ControlBlock
	tcb.prepareToHandshake(iss, 4096, StateEstablished)
	tcb.snd.WND = 4096
	tcb.snd.MSS = 500
	tcb.rcv.NXT = 9000
	tcb.rcv.WND = 4096
	tcb.snd.NXT = iss + Value(sent)
	tcb.snd.UNA = iss
	return &tcb
}

// TestPendingRetransmitKeepsHighWaterMark verifies a resend goes out at the
// requested sequence and sending it leaves snd.NXT where it was.
func TestPendingRetransmitKeepsHighWaterMark(t *testing.T) {
	const iss Value = 1000
	tcb := cbSending(t, iss, 1500)
	nxtBefore := tcb.snd.NXT

	seg, ok := tcb.PendingRetransmit(iss+500, 500)
	if !ok {
		t.Fatal("PendingRetransmit refused a sequence inside [snd.UNA, snd.NXT)")
	}
	want := Segment{SEQ: iss + 500, DATALEN: 500, ACK: tcb.rcv.NXT, WND: tcb.rcv.WND, Flags: FlagACK}
	if seg != want {
		t.Fatalf("PendingRetransmit = %+v, want %+v", seg, want)
	}
	if tcb.snd.NXT != nxtBefore {
		t.Fatalf("PendingRetransmit moved snd.NXT to %d, want %d", tcb.snd.NXT, nxtBefore)
	}
	nrtx := tcb.nRetransmit
	if err := tcb.Send(seg); err != nil {
		t.Fatal("send resend:", err)
	}
	if tcb.snd.NXT != nxtBefore {
		t.Errorf("snd.NXT moved to %d by resending, want %d", tcb.snd.NXT, nxtBefore)
	}
	if tcb.nRetransmit != nrtx+1 {
		t.Errorf("nRetransmit = %d, want %d", tcb.nRetransmit, nrtx+1)
	}
	// Only the requested range was resent: the next segment is new data.
	seg, ok = tcb.PendingSegment(500)
	if !ok {
		t.Fatal("no segment offered after the resend")
	}
	if seg.SEQ != nxtBefore {
		t.Errorf("next segment at %d, want new data at snd.NXT %d", seg.SEQ, nxtBefore)
	}
}

func TestPendingRetransmitClamps(t *testing.T) {
	const iss Value = 1000
	tests := map[string]struct {
		sent    Size
		mss     Size
		seq     Value
		payload int
		wantLen Size
	}{
		"to snd.NXT":        {sent: 300, mss: 1000, seq: iss, payload: 1000, wantLen: 300},
		"to snd.NXT mid":    {sent: 300, mss: 1000, seq: iss + 100, payload: 1000, wantLen: 200},
		"to MSS":            {sent: 1500, mss: 500, seq: iss, payload: 1000, wantLen: 500},
		"to payload":        {sent: 1500, mss: 500, seq: iss, payload: 100, wantLen: 100},
		"no MSS":            {sent: 1500, mss: 0, seq: iss, payload: 1000, wantLen: 1000},
		"last octet at NXT": {sent: 1500, mss: 500, seq: iss + 1499, payload: 1000, wantLen: 1},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tcb := cbSending(t, iss, tc.sent)
			tcb.snd.MSS = tc.mss
			seg, ok := tcb.PendingRetransmit(tc.seq, tc.payload)
			if !ok {
				t.Fatal("PendingRetransmit refused")
			}
			if seg.SEQ != tc.seq || seg.DATALEN != tc.wantLen {
				t.Errorf("PendingRetransmit(%d, %d) = seq %d len %d, want seq %d len %d",
					tc.seq, tc.payload, seg.SEQ, seg.DATALEN, tc.seq, tc.wantLen)
			}
		})
	}
}

func TestPendingRetransmitRefuses(t *testing.T) {
	const iss Value = 1000
	tests := map[string]struct {
		setup   func(tcb *ControlBlock)
		seq     Value
		payload int
	}{
		"before snd.UNA":  {setup: func(tcb *ControlBlock) { tcb.snd.UNA = iss + 200 }, seq: iss + 100, payload: 500},
		"at snd.NXT":      {seq: iss + 1000, payload: 500},
		"past snd.NXT":    {seq: iss + 5000, payload: 500},
		"zero payload":    {seq: iss, payload: 0},
		"pending FIN":     {setup: func(tcb *ControlBlock) { tcb.pending[0] = FlagFIN | FlagACK }, seq: iss, payload: 500},
		"pending RST":     {setup: func(tcb *ControlBlock) { tcb.pending[0] = FlagRST }, seq: iss, payload: 500},
		"challenge ACK":   {setup: func(tcb *ControlBlock) { tcb.triggerChallengeAckEmit() }, seq: iss, payload: 500},
		"FIN-WAIT-2":      {setup: func(tcb *ControlBlock) { tcb._state = StateFinWait2 }, seq: iss, payload: 500},
		"TIME-WAIT":       {setup: func(tcb *ControlBlock) { tcb._state = StateTimeWait }, seq: iss, payload: 500},
		"CLOSED":          {setup: func(tcb *ControlBlock) { tcb._state = StateClosed }, seq: iss, payload: 500},
		"SYN-SENT":        {setup: func(tcb *ControlBlock) { tcb._state = StateSynSent }, seq: iss, payload: 500},
		"pending SYN-ACK": {setup: func(tcb *ControlBlock) { tcb.pending[0] = synack }, seq: iss, payload: 500},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tcb := cbSending(t, iss, 1000)
			if tc.setup != nil {
				tc.setup(tcb)
			}
			snd, pending, chal := tcb.snd, tcb.pending, tcb.challengeAcks
			if seg, ok := tcb.PendingRetransmit(tc.seq, tc.payload); ok {
				t.Errorf("PendingRetransmit(%d, %d) = %+v, want refused", tc.seq, tc.payload, seg)
			}
			if tcb.snd != snd || tcb.pending != pending || tcb.challengeAcks != chal {
				t.Error("PendingRetransmit modified the ControlBlock")
			}
		})
	}
}

// TestPendingRetransmitAllowedAfterClose verifies data under a sent FIN can still
// be resent, or the peer could never cross the gap below it.
func TestPendingRetransmitAllowedAfterClose(t *testing.T) {
	const iss Value = 1000
	for _, state := range []State{StateFinWait1, StateClosing, StateLastAck, StateCloseWait} {
		tcb := cbSending(t, iss, 1000)
		tcb._state = state
		if _, ok := tcb.PendingRetransmit(iss, 500); !ok {
			t.Errorf("%s: PendingRetransmit refused", state)
		}
	}
}
