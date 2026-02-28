package tcp

// Tests for the "seqs: bad calculation" panic bug caused by a retransmitted SYN
// being accepted on an ESTABLISHED connection.
//
// Bug 1: validateIncomingSegment skips SEQ checks for any SYN, even in synchronized states.
// Bug 2: rcvEstablished silently accepts bare SYN segments (no data, no FIN).
// Combined: SYN overwrites snd.WND with a small value while data is in flight, causing
// uint32 underflow in maxSend() → panic in PendingSegment.

import "testing"

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
			WND:   Size(1 << 17), // > MaxUint16.
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
