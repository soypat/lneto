package tcp

import "testing"

// cbSending returns a control block in ESTABLISHED with iss..iss+sent already given
// to the network, so retransmission has something to resume into.
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

// TestRetransmitAtKeepsHighWaterMark verifies resending does not forget how far the
// stream has been sent, which is the whole reason the pointer is separate from
// snd.NXT. Rewinding snd.NXT to resend loses the high-water mark, so the connection
// cannot know that the data after the hole is already out.
func TestRetransmitAtKeepsHighWaterMark(t *testing.T) {
	const iss Value = 1000
	tcb := cbSending(t, iss, 1500)
	nxtBefore := tcb.snd.NXT

	resume, ok := tcb.RetransmitAt(iss + 500)
	if !ok {
		t.Fatal("RetransmitAt refused a sequence inside the outstanding range")
	}
	if resume != iss+500 {
		t.Errorf("resume at %d, want %d", resume, iss+500)
	}
	if tcb.snd.NXT != nxtBefore {
		t.Errorf("snd.NXT moved to %d by arranging a retransmission, want %d", tcb.snd.NXT, nxtBefore)
	}

	// The resend goes out at the pointer, not at the high-water mark.
	seg, ok := tcb.PendingSegment(500)
	if !ok {
		t.Fatal("no segment offered for the retransmission")
	}
	if seg.SEQ != iss+500 {
		t.Errorf("segment SEQ=%d, want the retransmit pointer %d", seg.SEQ, iss+500)
	}
	if err := tcb.Send(seg); err != nil {
		t.Fatal("send resend:", err)
	}
	if tcb.snd.NXT != nxtBefore {
		t.Errorf("snd.NXT moved to %d by resending, want %d", tcb.snd.NXT, nxtBefore)
	}
}

// TestRetransmitAtResendsOnlyTheHole verifies a request resends the range asked for
// and stops, leaving the data after it sent and new data continuing from the
// high-water mark.
//
// One request, one segment. Holding the request open until it reached snd.NXT would
// resend everything after the range asked for, which is the go-back-N this pointer
// exists to avoid; RFC 6298 §5.4 also asks for the earliest unacknowledged segment on
// a timeout rather than all of them. Anything further is asked for by the next
// directive, derived from what the peer has reported by then.
func TestRetransmitAtResendsOnlyTheHole(t *testing.T) {
	const iss Value = 1000
	const mss = 500
	tcb := cbSending(t, iss, 1500) // Three segments of 500 sent.
	tcb.snd.MSS = mss

	// Resend the middle segment only.
	if _, ok := tcb.RetransmitAt(iss + 500); !ok {
		t.Fatal("RetransmitAt refused")
	}
	seg, ok := tcb.PendingSegment(mss)
	if !ok {
		t.Fatal("no resend offered")
	}
	if seg.SEQ != iss+500 || seg.DATALEN != mss {
		t.Fatalf("resend = seq %d len %d, want seq %d len %d", seg.SEQ, seg.DATALEN, iss+500, mss)
	}
	if err := tcb.Send(seg); err != nil {
		t.Fatal(err)
	}
	// The request is satisfied: the third segment is not resent even though it too
	// lies below the high-water mark.
	if ptr, active := tcb.RetransmitPointer(); active {
		t.Errorf("retransmission still pending at %d after the range asked for was sent", ptr)
	}
	seg, ok = tcb.PendingSegment(mss)
	if !ok {
		t.Fatal("no segment offered after the retransmission")
	}
	if seg.SEQ != iss+1500 {
		t.Errorf("next segment at %d, want new data at the high-water mark %d: the data after the hole was resent", seg.SEQ, iss+1500)
	}
	// Asking again resends the next range, so nothing is unreachable.
	if _, ok = tcb.RetransmitAt(iss + 1000); !ok {
		t.Fatal("second RetransmitAt refused")
	}
	seg, ok = tcb.PendingSegment(mss)
	if !ok {
		t.Fatal("no second resend offered")
	}
	if seg.SEQ != iss+1000 {
		t.Errorf("second resend at %d, want %d", seg.SEQ, iss+1000)
	}
}

// TestRetransmitAtNeverExceedsHighWaterMark verifies a resend cannot invent data:
// asked for more than has been sent, it stops at the high-water mark.
func TestRetransmitAtNeverExceedsHighWaterMark(t *testing.T) {
	const iss Value = 1000
	tcb := cbSending(t, iss, 300) // Only 300 octets ever sent.
	tcb.snd.MSS = 1000
	if _, ok := tcb.RetransmitAt(iss); !ok {
		t.Fatal("RetransmitAt refused")
	}
	seg, ok := tcb.PendingSegment(1000) // Room offered for far more.
	if !ok {
		t.Fatal("no resend offered")
	}
	if seg.DATALEN != 300 {
		t.Errorf("resend length %d, want 300: only sent data may be resent", seg.DATALEN)
	}
	if err := tcb.Send(seg); err != nil {
		t.Fatal(err)
	}
	if _, active := tcb.RetransmitPointer(); active {
		t.Error("retransmission still active after resending everything outstanding")
	}
}

// TestRetransmitAtClampsAndRefuses verifies out-of-range requests are clamped or
// refused rather than corrupting the send space, since a policy's view of the
// sequence space can lag the connection's.
func TestRetransmitAtClampsAndRefuses(t *testing.T) {
	const iss Value = 1000
	t.Run("before UNA is clamped up", func(t *testing.T) {
		tcb := cbSending(t, iss, 1000)
		tcb.snd.UNA = iss + 200 // First 200 octets acknowledged.
		resume, ok := tcb.RetransmitAt(iss)
		if !ok {
			t.Fatal("refused a request that clamps into range")
		}
		if resume != iss+200 {
			t.Errorf("resume at %d, want snd.UNA %d: acknowledged data must not be resent", resume, iss+200)
		}
	})
	t.Run("at the high-water mark is refused", func(t *testing.T) {
		tcb := cbSending(t, iss, 1000)
		if _, ok := tcb.RetransmitAt(iss + 1000); ok {
			t.Error("accepted a resend at snd.NXT, where nothing has been sent yet")
		}
		if _, active := tcb.RetransmitPointer(); active {
			t.Error("a refused request must leave no retransmission in progress")
		}
	})
	t.Run("past the high-water mark is refused", func(t *testing.T) {
		tcb := cbSending(t, iss, 1000)
		if _, ok := tcb.RetransmitAt(iss + 5000); ok {
			t.Error("accepted a resend past snd.NXT")
		}
	})
	t.Run("closed send side is refused", func(t *testing.T) {
		var tcb ControlBlock
		if _, ok := tcb.RetransmitAt(iss); ok {
			t.Error("accepted a resend on a connection that cannot send data")
		}
	})
}

// TestRetransmitPointerClearedByAcknowledgement verifies an acknowledgement covering
// the hole abandons the retransmission, so acknowledged data is not resent.
func TestRetransmitPointerClearedByAcknowledgement(t *testing.T) {
	const iss Value = 1000
	tcb := cbSending(t, iss, 1500)
	if _, ok := tcb.RetransmitAt(iss + 500); !ok {
		t.Fatal("RetransmitAt refused")
	}
	// The peer acknowledges past the pointer: what was going to be resent arrived.
	err := tcb.Recv(Segment{SEQ: tcb.rcv.NXT, ACK: iss + 1000, WND: 4096, Flags: FlagACK})
	if err != nil {
		t.Fatal("recv ack:", err)
	}
	ptr, active := tcb.RetransmitPointer()
	if !active {
		t.Fatal("retransmission abandoned entirely, but data past the ack is still unacknowledged")
	}
	if ptr != iss+1000 {
		t.Errorf("pointer = %d, want snd.UNA %d: resending acknowledged data is wasted", ptr, iss+1000)
	}
	// An acknowledgement of everything ends the retransmission.
	err = tcb.Recv(Segment{SEQ: tcb.rcv.NXT, ACK: iss + 1500, WND: 4096, Flags: FlagACK})
	if err != nil {
		t.Fatal("recv full ack:", err)
	}
	if _, active = tcb.RetransmitPointer(); active {
		t.Error("retransmission still in progress after everything was acknowledged")
	}
}

// TestRetransmitPointerYieldsToControlSegments verifies a pending RST or FIN is not
// displaced by a retransmission, matching how the existing retransmit strategy
// defers to control segments.
func TestRetransmitPointerYieldsToControlSegments(t *testing.T) {
	const iss Value = 1000
	tcb := cbSending(t, iss, 1000)
	if _, ok := tcb.RetransmitAt(iss); !ok {
		t.Fatal("RetransmitAt refused")
	}
	tcb.pending[0] = FlagFIN | FlagACK
	seg, ok := tcb.PendingSegment(500)
	if !ok {
		t.Fatal("no segment offered")
	}
	if !seg.Flags.HasAny(FlagFIN) {
		t.Errorf("segment flags %s, want the pending FIN to take precedence", seg.Flags)
	}
}
