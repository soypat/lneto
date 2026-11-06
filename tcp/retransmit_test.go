package tcp

import (
	"testing"

	"github.com/soypat/lneto/ethernet"
)

func TestPendingRetransmitClamps(t *testing.T) {
	const iss Value = 1000
	tests := []struct {
		name    string
		sent    Size
		mss     Size
		seq     Value
		payload int
		wantLen Size
	}{
		{name: "to snd.NXT", sent: 300, mss: 1000, seq: iss, payload: 1000, wantLen: 300},
		{name: "to snd.NXT mid", sent: 300, mss: 1000, seq: iss + 100, payload: 1000, wantLen: 200},
		{name: "to MSS", sent: 1500, mss: 500, seq: iss, payload: 1000, wantLen: 500},
		{name: "to payload", sent: 1500, mss: 500, seq: iss, payload: 100, wantLen: 100},
		{name: "no MSS", sent: 1500, mss: 0, seq: iss, payload: 1000, wantLen: 1000},
		{name: "last octet at NXT", sent: 1500, mss: 500, seq: iss + 1499, payload: 1000, wantLen: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
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
	tests := []struct {
		name    string
		setup   func(tcb *ControlBlock)
		seq     Value
		payload int
	}{
		{name: "before snd.UNA", setup: func(tcb *ControlBlock) { tcb.snd.UNA = iss + 200 }, seq: iss + 100, payload: 500},
		{name: "at snd.NXT", seq: iss + 1000, payload: 500},
		{name: "past snd.NXT", seq: iss + 5000, payload: 500},
		{name: "zero payload", seq: iss, payload: 0},
		{name: "pending FIN", setup: func(tcb *ControlBlock) { tcb.pending[0] = FlagFIN | FlagACK }, seq: iss, payload: 500},
		{name: "pending RST", setup: func(tcb *ControlBlock) { tcb.pending[0] = FlagRST }, seq: iss, payload: 500},
		{name: "challenge ACK", setup: func(tcb *ControlBlock) { tcb.triggerChallengeAckEmit() }, seq: iss, payload: 500},
		{name: "FIN-WAIT-2", setup: func(tcb *ControlBlock) { tcb._state = StateFinWait2 }, seq: iss, payload: 500},
		{name: "TIME-WAIT", setup: func(tcb *ControlBlock) { tcb._state = StateTimeWait }, seq: iss, payload: 500},
		{name: "CLOSED", setup: func(tcb *ControlBlock) { tcb._state = StateClosed }, seq: iss, payload: 500},
		{name: "SYN-SENT", setup: func(tcb *ControlBlock) { tcb._state = StateSynSent }, seq: iss, payload: 500},
		{name: "pending SYN-ACK", setup: func(tcb *ControlBlock) { tcb.pending[0] = synack }, seq: iss, payload: 500},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
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

// TestHandlerRetransmitAtPacketStart verifies a directed resend inside a queued
// packet emits that whole packet from its start, leaves snd.NXT alone, and the
// following Send continues with new data from snd.NXT.
func TestHandlerRetransmitAtPacketStart(t *testing.T) {
	var buf [ethernet.MaxMTU]byte
	client, pol := rtxSetup(t, 21, buf[:])
	seqA := rtxSendData(t, client, buf[:], "alpha")
	rtxSendData(t, client, buf[:], "bravo")
	nxt := client.ControlBlock().SendNext()
	if _, err := client.Write([]byte("charlie")); err != nil {
		t.Fatal(err)
	}

	pol.rtxFrom, pol.retransmit = seqA+2, true
	seg, payload := rtxSend(t, client, buf[:])
	if seg.SEQ != seqA || payload != "alpha" {
		t.Fatalf("resend = seq %d %q, want seq %d %q", seg.SEQ, payload, seqA, "alpha")
	}
	if got := client.ControlBlock().SendNext(); got != nxt {
		t.Fatalf("snd.NXT = %d after resend, want %d", got, nxt)
	}

	pol.retransmit = false
	seg, payload = rtxSend(t, client, buf[:])
	if seg.SEQ != nxt || payload != "charlie" {
		t.Fatalf("next segment = seq %d %q, want new data seq %d %q", seg.SEQ, payload, nxt, "charlie")
	}
}

// TestHandlerRetransmitNothingQueued verifies a directive with no unsent data
// still emits the resend, as an RTO with nothing new to send requires.
func TestHandlerRetransmitNothingQueued(t *testing.T) {
	var buf [ethernet.MaxMTU]byte
	client, pol := rtxSetup(t, 22, buf[:])
	seqA := rtxSendData(t, client, buf[:], "alpha")
	if client.bufTx.BufferedUnsent() != 0 {
		t.Fatal("test requires no unsent data")
	}
	pol.rtxFrom, pol.retransmit = seqA, true
	seg, payload := rtxSend(t, client, buf[:])
	if seg.SEQ != seqA || payload != "alpha" {
		t.Fatalf("resend = seq %d %q, want seq %d %q", seg.SEQ, payload, seqA, "alpha")
	}
}

// TestHandlerRetransmitIgnoresTxLimit verifies a resend is not held back by the
// Policy's new-data limit, while new data still is.
func TestHandlerRetransmitIgnoresTxLimit(t *testing.T) {
	var buf [ethernet.MaxMTU]byte
	client, pol := rtxSetup(t, 23, buf[:])
	seqA := rtxSendData(t, client, buf[:], "alpha")
	if _, err := client.Write([]byte("bravo")); err != nil {
		t.Fatal(err)
	}
	pol.txLimit = 0
	pol.rtxFrom, pol.retransmit = seqA, true
	seg, payload := rtxSend(t, client, buf[:])
	if seg.SEQ != seqA || payload != "alpha" {
		t.Fatalf("resend = seq %d %q, want seq %d %q", seg.SEQ, payload, seqA, "alpha")
	}
	pol.retransmit = false
	clear(buf[:])
	n, err := client.Send(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if n > sizeHeaderTCP {
		t.Errorf("sent %d payload octets of new data with txLimit=0", n-sizeHeaderTCP)
	}
}

// TestHandlerRetransmitPartialPacket documents a known limitation: when the
// offered payload is smaller than the queued packet only its head is resent,
// and a later request for the tail snaps back to the head.
func TestHandlerRetransmitPartialPacket(t *testing.T) {
	var buf [ethernet.MaxMTU]byte
	client, pol := rtxSetup(t, 24, buf[:])
	seqA := rtxSendData(t, client, buf[:], "0123456789")
	nxt := client.ControlBlock().SendNext()
	small := buf[:sizeHeaderTCP+4]

	pol.rtxFrom, pol.retransmit = seqA, true
	seg, payload := rtxSend(t, client, small)
	if seg.SEQ != seqA || payload != "0123" {
		t.Fatalf("resend = seq %d %q, want seq %d %q", seg.SEQ, payload, seqA, "0123")
	}
	pol.rtxFrom = seqA + 4
	seg, payload = rtxSend(t, client, small)
	if seg.SEQ != seqA || payload != "0123" {
		t.Fatalf("tail resend = seq %d %q, want head seq %d %q", seg.SEQ, payload, seqA, "0123")
	}
	if got := client.ControlBlock().SendNext(); got != nxt {
		t.Fatalf("snd.NXT = %d, want %d", got, nxt)
	}
}
