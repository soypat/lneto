package tcp

import (
	"math/rand"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

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

// rtxSetup establishes a client with a recordingPolicy and returns it.
func rtxSetup(t *testing.T, seed int64, buf []byte) (client *Handler, pol *recordingPolicy) {
	t.Helper()
	client, server := newHandler(t, ethernet.MaxMTU, 4), newHandler(t, ethernet.MaxMTU, 4)
	pol = newRecordingPolicy()
	client.SetPolicy(pol)
	setupClientServer(t, rand.New(rand.NewSource(seed)), client, server)
	establish(t, client, server, buf)
	return client, pol
}

// rtxSendData writes data and emits it as one segment, returning its SEQ.
func rtxSendData(t *testing.T, h *Handler, buf []byte, data string) Value {
	t.Helper()
	if _, err := h.Write([]byte(data)); err != nil {
		t.Fatal("write:", err)
	}
	seq := h.ControlBlock().SendNext()
	clear(buf)
	n, err := h.Send(buf)
	if err != nil {
		t.Fatal("send:", err)
	} else if n != sizeHeaderTCP+len(data) {
		t.Fatalf("sent %d bytes, want %d", n, sizeHeaderTCP+len(data))
	}
	return seq
}

// rtxSend emits one segment and returns it with its payload.
func rtxSend(t *testing.T, h *Handler, buf []byte) (Segment, string) {
	t.Helper()
	clear(buf)
	n, err := h.Send(buf)
	if err != nil {
		t.Fatal("send:", err)
	} else if n == 0 {
		t.Fatal("no segment emitted")
	}
	return mustSegment(t, buf[:n], n-sizeHeaderTCP), string(buf[sizeHeaderTCP:n])
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
