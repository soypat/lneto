package tcp

import (
	"testing"

	"github.com/soypat/lneto/ethernet"
)

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
