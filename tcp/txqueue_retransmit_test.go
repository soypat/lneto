package tcp

import (
	"bytes"
	"testing"
)

// newRetransmitQueue builds a queue holding npkt sent packets of pktlen octets
// each, starting at iss, plus any leftover unsent data. It returns the queue and
// the full byte stream that was written.
func newRetransmitQueue(t *testing.T, bufsize, maxPkts, npkt, pktlen, unsent int, iss Value) (*ringTx, []byte) {
	t.Helper()
	var rtx ringTx
	if err := rtx.Reset(make([]byte, bufsize), maxPkts, iss); err != nil {
		t.Fatal(err)
	}
	stream := make([]byte, npkt*pktlen+unsent)
	for i := range stream {
		stream[i] = byte(i + 1) // Non-zero so a stale ring shows up as a mismatch.
	}
	if n, err := rtx.Write(stream); err != nil || n != len(stream) {
		t.Fatalf("write n=%d err=%v", n, err)
	}
	seq := iss
	scratch := make([]byte, pktlen)
	for i := range npkt {
		n, err := rtx.MakePacket(scratch, seq)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if n != pktlen {
			t.Fatalf("packet %d: n=%d, want %d", i, n, pktlen)
		}
		seq += Value(n)
	}
	testQueueSanity(t, &rtx)
	return &rtx, stream
}

// mustRemake asserts the queue re-emits datalen octets at seq matching want.
func mustRemake(t *testing.T, rtx *ringTx, seq Value, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	n, err := rtx.MakePacket(got, seq)
	if err != nil {
		t.Fatalf("MakePacket at seq %d: %v", seq, err)
	}
	if n != len(want) {
		t.Fatalf("MakePacket at seq %d: n=%d, want %d", seq, n, len(want))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("MakePacket at seq %d: got %v, want %v", seq, got, want)
	}
}

// TestRingTx_RetransmitFromBoundary rewinds to the start of the second of three
// sent packets: the first stays sent, the rest become unsent and re-emit their
// original bytes.
func TestRingTx_RetransmitFromBoundary(t *testing.T) {
	const iss, pktlen = Value(100), 4
	rtx, stream := newRetransmitQueue(t, 64, 4, 3, pktlen, 0, iss)

	sentBefore := rtx.BufferedSent()
	rtx.RetransmitFrom(iss + pktlen) // Start of packet 2.
	testQueueSanity(t, rtx)

	if got := rtx.BufferedSent(); got != pktlen {
		t.Fatalf("sent=%d, want %d (only packet 1 remains sent)", got, pktlen)
	}
	if got := rtx.BufferedUnsent(); got != sentBefore-pktlen {
		t.Fatalf("unsent=%d, want %d", got, sentBefore-pktlen)
	}
	mustRemake(t, rtx, iss+pktlen, stream[pktlen:2*pktlen])
	testQueueSanity(t, rtx)
	mustRemake(t, rtx, iss+2*pktlen, stream[2*pktlen:3*pktlen])
	testQueueSanity(t, rtx)
}

// TestRingTx_RetransmitFromMidPacket verifies a sequence inside a packet is
// snapped down to that packet's start: the queue tracks whole packets.
func TestRingTx_RetransmitFromMidPacket(t *testing.T) {
	const iss, pktlen = Value(100), 4
	rtx, stream := newRetransmitQueue(t, 64, 4, 3, pktlen, 0, iss)

	rtx.RetransmitFrom(iss + pktlen + 2) // Two octets into packet 2.
	testQueueSanity(t, rtx)

	if got := rtx.BufferedSent(); got != pktlen {
		t.Fatalf("sent=%d, want %d: rewind must floor to the packet start", got, pktlen)
	}
	mustRemake(t, rtx, iss+pktlen, stream[pktlen:2*pktlen])
}

// TestRingTx_RetransmitFromOldest rewinds the whole queue, which must match
// RetransmitFromUNA.
func TestRingTx_RetransmitFromOldest(t *testing.T) {
	const iss, pktlen, npkt = Value(100), 4, 3
	rtx, stream := newRetransmitQueue(t, 64, 4, npkt, pktlen, 0, iss)
	rtx.RetransmitFrom(iss)
	testQueueSanity(t, rtx)

	viaUNA, _ := newRetransmitQueue(t, 64, 4, npkt, pktlen, 0, iss)
	viaUNA.RetransmitFromUNA()
	testQueueSanity(t, viaUNA)

	if rtx.BufferedSent() != 0 {
		t.Fatalf("sent=%d, want 0 after a full rewind", rtx.BufferedSent())
	}
	if rtx.BufferedUnsent() != npkt*pktlen {
		t.Fatalf("unsent=%d, want %d", rtx.BufferedUnsent(), npkt*pktlen)
	}
	if rtx.BufferedSent() != viaUNA.BufferedSent() || rtx.BufferedUnsent() != viaUNA.BufferedUnsent() {
		t.Fatal("RetransmitFrom(oldest) must match RetransmitFromUNA")
	}
	mustRemake(t, rtx, iss, stream[:pktlen])
}

// TestRingTx_RetransmitFromUnknownSeq verifies a sequence covered by no queued
// packet leaves the queue untouched.
func TestRingTx_RetransmitFromUnknownSeq(t *testing.T) {
	const iss, pktlen, npkt = Value(100), 4, 3
	rtx, _ := newRetransmitQueue(t, 64, 4, npkt, pktlen, 0, iss)
	sent, unsent := rtx.BufferedSent(), rtx.BufferedUnsent()

	rtx.RetransmitFrom(iss - 1)           // Before the queue.
	rtx.RetransmitFrom(iss + npkt*pktlen) // One past the last octet sent.
	rtx.RetransmitFrom(iss + 1000)        // Far beyond.
	testQueueSanity(t, rtx)

	if rtx.BufferedSent() != sent || rtx.BufferedUnsent() != unsent {
		t.Fatalf("queue moved: sent %d→%d, unsent %d→%d", sent, rtx.BufferedSent(), unsent, rtx.BufferedUnsent())
	}
}

// TestRingTx_RetransmitWithUnsentTail verifies a rewind reopens the unsent region
// over the rewound packets without losing the unsent tail behind them.
func TestRingTx_RetransmitWithUnsentTail(t *testing.T) {
	const iss, pktlen, npkt, tail = Value(100), 4, 2, 5
	rtx, stream := newRetransmitQueue(t, 64, 4, npkt, pktlen, tail, iss)
	if got := rtx.BufferedUnsent(); got != tail {
		t.Fatalf("unsent tail=%d, want %d", got, tail)
	}

	rtx.RetransmitFrom(iss + pktlen) // Rewind the second packet only.
	testQueueSanity(t, rtx)

	if got := rtx.BufferedUnsent(); got != pktlen+tail {
		t.Fatalf("unsent=%d, want %d (rewound packet plus the tail)", got, pktlen+tail)
	}
	// The rewound packet re-emits first, then the tail follows in order.
	mustRemake(t, rtx, iss+pktlen, stream[pktlen:2*pktlen])
	testQueueSanity(t, rtx)
	mustRemake(t, rtx, iss+2*pktlen, stream[2*pktlen:])
}

// TestRingTx_RetransmitAfterDrainedUnsent pins the write-position recovery: when
// every octet written has been packetized the unsent region is empty, so the
// rewind must reconstruct where data ends from the sent region.
func TestRingTx_RetransmitAfterDrainedUnsent(t *testing.T) {
	const iss, pktlen, npkt = Value(100), 4, 3
	rtx, stream := newRetransmitQueue(t, 64, 4, npkt, pktlen, 0, iss)
	if got := rtx.BufferedUnsent(); got != 0 {
		t.Fatalf("unsent=%d, want 0: all written data was packetized", got)
	}

	rtx.RetransmitFrom(iss + pktlen)
	testQueueSanity(t, rtx)

	if got := rtx.BufferedUnsent(); got != 2*pktlen {
		t.Fatalf("unsent=%d, want %d: rewind lost the end of the data", got, 2*pktlen)
	}
	mustRemake(t, rtx, iss+pktlen, stream[pktlen:2*pktlen])
	testQueueSanity(t, rtx)
	mustRemake(t, rtx, iss+2*pktlen, stream[2*pktlen:3*pktlen])
}

// TestRingTx_RetransmitWrapped exercises a rewind on a queue whose regions wrap
// the end of the ring buffer.
func TestRingTx_RetransmitWrapped(t *testing.T) {
	const bufsize, pktlen = 16, 4
	const iss = Value(100)
	var rtx ringTx
	if err := rtx.Reset(make([]byte, bufsize), 4, iss); err != nil {
		t.Fatal(err)
	}
	// Push the queue most of the way around the ring, acking as we go.
	seq := iss
	scratch := make([]byte, pktlen)
	for round := range 3 {
		chunk := make([]byte, pktlen)
		for i := range chunk {
			chunk[i] = byte(round*pktlen + i + 1)
		}
		if _, err := rtx.Write(chunk); err != nil {
			t.Fatal(err)
		}
		if _, err := rtx.MakePacket(scratch, seq); err != nil {
			t.Fatal(err)
		}
		seq += Value(pktlen)
		if round < 2 {
			if err := rtx.RecvACK(seq); err != nil {
				t.Fatal(err)
			}
		}
		testQueueSanity(t, &rtx)
	}
	// Two packets outstanding, straddling the wrap. Rewind the newest.
	rewindSeq := seq - Value(pktlen)
	want := append([]byte(nil), scratch...)
	rtx.RetransmitFrom(rewindSeq)
	testQueueSanity(t, &rtx)
	mustRemake(t, &rtx, rewindSeq, want)
	testQueueSanity(t, &rtx)
}
