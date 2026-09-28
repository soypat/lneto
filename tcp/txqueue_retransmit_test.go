package tcp

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/soypat/lneto"
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

func TestMakePacketRetransmitWithFullQueue(t *testing.T) {
	const iss, pktlen, npkt = Value(100), 4, 3
	rtx, stream := newRetransmitQueue(t, 64, npkt, npkt, pktlen, pktlen, iss)
	if free := rtx.slist.Free(); free != 0 {
		t.Fatalf("queue has %d free entries, want 0", free)
	}
	uo, ue, so, se := rtx.lims()
	packets := slices.Clone(rtx.slist.pkts)
	for range 2 {
		for i := range npkt {
			mustRemake(t, rtx, iss+Value(i*pktlen), stream[i*pktlen:(i+1)*pktlen])
		}
	}
	if gotUO, gotUE, gotSO, gotSE := rtx.lims(); gotUO != uo || gotUE != ue || gotSO != so || gotSE != se {
		t.Fatal("retransmission changed sent/unsent buffer boundaries")
	}
	if !slices.Equal(rtx.slist.pkts, packets) {
		t.Fatal("retransmission changed tracked packets")
	}
	testQueueSanity(t, rtx)
	var scratch [pktlen]byte
	next := iss + npkt*pktlen
	if n, err := rtx.MakePacket(scratch[:], next); n != 0 || !errors.Is(err, lneto.ErrBufferFull) {
		t.Fatalf("new packet on full queue: n=%d err=%v, want 0 and ErrBufferFull", n, err)
	}
	if err := rtx.RecvACK(iss + pktlen); err != nil {
		t.Fatal(err)
	}
	mustRemake(t, rtx, next, stream[npkt*pktlen:])
	testQueueSanity(t, rtx)
}

// TestRingTx_RetransmitBoundary replaces the removed rewind tests: it checks that
// retransmitBoundary snaps a sequence to its packet start without modifying the
// queue, and that the packet then replays its original bytes.
func TestRingTx_RetransmitBoundary(t *testing.T) {
	const iss, pktlen = Value(100), 4
	sent3 := func(t *testing.T) (*ringTx, []byte) { return newRetransmitQueue(t, 64, 4, 3, pktlen, 0, iss) }
	tail := func(t *testing.T) (*ringTx, []byte) { return newRetransmitQueue(t, 64, 4, 2, pktlen, 5, iss) }
	partial := func(t *testing.T) (*ringTx, []byte) {
		rtx, stream := sent3(t)
		if err := rtx.RecvACK(iss + pktlen + 1); err != nil {
			t.Fatal(err)
		}
		return rtx, stream
	}
	// wrapped sends a 2-octet packet then 4-octet packets, acking all but the
	// newest, so the last packet occupies [14,16)+[0,2) of the 16-octet ring.
	wrapped := func(t *testing.T) (*ringTx, []byte) {
		var rtx ringTx
		if err := rtx.Reset(make([]byte, 16), 4, iss); err != nil {
			t.Fatal(err)
		}
		var stream []byte
		seq := iss
		for round := range 5 {
			n := pktlen
			if round == 0 {
				n = 2
			}
			chunk := make([]byte, n)
			for i := range chunk {
				chunk[i] = byte(len(stream) + i + 1)
			}
			stream = append(stream, chunk...)
			if _, err := rtx.Write(chunk); err != nil {
				t.Fatal(err)
			}
			if _, err := rtx.MakePacket(make([]byte, n), seq); err != nil {
				t.Fatal(err)
			}
			if round > 0 {
				if err := rtx.RecvACK(seq); err != nil {
					t.Fatal(err)
				}
			}
			seq += Value(n)
			testQueueSanity(t, &rtx)
		}
		if pkt := rtx.slist.Newest(); pkt.end >= pkt.off {
			t.Fatalf("packet [%d,%d) does not wrap the ring", pkt.off, pkt.end)
		}
		return &rtx, stream
	}
	for _, tc := range []struct {
		name    string
		setup   func(*testing.T) (*ringTx, []byte)
		seq     Value
		want    Value
		wantOK  bool
		wantLen int
	}{
		{"boundary(RetransmitFromBoundary)", sent3, iss + pktlen, iss + pktlen, true, pktlen},
		{"mid-packet(RetransmitFromMidPacket)", sent3, iss + pktlen + 2, iss + pktlen, true, pktlen},
		{"oldest(RetransmitFromOldest)", sent3, iss, iss, true, pktlen},
		{"before-queue(RetransmitFromUnknownSeq)", sent3, iss - 1, 0, false, 0},
		{"past-sent(RetransmitFromUnknownSeq)", sent3, iss + 3*pktlen, 0, false, 0},
		{"far-beyond(RetransmitFromUnknownSeq)", sent3, iss + 1000, 0, false, 0},
		{"unsent-tail(RetransmitWithUnsentTail)", tail, iss + pktlen, iss + pktlen, true, pktlen},
		{"drained-unsent(RetransmitAfterDrainedUnsent)", sent3, iss + pktlen, iss + pktlen, true, pktlen},
		{"wrapped(RetransmitWrapped)", wrapped, iss + 2 + 3*pktlen + 1, iss + 2 + 3*pktlen, true, pktlen},
		{"partial-ack", partial, iss + pktlen + 2, iss + pktlen + 1, true, pktlen - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rtx, stream := tc.setup(t)
			uo, ue, so, se := rtx.lims()
			pkts := slices.Clone(rtx.slist.pkts)
			sent, unsent := rtx.BufferedSent(), rtx.BufferedUnsent()

			got, ok := rtx.retransmitBoundary(tc.seq)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("retransmitBoundary(%d)=(%d,%v), want (%d,%v)", tc.seq, got, ok, tc.want, tc.wantOK)
			}
			if ok {
				start := int(got - iss)
				mustRemake(t, rtx, got, stream[start:start+tc.wantLen])
			}
			if gotUO, gotUE, gotSO, gotSE := rtx.lims(); gotUO != uo || gotUE != ue || gotSO != so || gotSE != se {
				t.Fatal("queue buffer boundaries changed")
			}
			if !slices.Equal(rtx.slist.pkts, pkts) {
				t.Fatal("tracked packets changed")
			}
			if rtx.BufferedSent() != sent || rtx.BufferedUnsent() != unsent {
				t.Fatalf("sent %d→%d, unsent %d→%d", sent, rtx.BufferedSent(), unsent, rtx.BufferedUnsent())
			}
			testQueueSanity(t, rtx)

			// New data resumes at the high-water mark with exactly the unsent tail.
			hwm, _ := rtx.sentEndSeq()
			buf := make([]byte, len(stream))
			n, err := rtx.MakePacket(buf, hwm)
			if err != nil {
				t.Fatalf("MakePacket at high-water mark %d: %v", hwm, err)
			}
			if tail := stream[int(hwm-iss):]; !bytes.Equal(buf[:n], tail) {
				t.Fatalf("MakePacket at high-water mark: got %v, want %v", buf[:n], tail)
			}
			testQueueSanity(t, rtx)
		})
	}
}
