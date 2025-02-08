package tcp

import (
	"bytes"
	"fmt"
	"math/rand"
	"slices"
	"testing"
)

func TestTxQueue(t *testing.T) {
	var msgBuf, ringBuf, readBuf, aux [1024]byte
	rng := rand.New(rand.NewSource(1))

	var rtx ringTx
	defer func() {
		testQueueSanity(t, &rtx)
	}()
	increasingComplexityTests := []struct {
		name string
		test func(*testing.T)
	}{
		0: {
			name: "SequentialMessages",
			test: func(t *testing.T) {
				const startAck = 0
				for i := 0; i < 10; i++ {
					rng.Read(msgBuf[:])
					msgs := removeEmptyMsgs(bytes.SplitAfter(msgBuf[:], []byte{0}))
					currentAck := Value(startAck)
					rtx.Reset(ringBuf[:], rng.Intn(4)+1, startAck)
					for imsg, msg := range msgs {
						// Write and create packet from single messages.
						currentAck = Add(currentAck, Size(len(msg)))
						operateOnRing(t, &rtx, msg, readBuf[:], aux[:], &currentAck)
						buffered := rtx.Buffered()
						if buffered != 0 {
							t.Fatalf("msg%d: want no buffered data after transaction, got %d", imsg, buffered)
						}
						newSeq := rtx.currentSeq()
						wantSeq := currentAck
						if newSeq != wantSeq {
							t.Fatalf("msg%d: want seq %d, got %d", imsg, wantSeq, newSeq)
						}
						if t.Failed() {
							t.Fatalf("failed on msg %d", imsg)
						}
					}
				}
			},
		},
		1: {
			name: "N-Messages",
			test: func(t *testing.T) {
				const startAck = 0
				for i := 0; i < 10; i++ {
					rng.Read(msgBuf[:])
					msgs := removeEmptyMsgs(bytes.SplitAfter(msgBuf[:], []byte{0}))
					currentAck := Value(startAck)
					rtx.Reset(ringBuf[:], rng.Intn(4)+1, startAck)
					for _, msg := range msgs {
						// Send all messages.
						operateOnRing(t, &rtx, msg, nil, aux[:], nil)
						if t.Failed() {
							return
						}
						gotSeq := rtx.currentSeq()
						if gotSeq != startAck {
							t.Fatalf("expected seq to not change during writes")
						}
						currentAck = Add(currentAck, Size(len(msg)))
					}
					operateOnRing(t, &rtx, nil, readBuf[:], aux[:], &currentAck)
				}
			},
		},
	}
	for i, test := range increasingComplexityTests {
		t.Run(test.name, test.test)
		if t.Failed() {
			t.Fatalf("subtest %d/%d %q failed, not running more complex tests until fixed", i+1, len(increasingComplexityTests), test.name)
		}
	}
}

func testTxQueue_NMessages(t *testing.T, rtx *ringTx, msgs [][]byte, buf, aux []byte, maxPkt int, startAck Value) {
	if len(msgs) > maxPkt {
		panic("need ring buffer to contain messages")
	}
	err := rtx.Reset(buf, maxPkt, startAck)
	if err != nil {
		t.Fatal(err)
	}

	prevSeq := Value(startAck)
	packets := make([][]byte, len(msgs))
	sent := 0
	for i := range aux {
		aux[i] = 0
	}
	for i, msg := range msgs {
		if len(aux) < len(msg) {
			panic("need aux to contain message")
		}
		n, err := rtx.Write(msg)
		if err != nil {
			t.Fatalf("writing packet %d: %s", i, err)
		} else if n != len(msg) {
			t.Fatalf("want %d written, got %d", len(msg), n)
		}
		testQueueSanity(t, rtx)
		unsent := rtx.Buffered()
		if unsent != n {
			t.Fatalf("want unsent %d, got %d", n, unsent)
		}
		testQueueSanity(t, rtx)
		n, seq, err := rtx.MakePacket(aux[sent : sent+len(msg)])
		if err != nil {
			t.Fatal("MakePacket: ", err)
		} else if seq != prevSeq {
			t.Fatalf("want seq %d, got %d", prevSeq, seq)
		} else if n != len(msg) {
			t.Fatalf("want full message %d sent, got %d", len(msg), n)
		}
		testQueueSanity(t, rtx)
		gotSent := rtx.BufferedSent()
		if gotSent != sent+n {
			t.Fatalf("want sent %d, got %d", sent+n, gotSent)
		}
		testQueueSanity(t, rtx)
		packets = append(packets, aux[sent:sent+n])
		prevSeq += Value(n)
		sent += n
	}
}

func testTxQueue_SequentialMessages(t *testing.T, rtx *ringTx, msgs [][]byte, buf, aux []byte, maxPkt int, startAck Value) {
	err := rtx.Reset(buf, maxPkt, startAck)
	if err != nil {
		t.Fatal(err)
	}
	prevSeq := Value(startAck)
	for i, msg := range msgs {
		if t.Failed() {
			t.Errorf("%s failed on message %d", t.Name(), i)
			return
		}
		if len(aux) < len(msg) {
			panic("need aux to contain message")
		}
		n, err := rtx.Write(msg)
		if err != nil {
			t.Fatalf("writing packet %d: %s", i, err)
		} else if n != len(msg) {
			t.Fatalf("want %d written, got %d", len(msg), n)
		}
		testQueueSanity(t, rtx)
		unsent := rtx.Buffered()
		if len(msg) != unsent {
			t.Fatalf("want %d unsent buffered, got %d", len(msg), unsent)
		}
		testQueueSanity(t, rtx)
		sent := rtx.BufferedSent()
		if sent != 0 {
			t.Fatalf("want 0 bytes sent, got %d", sent)
		}
		testQueueSanity(t, rtx)
		n, seq, err := rtx.MakePacket(aux[:])
		data := aux[:n]
		if err != nil {
			t.Fatalf("making packet %d: %s", i, err)
		} else if n != len(msg) {
			t.Fatalf("want %d packet read, got %d", len(msg), n)
		} else if !bytes.Equal(msg, aux[:n]) {
			t.Fatalf("want data %q, got data read %q", msg, data[:n])
		} else if seq != prevSeq {
			t.Fatalf("want seq %d, got %d", prevSeq, seq)
		}
		testQueueSanity(t, rtx)
		sent = rtx.BufferedSent()
		if sent != len(msg) {
			t.Fatalf("want %d sent, got %d", len(msg), sent)
		}
		testQueueSanity(t, rtx)
		prevSeq += Value(n)
		err = rtx.RecvACK(prevSeq)
		if err != nil {
			t.Fatal(err)
		}
		sent = rtx.BufferedSent()
		unsent = rtx.Buffered()
		if sent != 0 {
			t.Errorf("message not marked as sent- expected no data left got %d", sent)
		}
		if unsent != 0 {
			t.Errorf("huge bug, unexpected data loaded to unsent buffer")
		}
		testQueueSanity(t, rtx)
	}
}

func testQueueSanity(t *testing.T, rtx *ringTx) {
	// t.Helper()
	alreadyFailed := t.Failed()
	if !alreadyFailed {
		defer func() {
			if t.Failed() {
				t.Helper()
				t.Log("sanity failed with:\n" + rtx.string())
			}
		}()
	}

	if rtx.emptyRing != (ringidx{}) {
		t.Fatalf("empty ring not empty")
	}

	free := rtx.Free()
	sent := rtx.BufferedSent()
	unsent := rtx.Buffered()
	sz := rtx.Size()
	gotSz := free + sent + unsent
	if gotSz != sz {
		t.Fatal("\n" + rtx.string())
		t.Fatalf("want size=%d, got size=%d (free+sent+unsent=%d+%d+%d)", sz, gotSz, free, sent, unsent)
	}
	rsent, _ := rtx.sentRing()
	sentEmpty := rsent.Buffered() == 0
	runsent, _ := rtx.unsentRing()
	unsentEmpty := runsent.Buffered() == 0
	all := rtx.sentAndUnsentBuffer()
	allEmpty := all.Buffered() == 0
	if !sentEmpty {
		if all.Off != rsent.Off {
			t.Fatalf("want entire buffer start %d to equal sent start %d", all.Off, rsent.Off)
		} else if rsent.End == 0 {
			t.Fatalf("expected not empty sent buffer End to be !=0, got %d", rsent.End)
		}
		gotSentEnd := rtx.addEnd(rsent.Off, sent)
		if gotSentEnd != rsent.End {
			t.Fatalf("calculated sent end mismatches lim sent end %d != %d", gotSentEnd, rsent.End)
		}
	}
	if !unsentEmpty {
		if all.End != runsent.End {
			t.Fatalf("want entire buffer end %d to equal unsent end %d", all.End, runsent.End)
		} else if runsent.End == 0 {
			t.Fatalf("expected not empty unsent buffer End to be !=0, got %d", runsent.End)
		}
		gotUnsentEnd := rtx.addEnd(runsent.Off, unsent)
		if gotUnsentEnd != runsent.End {
			t.Fatalf("calculated unsent end mismatches lim unsent end %d != %d", gotUnsentEnd, runsent.End)
		}
	}
	if allEmpty && (!sentEmpty || !unsentEmpty) {
		t.Fatalf("all buffer empty but sent|unsent(%v/%v) not empty", sentEmpty, unsentEmpty)
	} else if !allEmpty && sentEmpty && unsentEmpty {
		t.Fatal("all buffer not empty but sent&unsentempty")
	}
}

func (rx *ringTx) string() string {
	sz := rx.Size()
	unsent, _ := rx.unsentRing()
	sent, _ := rx.sentRing()
	all := rx.sentAndUnsentBuffer()
	if all.End == 0 || // Empty buffer, set offset so that free zone occupies whole buffer.
		all.Off == 0 { // Buffer offset starts at zero which would set Free.End to 0 making it empty, patch that.
		all.Off = sz
	}
	type zone struct {
		name       string
		start, end int
	}
	zcontains := func(off int, z *zone) bool {
		if z.end == 0 {
			return false // Empty
		} else if z.end < z.start {
			return off < z.end || off >= z.start
		}
		return off >= z.start && off < z.end
	}
	var zones = []zone{
		{name: "free", start: all.End, end: all.Off},
		{name: "usnt", start: unsent.Off, end: unsent.End},
		{name: "sent", start: sent.Off, end: sent.End},
	}
	var wrapZone *zone
	for i := range zones {
		wraps := zones[i].end != 0 && zones[i].end < zones[i].start
		if wraps {
			if wrapZone != nil {
				panic("illegal to have more than one wrap zone")
			}
			wrapZone = &zones[i]
		}
	}
	var currentZone *zone
	var lastPrintedZone *zone
	var l1, l2 bytes.Buffer
	changes := 0
	for ib := 0; ib < sz; ib++ {
		currentContainsIdx := currentZone != nil && zcontains(ib, currentZone)
		for iz := 0; !currentContainsIdx && iz < len(zones); iz++ {
			z := &zones[iz]
			if zcontains(ib, z) {
				currentZone = z
			}
		}
		if currentZone == lastPrintedZone {
			continue
		}
		changes++
		if changes > 4 {
			panic("found too many zone changes")
		}
		lastPrintedZone = currentZone
		// Change of zone.
		top := "|-----" + currentZone.name + "-----"
		l2.WriteString(top)
		n, _ := fmt.Fprintf(&l1, "%d", currentZone.start)
		for i := 0; i < len(top)-n; i++ {
			l1.WriteByte(' ')
		}
	}
	l2.WriteByte('|')
	fmt.Fprintf(&l1, "%d\n", currentZone.end)
	l2.WriteTo(&l1)
	return l1.String()
}

func removeEmptyMsgs(msgs [][]byte) [][]byte {
	return slices.DeleteFunc(msgs, func(b []byte) bool { return len(b) == 0 })
}

func operateOnRing(t *testing.T, rtx *ringTx, write, readPacket, aux []byte, argRecvAck *Value) {
	if len(aux) < rtx.Size() {
		panic("too small auxiliary buffer")
	}
	free := rtx.Free()
	// Prepare aux with data expected from read after write.
	runsent, _ := rtx.unsentRing()
	unsent := runsent.Buffered()

	wantWritten := min(free, len(write))
	wantBufRead := aux[:min(unsent+wantWritten, len(readPacket))]

	if len(wantBufRead) > 0 {
		testQueueSanity(t, rtx)
		var n int
		if runsent.Buffered() > 0 {
			ngot, err := runsent.Read(wantBufRead)
			wantRead := len(wantBufRead)
			if err != nil {
				panic(err)
			} else if ngot < wantRead {
				panic("expected read of at least length calculated above")
			}
			n = ngot
		}
		copy(wantBufRead[n:], write)
	}

	prevSeq := rtx.currentSeq()
	if len(write) != 0 {
		testQueueSanity(t, rtx)
		preBuffered := rtx.Buffered()
		n, err := rtx.Write(write)
		if err != nil && wantWritten > 0 {
			t.Errorf("error writing packet: %s", err)
		} else if n != wantWritten {
			t.Errorf("want %d written, got %d", wantWritten, n)
		}
		newBuffered := rtx.Buffered()
		gotWritten := newBuffered - preBuffered
		if gotWritten != wantWritten {
			t.Errorf("expected %d data written, got %d", wantWritten, gotWritten)
		}
	}

	if !t.Failed() && len(readPacket) != 0 {
		testQueueSanity(t, rtx)
		preSent := rtx.BufferedSent()
		canRead := rtx.Buffered()
		wantRead := min(canRead, len(readPacket))
		if wantRead != len(wantBufRead) {
			t.Fatalf("miscalculated expect read %d != %d", wantRead, len(wantBufRead))
		}
		n, seq, err := rtx.MakePacket(readPacket)
		if err != nil && wantRead != 0 {
			t.Errorf("error reading: %s", err)
		} else if n != wantRead {
			t.Errorf("want read %d, got %d", wantRead, n)
		}
		wantSeq := prevSeq
		if seq != wantSeq {
			t.Errorf("want new seq %d, got %d", wantSeq, seq)
		}
		if !bytes.Equal(readPacket[:n], wantBufRead) {
			t.Error("data content packet read not match wanted packet")
		}
		gotCalcRead := rtx.BufferedSent() - preSent
		if gotCalcRead != n {
			t.Errorf("want data written to be %d calculated from BufferedSent diff, got %d", n, gotCalcRead)
		}
	}

	if !t.Failed() && argRecvAck != nil {
		testQueueSanity(t, rtx)
		preAcked := rtx.BufferedSent()
		rcvAck := *argRecvAck
		seq := rtx.currentSeq()
		startSeq := Add(seq, Size(-rtx.BufferedSent()))
		acklInSentRange := startSeq.LessThan(rcvAck) && rcvAck.LessThanEq(seq)
		err := rtx.RecvACK(rcvAck)
		if err != nil && acklInSentRange {
			t.Errorf("expected correct acking %d < %d <= %d: %s", startSeq, rcvAck, seq, err)
		}
		gotCalcAcked := preAcked - rtx.BufferedSent()
		wantAcked := int(Sizeof(prevSeq, rtx.currentSeq()))
		if gotCalcAcked != wantAcked {
			t.Errorf("want acked %d, got %d", wantAcked, gotCalcAcked)
		}
	}
	testQueueSanity(t, rtx)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
