package tcp

import (
	"bytes"
	"fmt"
	"math/rand"
	"slices"
	"testing"
)

func TestTxQueue_multipacket(t *testing.T) {
	const mtu = 256
	const iss = 1
	const maxPkts = 3
	const maxWrites = 20
	const maxWriteSize = mtu / maxWrites
	var rtx ringTx
	internalbuff := make([]byte, mtu)
	rng := rand.New(rand.NewSource(3))
	var wbuf, rbuf [mtu]byte
	for itest := 0; itest < 32; itest++ {
		// rng.Seed(int64(itest))
		println(itest)
		err := rtx.Reset(internalbuff, maxPkts, iss)
		if err != nil {
			t.Fatal(err)
		}
		numWrites := rng.Intn(maxWrites) + 1
		total := 0
		woff := 0
		for iw := 0; iw < numWrites; iw++ {
			wlen := rng.Intn(maxWriteSize) + 1
			towrite := wbuf[woff : woff+wlen]
			rng.Read(towrite)
			n, err := rtx.Write(towrite)
			testQueueSanity(t, &rtx)
			woff += n
			if err != nil {
				t.Fatal(err)
			} else if n != wlen {
				t.Fatal("expected wlen==n", wlen, n)
			}
			total += wlen
		}
		npkt := rng.Intn(maxPkts) + 1
		roff := 0
		seq := Value(iss)
		for ipkt := 0; ipkt < npkt; ipkt++ {
			maxToPacket := min(total-roff, maxWriteSize)
			pktlen := rng.Intn(maxToPacket) + 1
			pkt := rbuf[roff : roff+pktlen]
			expectPkt := wbuf[roff : roff+pktlen]
			ngot, err := rtx.MakePacket(pkt, seq)
			testQueueSanity(t, &rtx)
			roff += ngot
			seq += Value(ngot)
			if err != nil {
				t.Fatal(err)
			} else if pktlen != ngot && roff != total {
				t.Fatal(err)
			} else if !bytes.Equal(expectPkt, pkt) {
				t.Fatal("mismatched data written", expectPkt, pkt)
			}
			if roff == total {
				break // made packet from all data.
			}
		}
		acked := 0
		for acked < roff {
			maxToack := min(roff-acked, maxWriteSize)
			toack := rng.Intn(maxToack) + 1
			// t.Log("\n", rtx.string())
			err = rtx.RecvACK(iss + Value(acked+toack))
			testQueueSanity(t, &rtx)
			if err != nil {
				t.Fatal(err)
			}
			acked += toack
		}
	}
}

func TestTxQueue(t *testing.T) {
	const bufsize = 1024
	var msgBuf, ringBuf, readBuf, aux [bufsize]byte
	rng := rand.New(rand.NewSource(1))
	panicked := true
	var rtx ringTx
	defer func() {
		if panicked {
			t.Error("panicked, rtx:\n", rtx.string())
		}
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
					err := rtx.Reset(ringBuf[:], rng.Intn(4)+1, startAck)
					if err != nil {
						t.Fatal(err)
					}
					for imsg, msg := range msgs {
						// Write and create packet from single messages.
						seq := currentAck
						currentAck = Add(currentAck, Size(len(msg)))
						operateOnRing(t, &rtx, msg, readBuf[:], aux[:], seq, &currentAck)
						buffered := rtx.Buffered()
						if buffered != 0 {
							t.Fatalf("msg%d: want no buffered data after transaction, got %d", imsg, buffered)
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
					err := rtx.Reset(ringBuf[:], rng.Intn(4)+1, startAck)
					if err != nil {
						t.Fatal(err)
					}
					expectBuffered := 0
					for _, msg := range msgs {
						// Send all messages.
						seq := currentAck
						operateOnRing(t, &rtx, msg, nil, aux[:], seq, nil)
						if t.Failed() {
							return
						}
						expectBuffered += len(msg)
						buffered := rtx.Buffered()
						if buffered != expectBuffered {
							t.Fatalf("expected seq to not change during writes")
						}
						currentAck = Add(currentAck, Size(len(msg)))
					}
					sent := rtx.BufferedSent()
					unsent := rtx.Buffered()
					wantUnsent := int(Add(currentAck, -startAck))
					if unsent != wantUnsent {
						t.Fatalf("want %d data buffered, got %d", wantUnsent, unsent)
					} else if sent != 0 {
						t.Fatalf("want no data sent, got %d", sent)
					}
					operateOnRing(t, &rtx, nil, readBuf[:], aux[:], 0, &currentAck)
					unsent = rtx.Buffered()
					if unsent != 0 {
						t.Fatalf("expected all data to be sent after ack of most recent packet, %d", unsent)
					} else if rtx.BufferedSent() != 0 {
						t.Fatal("unexpected buffer not completely acked")
					}
				}
			},
		},
		2: {
			name: "PartialAcks",
			test: func(t *testing.T) {
				const startAck = 0
				const packets = 100
				const maxPacketSize = bufsize / 4
				var datalens [][]byte
				for i := 0; i < 10; i++ {
					rng.Read(msgBuf[:])
					err := rtx.Reset(ringBuf[:], packets, startAck)
					if err != nil {
						t.Fatal(err)
					}
					operateOnRing(t, &rtx, msgBuf[:], nil, aux[:], 0, nil)
					// Send all bytes over wire.
					currentSeq := Value(startAck)
					datalens = datalens[:0]
					for rtx.Buffered() != 0 {
						nbytes := rng.Intn(maxPacketSize-minBufferSize) + minBufferSize
						n, err := rtx.MakePacket(readBuf[:nbytes], currentSeq)
						if err != nil {
							t.Fatal(err)
						} else if n == 0 {
							t.Fatal("got zero length")
						}
						// Reuse memory in slice of byte buffers.
						if len(datalens) == cap(datalens) {
							datalens = append(datalens, append([]byte{}, readBuf[:n]...))
						} else {
							datalens = datalens[:len(datalens)+1]
							datalens[len(datalens)-1] = append(datalens[len(datalens)-1][:0], readBuf[:n]...)
						}
						currentSeq += Value(n)
					}
					currentAck := Value(startAck)
					for idata, data := range datalens {
						plen := len(data)
						partialLen0 := plen - (rng.Intn(plen)/2 + minBufferSize)
						// partialLen1 := plen - partialLen0
						// sent := rtx.BufferedSent()
						ack1 := currentAck + Value(partialLen0)
						ack2 := currentAck + Value(plen)
						err = rtx.RecvACK(ack1)
						if err != nil {
							t.Fatalf("data%d acking first partial %d..%d(..%d): %s", idata, currentAck, ack1, ack2, err)
						}
						err = rtx.RecvACK(ack2)
						if err != nil {
							t.Fatalf("data%d acking second partial (%d..)%d..%d: %s", idata, currentAck, ack1, ack2, err)
						}
						currentAck = ack2
					}
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
	panicked = false
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

	// Check sanenness of last/first packets.
	last := rtx.lastPkt()
	first := rtx.firstPkt()
	if first < 0 && last >= 0 || last < 0 && first >= 0 {
		t.Fatalf("found first/last(%d,%d) but did not find last/first", first, last)
	}
	// Check sent data or return if no sent data available.
	if sent == 0 {
		return
	}
	lastPkt := rtx.pkt(last)
	endseq, ok := rtx.endSeq()
	firstPkt := rtx.pkt(first)
	lastEndSeq := Add(lastPkt.seq, lastPkt.size)
	if lastPkt.seq.LessThan(firstPkt.seq) {
		t.Fatalf("first packet not previous to last packet seq, wanted %d<%d", firstPkt.seq, lastPkt.seq)
	} else if !ok {
		t.Fatal("unexpected end sequence not found")
	} else if lastEndSeq != endseq {
		t.Fatalf("last packet end sequence not match with got endSeq %d!=%d", lastEndSeq, endseq)
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
	var currentZone *zone = wrapZone
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

func operateOnRing(t *testing.T, rtx *ringTx, write, readPacket, aux []byte, newPacketSeq Value, argRecvAck *Value) {
	if len(aux) < rtx.Size() {
		panic("too small auxiliary buffer")
	}
	free := rtx.Free()
	// Prepare aux with data expected from read after write.
	runsent, _ := rtx.unsentRing()
	unsent := runsent.Buffered()
	startSeq, startSeqOK := rtx.firstSeq()
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
		n, err := rtx.MakePacket(readPacket, newPacketSeq)
		if err != nil && wantRead != 0 {
			t.Errorf("error reading: %s", err)
		} else if n != wantRead {
			t.Errorf("want read %d, got %d", wantRead, n)
		}
		lastSeq, lastSeqOK := rtx.lastSeq()
		endSeq, endSeqOK := rtx.endSeq()
		if !lastSeqOK || lastSeq != newPacketSeq {
			t.Fatalf("expected last seq to be %d, got %d (or lastSeqOK=%v)", newPacketSeq, lastSeq, lastSeqOK)
		} else if !endSeqOK || endSeq != Add(newPacketSeq, Size(n)) {
			t.Fatalf("expected end seq to be %d, got %d (or endSeqOK=%v)", Add(newPacketSeq, Size(n)), endSeq, endSeqOK)
		}
		if !bytes.Equal(readPacket[:n], wantBufRead) {
			t.Error("data content packet read not match wanted packet")
		}
		gotCalcRead := rtx.BufferedSent() - preSent
		if gotCalcRead != n {
			t.Errorf("want data written to be %d calculated from BufferedSent diff, got %d", n, gotCalcRead)
		}
	}

	startSeq2, sseqOK := rtx.firstSeq()
	if sseqOK == startSeqOK && startSeq2 != startSeq {
		t.Fatalf("expected FIRST seq to not change during writes")
	}

	if !t.Failed() && argRecvAck != nil {
		testQueueSanity(t, rtx)
		// preAcked := rtx.BufferedSent()
		rcvAck := *argRecvAck
		seq, ok := rtx.firstSeq()
		if !ok {
			t.Fatal("no first packet found")
		}
		startSeq := Add(seq, Size(-rtx.BufferedSent()))
		acklInSentRange := startSeq.LessThan(rcvAck) && rcvAck.LessThanEq(seq)
		err := rtx.RecvACK(rcvAck)
		if err != nil && acklInSentRange {
			t.Errorf("expected correct acking %d < %d <= %d: %s", startSeq, rcvAck, seq, err)
		}
		bufSent := rtx.BufferedSent()
		gotFirstSeq, ok := rtx.firstSeq()
		if !ok && bufSent != 0 {
			t.Fatalf("no first packet found after acking")
		}
		if ok && gotFirstSeq.LessThanEq(rcvAck) {
			t.Fatalf("expected first seq %d to be greater than ack %d", gotFirstSeq, rcvAck)
		}
		// wantAcked := int(Sizeof(prevSeq, gotFirstSeq))
		// if gotCalcAcked != wantAcked {
		// 	t.Errorf("want acked %d, got %d", wantAcked, gotCalcAcked)
		// }
	}
	testQueueSanity(t, rtx)
}
