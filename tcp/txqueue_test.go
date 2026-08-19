package tcp

import (
	"bytes"
	"math/rand"
	"slices"
	"testing"
	"unsafe"

	"github.com/soypat/lneto/internal"
)

func TestRingTx_op(t *testing.T) {
	const maxBuf = 32
	const maxpkt = 3
	const Nops = 6
	const log = false
	type op uint8
	const (
		opWrite op = iota
		opSend
		opAck
		opmax
	)
	var buf, auxbuf [maxBuf]byte
	dataWritten := make([]byte, 0, maxBuf*10)
	dataSent := make([]byte, 0, maxBuf*10)
	var rtx ringTx
	rng := rand.New(rand.NewSource(0))
	for iseed := range int64(1000) {
		rng.Seed(iseed + rng.Int63())
		for itest := range 32 {
			bufsize := rng.Intn(maxBuf/2) + maxBuf/2
			iss := Value(0)
			npackets := rng.Intn(maxpkt-1) + 1
			err := rtx.Reset(buf[:bufsize], npackets, iss)
			if err != nil {
				t.Fatal(err)
			}
			// Prepare state for keeping track of test.
			currentAcked := iss
			currentSeq := iss
			nsent := 0
			nunsent := 0
			nacked := 0
			dataWritten = dataWritten[:0]
			dataSent = dataSent[:0]
			for iop := range Nops {
				free := bufsize - nsent - nunsent
				availPkt := rtx.slist.Free()
				op := op(rng.Intn(int(opmax)))
				var oplen int
				var opname string
				var opWriteData []byte
				switch op {
				case opWrite:
					opname, oplen = "write", rng.Intn(free+1)+1
					opWriteData = auxbuf[:oplen]
					rng.Read(opWriteData)
				case opSend:
					opname, oplen = "send", rng.Intn(nunsent+1)+1
				case opAck:
					opname, oplen = "ack", rng.Intn(nsent+1)+1
				}
				if log {
					t.Logf("\n%s\nseed=%d itest=%d iop=%d op=%s len=%d npkt=%d", rtx.mustAppendString(nil), iseed, itest, iop, opname, oplen, len(rtx.slist.pkts))
				}
				switch op {
				case opWrite:
					// oplen=number of bytes to write into unsent buffer.
					nwgot, err := rtx.Write(opWriteData)
					wantErr := oplen > free
					if err != nil && oplen <= free {
						t.Fatal(itest, iop, err)
					} else if err == nil {
						if wantErr {
							panic("wanted write error")
						}
						nunsent += nwgot
						dataWritten = append(dataWritten, opWriteData[:nwgot]...)
					} else if log {
						t.Logf("opwrite: %s", err)
					}
					clear(opWriteData)
				case opSend:
					// oplen=num bytes to send in this operation.
					nsgot, err := rtx.MakePacket(auxbuf[:oplen], currentSeq)
					megafail := nsgot > nunsent
					if err != nil && oplen <= nunsent && availPkt > 0 {
						t.Fatal(itest, iop, err)
					} else if err == nil {
						if megafail {
							panic("megafail")
						}
						nunsent -= nsgot
						nsent += nsgot
						dataSent = append(dataSent, auxbuf[:nsgot]...)
						currentSeq += Value(nsgot)
					} else if log {
						t.Logf("opsend: %s", err)
					}
					clear(auxbuf[:oplen])
				case opAck:
					// oplen=acklength.
					tryAck := currentAcked + Value(oplen)
					err = rtx.RecvACK(tryAck)
					if err != nil && oplen <= nsent {
						t.Fatal(itest, iop, err)
					} else if err == nil {
						nsent -= oplen
						nacked += oplen
						currentAcked = tryAck
					} else if log {
						t.Logf("opack: %s", err)
					}
				default:
					panic("unknown op")
				}
				wantFree := bufsize - nsent - nunsent
				gotFree := rtx.Free()
				if wantFree != gotFree {
					t.Fatalf("free mismatch got=%d want=%d  size=%d sent=%d nunsent=%d", gotFree, wantFree, bufsize, nsent, nunsent)
				}
				minlen := min(len(dataSent), len(dataWritten))
				matched := bytes.Equal(dataSent[:minlen], dataWritten[:minlen])
				if !matched {
					t.Fatal("mismatched data written\n", dataSent, "\n", dataWritten)
				}
				testQueueSanity(t, &rtx)
			}
		}
	}
}

func TestSentlist_multi(t *testing.T) {
	const bufsize = 10
	var sl sentlist
	sl.Reset(3, 0)

	// Test multi packet x2.
	p1 := sl.AddPacket(5, 0, bufsize, 0)
	p2 := sl.AddPacket(5, p1.end, bufsize, p1.endSeq())
	sl.RecvAck(Value(p2.size+p1.size), bufsize)
	if sl.Oldest() != nil {
		t.Fatal("expected full ack")
	}
	// multi packet x3.
	sl.Reset(3, 0)
	p1 = sl.AddPacket(3, 0, bufsize, 0)
	p2 = sl.AddPacket(3, p1.end, bufsize, p1.endSeq())
	p3 := sl.AddPacket(4, p2.end, bufsize, p2.endSeq())
	sl.RecvAck(2, bufsize)
	oldest := sl.Oldest()
	if oldest != p1 {
		t.Error("oldest should be partial acked")
	} else if oldest.size != 1 {
		t.Error("bad size")
	} else if oldest.off != 2 {
		t.Error("bad offset")
	}
	_ = p3
}

func TestSentlist_simple(t *testing.T) {
	var sl sentlist
	sl.Reset(3, 0)
	// Test full ack.
	const bufsize = 16
	const pkt = 10
	sl.AddPacket(pkt, 0, bufsize, 0)
	if sl.Oldest() == nil || sl.Newest() != sl.Oldest() {
		t.Error("expected same oldest/newest non-nil packet")
	}
	ack := Value(pkt)
	sl.RecvAck(ack, bufsize)
	oldest := sl.Oldest()
	if oldest != nil {
		t.Fatal("expected packet to be fully read")
	}

	// Test partial ack.
	sl.AddPacket(pkt, 0, bufsize, sl.ssn)
	for range Value(pkt - 1) {
		ack++
		sl.RecvAck(ack, bufsize)
		oldest = sl.Oldest()
		if oldest == nil {
			t.Fatal("partially acked packet removed")
		} else if oldest.seq != ack {
			t.Errorf("want pkt.seq=%d got %d", ack, oldest.seq)
		}
	}
	ack++
	sl.RecvAck(ack, bufsize)
	oldest = sl.Oldest()
	if oldest != nil {
		t.Fatal("expected packet to be fully read")
	}
}

func TestRingTx_retransmitBoundary(t *testing.T) {
	const bufsize = 16
	const maxpkts = 4
	const iss = Value(1000)
	const npkt, pktlen = 3, 4
	const datalen = npkt * pktlen
	for _, test := range []struct {
		name string
		// rotate is a number of octets pushed through and acked before the test
		// data is queued, to move the ring offsets and force a wraparound.
		rotate int
		// start is the retransmission point relative to the first test octet.
		start int
		// want is the expected resume point relative to the first test octet,
		// only meaningful when ok is true.
		want int
		ok   bool
	}{
		{name: "at UNA", start: 0, want: 0, ok: true},
		{name: "second packet", start: pktlen, want: pktlen, ok: true},
		{name: "last packet", start: 2 * pktlen, want: 2 * pktlen, ok: true},
		{name: "mid packet clamps down", start: pktlen + 2, want: pktlen, ok: true},
		{name: "last octet clamps down", start: datalen - 1, want: 2 * pktlen, ok: true},
		{name: "before UNA", start: -1},
		{name: "at NXT", start: datalen},
		{name: "past NXT", start: datalen + 1},
		{name: "wrapped at UNA", rotate: bufsize - 6, start: 0, want: 0, ok: true},
		{name: "wrapped mid packet", rotate: bufsize - 6, start: pktlen + 2, want: pktlen, ok: true},
		{name: "wrapped last packet", rotate: bufsize - 6, start: 2 * pktlen, want: 2 * pktlen, ok: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var rtx ringTx
			var scratch [bufsize]byte
			err := rtx.Reset(make([]byte, bufsize), maxpkts, iss)
			if err != nil {
				t.Fatal(err)
			}
			// Rotate the ring so the test data does not start at offset zero.
			base := iss
			for range test.rotate {
				if _, err = rtx.Write([]byte{0}); err != nil {
					t.Fatal(err)
				}
				if _, err = rtx.MakePacket(scratch[:1], base); err != nil {
					t.Fatal(err)
				}
				base = Add(base, 1)
				if err = rtx.RecvACK(base); err != nil {
					t.Fatal(err)
				}
			}
			data := make([]byte, datalen)
			for i := range data {
				data[i] = byte(i + 1)
			}
			if _, err = rtx.Write(data); err != nil {
				t.Fatal(err)
			}
			for i := range npkt {
				seq := Add(base, Size(i*pktlen))
				if _, err = rtx.MakePacket(scratch[:pktlen], seq); err != nil {
					t.Fatal(err)
				}
			}
			testQueueSanity(t, &rtx)
			if rtx.BufferedSent() != datalen {
				t.Fatalf("want %d sent, got %d", datalen, rtx.BufferedSent())
			}

			at, ok := rtx.retransmitBoundary(base + Value(test.start))
			if ok != test.ok {
				t.Fatalf("want ok=%v, got %v", test.ok, ok)
			}
			testQueueSanity(t, &rtx)
			// The query never modifies the queue, whatever it reports: the data
			// stays sent, which is what lets the range after a hole stay sent.
			if rtx.BufferedSent() != datalen || rtx.BufferedUnsent() != 0 {
				t.Fatalf("queue modified by a query: sent=%d unsent=%d",
					rtx.BufferedSent(), rtx.BufferedUnsent())
			}
			if !ok {
				return
			}
			if want := base + Value(test.want); at != want {
				t.Fatalf("want resume at %d, got %d", want, at)
			}
			// The boundary reported must be one MakePacket can resend by exact
			// sequence, which is the invariant the clamping exists to maintain.
			n, err := rtx.MakePacket(scratch[:], at)
			if err != nil {
				t.Fatalf("resend at the reported boundary %d: %s", at, err)
			}
			testQueueSanity(t, &rtx)
			if want := data[test.want : test.want+pktlen]; !bytes.Equal(scratch[:n], want) {
				t.Fatalf("want resent data %v, got %v", want, scratch[:n])
			}
		})
	}
}

// TestRingTx_RetransmitByExactSeqIsNonDestructive pins the property selective
// retransmission depends on: an already-sent segment can be resent by its exact
// sequence number without disturbing the sent/unsent split, so ranges the peer has
// acknowledged selectively can be skipped rather than resent.
//
// This is what makes SACK cheap here. The alternative, rewinding the queue with
// [ringTx.RetransmitFrom], turns everything from the rewind point back into unsent
// data and so can only ever express go-back-N.
func TestRingTx_RetransmitByExactSeqIsNonDestructive(t *testing.T) {
	const bufsize, maxpkts = 32, 4
	const iss = Value(500)
	const npkt, pktlen = 3, 4
	var rtx ringTx
	if err := rtx.Reset(make([]byte, bufsize), maxpkts, iss); err != nil {
		t.Fatal(err)
	}
	if _, err := rtx.Write([]byte("AAAABBBBCCCC")); err != nil {
		t.Fatal(err)
	}
	var scratch [bufsize]byte
	for i := range npkt {
		if _, err := rtx.MakePacket(scratch[:pktlen], Add(iss, Size(i*pktlen))); err != nil {
			t.Fatal(err)
		}
	}
	testQueueSanity(t, &rtx)
	wantUO, wantUE, wantSO, wantSE := rtx.lims()

	// Resend only the middle segment, as a receiver reporting a single hole would
	// have the sender do.
	n, err := rtx.MakePacket(scratch[:], Add(iss, pktlen))
	if err != nil {
		t.Fatal("retransmit middle segment:", err)
	}
	if got := string(scratch[:n]); got != "BBBB" {
		t.Fatalf("retransmitted %q, want BBBB", got)
	}
	testQueueSanity(t, &rtx)
	if uo, ue, so, se := rtx.lims(); uo != wantUO || ue != wantUE || so != wantSO || se != wantSE {
		t.Fatalf("queue moved: unsent=[%d,%d) sent=[%d,%d), want unsent=[%d,%d) sent=[%d,%d)",
			uo, ue, so, se, wantUO, wantUE, wantSO, wantSE)
	}
	if rtx.BufferedSent() != npkt*pktlen || rtx.BufferedUnsent() != 0 {
		t.Errorf("accounting changed: sent=%d unsent=%d, want %d and 0",
			rtx.BufferedSent(), rtx.BufferedUnsent(), npkt*pktlen)
	}

	// A later segment must still be resendable, and new data must still flow, so
	// the retransmission left no dent in the queue.
	if n, err = rtx.MakePacket(scratch[:], Add(iss, 2*pktlen)); err != nil {
		t.Fatal("retransmit last segment:", err)
	} else if got := string(scratch[:n]); got != "CCCC" {
		t.Errorf("retransmitted %q, want CCCC", got)
	}
	if _, err = rtx.Write([]byte("DDDD")); err != nil {
		t.Fatal("write after retransmit:", err)
	}
	if n, err = rtx.MakePacket(scratch[:], Add(iss, 3*pktlen)); err != nil {
		t.Fatal("send new data after retransmit:", err)
	} else if got := string(scratch[:n]); got != "DDDD" {
		t.Errorf("sent %q after retransmit, want DDDD", got)
	}
	testQueueSanity(t, &rtx)
}

func TestTxQueue_multipacket(t *testing.T) {
	const mtu = 32
	const iss = 1
	const maxPkts = 3
	const maxWrites = 6
	const maxWriteSize = mtu / maxWrites
	var rtx ringTx
	internalbuff := make([]byte, mtu)
	rng := rand.New(rand.NewSource(3))
	var wbuf, rbuf [mtu]byte
	for itest := range 32 {
		rng.Seed(int64(itest))
		err := rtx.Reset(internalbuff, maxPkts, iss)
		if err != nil {
			t.Fatal(err)
		}
		numWrites := rng.Intn(maxWrites) + 1
		total := 0
		woff := 0
		for range numWrites {
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
		for range npkt {
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
				for range 10 {
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
						buffered := rtx.BufferedUnsent()
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
				for range 10 {
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
						buffered := rtx.BufferedUnsent()
						if buffered != expectBuffered {
							t.Fatalf("expected seq to not change during writes")
						}
						currentAck = Add(currentAck, Size(len(msg)))
					}
					sent := rtx.BufferedSent()
					unsent := rtx.BufferedUnsent()
					wantUnsent := int(Add(currentAck, -startAck))
					if unsent != wantUnsent {
						t.Fatalf("want %d data buffered, got %d", wantUnsent, unsent)
					} else if sent != 0 {
						t.Fatalf("want no data sent, got %d", sent)
					}
					operateOnRing(t, &rtx, nil, readBuf[:], aux[:], 0, &currentAck)
					unsent = rtx.BufferedUnsent()
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
				for range 10 {
					rng.Read(msgBuf[:])
					err := rtx.Reset(ringBuf[:], packets, startAck)
					if err != nil {
						t.Fatal(err)
					}
					operateOnRing(t, &rtx, msgBuf[:], nil, aux[:], 0, nil)
					// Send all bytes over wire.
					currentSeq := Value(startAck)
					datalens = datalens[:0]
					for rtx.BufferedUnsent() != 0 {
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
			a := recover()
			if a != nil {
				t.Log("panic", a)
			}
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
	unsent := rtx.BufferedUnsent()
	sz := rtx.Size()
	gotSz := free + sent + unsent
	if gotSz != sz {
		t.Error("\n" + rtx.string())
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
	last := rtx.slist.Newest()
	first := rtx.slist.Oldest()
	if first == nil && last != nil || last == nil && first != nil {
		t.Fatalf("found first/last(%d,%d) but did not find last/first", first, last)
	}
	// Check sent data or return if no sent data available.
	if sent == 0 {
		return
	}

	endseq, ok := rtx.sentEndSeq()

	lastEndSeq := Add(last.seq, last.size)
	if last.seq.LessThan(first.seq) {
		t.Fatalf("first packet not previous to last packet seq, wanted %d<%d", first.seq, last.seq)
	} else if !ok {
		t.Fatal("unexpected end sequence not found")
	} else if lastEndSeq != endseq {
		t.Fatalf("last packet end sequence not match with got endSeq %d!=%d", lastEndSeq, endseq)
	}
}

func (rx *ringTx) string() string {
	s := rx.appendString(nil)
	return unsafe.String(&s[0], len(s))
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
	oldest := rtx.slist.Oldest()
	var startSeq Value
	startSeqOk := oldest != nil
	if startSeqOk {
		startSeq = oldest.seq
	}
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
		preBuffered := rtx.BufferedUnsent()
		n, err := rtx.Write(write)
		if err != nil && wantWritten > 0 {
			t.Errorf("error writing packet: %s", err)
		} else if n != wantWritten {
			t.Errorf("want %d written, got %d", wantWritten, n)
		}
		newBuffered := rtx.BufferedUnsent()
		gotWritten := newBuffered - preBuffered
		if gotWritten != wantWritten {
			t.Errorf("expected %d data written, got %d", wantWritten, gotWritten)
		}
	}

	if !t.Failed() && len(readPacket) != 0 {
		testQueueSanity(t, rtx)
		preSent := rtx.BufferedSent()
		canRead := rtx.BufferedUnsent()
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
		last := rtx.slist.Newest()
		var lastSeq Value
		lastSeqOK := last != nil
		if lastSeqOK {
			lastSeq = last.seq
		}
		endSeq, endSeqOK := rtx.sentEndSeq()
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
	oldest2 := rtx.slist.Oldest()
	var startSeq2 Value
	sseqOk := oldest != nil
	if sseqOk {
		startSeq2 = oldest2.seq
	}

	if sseqOk == startSeqOk && startSeq2 != startSeq {
		t.Fatalf("expected FIRST seq to not change during writes")
	}

	if !t.Failed() && argRecvAck != nil {
		testQueueSanity(t, rtx)
		// preAcked := rtx.BufferedSent()
		rcvAck := *argRecvAck
		oldest := rtx.slist.Oldest()
		var seq Value
		ok := oldest != nil
		if ok {
			seq = oldest.seq
		}
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
		var gotFirstSeq Value
		oldest = rtx.slist.Oldest()
		ok = oldest != nil
		if ok {
			gotFirstSeq = oldest.seq
		}
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

// prints out buffer zones with indices:
//
// 0              32             42            47
// |---free(32)---|---usnt(10)---|---free(5)---|
func (rtx *ringTx) appendString(b []byte) []byte {
	var zprinter internal.ZonePrinter
	result, err := zprinter.AppendPrintZones(b, rtx.Size(), rtx.zones()...)
	if err != nil {
		result = append(result, err.Error()...)
	}
	return result
}

func (rtx *ringTx) mustAppendString(b []byte) []byte {
	var zprinter internal.ZonePrinter
	result, err := zprinter.AppendPrintZones(b, rtx.Size(), rtx.zones()...)
	if err != nil {
		panic(err)
	}
	return result
}

func (rtx *ringTx) zones() []internal.BufferZone {
	return []internal.BufferZone{
		{
			Name:  "sent",
			Start: rtx.sentoff, End: rtx.sentend,
		},
		{
			Name:  "usnt",
			Start: rtx.unsentoff, End: rtx.unsentend,
		},
	}
}

// TestMakePacketRetransmitWithFullQueue verifies a packet the queue already tracks
// can be resent when the queue is full.
//
// The free-entry check ran before the retransmission path, so a full queue refused
// to resend anything. Resending a tracked packet needs no new entry — it is the same
// packet — and a full queue is exactly the state a stalled connection is in: nothing
// is being acknowledged, which is why entries are not being freed, which is why a
// retransmission is due. Refusing there means the one action that could recover the
// connection is the one action unavailable.
func TestMakePacketRetransmitWithFullQueue(t *testing.T) {
	const (
		bufsize = 64
		maxpkts = 3
		pktlen  = 4
		iss     = Value(1000)
	)
	var rtx ringTx
	if err := rtx.Reset(make([]byte, bufsize), maxpkts, iss); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, maxpkts*pktlen)
	for i := range data {
		data[i] = byte(i + 1)
	}
	if _, err := rtx.Write(data); err != nil {
		t.Fatal(err)
	}
	var scratch [bufsize]byte
	for i := range maxpkts {
		if _, err := rtx.MakePacket(scratch[:pktlen], Add(iss, Size(i*pktlen))); err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
	if rtx.slist.Free() != 0 {
		t.Fatalf("queue has %d free entries, want a full queue for this test", rtx.slist.Free())
	}

	// Every packet in the full queue must still be resendable, with its data intact.
	for i := range maxpkts {
		seq := Add(iss, Size(i*pktlen))
		clear(scratch[:])
		n, err := rtx.MakePacket(scratch[:pktlen], seq)
		if err != nil {
			t.Fatalf("retransmit of packet %d at seq %d: %v", i, seq, err)
		}
		if n != pktlen {
			t.Errorf("retransmit of packet %d read %d octets, want %d", i, n, pktlen)
		}
		want := data[i*pktlen : (i+1)*pktlen]
		if string(scratch[:n]) != string(want) {
			t.Errorf("retransmit of packet %d = %v, want %v", i, scratch[:n], want)
		}
	}
	testQueueSanity(t, &rtx)
	// The queue is unchanged: resending is not a new packet.
	if rtx.slist.Free() != 0 {
		t.Errorf("queue has %d free entries after retransmitting, want 0", rtx.slist.Free())
	}
	if rtx.BufferedSent() != len(data) {
		t.Errorf("sent octets = %d after retransmitting, want %d", rtx.BufferedSent(), len(data))
	}
	if rtx.BufferedUnsent() != 0 {
		t.Errorf("unsent octets = %d after retransmitting, want 0", rtx.BufferedUnsent())
	}
	// New data still needs an entry, so a full queue still refuses it.
	if _, err := rtx.Write([]byte{99}); err != nil {
		t.Fatal(err)
	}
	if _, err := rtx.MakePacket(scratch[:1], Add(iss, Size(len(data)))); err == nil {
		t.Error("new data on a full queue was accepted, want a refusal")
	}
}
