package tcp

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestTxQueue(t *testing.T) {
	var msgBuf, buf, aux [1024]byte
	rng := rand.New(rand.NewSource(1))

	var rtx ringTx
	increasingComplexityTests := []struct {
		name string
		test func(*testing.T)
	}{
		0: {
			name: "SequentialMessages",
			test: func(t *testing.T) {
				for i := 0; i < 10; i++ {
					rng.Read(msgBuf[:])
					msgs := bytes.SplitAfter(msgBuf[:], []byte{0})
					testTxQueue_SequentialMessages(t, &rtx, msgs, buf[:], aux[:], rng.Intn(4)+1, 0)
				}
			},
		},
		1: {
			name: "N-Messages",
			test: func(t *testing.T) {
				for i := 0; i < 10; i++ {
					rng.Read(msgBuf[:])
					msgs := bytes.SplitAfter(msgBuf[:], []byte{0})
					testTxQueue_NMessages(t, &rtx, msgs, buf[:], aux[:], len(msgs), 0)
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
			t.Fatalf("want unset %d, got %d", n, unsent)
		}
		testQueueSanity(t, rtx)
		n, seq, err := rtx.MakePacket(aux[sent : sent+len(msg)])
		if err != nil {
			t.Fatal(err)
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
		testQueueSanity(t, rtx)
	}
}

func testQueueSanity(t *testing.T, rtx *ringTx) {
	t.Helper()
	if rtx.emptyRing != (ringidx{}) {
		t.Fatalf("empty ring not empty")
	}
	free := rtx.Free()
	sent := rtx.BufferedSent()
	unsent := rtx.Buffered()
	sz := rtx.Size()
	gotSz := free + sent + unsent
	if gotSz != sz {
		t.Fatal("\n", rtx.string())
		t.Fatalf("want size=%d, got size=%d (free+sent+unsent=%d+%d+%d)", sz, gotSz, free, sent, unsent)
	}
	freeStart, freeEnd, sentEnd := rtx.lims()
	gotFreeEnd := rtx.addOff(freeStart, free)
	gotSentEnd := rtx.addOff(freeEnd, sent)
	gotUnsentEnd := rtx.addOff(sentEnd, unsent)
	if free != 0 && gotFreeEnd != freeEnd {
		t.Fatalf("want freeEnd=%d, got %d", freeEnd, gotFreeEnd)
	} else if sent != 0 && gotSentEnd != sentEnd {
		t.Fatalf("want sentEnd=%d, got %d", sentEnd, gotSentEnd)
	} else if unsent != 0 && gotUnsentEnd != freeStart {
		t.Fatalf("want unsentEnd=%d, got %d (freeStart)", freeStart, gotUnsentEnd)
	}
}

func (rx *ringTx) string() string {
	return ""
	type zone struct {
		name                 string
		start, end           int
		printStart, printEnd bool
	}

	fs, fe, us := rx.lims()
	var zones = []zone{
		{name: "free", start: fs, end: fe},
		{name: "usnt", start: us, end: fs},
		{name: "sent", start: fe, end: us},
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

	var b1, b2 bytes.Buffer
	b1.WriteByte('|')
	b2.WriteByte(' ')
	b2.WriteByte(' ')
	for i := 0; i < len(rx.rawbuf); {
		var printedThisline int
		var zoneName string
		for k := range zones {
			z := &zones[k]
			if z.end == 0 {
				continue // No data in zone.
			}
			if !z.printStart && i >= z.start {
				zoneName = z.name
				if printedThisline > 0 {
					b2.WriteByte('/')
					printedThisline++
				}
				b2.WriteString(zoneName + "_s")
				printedThisline += len(zoneName) + 2
				z.printStart = true
			}

		}
		if printedThisline > 0 {
			b1.WriteByte('|')
			b2.WriteByte(' ')
			b2.WriteByte(' ')
			for j := 0; j < printedThisline+1; j++ {
				b1.WriteByte('-')
			}
		}
		b2.WriteByte(' ')
		b1.WriteByte('-')
	}
	b1.WriteString("|\n")
	b1.Write(b2.Bytes())
	return b1.String()
}
