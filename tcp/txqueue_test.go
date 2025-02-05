package tcp

import (
	"bytes"
	"fmt"
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
	// t.Helper()
	defer func() {
		if t.Failed() {
			t.Log("\n" + rtx.string())
		}
	}()
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
