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
	t.Run("SequentialMessages", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			rng.Read(msgBuf[:])
			msgs := bytes.SplitAfter(msgBuf[:], []byte{0})
			testTxQueue_SequentialMessages(t, &rtx, msgs, buf[:], aux[:], rng.Intn(4)+1, Value(rng.Int()))
		}
	})
	t.Run("N-Messages", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			rng.Read(msgBuf[:])
			msgs := bytes.SplitAfter(msgBuf[:], []byte{0})

			testTxQueue_NMessages(t, &rtx, msgs, buf[:], aux[:], len(msgs), Value(rng.Int()))
		}
	})
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
		unsent := rtx.Buffered()
		if unsent != n {
			t.Fatalf("want unset %d, got %d", n, unsent)
		}
		n, seq, err := rtx.MakePacket(aux[sent : sent+len(msg)])
		if err != nil {
			t.Fatal(err)
		} else if seq != prevSeq {
			t.Fatalf("want seq %d, got %d", prevSeq, seq)
		} else if n != len(msg) {
			t.Fatalf("want full message %d sent, got %d", len(msg), n)
		}
		gotSent := rtx.BufferedSent()
		if gotSent != sent+n {
			t.Fatalf("want sent %d, got %d", sent+n, gotSent)
		}
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
		unsent := rtx.Buffered()
		if len(msg) != unsent {
			t.Fatalf("want %d unsent buffered, got %d", unsent, len(msg))
		}
		sent := rtx.BufferedSent()
		if sent != 0 {
			t.Fatalf("want 0 bytes sent, got %d", sent)
		}
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
		sent = rtx.BufferedSent()
		if sent != len(msg) {
			t.Fatalf("want %d sent, got %d", len(msg), sent)
		}
		prevSeq += Value(n)
		err = rtx.RecvACK(prevSeq)
		if err != nil {
			t.Fatal(err)
		}
	}
}
