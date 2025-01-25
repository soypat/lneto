package tcp

import (
	"bytes"
	"testing"
)

func TestTxQueue_SequentialMessages(t *testing.T) {
	const (
		bufsize  = 2
		maxPkt   = 1
		msg      = "hello world"
		startAck = 0 // this is the initial sequence number.
	)
	buf := make([]byte, bufsize)
	var rtx ringTx
	err := rtx.Reset(buf, maxPkt, startAck)
	if err != nil {
		t.Fatal(err)
	}
	// msgs := bytes.SplitAfter([]byte(msg), []byte("e"))
	msgs := bytes.Split([]byte(msg), []byte(""))
	var data [bufsize]byte
	prevSeq := Value(startAck)
	for i, msg := range msgs {
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
		n, seq, err := rtx.MakePacket(data[:])
		if err != nil {
			t.Fatalf("making packet %d: %s", i, err)
		} else if n != len(msg) {
			t.Fatalf("want %d packet read, got %d", len(msg), n)
		} else if !bytes.Equal(msg, data[:n]) {
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
