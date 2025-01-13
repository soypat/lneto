package tcp

import (
	"bytes"
	"testing"
)

func TestTxQueueWrite(t *testing.T) {
	const (
		bufsize = 1024
		maxPkt  = 3
		msg     = "hello world"
	)
	buf := make([]byte, bufsize)
	rtx := newRingTx(buf, maxPkt)

	bufs := bytes.SplitAfter([]byte(msg), []byte("e"))
	var data [bufsize]byte
	for i, buf := range bufs {
		n, err := rtx.Write(buf)
		if err != nil {
			t.Fatalf("writing packet %d: %s", i, err)
		} else if n != len(buf) {
			t.Fatalf("want %d written, got %d", len(buf), n)
		}
		n, err = rtx.MakePacket(data[:])
		if err != nil {
			t.Fatalf("making packet %d: %s", i, err)
		} else if n != len(buf) {
			t.Fatalf("want %d packet read, got %d", len(buf), n)
		} else if !bytes.Equal(buf, data[:n]) {
			t.Fatalf("want data %q, got data read %q", buf, data[:n])
		}
	}
}
