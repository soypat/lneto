package udp

import (
	"testing"

	"github.com/soypat/lneto/internal"
)

func newTestConn(t *testing.T) *Conn {
	t.Helper()
	var conn Conn
	err := conn.Configure(ConnConfig{
		RxBuf:       make([]byte, 256),
		TxBuf:       make([]byte, 256),
		RxQueueSize: 4,
		TxQueueSize: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = conn.Open(1234, 8080, []byte{10, 0, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	return &conn
}

func TestConn_WriteEncapsulateRoundtrip(t *testing.T) {
	conn := newTestConn(t)
	payload := []byte("hello udp")
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("wrote %d, want %d", n, len(payload))
	}

	var buf [128]byte
	n, err = conn.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("encapsulated %d, want %d", n, len(payload))
	}
	if !internal.BytesEqual(buf[:n], payload) {
		t.Fatalf("encapsulated data mismatch")
	}

	// No more data pending.
	n, err = conn.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected no pending data, got %d", n)
	}
}

func TestConn_DemuxReadRoundtrip(t *testing.T) {
	conn := newTestConn(t)
	payload := []byte("incoming datagram")
	err := conn.Demux(payload, 0)
	if err != nil {
		t.Fatal(err)
	}

	var buf [64]byte
	n, err := conn.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("read %d, want %d", n, len(payload))
	}
	if !internal.BytesEqual(buf[:n], payload) {
		t.Fatal("read data mismatch")
	}
}

func TestConn_MultipleDatagrams(t *testing.T) {
	conn := newTestConn(t)
	messages := []string{"first", "second", "third"}
	for _, msg := range messages {
		err := conn.Demux([]byte(msg), 0)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Read back in order.
	var buf [64]byte
	for _, want := range messages {
		n, err := conn.Read(buf[:])
		if err != nil {
			t.Fatal(err)
		}
		got := string(buf[:n])
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

func TestConn_ReadTruncates(t *testing.T) {
	conn := newTestConn(t)
	payload := []byte("a]longer_datagram")
	err := conn.Demux(payload, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Read into small buffer: truncates, discards remainder.
	var buf [4]byte
	n, err := conn.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if n != len(buf) {
		t.Fatalf("read %d, want %d", n, len(buf))
	}
	if !internal.BytesEqual(buf[:], payload[:4]) {
		t.Fatal("truncated data mismatch")
	}

	// Next Demux+Read should work cleanly after truncation.
	payload2 := []byte("ok")
	err = conn.Demux(payload2, 0)
	if err != nil {
		t.Fatal(err)
	}
	var buf2 [64]byte
	n, err = conn.Read(buf2[:])
	if err != nil {
		t.Fatal(err)
	}
	if !internal.BytesEqual(buf2[:n], payload2) {
		t.Fatal("post-truncation read mismatch")
	}
}

func TestConn_DemuxExhausted(t *testing.T) {
	conn := newTestConn(t) // queue size 4
	for i := 0; i < 4; i++ {
		err := conn.Demux([]byte{byte(i)}, 0)
		if err != nil {
			t.Fatal(err)
		}
	}
	// 5th should fail.
	err := conn.Demux([]byte{0xff}, 0)
	if err == nil {
		t.Fatal("expected error on exhausted rx queue")
	}
}

func TestConn_ClosedBehavior(t *testing.T) {
	conn := newTestConn(t)
	conn.Close()

	_, err := conn.Write([]byte("data"))
	if err == nil {
		t.Fatal("expected error writing to closed conn")
	}

	err = conn.Demux([]byte("data"), 0)
	if err == nil {
		t.Fatal("expected error demuxing to closed conn")
	}
}

func TestConn_EncapsulateMultiple(t *testing.T) {
	conn := newTestConn(t)
	msgs := []string{"aaa", "bbb"}
	for _, msg := range msgs {
		_, err := conn.Write([]byte(msg))
		if err != nil {
			t.Fatal(err)
		}
	}

	var buf [128]byte
	for _, want := range msgs {
		n, err := conn.Encapsulate(buf[:], -1, 0)
		if err != nil {
			t.Fatal(err)
		}
		got := string(buf[:n])
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

func TestConn_FrameOffset(t *testing.T) {
	conn := newTestConn(t)
	// Demux with an offset simulating a UDP header already parsed.
	carrier := []byte{0, 0, 0, 0, 0, 0, 0, 0, 'h', 'i'}
	err := conn.Demux(carrier, 8)
	if err != nil {
		t.Fatal(err)
	}
	var buf [8]byte
	n, err := conn.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hi" {
		t.Fatalf("got %q, want %q", string(buf[:n]), "hi")
	}
}
