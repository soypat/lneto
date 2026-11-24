package tlsraw

import (
	"bytes"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

func testRecord(ct ContentType, body int) []byte {
	rec := []byte{byte(ct), 3, 3, byte(body >> 8), byte(body)}
	for i := range body {
		rec = append(rec, byte(i))
	}
	return rec
}

func testMessage(typ HandshakeType, body int) []byte {
	m := []byte{byte(typ), byte(body >> 16), byte(body >> 8), byte(body)}
	for i := range body {
		m = append(m, byte(i))
	}
	return m
}

// ringRecords feeds stream through ring in chunks of size, frames records with
// rr as a ring owner would, and returns them. It stops at the first framing error.
func ringRecords(rr *RecordReader, ring *internal.Ring, stream []byte, size int) (recs [][]byte, err error) {
	for len(stream) > 0 {
		n := min(size, len(stream), ring.Free())
		if n > 0 {
			ring.Write(stream[:n])
			stream = stream[n:]
		}
		for {
			first, second := ring.BufferedData()
			n, needMore, err := rr.Next(first, second)
			if needMore {
				break
			} else if err != nil {
				return recs, err
			}
			if n > len(first) {
				ring.LinearizeInput()
				first, _ = ring.BufferedData()
			}
			recs = append(recs, append([]byte(nil), first[:n]...))
			ring.DiscardInput(n)
		}
	}
	return recs, nil
}

func TestRecordReaderRing(t *testing.T) {
	var want [][]byte
	var stream []byte
	for _, body := range []int{0, 1, 4, 300, 1000, 7, MaxCiphertext, 2, 3, 900} {
		rec := testRecord(ContentTypeHandshake, body)
		want = append(want, rec)
		stream = append(stream, rec...)
	}
	for _, size := range []int{1, 3, 5, 6, 100, 4096, len(stream)} {
		for _, off := range []int{0, 1, 4, 5000, MaxRecord - 3} {
			var rr RecordReader
			if err := rr.Reset(0); err != nil {
				t.Fatal(err)
			}
			ring := internal.Ring{Buf: make([]byte, MaxRecord), Off: off}
			got, err := ringRecords(&rr, &ring, stream, size)
			if err != nil {
				t.Fatalf("chunks of %d at %d: %v", size, off, err)
			} else if len(got) != len(want) {
				t.Fatalf("chunks of %d at %d: got %d records, want %d", size, off, len(got), len(want))
			}
			for i := range want {
				if !bytes.Equal(got[i], want[i]) {
					t.Fatalf("chunks of %d at %d: record %d differs", size, off, i)
				}
			}
			if ring.Buffered() != 0 {
				t.Fatalf("chunks of %d at %d: %d bytes left", size, off, ring.Buffered())
			}
		}
	}
}

func TestRecordReaderSplit(t *testing.T) {
	rec := testRecord(ContentTypeApplicationData, 9)
	var rr RecordReader
	rr.Reset(0)
	for i := 0; i <= len(rec); i++ {
		// Every split of the record between first and second, header included.
		if n, needMore, err := rr.Next(rec[:i], rec[i:]); n != len(rec) || needMore || err != nil {
			t.Fatalf("split at %d: %d, %v, %v", i, n, needMore, err)
		}
		// Every incomplete prefix.
		if n, needMore, err := rr.Next(rec[:i/2], rec[i/2:i]); i < len(rec) && (n != 0 || !needMore || err != lneto.ErrTruncatedFrame) {
			t.Fatalf("prefix of %d: %d, %v, %v", i, n, needMore, err)
		}
	}
}

func TestRecordReaderErrors(t *testing.T) {
	var rr RecordReader
	if err := rr.Reset(-1); err != lneto.ErrInvalidConfig {
		t.Fatalf("negative limit: %v", err)
	} else if err := rr.Reset(MaxCiphertext + 1); err != lneto.ErrInvalidConfig {
		t.Fatalf("limit over MaxCiphertext: %v", err)
	} else if err := rr.Reset(16); err != nil {
		t.Fatal(err)
	}
	if _, needMore, err := rr.Next([]byte{22, 3, 3, 0}, []byte{17}); needMore || err != lneto.ErrInvalidLengthField {
		t.Fatalf("body over limit: %v, %v", needMore, err)
	}
}

// readMessages feeds stream to hr as records of size and returns every message Next yields.
func readMessages(t *testing.T, hr *HandshakeReader, stream []byte, size int) [][]byte {
	t.Helper()
	var got [][]byte
	for len(stream) > 0 {
		n := min(size, len(stream))
		if err := hr.Write(stream[:n]); err != nil {
			t.Fatal(err)
		}
		stream = stream[n:]
		for {
			msg, err := hr.Next()
			if err != nil {
				t.Fatal(err)
			} else if msg == nil {
				break
			}
			got = append(got, append([]byte(nil), msg...))
		}
	}
	return got
}

func TestHandshakeReaderChunks(t *testing.T) {
	var want [][]byte
	var stream []byte
	for _, body := range []int{0, 1, 3, 200, 1000, 5, 0} {
		m := testMessage(HandshakeTypeCertificate, body)
		want = append(want, m)
		stream = append(stream, m...)
	}
	for _, size := range []int{1, 3, 4, 7, 200, 1024} {
		var hr HandshakeReader
		hr.Reset(make([]byte, 2048))
		got := readMessages(t, &hr, stream, size)
		if len(got) != len(want) {
			t.Fatalf("records of %d: got %d messages, want %d", size, len(got), len(want))
		}
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("records of %d: message %d differs", size, i)
			}
		}
		if hr.Pending() {
			t.Fatalf("records of %d: bytes left", size)
		}
	}
}

func TestHandshakeReaderPending(t *testing.T) {
	var hr HandshakeReader
	hr.Reset(make([]byte, 64))
	hr.Write(append(testMessage(HandshakeTypeServerHello, 2), 8))
	msg, err := hr.Next()
	if err != nil || msg == nil {
		t.Fatal(msg, err)
	} else if !hr.Pending() {
		t.Fatal("byte after the message not pending")
	}
	hr.Reset(make([]byte, 64))
	hr.Write(testMessage(HandshakeTypeServerHello, 2))
	if msg, _ = hr.Next(); msg == nil || hr.Pending() {
		t.Fatal("pending without extra bytes")
	}
}

func TestHandshakeReaderErrors(t *testing.T) {
	var hr HandshakeReader
	hr.Reset(make([]byte, 16))
	if err := hr.Write(make([]byte, 17)); err != lneto.ErrBufferFull {
		t.Fatalf("content over buffer: %v", err)
	}
	hr.Write([]byte{byte(HandshakeTypeCertificate), 0, 0, 13})
	if _, err := hr.Next(); err != lneto.ErrBufferFull {
		t.Fatalf("message over buffer: %v", err)
	}
	hr.Zeroize()
	if hr.Pending() {
		t.Fatal("zeroize kept data")
	}
}

func TestHandshakeReaderDiscard(t *testing.T) {
	stream := append(testMessage(HandshakeTypeNewSessionTicket, 200), testMessage(HandshakeTypeNewSessionTicket, 5000)...)
	stream = append(stream, testMessage(HandshakeTypeNewSessionTicket, 0)...)
	for _, size := range []int{1, 3, 4, 7, 200, 4096, len(stream)} {
		var hr HandshakeReader
		for rest := stream; len(rest) > 0; {
			n := min(size, len(rest))
			if err := hr.Discard(rest[:n], HandshakeTypeNewSessionTicket); err != nil {
				t.Fatalf("records of %d bytes: %v", size, err)
			}
			rest = rest[n:]
		}
		if hr.hdrN != 0 || hr.skip != 0 {
			t.Fatalf("records of %d bytes: stopped inside a message", size)
		}
	}
	var hr HandshakeReader
	keyUpdate := testMessage(HandshakeTypeKeyUpdate, 1)
	if err := hr.Discard(append(testMessage(HandshakeTypeNewSessionTicket, 10), keyUpdate...), HandshakeTypeNewSessionTicket); err != lneto.ErrMismatch {
		t.Fatalf("KeyUpdate after a ticket: got %v, want ErrMismatch", err)
	}
}

func FuzzRecordReader(f *testing.F) {
	f.Add(append(testRecord(ContentTypeHandshake, 3), testRecord(ContentTypeAlert, 2)...), uint8(2), uint16(250))
	f.Add([]byte{22, 3, 3, 0xff, 0xff}, uint8(1), uint16(0))
	f.Fuzz(func(t *testing.T, stream []byte, size uint8, off uint16) {
		const maxLen = 256
		var rr RecordReader
		rr.Reset(maxLen)
		ring := internal.Ring{Buf: make([]byte, SizeHeaderRecord+maxLen)}
		ring.Off = int(off) % len(ring.Buf)
		recs, err := ringRecords(&rr, &ring, stream, int(size)+1)
		var got []byte
		for _, rec := range recs {
			got = append(got, rec...)
		}
		if !bytes.Equal(got, stream[:len(got)]) {
			t.Fatal("records do not reproduce the stream")
		} else if err != nil && int(stream[len(got)+3])<<8|int(stream[len(got)+4]) <= maxLen {
			t.Fatal("rejected a record within the limit")
		} else if err == nil && len(stream)-len(got) != ring.Buffered() {
			t.Fatal("bytes lost between records")
		}
	})
}

func FuzzHandshakeReader(f *testing.F) {
	f.Add(append(testMessage(HandshakeTypeCertificate, 3), testMessage(HandshakeTypeFinished, 2)...), uint8(2))
	f.Add([]byte{11, 0xff, 0xff, 0xff}, uint8(0))
	f.Fuzz(func(t *testing.T, stream []byte, size uint8) {
		var hr HandshakeReader
		hr.Reset(make([]byte, 512))
		chunk := int(size) + 1
		var got []byte
		for rest := stream; len(rest) > 0; {
			n := min(chunk, len(rest))
			if err := hr.Write(rest[:n]); err != nil {
				return
			}
			rest = rest[n:]
			for {
				msg, err := hr.Next()
				if err != nil {
					return
				} else if msg == nil {
					break
				}
				got = append(got, msg...)
			}
		}
		if !bytes.Equal(got, stream[:len(got)]) {
			t.Fatal("messages do not reproduce the stream")
		}
	})
}
