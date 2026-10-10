package wire

import (
	"bytes"
	"testing"

	"github.com/soypat/lneto"
)

func TestEncoderShortBuffer(t *testing.T) {
	var e Encoder
	e.Reset(make([]byte, 4), 1)
	e.Uint16(0x0102)
	if e.IsFailed() || e.Len() != 3 {
		t.Fatalf("fitting write: failed=%v len=%d", e.IsFailed(), e.Len())
	}
	e.Uint16(0x0304) // Does not fit.
	if !e.IsFailed() {
		t.Fatal("write past end did not fail")
	}
	e.Uint8(5) // Would fit, but encoder has failed.
	if e.Len() != 3 {
		t.Fatalf("write after failure advanced len to %d", e.Len())
	} else if e.Rest() != nil || e.Reserve(0) != nil || e.Since(0) != nil {
		t.Fatal("buffer access after failure")
	}
}

func TestEncoderFail(t *testing.T) {
	var e Encoder
	e.Reset(make([]byte, 4), 0)
	e.Fail()
	e.Uint8(1)
	if !e.IsFailed() || e.Len() != 0 {
		t.Fatalf("write after Fail: failed=%v len=%d", e.IsFailed(), e.Len())
	}
}

func TestEncoderWrites(t *testing.T) {
	var e Encoder
	buf := make([]byte, 32)
	e.Reset(buf, 0)
	e.Uint8(1)
	e.Uint16(0x0203)
	e.Uint32(0x04050607)
	e.Uint64(0x08090a0b0c0d0e0f)
	e.Bytes([]byte{0x10, 0x11})
	copy(e.Reserve(1), []byte{0x12})
	e.Rest()[0] = 0x13
	e.Advance(1)
	want := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
	if got := e.Since(0); e.IsFailed() || !bytes.Equal(got, want) {
		t.Fatalf("got %x failed=%v, want %x", got, e.IsFailed(), want)
	} else if cap(got) != len(buf) {
		t.Fatalf("Since cap=%d, want %d to write past written bytes", cap(got), len(buf))
	} else if got = e.Since(3); !bytes.Equal(got, want[3:]) || cap(got) != len(buf)-3 {
		t.Fatalf("Since(3)=%x cap=%d, want %x cap=%d", got, cap(got), want[3:], len(buf)-3)
	}
	e.Advance(len(buf)) // Past end.
	if !e.IsFailed() {
		t.Fatal("Advance past end did not fail")
	}
}

func TestEncoderOpenClose(t *testing.T) {
	for width := 1; width <= 4; width++ {
		var e Encoder
		e.Reset(make([]byte, 4+300), 0)
		start := e.Open(width)
		e.Advance(200)
		if e.Close(start, width) || e.IsFailed() {
			t.Fatalf("width %d: failed", width)
		}
		got := e.Since(0)[:width]
		want := []byte{0, 0, 0, 200}[4-width:]
		if !bytes.Equal(got, want) {
			t.Fatalf("width %d prefix %x, want %x", width, got, want)
		}
	}
	var e Encoder
	e.Reset(make([]byte, 1+256), 0)
	start := e.Open(1)
	e.Advance(256)
	if !e.Close(start, 1) || !e.IsFailed() {
		t.Fatalf("overflow not reported: failed=%v", e.IsFailed())
	}
}

func TestDecoder(t *testing.T) {
	var d Decoder
	d.Reset([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	if d.Uint8() != 1 || d.Uint16() != 0x0203 || d.Uint32() != 0x04050607 {
		t.Fatal("bad read")
	} else if got := d.Take(2); !bytes.Equal(got, []byte{8, 9}) {
		t.Fatalf("Take %x", got)
	} else if d.Off() != 9 || d.Remaining() != 1 || d.IsFailed() {
		t.Fatalf("off=%d rem=%d failed=%v", d.Off(), d.Remaining(), d.IsFailed())
	}
	if d.Take(0xffffffff) != nil || !d.IsFailed() {
		t.Fatal("oversized Take returned data or did not fail")
	}
	if d.Uint8() != 0 || d.Off() != 9 {
		t.Fatalf("read after failure off=%d", d.Off())
	}
}

func TestEncoderErr(t *testing.T) {
	var e EncoderErr
	e.Reset(make([]byte, 1), 0)
	e.Uint16(1)
	if e.Err() != lneto.ErrShortBuffer {
		t.Fatalf("short write err=%v", e.Err())
	}
	e.Reset(make([]byte, 1), 0)
	if e.Err() != nil || e.IsFailed() {
		t.Fatalf("after Reset err=%v failed=%v", e.Err(), e.IsFailed())
	}
	e.Fail(lneto.ErrInvalidField)
	if e.Err() != lneto.ErrInvalidField || !e.IsFailed() {
		t.Fatalf("Fail err=%v failed=%v", e.Err(), e.IsFailed())
	}
	e.Reset(make([]byte, 1), 0)
	if e.Err() != nil {
		t.Fatalf("after Reset err=%v", e.Err())
	}
}

func TestDecoderErr(t *testing.T) {
	var d DecoderErr
	d.Reset([]byte{1})
	d.Uint16()
	if d.Err() != lneto.ErrTruncatedFrame {
		t.Fatalf("short read err=%v", d.Err())
	}
	d.Reset([]byte{1})
	if d.Err() != nil || d.IsFailed() {
		t.Fatalf("after Reset err=%v failed=%v", d.Err(), d.IsFailed())
	}
	d.Fail(lneto.ErrInvalidField)
	if d.Err() != lneto.ErrInvalidField || !d.IsFailed() {
		t.Fatalf("Fail err=%v failed=%v", d.Err(), d.IsFailed())
	}
	d.Reset([]byte{1})
	if d.Err() != nil {
		t.Fatalf("after Reset err=%v", d.Err())
	}
}

func TestDecoderFail(t *testing.T) {
	var d Decoder
	d.Reset([]byte{1, 2})
	d.Fail()
	if d.Uint8() != 0 || d.Off() != 0 || !d.IsFailed() {
		t.Fatalf("read after Fail off=%d failed=%v", d.Off(), d.IsFailed())
	}
}
