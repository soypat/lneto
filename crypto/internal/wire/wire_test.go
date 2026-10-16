package wire

import (
	"bytes"
	"errors"
	"testing"

	"github.com/soypat/lneto"
)

func TestEncoderShortBuffer(t *testing.T) {
	var e Encoder
	e.Reset(make([]byte, 4), 1)
	e.Uint16(0x0102)
	if e.Err() != nil || e.Len() != 3 {
		t.Fatalf("fitting write: err=%v len=%d", e.Err(), e.Len())
	}
	e.Uint16(0x0304) // Does not fit.
	if !errors.Is(e.Err(), lneto.ErrShortBuffer) {
		t.Fatalf("err=%v, want %v", e.Err(), lneto.ErrShortBuffer)
	}
	e.Uint8(5) // Would fit, but encoder has failed.
	if e.Len() != 3 {
		t.Fatalf("write after error advanced len to %d", e.Len())
	} else if e.Rest() != nil || e.Reserve(0) != nil || e.Since(0) != nil {
		t.Fatal("buffer access after error")
	}
	e.Fail(lneto.ErrInvalidField)
	if !errors.Is(e.Err(), lneto.ErrShortBuffer) {
		t.Fatalf("Fail overwrote first error: %v", e.Err())
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
	if got := e.Since(0); e.Err() != nil || !bytes.Equal(got, want) {
		t.Fatalf("got %x err=%v, want %x", got, e.Err(), want)
	} else if cap(got) != len(buf) {
		t.Fatalf("Since cap=%d, want %d to write past written bytes", cap(got), len(buf))
	} else if got = e.Since(3); !bytes.Equal(got, want[3:]) || cap(got) != len(buf)-3 {
		t.Fatalf("Since(3)=%x cap=%d, want %x cap=%d", got, cap(got), want[3:], len(buf)-3)
	}
	e.Advance(len(buf)) // Past end.
	if !errors.Is(e.Err(), lneto.ErrShortBuffer) {
		t.Fatalf("Advance past end err=%v", e.Err())
	}
}

func TestEncoderOpenClose(t *testing.T) {
	for width := 1; width <= 4; width++ {
		var e Encoder
		e.Reset(make([]byte, 4+300), 0)
		start := e.Open(width)
		e.Advance(200)
		e.Close(start, width)
		if e.Err() != nil {
			t.Fatalf("width %d: %v", width, e.Err())
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
	e.Close(start, 1)
	if !errors.Is(e.Err(), lneto.ErrInvalidLengthField) {
		t.Fatalf("overflow err=%v, want %v", e.Err(), lneto.ErrInvalidLengthField)
	}
}

func TestDecoder(t *testing.T) {
	var vld lneto.Validator
	var d Decoder
	d.Reset([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, &vld)
	if d.Uint8() != 1 || d.Uint16() != 0x0203 || d.Uint32() != 0x04050607 {
		t.Fatal("bad read")
	} else if got := d.Take(2); !bytes.Equal(got, []byte{8, 9}) {
		t.Fatalf("Take %x", got)
	} else if d.Off() != 9 || d.Remaining() != 1 || vld.HasError() {
		t.Fatalf("off=%d rem=%d err=%v", d.Off(), d.Remaining(), vld.ErrPop())
	}
	if d.Take(0xffffffff) != nil {
		t.Fatal("oversized Take returned data")
	}
	if d.Uint8() != 0 || d.Off() != 9 {
		t.Fatalf("read after error off=%d", d.Off())
	}
	d.Advance(0)
	d.Fail(lneto.ErrInvalidField)
	if err := vld.ErrPop(); err != lneto.ErrTruncatedFrame {
		t.Fatalf("err=%v, want only %v", err, lneto.ErrTruncatedFrame)
	}
}
