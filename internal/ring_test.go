package internal

import (
	"bytes"
	"io"
	"math/rand"
	"testing"
)

func TestRing(t *testing.T) {
	rng := rand.New(rand.NewSource(0))
	const bufSize = 10
	r := &Ring{
		Buf: make([]byte, bufSize),
	}
	const data = "hello"
	_, err := r.WriteString(data)
	if err != nil {
		t.Error(err)
	}
	// Case where data is contiguous and at start of buffer.
	var buf [bufSize]byte
	n, err := fragmentReadInto(r, buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != data {
		t.Fatalf("got %q; want %q", buf[:n], data)
	}

	// Case where data overwrites end of buffer.
	const overdata = "hello world"
	n, err = r.Write([]byte(overdata))
	if err == nil || n > 0 {
		t.Fatal(err, n)
	}

	// Set Random data in ring buffer and read it back.
	for i := 0; i < 32; i++ {
		n := rng.Intn(bufSize)
		copy(buf[:], overdata[:n])
		offset := rng.Intn(bufSize - 1)
		setRingData(t, r, offset, buf[:n])

		// Case where data wraps around end of buffer.
		n, err = r.Read(buf[:])
		if err != nil {
			break
		}
		if string(buf[:n]) != overdata[:n] {
			t.Error("got", buf[:n], "want", overdata[:n])
		}
	}

	// Set random data and write some more and read it back.
	for i := 0; i < 32; i++ {
		nfirst := rng.Intn(bufSize) / 2
		nsecond := rng.Intn(bufSize) / 2
		if nfirst+nsecond > bufSize {
			nfirst = bufSize - nsecond
		}
		offset := rng.Intn(bufSize - 1)

		copy(buf[:], overdata[:nfirst])
		setRingData(t, r, offset, buf[:nfirst])
		// println("test", r.end, r.off, offset, r)
		ngot, err := r.WriteString(overdata[nfirst : nfirst+nsecond])
		if err != nil {
			t.Fatal(err)
		}
		if ngot != nsecond {
			t.Errorf("%d did not write data correctly: got %d; want %d", i, ngot, nsecond)
		}
		buf = [bufSize]byte{}
		// Case where data wraps around end of buffer.
		n, err = r.Read(buf[:])
		if err != nil {
			break
		}

		if n != nfirst+nsecond {
			t.Errorf("got %d; want %d (%d+%d)", n, nfirst+nsecond, nfirst, nsecond)
		}
		if string(buf[:n]) != overdata[:n] {
			t.Errorf("got %q; want %q", buf[:n], overdata[:n])
		}
	}

	var readback [bufSize]byte
	var zeros [bufSize]byte

	// Set random data and write some more and read it back with ReadAt and ReadPeek and ReadDiscard.
	for i := 0; i < 32; i++ {
		nfirst := rng.Intn(len(data))/2 + 1 // write garbage data first.
		nsecond := rng.Intn(len(data))/2 + 1
		if nfirst+nsecond > bufSize {
			nfirst = bufSize - nsecond
		}
		r.Reset()

		randOff := rng.Intn(bufSize)
		content := append([]byte{}, zeros[:nfirst]...)
		content = append(content, data[:nsecond]...)
		setRingData(t, r, randOff, content)
		// Two-tap ReadPeek to make sure pointer not advanced.
		for i := 0; i < 2; i++ {
			n, err = r.ReadPeek(readback[:])
			if err != nil && err != io.EOF {
				t.Fatal("read failed", err)
			} else if n != nfirst+nsecond {
				t.Errorf("want!=got bytes read %d, %d", nfirst+nsecond, n)
			} else if !bytes.Equal(readback[:nfirst], zeros[:nfirst]) {
				t.Error("first section not match")
			} else if !bytes.Equal(readback[nfirst:nfirst+nsecond], []byte(data[:nsecond])) {
				t.Error("second section not match")
			}
		}

		// Two-tap ReadAt to make sure pointer not advanced.
		for i := 0; i < 2; i++ {
			off := rng.Intn(nfirst + nsecond)
			n, err = r.ReadAt(readback[:nfirst+nsecond-off], int64(off))

			readat := readback[:n]
			first := zeros[min(off, nfirst):nfirst]
			secondOff := max(0, off-nfirst)
			second := []byte(data[secondOff:nsecond])
			gotSecond := readat[len(first):]
			if err != nil && err != io.EOF {
				t.Fatal("read failed", off, err)
			} else if n != nfirst+nsecond-off {
				t.Errorf("want!=got bytes read %d, %d", nfirst+nsecond-off, n)
			} else if len(first) > 0 && !bytes.Equal(readat[:nfirst-off], first) {
				t.Error("first section not match")
			} else if len(second) > 0 && !bytes.Equal(gotSecond, second) {
				t.Errorf("second section not match got=%q want=%q", gotSecond, second)
			}
		}

		// ReadDiscard test.
		discard := rng.Intn(nfirst+nsecond) + 1
		r.ReadDiscard(discard)
		n, err := r.Read(readback[:])
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		wantN := nfirst + nsecond - discard
		if wantN != n {
			t.Errorf("Want %d bytes read, got %d", wantN, n)
		}
		if !bytes.Equal(readback[:n], content[discard:]) {
			t.Errorf("want data read %q, got %q", content[discard:], readback[:n])
		}
	}

	_ = r._string(0)
}

func TestRing2(t *testing.T) {
	const maxsize = 6
	const ntests = 80000
	rng := rand.New(rand.NewSource(0))
	data := make([]byte, maxsize)
	ringbuf := make([]byte, maxsize)
	auxbuf := make([]byte, maxsize)
	rng.Read(data)
	for i := 0; i < ntests; i++ {
		dsize := max(rng.Intn(len(data)), 1)
		if !testRing1_loopback(t, rng, ringbuf, data[:dsize], auxbuf) {
			t.Fatalf("failed test %d", i)
		}
	}
}

func TestRing_findcrash(t *testing.T) {
	const maxsize = 33
	const ntests = 800000
	r := Ring{
		Buf: make([]byte, maxsize*6),
	}
	rng := rand.New(rand.NewSource(0))
	data := make([]byte, maxsize)

	for i := 0; i < ntests; i++ {
		free := r.Free()
		if free < 0 {
			t.Fatal("free < 0")
		}
		if rng.Intn(2) == 0 {
			l := max(rng.Intn(len(data)), 1)
			if l > free {
				continue // Buffer full.
			}
			n, err := r.Write(data[:l])
			expectFree := free - n
			free = r.Free()
			if n != l {
				t.Fatal(i, "write failed", n, l, err)
			} else if expectFree != free {
				t.Fatal(i, "free not updated correctly", expectFree, free)
			}
		}
		buffered := r.Buffered()
		if buffered < 0 {
			t.Fatal("buffered < 0")
		}
		if rng.Intn(2) == 0 {
			l := max(rng.Intn(len(data)), 1)
			n, err := r.Read(data[:l])
			expectRead := min(buffered, l)
			expectBuffered := buffered - n
			buffered = r.Buffered()
			if n != expectRead {
				t.Fatal(i, "read failed", n, l, expectRead, err)
			} else if buffered != expectBuffered {
				t.Fatal(i, "buffered not updated correctly", expectBuffered, buffered)
			}
		}
	}
}

func testRing1_loopback(t *testing.T, rng *rand.Rand, ringbuf, data, auxbuf []byte) bool {
	if len(data) > len(ringbuf) || len(data) > len(auxbuf) {
		panic("invalid ringbuf or data")
	}
	dsize := len(data)
	var r Ring
	r.Buf = ringbuf

	nfirst := rng.Intn(dsize) / 2
	nsecond := rng.Intn(dsize) / 2
	if nfirst == 0 || nsecond == 0 {
		return true
	}
	offset := rng.Intn(dsize - 1)

	setRingData(t, &r, offset, data[:nfirst])
	ngot, err := r.Write(data[nfirst : nfirst+nsecond])
	if err != nil {
		t.Error(err)
		return false
	}
	if ngot != nsecond {
		t.Errorf("did not write data correctly: got %d; want %d", ngot, nsecond)
	}
	// Case where data wraps around end of buffer.
	n, err := r.Read(auxbuf[:])
	if err != nil {
		t.Error(err)
		return false
	}

	if n != nfirst+nsecond {
		t.Errorf("got %d; want %d (%d+%d)", n, nfirst+nsecond, nfirst, nsecond)
	}
	if !bytes.Equal(auxbuf[:n], data[:n]) {
		t.Errorf("got %q; want %q", auxbuf[:n], data[:n])
	}
	return !t.Failed()
}

func fragmentReadInto(r io.Reader, buf []byte) (n int, _ error) {
	maxSize := len(buf) / 4
	for {
		ntop := min(n+rand.Intn(maxSize)+1, len(buf))
		ngot, err := r.Read(buf[n:ntop])
		n += ngot
		if err != nil {
			if err == io.EOF {
				return n, nil
			}
			return n, err
		}
		if n == len(buf) {
			return n, nil
		}
	}
}

func setRingData(t *testing.T, r *Ring, offset int, data []byte) {
	t.Helper()
	if len(data) > len(r.Buf) {
		panic("data too large")
	}
	n := copy(r.Buf[offset:], data)
	r.End = offset + n
	if len(data)+offset > len(r.Buf) {
		// End of buffer not enough to hold data, wrap around.
		n = copy(r.Buf, data[n:])
		r.End = n
	}
	r.Off = offset
	r.onReadEnd()
	// println("buf:", len(r.buf), "end:", r.end, "off:", r.off, offset, "data:", len(data))
	free := r.Free()
	wantFree := len(r.Buf) - len(data)
	if free != wantFree {
		t.Fatalf("free got %d; want %d", free, wantFree)
	}
	buffered := r.Buffered()
	wantBuffered := len(data)
	if buffered != wantBuffered {
		t.Fatalf("buffered got %d; want %d", buffered, wantBuffered)
	}
	end := r.End
	off := r.Off
	sdata := r.string()
	if sdata != string(data) {
		t.Fatalf("data got %q; want %q", sdata, data)
	}
	r.End = end
	r.Off = off
}
