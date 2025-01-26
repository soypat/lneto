package internal

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"testing"
)

func TestRing(t *testing.T) {
	rng := rand.New(rand.NewSource(0))
	const overdata = "hello world"
	const bufSize = 8
	var n int
	var err error
	var buf [bufSize]byte
	r := &Ring{
		Buf: make([]byte, bufSize),
	}
	const data = "hello"
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
		testRingSanity(t, r)
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
		testRingSanity(t, r)
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
			testRingSanity(t, r)
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
			testRingSanity(t, r)
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
		testRingSanity(t, r)
	}
	_ = r._string(0)
}

func TestRing2(t *testing.T) {
	const maxsize = 8
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

func TestRingEmpty(t *testing.T) {
	const bufSize = 8
	data := make([]byte, bufSize)
	r := &Ring{Buf: data}
	readCalls := []func([]byte) (int, error){
		r.read,
		r.Read,
		r.ReadPeek,
	}
	for _, isResetCalled := range []bool{false, true} {
		for _, isonReadEndCalled := range []bool{false, true} {
			name := fmt.Sprintf("reset=%v readend=%v", isResetCalled, isonReadEndCalled)
			t.Run(name, func(t *testing.T) {
				for off := 0; off < bufSize+1; off++ {
					r.End = 0
					r.Off = off
					if isResetCalled {
						testRingSanity(t, r)
						r.Reset()
					}
					buf := r.Buffered()
					if buf != 0 {
						t.Fatalf("want 0 bytes buffered, got %d for off=%d, end=%d size=%d", buf, r.Off, r.End, r.Size())
					}
					if isonReadEndCalled {
						testRingSanity(t, r)
						canonRing(r)
					}
					buf2 := r.Buffered()
					if buf2 != 0 {
						t.Fatalf("want 0 bytes buffered(second call), got buf=%d->%d for off=%d->%d, end=0->%d size=%d", buf, buf2, off, r.Off, r.End, r.Size())
					}
					testRingSanity(t, r)
					for _, read := range readCalls {
						n, err := read(data)
						if err != io.EOF {
							t.Fatal("want EOF for empty read call")
						} else if n != 0 {
							t.Fatalf("expected no bytes read, got %d", n)
						}
						testRingSanity(t, r)
					}
				}
			})
		}
	}
}

func TestRingNonEmpty(t *testing.T) {
	const bufSize = 8
	data := make([]byte, bufSize)
	r := &Ring{Buf: data}
	for _, checkRead := range []bool{false, true} {
		for _, checkWrite := range []bool{false, true} {
			for _, isonReadEndCalled := range []bool{false, true} {
				name := fmt.Sprintf("readend=%v checkWrite=%v checkRead=%v", isonReadEndCalled, checkWrite, checkRead)
				t.Run(name, func(t *testing.T) {
					for end := 1; end < bufSize+1; end++ {
						for off := 0; off < bufSize+1; off++ {
							r.End = end
							r.Off = off
							buf := r.Buffered()
							if buf == 0 {
								t.Fatalf("want !=0 bytes buffered, got %d for off=%d, end=%d size=%d", buf, r.Off, r.End, r.Size())
							}
							if isonReadEndCalled {
								testRingSanity(t, r)
								canonRing(r)
							}
							buf2 := r.Buffered()
							if buf2 != buf {
								t.Fatalf("Buffered changed on no-op %d->%d? for off=%d->%d, end=%d->%d size=%d", buf, buf2, off, r.Off, end, r.End, r.Size())
							}
							if r.Off != off {
								t.Fatalf("want off=%d, got off=%d off modified with no read call?!", off, r.Off)
							}
							if checkWrite {
								testRingSanity(t, r)
								free := r.Size() - buf
								n, err := r.Write(data[:free])
								if n != free || err != nil {
									t.Errorf("want %d to fill buffer, got n=%d err=%v", free, n, err)
								}
							}
							if checkRead {
								testRingSanity(t, r)
								buf := r.Buffered()
								n, err := r.Read(data[:buf])
								if n != buf || err != nil {
									t.Errorf("want %d read bytes, got n=%d err=%v", buf, n, err)
								}
							}
							testRingSanity(t, r)
						}
					}
				})
			}
		}
	}
}

func TestRing_OffWrite(t *testing.T) {
	const bufSize = 8
	var rawbuf, auxbuf, readback [bufSize]byte
	r := &Ring{Buf: rawbuf[:]}
	for n := 1; n < bufSize+1; n++ {
		for off := 0; off < bufSize+1; off++ {
			r.Off = off // Start write at off.
			r.End = 0   // Reset to use no data.
			for i := 0; i < n; i++ {
				rawbuf[(off+i)%len(rawbuf)] = 0
				auxbuf[i] = byte(i) + 1
			}
			ngot, err := r.Write(auxbuf[:n])
			if err != nil {
				t.Fatal(err)
			} else if ngot != n {
				t.Fatal(n, ngot)
			}
			for i := 0; i < n; i++ {
				offz := (off + i) % len(rawbuf)
				if rawbuf[offz] != auxbuf[i] {
					t.Fatalf("mismatch pos=%d off=%d %q!=%q", i, offz, rawbuf[offz], auxbuf[i])
				}
			}
			ngot, err = r.Read(readback[:])
			if err != nil {
				t.Fatal(err)
			} else if ngot != n {
				t.Fatal(n, ngot)
			} else if !bytes.Equal(readback[:n], auxbuf[:n]) {
				t.Fatalf("want readback %q, got %q", auxbuf[:n], readback[:n])
			}
		}
	}
}

func TestRing_TwoWrite(t *testing.T) {
	const bufSize = 8
	rng := rand.New(rand.NewSource(1))
	var rawbuf, auxbuf, readback [bufSize]byte
	r := &Ring{Buf: rawbuf[:]}

	for i := 0; i < 1024; i++ {
		n1 := rng.Intn(bufSize-1) + 1 // leave space for one more write
		n2 := rng.Intn(bufSize-n1) + 1
		off := rng.Intn(bufSize + 1)
		if n1+n2 > r.Size() {
			panic("invalid test")
		}
		r.Reset()
		rng.Read(auxbuf[:])
		setRingData(t, r, off, auxbuf[:n1])
		n2got, err := r.Write(auxbuf[n1 : n1+n2])
		if err != nil || n2got != n2 {
			t.Fatal(err, n2, n2got)
		}
		testRingSanity(t, r)
		n, err := r.Read(readback[:])
		if err != nil {
			t.Fatal(err)
		} else if n != n1+n2 {
			t.Fatalf("failed to read complete written data %d/%d (%d+%d)", n, n1+n2, n1, n2)
		} else if !bytes.Equal(readback[:n], auxbuf[:n]) {
			t.Fatalf("integrity of data compromised %q!=%q", readback[:n], auxbuf[:n])
		}
		testRingSanity(t, r)
	}
}

func TestRingOverwrite(t *testing.T) {
	const bufSize = 8
	var rawbuf, auxbuf [bufSize]byte
	r := &Ring{Buf: rawbuf[:]}
	for off := 0; off < bufSize+1; off++ {
		for buf := 0; buf < bufSize+1; buf++ {
			setRingData(t, r, off, rawbuf[:buf])
			// Select write size overwriting data.
			for osz := bufSize - buf + 1; osz < bufSize+1; osz++ {
				if osz <= r.Free() {
					panic("invalid test")
				}
				ngot, err := r.Write(auxbuf[:osz])
				if err == nil {
					t.Fatal("expected error")
				} else if ngot > 0 {
					t.Fatalf("expected no data written, got %d", ngot)
				}
			}
		}
	}
}

func TestRingWriteLimited(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	const bufSize = 8
	r := &Ring{
		Buf: make([]byte, bufSize),
	}
	testRingSanity(t, r)
	var data [bufSize]byte
	var wdata [bufSize]byte
	for i := 0; i < 10000; i++ {
		for i := range r.Buf {
			r.Buf[i] = 0
		}
		buffered, _ := rng.Read(data[:rng.Intn(bufSize-2)+1])
		off := rng.Intn(bufSize)
		setRingData(t, r, off, data[:buffered])
		if r.Buffered() != buffered {
			t.Fatalf("failed to set buffered amount of data")
		} else if r.Off != off {
			t.Fatal("bad offset")
		}
		free := r.Free()

		toWrite := rng.Intn(free-1) + 1
		rng.Read(wdata[:toWrite])
		limOff := rng.Intn(bufSize) + 1
		var wantN int
		isContiguous := limOff > r.End
		if isContiguous {
			wantN = min(toWrite, limOff-r.End)
		} else {
			wantN = min(toWrite, len(r.Buf)-r.End+limOff)
		}
		overwrite := toWrite > wantN

		n, err := r.WriteLimited(wdata[:toWrite], limOff)
		if !overwrite && err != nil {
			t.Errorf("limited write: %s", err)
		} else if !overwrite && n != wantN {
			t.Errorf("nwant=%d ngot=%d off=%d lim=%d towrite=%d buffered=%d/%d wantremain=%d gotremain=%d endOff=%d", wantN, n, off, limOff, toWrite, buffered, r.Size(), free-wantN, free-n, r.Off)
		} else if overwrite && (err == nil || n != 0) {
			t.Errorf("expected full buffer error and no data written on limit overwrite, got %d", n)
		}
		for i := r.End % r.Size(); i != limOff && i != r.Off; i = (i + 1) % r.Size() {
			if r.Buf[i] != 0 {
				t.Fatalf("OVERWRITE pos=%d end=%d lim=%d", i, r.End, limOff)
			}
		}
		testRingSanity(t, r)
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
			testRingSanity(t, &r)
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
			testRingSanity(t, &r)
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
	testRingSanity(t, &r)
	// Case where data wraps around end of buffer.
	n, err := r.Read(auxbuf[:])
	if err != nil {
		t.Error(err)
		return false
	}
	testRingSanity(t, &r)
	if n != nfirst+nsecond {
		t.Errorf("got %d; want %d (%d+%d)", n, nfirst+nsecond, nfirst, nsecond)
	}
	if !bytes.Equal(auxbuf[:n], data[:n]) {
		t.Errorf("got %q; want %q", auxbuf[:n], data[:n])
	}
	return !t.Failed()
}

func setRingData(t *testing.T, r *Ring, offset int, data []byte) {
	t.Helper()
	sz := r.Size()
	if len(data) > sz {
		panic("data too large")
	}
	n := copy(r.Buf[offset:], data)
	if len(data) > 0 {
		r.End = offset + n
		if len(data)+offset > sz {
			// End of buffer not enough to hold data, wrap around.
			n = copy(r.Buf, data[n:])
			r.End = n
		}
	} else {
		r.End = 0
	}

	r.Off = offset
	canonRing(r)
	// println("buf:", sz, "end:", r.end, "off:", r.off, offset, "data:", len(data))
	free := r.Free()
	wantFree := sz - len(data)
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
	testRingSanity(t, r)
}

func testRingSanity(t *testing.T, r *Ring) {
	// t.Helper() // Really costly call. Avoid calling it every single function call.
	buf := r.Buffered()
	free := r.Free()
	sz := r.Size()
	if r.End == 0 && buf > 0 {
		t.Helper()
		t.Fatalf("want end=0 to encode no data, got off=%d end=%d => buffered=%d", r.Off, r.End, r.Buffered())
	} else if sz != free+buf {
		t.Helper()
		t.Fatalf("want size=free+buffered, got %d=%d+%d", sz, free, buf)
	} else if r.End != 0 && r.Off == r.End && buf != sz {
		t.Helper()
		t.Fatalf("want (off==end && end!=0) to encode full buffer, got off=%d end=%d show fill ration %d/%d", r.Off, r.End, buf, sz)
	}
}

func canonRing(r *Ring) {
	if r.Buffered() == 0 {
		r.End = r.addOff(r.Off, 1)
		r.onReadEnd(1)
	}
}
