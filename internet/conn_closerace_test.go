package internet

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soypat/lneto/tcp"
)

// TestConn_ConcurrentCloseDoesNotDropWrite is a regression test for issue #82:
// when one goroutine has a Write in progress (blocked because the TX buffer is
// full) and another goroutine calls Close, the in-flight write data must not be
// silently dropped. With the atomic write-lock, Close waits for the in-progress
// write to finish queueing all of its data before tearing the connection down.
//
// The scenario is made deterministic by filling the TX buffer before any packets
// are exchanged: the writer blocks holding the write lock, Close is then issued
// (and must wait), and only afterwards is the packet pump started so the buffer
// can drain and the writer can run to completion.
func TestConn_ConcurrentCloseDoesNotDropWrite(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var sbCl, sbSv StackIPv4
	var connCl, connSv tcp.Conn
	setupClientServerEstablished(t, rng, &sbCl, &sbSv, &connCl, &connSv)

	// Payload several times larger than the 2048-byte TX buffer so the writer
	// must block waiting for the buffer to drain across many segments.
	payload := make([]byte, 4*2048)
	for i := range payload {
		payload[i] = byte(i)
	}

	// Watchdog: break any deadlock so a regression fails fast instead of hanging.
	watchdog := time.AfterFunc(10*time.Second, func() {
		t.Error("test timed out: Close likely blocked waiting on a stuck write")
		connCl.Abort()
		connSv.Abort()
	})
	defer watchdog.Stop()

	// Writer (G1): writes the whole payload. Blocks once the TX buffer fills.
	type writeResult struct {
		n   int
		err error
	}
	writeDone := make(chan writeResult, 1)
	go func() {
		n, err := connCl.Write(payload)
		writeDone <- writeResult{n, err}
	}()

	// Wait until the writer has filled the TX buffer and is blocked. At this
	// point it owns the write lock, reproducing "Write in progress".
	for connCl.FreeOutput() != 0 {
		runtime.Gosched()
	}

	// Close (G2): issued while the write is in progress. Must wait for the
	// writer to drain instead of dropping its data.
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- connCl.Close()
	}()

	// Reader: drains the server side until EOF, accumulating everything received.
	readDone := make(chan []byte, 1)
	go func() {
		got := make([]byte, 0, len(payload))
		rbuf := make([]byte, 1024)
		for {
			n, err := connSv.Read(rbuf)
			got = append(got, rbuf[:n]...)
			if err != nil {
				break
			}
		}
		readDone <- got
	}()

	// Packet pump: only now do we move packets between the two stacks, letting
	// the buffer drain so the blocked writer can finish.
	var stop atomic.Bool
	pumpStopped := make(chan struct{})
	go func() {
		defer close(pumpStopped)
		var buf [2048]byte
		for !stop.Load() {
			progressed := false
			if n, err := sbCl.Encapsulate(buf[:], 0, 0); err == nil && n > 0 {
				_ = sbSv.Demux(buf[:n], 0)
				progressed = true
			}
			if n, err := sbSv.Encapsulate(buf[:], 0, 0); err == nil && n > 0 {
				_ = sbCl.Demux(buf[:n], 0)
				progressed = true
			}
			if !progressed {
				runtime.Gosched()
			}
		}
	}()

	wr := <-writeDone
	if wr.err != nil {
		t.Errorf("issue #82: Write returned error %v; concurrent Close dropped in-flight data", wr.err)
	}
	if wr.n != len(payload) {
		t.Errorf("issue #82: Write wrote %d of %d bytes; concurrent Close truncated the write", wr.n, len(payload))
	}
	if err := <-closeDone; err != nil {
		t.Errorf("Close returned error: %v", err)
	}
	got := <-readDone
	stop.Store(true)
	<-pumpStopped

	if len(got) != len(payload) {
		t.Fatalf("server received %d of %d bytes; data was dropped by concurrent Close", len(got), len(payload))
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("server received corrupted data")
	}
}

// TestConn_ConcurrentWritesSerialize verifies that the atomic write-lock
// serializes concurrent Write calls on the same connection so their payloads are
// not interleaved on the wire, and that all bytes from both writers are delivered.
func TestConn_ConcurrentWritesSerialize(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	var sbCl, sbSv StackIPv4
	var connCl, connSv tcp.Conn
	setupClientServerEstablished(t, rng, &sbCl, &sbSv, &connCl, &connSv)

	const chunk = 1500
	a := bytes.Repeat([]byte{0xAA}, chunk)
	b := bytes.Repeat([]byte{0xBB}, chunk)

	watchdog := time.AfterFunc(10*time.Second, func() {
		t.Error("test timed out")
		connCl.Abort()
		connSv.Abort()
	})
	defer watchdog.Stop()

	var stop atomic.Bool
	pumpStopped := make(chan struct{})
	go func() {
		defer close(pumpStopped)
		var buf [2048]byte
		for !stop.Load() {
			progressed := false
			if n, err := sbCl.Encapsulate(buf[:], 0, 0); err == nil && n > 0 {
				_ = sbSv.Demux(buf[:n], 0)
				progressed = true
			}
			if n, err := sbSv.Encapsulate(buf[:], 0, 0); err == nil && n > 0 {
				_ = sbCl.Demux(buf[:n], 0)
				progressed = true
			}
			if !progressed {
				runtime.Gosched()
			}
		}
	}()

	writeErr := make(chan error, 2)
	writer := func(b []byte) {
		n, err := connCl.Write(b)
		if err == nil && n != len(b) {
			err = io.ErrShortWrite
		}
		writeErr <- err
	}
	go writer(a)
	go writer(b)

	got := make([]byte, 0, 2*chunk)
	rbuf := make([]byte, 1024)
	for len(got) < 2*chunk {
		n, err := connSv.Read(rbuf)
		got = append(got, rbuf[:n]...)
		if err != nil && !errors.Is(err, io.EOF) {
			break
		}
	}
	for range 2 {
		if err := <-writeErr; err != nil {
			t.Errorf("concurrent write failed: %v", err)
		}
	}
	stop.Store(true)
	<-pumpStopped

	if len(got) != 2*chunk {
		t.Fatalf("received %d bytes, want %d", len(got), 2*chunk)
	}
	// Serialized writes mean one chunk's bytes appear fully before the other's;
	// the boundary is a single transition, never interleaved.
	transitions := 0
	for i := 1; i < len(got); i++ {
		if got[i] != got[i-1] {
			transitions++
		}
	}
	if transitions != 1 {
		t.Fatalf("expected exactly one A/B boundary (serialized writes), got %d transitions", transitions)
	}
}
