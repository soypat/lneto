package tcp_test

// This file deliberately drives a bulk transfer through repeated zero-window
// episodes using exported API only, with the real retransmission timer installed.
// The zero-window path was where a stall and a truncated write went unnoticed
// until an unrelated liveness test in package internet happened to fail on a
// timeout, so the class of bug is worth catching here on purpose.

import (
	"bytes"
	"testing"

	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
)

// zwPair returns two handshaken handlers whose receive buffers are small enough
// that a bulk transfer repeatedly closes the receive window. The sender carries a
// real retransmission timer, which is what makes zero-window probing legal.
func zwPair(t *testing.T, bufSize int, nanotime func() int64) (client, server *tcp.Handler, mtu int) {
	t.Helper()
	mtu = 128
	client, server = new(tcp.Handler), new(tcp.Handler)
	for _, h := range []*tcp.Handler{client, server} {
		if err := h.SetBuffers(make([]byte, bufSize), make([]byte, bufSize), 4); err != nil {
			t.Fatal(err)
		}
	}
	client.SetPolicy(new(rto.Timer), nanotime)
	if err := server.OpenListen(80, 0); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenActive(1234, 80, 0); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, mtu)
	relay := func(from, to *tcp.Handler) {
		t.Helper()
		clear(buf)
		n, err := from.Send(buf)
		if err != nil {
			t.Fatal("handshake send:", err)
		}
		if n > 0 {
			if err = to.Recv(buf[:n]); err != nil {
				t.Fatal("handshake recv:", err)
			}
		}
	}
	relay(client, server) // SYN
	relay(server, client) // SYN-ACK
	relay(client, server) // ACK
	if client.State() != tcp.StateEstablished || server.State() != tcp.StateEstablished {
		t.Fatalf("handshake failed: client=%s server=%s", client.State(), server.State())
	}
	return client, server, mtu
}

// TestZeroWindowBulkTransferCompletes verifies a transfer larger than the
// receiver's buffer still delivers every octet, in order, when the reader drains
// slowly enough to close the window repeatedly. A stall, a truncated write or a
// single dropped octet all fail this.
//
// What it does not cover is zero-window probing itself. A sender in a continuous
// transfer nearly always has data outstanding, so the retransmission timer is what
// recovers a lost window update and the probe's narrow case, a closed window with
// nothing outstanding, seldom arises. That case is covered by
// TestZeroWindowProbeRecoversLostUpdate instead. What this test does guard is the
// pair of mistakes made while implementing that probe: dropping an unacceptable
// segment without acknowledging it, and probing while data is still outstanding,
// which fragments the stream into single octets.
func TestZeroWindowBulkTransferCompletes(t *testing.T) {
	for _, test := range []struct {
		name string
		// dropReverseEvery drops every nth segment the receiver sends, window
		// updates included, so recovery must come from probing and retransmission
		// rather than from an acknowledgement that always arrives. Zero is lossless.
		dropReverseEvery int
	}{
		{name: "lossless"},
		{name: "window updates lost", dropReverseEvery: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			zeroWindowBulkTransfer(t, test.dropReverseEvery)
		})
	}
}

func zeroWindowBulkTransfer(t *testing.T, dropReverseEvery int) {
	const (
		bufSize   = 256
		total     = 4096
		chunk     = 64
		readEvery = 6  // Drain rarely enough that the window keeps closing.
		readSize  = 32 // ...and in smaller bites than arrive.
		maxSteps  = 200000
	)
	var now int64
	client, server, mtu := zwPair(t, bufSize, func() int64 { return now })

	want := make([]byte, total)
	for i := range want {
		want[i] = byte(i*31 + 7)
	}

	var (
		got      []byte
		written  int
		buf      = make([]byte, mtu)
		rbuf     = make([]byte, readSize)
		closed   int
		steps    int
		revSeg   int
		rejected int
	)
	for steps = 0; steps < maxSteps && len(got) < total; steps++ {
		// Advance the clock so a retransmission timer can expire; a probe the
		// receiver could not accept is resent from here.
		now += int64(10 * 1000 * 1000) // 10ms per step.

		if written < total {
			end := min(written+chunk, total)
			// A short or refused write is normal while the transmit buffer backs up
			// behind a closed window, so only the delivered count matters here.
			n, _ := client.Write(want[written:end])
			written += n
		}

		clear(buf)
		n, err := client.Send(buf)
		if err != nil {
			t.Fatalf("step %d: client send: %s", steps, err)
		}
		if n > 0 {
			// A receiver may refuse a segment for several legitimate reasons here:
			// no buffer space, or a sender working from a stale window
			// advertisement after an update was lost. Either way it is a drop, and
			// the transfer is still required to complete intact.
			if err = server.Recv(buf[:n]); err != nil {
				rejected++
			}
		}

		clear(buf)
		m, err := server.Send(buf)
		if err != nil {
			t.Fatalf("step %d: server send: %s", steps, err)
		}
		if m > 0 {
			revSeg++
			drop := dropReverseEvery > 0 && revSeg%dropReverseEvery == 0
			if !drop {
				if err = client.Recv(buf[:m]); err != nil {
					t.Fatalf("step %d: client recv: %s", steps, err)
				}
			}
		}

		if server.FreeInput() == 0 {
			closed++
		}
		if steps%readEvery == 0 {
			rn, _ := server.Read(rbuf) // An empty read is normal while a gap is pending.
			got = append(got, rbuf[:rn]...)
		}
	}
	// Drain whatever is left buffered.
	for {
		rn, _ := server.Read(rbuf)
		if rn == 0 {
			break
		}
		got = append(got, rbuf[:rn]...)
	}

	if len(got) != total {
		t.Fatalf("delivered %d of %d octets after %d steps; transfer stalled", len(got), total, steps)
	}
	if !bytes.Equal(got, want) {
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("stream corrupted at octet %d: got %#x, want %#x", i, got[i], want[i])
			}
		}
	}
	if closed == 0 {
		t.Error("receive window never closed; the test did not exercise the zero-window path")
	}
	t.Logf("delivered %d octets in %d steps; window closed on %d, %d segments rejected, %d reverse segments (every %dth dropped)",
		total, steps, closed, rejected, revSeg, dropReverseEvery)
}
