package tcp

import (
	"math/rand"
	"testing"

	"github.com/soypat/lneto"
)

// stallZeroWindow drives client data into server until the server advertises a
// zero window while having acknowledged everything it accepted, then leaves data
// queued at the client. That is the state the persist timer exists for: nothing
// is outstanding, so no retransmission can double as a window probe.
//
// It returns the number of octets the client still has queued.
func stallZeroWindow(t *testing.T, client, server *Handler, buf []byte) int {
	t.Helper()
	payload := make([]byte, 32)
	for i := range payload {
		payload[i] = byte(i)
	}
	for round := 0; client.scb.snd.WND > 0; round++ {
		if round == 32 {
			t.Fatal("send window never closed")
		}
		if _, err := client.Write(payload); err != nil {
			t.Fatal("client write:", err)
		}
		n, err := client.Send(buf)
		if err != nil {
			t.Fatal("client send:", err)
		}
		if n == 0 {
			break
		}
		// Everything sent is accepted, so nothing is left outstanding once the
		// acknowledgement comes back.
		if err = server.Recv(buf[:n]); err != nil {
			t.Fatal("server recv:", err)
		}
		clear(buf)
		m, err := server.Send(buf)
		if err != nil {
			t.Fatal("server send:", err)
		}
		if m > 0 {
			if err = client.Recv(buf[:m]); err != nil {
				t.Fatal("client recv:", err)
			}
		}
	}
	if client.scb.snd.WND != 0 {
		t.Fatalf("expected a closed send window, got %d", client.scb.snd.WND)
	}
	if client.scb.snd.UNA != client.scb.snd.NXT {
		t.Fatalf("expected nothing outstanding at the stall, UNA=%d NXT=%d",
			client.scb.snd.UNA, client.scb.snd.NXT)
	}
	// Queue data with nowhere to go.
	if _, err := client.Write(payload); err != nil {
		t.Fatal("client write:", err)
	}
	buffered := client.bufTx.BufferedUnsent()
	if buffered == 0 {
		t.Fatal("expected data left queued at the stall")
	}
	return buffered
}

// TestZeroWindowProbeRecoversLostUpdate is the regression test for the stall this
// package had without a persist timer (RFC 9293 §3.8.6.1). The peer's window
// update is a bare ACK that is never retransmitted, so it is dropped here to
// reproduce the case that leaves a sender waiting forever. A probe must go out
// and, once answered, transmission must resume.
func TestZeroWindowProbeRecoversLostUpdate(t *testing.T) {
	const mtu = 128
	rng := rand.New(rand.NewSource(3))
	client, server := newHandler(t, mtu, 4), newHandler(t, mtu, 4)
	// Probing requires loss recovery: the probe octet is unacceptable to the peer
	// and must be retransmitted until it is not. A nop policy is enough to enable
	// probing here; resending it is exercised where the timer itself lives.
	client.SetPolicy(nopLoss{}, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])
	buffered := stallZeroWindow(t, client, server, buf[:])

	// The server application reads, reopening its window, but the resulting
	// window update never reaches the client: it is emitted and dropped.
	rbuf := make([]byte, mtu)
	if _, err := server.Read(rbuf); err != nil {
		t.Fatal("server read:", err)
	}
	clear(buf[:])
	if lost, err := server.Send(buf[:]); err != nil {
		t.Fatal("server send:", err)
	} else if lost == 0 {
		t.Fatal("expected a window update to drop")
	}
	if client.scb.snd.WND != 0 {
		t.Fatal("client must still believe the window is closed")
	}

	// Only a probe can break the stall now. Find it.
	probe := 0
	for attempt := 1; attempt <= 8 && probe == 0; attempt++ {
		clear(buf[:])
		n, err := client.Send(buf[:])
		if err != nil {
			t.Fatalf("attempt %d: client send: %s", attempt, err)
		}
		if n > 0 {
			probe = n
			seg := mustSegment(t, buf[:n], n-sizeHeaderTCP)
			// One octet, because a bare ACK draws no reply from the peer.
			if seg.DATALEN != 1 {
				t.Errorf("probe carries %d octets, want exactly 1", seg.DATALEN)
			}
			if seg.SEQ != client.scb.snd.UNA {
				t.Errorf("probe SEQ=%d, want snd.UNA=%d", seg.SEQ, client.scb.snd.UNA)
			}
			// The peer cannot buffer it, which is what forces it to answer.
			if err = server.Recv(buf[:n]); err != nil && err != lneto.ErrBufferFull {
				t.Fatalf("server rejected the probe: %s", err)
			}
		}
	}
	if probe == 0 {
		t.Fatal("no zero-window probe emitted; connection is deadlocked")
	}

	// The probe must draw out a fresh window update that resumes transmission.
	clear(buf[:])
	m, err := server.Send(buf[:])
	if err != nil {
		t.Fatal("server send after probe:", err)
	}
	if m == 0 {
		t.Fatal("probe drew no response from the peer")
	}
	if err = client.Recv(buf[:m]); err != nil {
		t.Fatal("client recv window update:", err)
	}
	if client.scb.snd.WND == 0 {
		t.Fatal("send window still closed after the probe was answered")
	}
	clear(buf[:])
	n, err := client.Send(buf[:])
	if err != nil {
		t.Fatal("client send after recovery:", err)
	}
	if n <= sizeHeaderTCP {
		t.Fatalf("expected queued data (%d octets) to flow after recovery", buffered)
	}
}

// TestZeroWindowProbeHandsOffToRetransmission verifies probing does not repeat
// on its own. One probe leaves an octet unacknowledged, which turns an
// unprobeable stall into a retransmittable one, and spacing further probes is
// then the retransmission timer's job rather than something this clock-free
// package tries to time itself.
func TestZeroWindowProbeHandsOffToRetransmission(t *testing.T) {
	const mtu = 128
	rng := rand.New(rand.NewSource(9))
	client, server := newHandler(t, mtu, 4), newHandler(t, mtu, 4)
	// Probing requires loss recovery: the probe octet is unacceptable to the peer
	// and must be retransmitted until it is not. A nop policy is enough to enable
	// probing here; resending it is exercised where the timer itself lives.
	client.SetPolicy(nopLoss{}, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])
	stallZeroWindow(t, client, server, buf[:])

	probes := 0
	for range 32 {
		clear(buf[:])
		n, err := client.Send(buf[:])
		if err != nil {
			t.Fatal("client send:", err)
		}
		if n > 0 {
			probes++
		}
	}
	if probes != 1 {
		t.Fatalf("emitted %d probes over 32 stalled attempts, want exactly 1", probes)
	}
	// The probe is what makes the stall retransmittable from here on.
	if client.scb.snd.UNA == client.scb.snd.NXT {
		t.Error("probe left nothing outstanding for the retransmission timer to resend")
	}
	if got := Sizeof(client.scb.snd.UNA, client.scb.snd.NXT); got != 1 {
		t.Errorf("probe left %d octets outstanding, want 1", got)
	}
}
