package tcp

import (
	"io"
	"math/rand"
	"net"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

// pumpHandlers exchanges segments between a and b until both have nothing to send
// or stop (if non-nil) returns true after a segment is received.
func pumpHandlers(t *testing.T, a, b *Handler, buf []byte, stop func() bool) {
	t.Helper()
	for range 16 {
		quiet := true
		for _, pair := range [2][2]*Handler{{a, b}, {b, a}} {
			n, err := pair[0].Send(buf)
			if err != nil && err != net.ErrClosed {
				t.Fatal("pump send:", err)
			} else if n == 0 {
				continue
			}
			quiet = false
			if err = pair[1].Recv(buf[:n]); err != nil && err != net.ErrClosed {
				t.Fatal("pump recv:", err)
			}
			if stop != nil && stop() {
				return
			}
		}
		if quiet {
			return
		}
	}
	t.Fatal("pump did not quiesce")
}

// M4: in CLOSE-WAIT the local side must not send FIN until the application calls Close.
func TestHandler_CloseWaitNoAutoFIN(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(1))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	// Client half-closes. Server gets FIN and enters CLOSE-WAIT.
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	n, err := client.Send(buf[:])
	if err != nil || n == 0 {
		t.Fatal("client FIN send:", n, err)
	}
	if err = server.Recv(buf[:n]); err != nil {
		t.Fatal(err)
	} else if server.State() != StateCloseWait {
		t.Fatal("server not in CLOSE-WAIT:", server.State())
	}

	// Server application has not written nor closed: only an ACK may leave.
	for range 3 {
		n, err = server.Send(buf[:])
		if err != nil {
			t.Fatal(err)
		} else if n == 0 {
			continue
		}
		_, flags := mustFrame(t, buf[:n]).OffsetAndFlags()
		if flags.HasAny(FlagFIN) {
			t.Fatalf("server sent FIN in CLOSE-WAIT without Close (flags %s)", flags)
		}
		if err = client.Recv(buf[:n]); err != nil {
			t.Fatal(err)
		}
	}
	if server.State() != StateCloseWait {
		t.Fatal("server left CLOSE-WAIT without Close:", server.State())
	}

	// Late response must still reach the half-closed client.
	resp := []byte("late response")
	if _, err = server.Write(resp); err != nil {
		t.Fatal("server write in CLOSE-WAIT:", err)
	}
	pumpHandlers(t, server, client, buf[:], nil)
	got := make([]byte, len(resp))
	n, _ = client.Read(got)
	if string(got[:n]) != string(resp) {
		t.Fatalf("client got %q, want %q", got[:n], resp)
	}
}

// M25: after the peer closes cleanly Read drains buffered data then returns io.EOF.
func TestConn_ReadEOFAfterPeerClose(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(2))
	conn := newConfiguredConn(t)
	server := conn.InternalHandler()
	client := newHandler(t, mtu, 3)
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	data := []byte("bye")
	if _, err := client.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	// Stop at CLOSED: see TestHandler_ClosedNoSpuriousSYN.
	pumpHandlers(t, client, server, buf[:], func() bool { return server.State() == StateClosed })

	got := make([]byte, 16)
	n, err := conn.Read(got)
	if err != nil || string(got[:n]) != string(data) {
		t.Fatalf("first read: got %q, %v; want %q, nil", got[:n], err, data)
	}
	n, err = conn.Read(got)
	if n != 0 || err != io.EOF {
		t.Fatalf("read after clean peer close: got n=%d err=%v, want 0, io.EOF (server state %s)", n, err, server.State())
	}
}

// A passive handler that closed normally must not send a SYN afterwards.
// AwaitingSynSend is true for any CLOSED handler with a remote port set.
func TestHandler_ClosedNoSpuriousSYN(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(3))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	pumpHandlers(t, client, server, buf[:], func() bool { return server.State() == StateCloseWait })
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	pumpHandlers(t, client, server, buf[:], func() bool { return server.State() == StateClosed })
	if server.State() != StateClosed {
		t.Fatal("server did not reach CLOSED:", server.State())
	}

	n, _ := server.Send(buf[:])
	if n > 0 {
		_, flags := mustFrame(t, buf[:n]).OffsetAndFlags()
		t.Errorf("closed passive handler sent %s segment, state now %s", flags, server.State())
	}
}

func mustFrame(t *testing.T, b []byte) Frame {
	t.Helper()
	frm, err := NewFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	return frm
}
