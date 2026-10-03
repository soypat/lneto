package internet

import (
	"math/rand"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
)

// setupListener replaces the server conn from setupClientServer with a listener on port 80.
func setupListener(t *testing.T, clientStack, serverStack *StackIPv4, clientConn *tcp.Conn, listener *tcp.Listener) {
	t.Helper()
	var serverConn tcp.Conn
	setupClientServer(t, rand.New(rand.NewSource(1)), clientStack, serverStack, clientConn, &serverConn)
	serverConn.Abort()
	if err := listener.Reset(80, newMockTCPPool(2, 3, 2048)); err != nil {
		t.Fatal(err)
	}
	if err := serverStack.Register4(listener); err != nil {
		t.Fatal(err)
	}
}

// pumpNodes exchanges packets between a and b until neither has anything to send.
// Errors are logged, not fatal: callers assert on resulting state.
func pumpNodes(t *testing.T, a, b lneto.StackNode, buf []byte) {
	t.Helper()
	for range 16 {
		quiet := true
		for _, pair := range [2][2]lneto.StackNode{{a, b}, {b, a}} {
			n, err := pair[0].Encapsulate(buf, 0, 0)
			if err != nil {
				t.Log("pump encapsulate:", err)
			}
			if n == 0 {
				continue
			}
			quiet = false
			if err = pair[1].Demux(buf[:n], 0); err != nil {
				t.Log("pump demux:", err)
			}
		}
		if quiet {
			return
		}
	}
}

// M20: closing a listener must not kill connections it already accepted.
func TestListener_CloseKeepsAcceptedConns(t *testing.T) {
	var clientStack, serverStack StackIPv4
	var clientConn tcp.Conn
	var listener tcp.Listener
	setupListener(t, &clientStack, &serverStack, &clientConn, &listener)
	var buf [2048]byte
	pumpNodes(t, &clientStack, &serverStack, buf[:])
	accepted, _, err := listener.TryAccept()
	if err != nil {
		t.Fatal("TryAccept:", err)
	}

	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}

	// Inbound: client data reaches accepted conn.
	if _, err = clientConn.Write([]byte("in")); err != nil {
		t.Fatal(err)
	}
	pumpNodes(t, &clientStack, &serverStack, buf[:])
	if got := accepted.BufferedInput(); got != 2 {
		t.Errorf("accepted conn got %d inbound bytes after listener Close, want 2", got)
	}
	// Outbound: accepted conn data reaches client.
	if _, err = accepted.Write([]byte("out")); err != nil {
		t.Fatal("accepted write after listener Close:", err)
	}
	pumpNodes(t, &clientStack, &serverStack, buf[:])
	if got := clientConn.BufferedInput(); got != 3 {
		t.Errorf("client got %d bytes from accepted conn after listener Close, want 3", got)
	}
}

// M4: a connection that receives data and FIN before Accept must still be accepted with its data.
func TestListener_AcceptHalfClosedConn(t *testing.T) {
	var clientStack, serverStack StackIPv4
	var clientConn tcp.Conn
	var listener tcp.Listener
	setupListener(t, &clientStack, &serverStack, &clientConn, &listener)
	var buf [2048]byte
	pumpNodes(t, &clientStack, &serverStack, buf[:])
	if listener.NumberOfReadyToAccept() != 1 {
		t.Fatal("handshake did not complete")
	}

	req := []byte("request")
	if _, err := clientConn.Write(req); err != nil {
		t.Fatal(err)
	}
	if err := clientConn.Close(); err != nil {
		t.Fatal(err)
	}
	pumpNodes(t, &clientStack, &serverStack, buf[:])

	accepted, _, err := listener.TryAccept()
	if err != nil {
		t.Fatalf("TryAccept of half-closed conn: %v (client state %s)", err, clientConn.State())
	}
	if got := accepted.BufferedInput(); got != len(req) {
		t.Fatalf("accepted conn has %d buffered bytes, want %d", got, len(req))
	}
}
