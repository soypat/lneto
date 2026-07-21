package tcp_test

import (
	"testing"

	"github.com/soypat/lneto/tcp"
)

// bigWSHandler builds a Handler with a receive/transmit buffer larger than the
// 65535-byte unscaled window ceiling, so window scaling is observable.
func bigWSHandler(t *testing.T, windowScaling bool) *tcp.Handler {
	t.Helper()
	const bufSize = 200_000 // > 65535 so a scaled window is required to advertise it all.
	h := new(tcp.Handler)
	if err := h.SetBuffers(make([]byte, bufSize), make([]byte, bufSize), 256); err != nil {
		t.Fatalf("SetBuffers: %v", err)
	}
	if err := h.EnableWindowScaling(windowScaling); err != nil {
		t.Fatalf("EnableWindowScaling: %v", err)
	}
	return h
}

// wsStep sends one segment from -> to, returning the number of bytes moved.
func wsStep(t *testing.T, from, to *tcp.Handler, buf []byte) int {
	t.Helper()
	n, err := from.Send(buf)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if n == 0 {
		return 0
	}
	if err := to.Recv(buf[:n]); err != nil {
		t.Fatalf("recv: %v", err)
	}
	return n
}

func wsOpenAndHandshake(t *testing.T, client, server *tcp.Handler) {
	t.Helper()
	if err := server.OpenListen(9000, 0); err != nil {
		t.Fatalf("OpenListen: %v", err)
	}
	if err := client.OpenActive(40000, 9000, 0); err != nil {
		t.Fatalf("OpenActive: %v", err)
	}
	buf := make([]byte, 1500)
	wsStep(t, client, server, buf) // SYN
	wsStep(t, server, client, buf) // SYN-ACK
	wsStep(t, client, server, buf) // ACK
	if client.State() != tcp.StateEstablished || server.State() != tcp.StateEstablished {
		t.Fatalf("handshake incomplete: client=%s server=%s", client.State(), server.State())
	}
}

// TestWindowScalingNegotiatedAllowsLargeWindow verifies that when both peers
// offer RFC 7323 window scaling the sender learns a send window larger than the
// 65535-byte unscaled ceiling (the server's ~200 KB receive buffer).
func TestWindowScalingNegotiatedAllowsLargeWindow(t *testing.T) {
	client, server := bigWSHandler(t, true), bigWSHandler(t, true)
	wsOpenAndHandshake(t, client, server)

	if !client.WindowScalingEnabled() || !server.WindowScalingEnabled() {
		t.Fatalf("window scaling not negotiated: client=%v server=%v",
			client.WindowScalingEnabled(), server.WindowScalingEnabled())
	}

	// Push data so the server replies with an established-state ACK carrying its
	// (scaled) window, which updates the client's view of the send window.
	buf := make([]byte, 1500)
	if _, err := client.Write(make([]byte, 4096)); err != nil {
		t.Fatalf("write: %v", err)
	}
	wsStep(t, client, server, buf) // data
	wsStep(t, server, client, buf) // ACK with scaled window

	if got := client.SendWindow(); got <= 65535 {
		t.Errorf("send window %d did not exceed the unscaled ceiling; scaling not applied", got)
	}
}

// TestWindowScalingNotNegotiatedCapsWindow verifies that if one peer does not
// offer window scaling the option is not negotiated and the send window stays
// within the 65535-byte unscaled ceiling.
func TestWindowScalingNotNegotiatedCapsWindow(t *testing.T) {
	client, server := bigWSHandler(t, true), bigWSHandler(t, false) // server declines.
	wsOpenAndHandshake(t, client, server)

	if client.WindowScalingEnabled() || server.WindowScalingEnabled() {
		t.Fatalf("window scaling must not be negotiated when a peer declines: client=%v server=%v",
			client.WindowScalingEnabled(), server.WindowScalingEnabled())
	}

	buf := make([]byte, 1500)
	if _, err := client.Write(make([]byte, 4096)); err != nil {
		t.Fatalf("write: %v", err)
	}
	wsStep(t, client, server, buf)
	wsStep(t, server, client, buf)

	if got := client.SendWindow(); got > 65535 {
		t.Errorf("send window %d exceeded the unscaled ceiling without negotiation", got)
	}
}
