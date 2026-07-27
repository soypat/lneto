package tcp_test

// This file is deliberately in the external test package: it can only reach
// exported API, so it fails to compile if [tcp.LossRecovery] ever stops being
// implementable from outside package tcp. Loss recovery, congestion control and
// similar policy are meant to be factorable into their own packages, and that
// property is easy to break by accident with an unexported type in a hook
// signature.

import (
	"testing"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/tcp"
)

// windowPolicy is a minimal congestion-control-shaped [tcp.LossRecovery]
// written against exported API only: it withholds new data once the octets in
// flight reach a fixed window, which is the core of any window-based
// controller.
type windowPolicy struct {
	window   tcp.Size
	resets   int
	preTx    int
	postTx   int
	preRx    int
	lastHeld bool
}

var _ tcp.LossRecovery = (*windowPolicy)(nil)

func (p *windowPolicy) Reset()              { p.resets++ }
func (p *windowPolicy) NextDeadline() int64 { return 0 }

func (p *windowPolicy) PreRx(incoming tcp.Segment, now int64) tcp.RxDirective {
	p.preRx++
	return tcp.RxDirective{Keep: true}
}

func (p *windowPolicy) PreTx(intent tcp.TxIntent) tcp.TxDirective {
	p.preTx++
	p.lastHeld = intent.InFlight >= p.window
	return tcp.TxDirective{HoldNew: p.lastHeld}
}

func (p *windowPolicy) PostTx(outgoing tcp.Segment, now int64) { p.postTx++ }

// TestLossRecovery_ExternallyImplementable drives a connection with a policy
// defined outside package tcp, proving the hooks carry enough exported state to
// implement window-based congestion control there.
func TestLossRecovery_ExternallyImplementable(t *testing.T) {
	const mtu = ethernet.MaxMTU
	client, server := new(tcp.Handler), new(tcp.Handler)
	for _, h := range []*tcp.Handler{client, server} {
		if err := h.SetBuffers(make([]byte, mtu), make([]byte, mtu), 3); err != nil {
			t.Fatal(err)
		}
	}
	policy := &windowPolicy{window: 4} // Tiny window: hold after 4 octets in flight.
	client.SetLossRecovery(policy, func() int64 { return 1 })

	if err := server.OpenListen(80, 0); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenActive(1234, 80, 0); err != nil {
		t.Fatal(err)
	}
	if policy.resets == 0 {
		t.Fatal("Reset not called on open")
	}

	buf := make([]byte, mtu)
	relay := func(from, to *tcp.Handler) int {
		t.Helper()
		clear(buf)
		n, err := from.Send(buf)
		if err != nil {
			t.Fatal("send:", err)
		}
		if n > 0 {
			if err = to.Recv(buf[:n]); err != nil {
				t.Fatal("recv:", err)
			}
		}
		return n
	}
	relay(client, server) // SYN
	relay(server, client) // SYN-ACK
	relay(client, server) // ACK
	if client.State() != tcp.StateEstablished || server.State() != tcp.StateEstablished {
		t.Fatalf("handshake failed: client=%s server=%s", client.State(), server.State())
	}
	if policy.preTx == 0 || policy.postTx == 0 || policy.preRx == 0 {
		t.Fatalf("hooks not exercised: preRx=%d preTx=%d postTx=%d", policy.preRx, policy.preTx, policy.postTx)
	}

	// Nothing is in flight yet, so the policy admits data.
	data := []byte("0123456789")
	if _, err := client.Write(data); err != nil {
		t.Fatal("write:", err)
	}
	clear(buf)
	n, err := client.Send(buf) // Sent, but deliberately not delivered: stays unacknowledged.
	if err != nil {
		t.Fatal("send first segment:", err)
	}
	if n == 0 {
		t.Fatal("expected a data segment while under the window")
	}

	// That segment is unacknowledged and exceeds the window, so newly queued
	// data must be withheld.
	if _, err = client.Write(data); err != nil {
		t.Fatal("write second chunk:", err)
	}
	before := client.BufferedUnsent()
	if before == 0 {
		t.Fatal("test needs queued data to observe the hold")
	}
	clear(buf)
	n, err = client.Send(buf)
	if err != nil {
		t.Fatal("send under hold:", err)
	}
	if !policy.lastHeld {
		t.Fatal("policy should have observed InFlight >= window")
	}
	if n != 0 {
		t.Fatalf("expected nothing sent while holding, got %d bytes", n)
	}
	if client.BufferedUnsent() != before {
		t.Fatalf("held data must stay buffered: got %d, want %d", client.BufferedUnsent(), before)
	}
}
