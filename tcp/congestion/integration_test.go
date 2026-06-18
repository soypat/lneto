package congestion_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/congestion"
)

// newBigHandler returns a Handler with large buffers so the peer's advertised
// receive window does not become the binding constraint before a (small)
// congestion window does. 32 KiB keeps the advertised window under the 2**16
// limit.
func newBigHandler(t *testing.T) *tcp.Handler {
	t.Helper()
	h := new(tcp.Handler)
	if err := h.SetBuffers(make([]byte, 1<<15), make([]byte, 1<<15), 16); err != nil {
		t.Fatal(err)
	}
	return h
}

// handshake performs a 3-way handshake between client and server using only the
// exported Handler API.
func handshake(t *testing.T, client, server *tcp.Handler, buf []byte) {
	t.Helper()
	step := func(from, to *tcp.Handler) {
		n, err := from.Send(buf)
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		if n == 0 {
			return
		}
		if err := to.Recv(buf[:n]); err != nil {
			t.Fatalf("recv: %v", err)
		}
	}
	step(client, server) // SYN
	step(server, client) // SYN-ACK
	step(client, server) // ACK
	if client.State() != tcp.StateEstablished || server.State() != tcp.StateEstablished {
		t.Fatalf("handshake incomplete: client=%s server=%s", client.State(), server.State())
	}
}

func openPair(t *testing.T, client, server *tcp.Handler) {
	t.Helper()
	rng := rand.New(rand.NewSource(1))
	if err := server.OpenListen(uint16(rng.Uint32()), 0); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenActive(uint16(rng.Uint32()), server.LocalPort(), 0); err != nil {
		t.Fatal(err)
	}
}

// TestHandlerCongestionGating proves the controller is wired into the Handler
// send path: with a tiny congestion window the client cannot dump its whole
// write buffer at once, and the window grows once the peer acknowledges data.
func TestHandlerCongestionGating(t *testing.T) {
	const mtu = ethernet.MaxMTU
	client, server := newBigHandler(t), newBigHandler(t)

	clock := time.Unix(0, 0)
	var cubic congestion.CUBIC
	if err := cubic.Configure(congestion.CUBICConfig{InitialCwnd: 2, Now: func() time.Time { return clock }}); err != nil {
		t.Fatal(err)
	}
	if err := client.SetCongestionControl(&cubic); err != nil {
		t.Fatal(err)
	}

	openPair(t, client, server)
	var buf [mtu]byte
	handshake(t, client, server, buf[:])

	// Changing the controller mid-connection must be rejected.
	if err := client.SetCongestionControl(nil); err == nil {
		t.Fatal("SetCongestionControl must fail on an open connection")
	}

	cwnd0 := int(cubic.CongestionWindow())
	if cwnd0 <= 0 {
		t.Fatalf("congestion window not initialized: %d", cwnd0)
	}

	// Queue more data than the congestion window allows (but within the buffer).
	payload := make([]byte, 24*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	written, err := client.Write(payload)
	if err != nil {
		t.Fatal("client write:", err)
	}

	// Burst-send WITHOUT delivering any ACK. The client must stop once in-flight
	// data reaches the congestion window. New-data bytes sent are measured by the
	// drain of the unsent buffer (no need to know the header size).
	unsent0 := client.BufferedUnsent()
	var segs [][]byte
	for range 64 {
		clock = clock.Add(time.Millisecond)
		n, err := client.Send(buf[:])
		if err != nil {
			t.Fatalf("client send: %v", err)
		}
		if n == 0 {
			break // congestion window exhausted: gated.
		}
		seg := make([]byte, n)
		copy(seg, buf[:n])
		segs = append(segs, seg)
	}
	sent := unsent0 - client.BufferedUnsent()
	if sent == 0 {
		t.Fatal("client sent no data at all")
	}
	if sent >= written {
		t.Fatalf("congestion control did not gate: sent all %d buffered bytes", written)
	}
	// Sent ≈ congestion window. Allow one max-size Ethernet segment of slack.
	if sent > cwnd0+int(ethernet.MaxMTU) {
		t.Errorf("client sent %d bytes, far exceeding congestion window %d", sent, cwnd0)
	}

	// Deliver the in-flight data and let the server acknowledge it.
	for _, seg := range segs {
		if err := server.Recv(seg); err != nil {
			t.Fatalf("server recv: %v", err)
		}
	}
	for range 8 { // drain server's read buffer so it keeps a large window.
		if _, err := server.Read(buf[:]); err != nil {
			break
		}
	}
	clock = clock.Add(20 * time.Millisecond)
	n, err := server.Send(buf[:]) // server emits cumulative ACK.
	if err != nil {
		t.Fatalf("server send ACK: %v", err)
	}
	if n > 0 {
		if err := client.Recv(buf[:n]); err != nil {
			t.Fatalf("client recv ACK: %v", err)
		}
	}

	if cwnd1 := int(cubic.CongestionWindow()); cwnd1 <= cwnd0 {
		t.Errorf("congestion window did not grow after ACK: %d -> %d", cwnd0, cwnd1)
	}
	// The client may now send again (in-flight data was acknowledged).
	clock = clock.Add(time.Millisecond)
	unsent := client.BufferedUnsent()
	if _, err := client.Send(buf[:]); err != nil {
		t.Fatalf("client resume send: %v", err)
	}
	if client.BufferedUnsent() >= unsent {
		t.Error("client could not resume sending new data after ACK opened the window")
	}
}

// TestHandlerBBRWiring confirms a BBR controller installed on the Handler
// observes a real data exchange and forms bandwidth/RTT estimates.
func TestHandlerBBRWiring(t *testing.T) {
	const mtu = ethernet.MaxMTU
	client, server := newBigHandler(t), newBigHandler(t)

	clock := time.Unix(0, 0)
	var bbr congestion.BBR
	if err := bbr.Configure(congestion.BBRConfig{InitialCwnd: 10, Now: func() time.Time { return clock }}); err != nil {
		t.Fatal(err)
	}
	if err := client.SetCongestionControl(&bbr); err != nil {
		t.Fatal(err)
	}

	openPair(t, client, server)
	var buf [mtu]byte
	handshake(t, client, server, buf[:])

	// Two round trips: each sends a data segment which the server ACKs 25ms
	// later. The first completed RTT sample anchors the delivery-rate interval;
	// the second produces a bandwidth estimate.
	for round := range 2 {
		if _, err := client.Write(make([]byte, 4096)); err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(time.Millisecond)
		n, err := client.Send(buf[:])
		if err != nil || n == 0 {
			t.Fatalf("round %d: client send data: n=%d err=%v", round, n, err)
		}
		if err := server.Recv(buf[:n]); err != nil {
			t.Fatalf("round %d: server recv: %v", round, err)
		}
		if server.BufferedInput() == 0 {
			t.Fatalf("round %d: server received no payload", round)
		}
		clock = clock.Add(25 * time.Millisecond)
		n, err = server.Send(buf[:])
		if err != nil {
			t.Fatalf("round %d: server send ACK: %v", round, err)
		}
		if n > 0 {
			if err := client.Recv(buf[:n]); err != nil {
				t.Fatalf("round %d: client recv ACK: %v", round, err)
			}
		}
		if _, err := server.Read(buf[:]); err != nil { // drain for next round.
			t.Fatalf("round %d: server read: %v", round, err)
		}
	}

	if bbr.MinRTT() <= 0 {
		t.Error("BBR did not measure an RTT from the exchange")
	}
	if bbr.BandwidthEstimate() <= 0 {
		t.Error("BBR did not estimate bandwidth from the exchange")
	}
}
