package congestion

import (
	"testing"

	"github.com/soypat/lneto/tcp"
)

// This file is the working proof of the loss-recovery seam: a congestion
// controller implemented in its own package, using only exported tcp API,
// throttling a real connection end to end.

const (
	connMTU = 1500
	connBuf = 8000
	// tcpHeaderLen is the length of a TCP header carrying no options.
	tcpHeaderLen = 20
)

// connPair returns two established handlers with the given policy installed on
// the client, plus a scratch packet buffer.
func connPair(t *testing.T, policy tcp.Policy, nanotime func() int64) (client, server *tcp.Handler, packet []byte) {
	t.Helper()
	client, server = new(tcp.Handler), new(tcp.Handler)
	for _, h := range []*tcp.Handler{client, server} {
		if err := h.SetBuffers(make([]byte, connBuf), make([]byte, connBuf), 8); err != nil {
			t.Fatal(err)
		}
	}
	if policy != nil {
		client.SetPolicy(policy, nanotime)
	}
	if err := server.OpenListen(80, 0); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenActive(1234, 80, 0); err != nil {
		t.Fatal(err)
	}
	packet = make([]byte, connMTU)
	relay(t, client, server, packet) // SYN
	relay(t, server, client, packet) // SYN-ACK
	relay(t, client, server, packet) // ACK
	if client.State() != tcp.StateEstablished || server.State() != tcp.StateEstablished {
		t.Fatalf("handshake failed: client=%s server=%s", client.State(), server.State())
	}
	return client, server, packet
}

// relay moves one segment from one handler to the other, returning the payload
// length transferred.
func relay(t *testing.T, from, to *tcp.Handler, packet []byte) int {
	t.Helper()
	clear(packet)
	n, err := from.Send(packet)
	if err != nil {
		t.Fatal("send:", err)
	}
	if n == 0 {
		return 0
	}
	if err = to.Recv(packet[:n]); err != nil {
		t.Fatal("recv:", err)
	}
	return n
}

// sendOnly transmits without delivering, so the data stays in flight.
func sendOnly(t *testing.T, h *tcp.Handler, packet []byte) int {
	t.Helper()
	clear(packet)
	n, err := h.Send(packet)
	if err != nil {
		t.Fatal("send:", err)
	}
	return n
}

// TestCUBIC_ThrottlesRealConnection drives an established connection with more
// data than the congestion window allows and verifies the controller stops the
// flow at the window, then resumes once the data is acknowledged. This
// exercises the whole path: TxIntent reporting octets in flight, the HoldNew
// directive, and the handler withholding payload.
func TestCUBIC_ThrottlesRealConnection(t *testing.T) {
	const initialSegments = 2
	cubic := new(CUBIC)
	if err := cubic.Configure(CUBICConfig{InitialCwnd: initialSegments}); err != nil {
		t.Fatal(err)
	}
	var clock int64
	client, server, packet := connPair(t, cubic, func() int64 {
		clock += int64(nanosPerSecond) / 1000 // 1ms per read.
		return clock
	})

	data := make([]byte, connBuf/2)
	for i := range data {
		data[i] = byte(i)
	}
	if _, err := client.Write(data); err != nil {
		t.Fatal("write:", err)
	}

	// Transmit without delivering: everything sent stays in flight.
	cwnd := cubic.CongestionWindow()
	var sent, segments int
	for range 32 {
		n := sendOnly(t, client, packet)
		if n == 0 {
			break // Withheld by congestion control.
		}
		sent += n - tcpHeaderLen
		segments++
	}
	if segments == 0 {
		t.Fatal("nothing was sent; the window should allow the first segments")
	}
	if segments >= 32 {
		t.Fatal("congestion control never withheld data")
	}
	if tcp.Size(sent) > cwnd {
		t.Errorf("sent %d octets with a congestion window of %d", sent, cwnd)
	}
	if client.BufferedUnsent() == 0 {
		t.Fatal("test needs data still queued to prove it was withheld")
	}
	held := client.BufferedUnsent()

	// A further attempt must stay blocked while the window is full.
	if n := sendOnly(t, client, packet); n != 0 {
		t.Errorf("sent %d bytes while the congestion window was full", n)
	}
	if client.BufferedUnsent() != held {
		t.Error("withheld data must remain queued")
	}
	_ = server // The peer is deliberately not fed here: see the resume test.
}

// TestCUBIC_ZeroAlloc verifies an installed congestion controller keeps the
// datapath allocation-free, which the charter requires of optional policy just
// as much as of the core.
func TestCUBIC_ZeroAlloc(t *testing.T) {
	cubic := new(CUBIC)
	if err := cubic.Configure(CUBICConfig{}); err != nil {
		t.Fatal(err)
	}
	var clock int64
	client, server, packet := connPair(t, cubic, func() int64 {
		clock += int64(nanosPerSecond) / 1000
		return clock
	})
	data := make([]byte, 512)
	readBuf := make([]byte, 512)
	allocs := testing.AllocsPerRun(100, func() {
		if _, err := client.Write(data); err != nil {
			t.Fatal("write:", err)
		}
		if n := relay(t, client, server, packet); n == 0 {
			t.Fatal("no data segment produced")
		}
		if _, err := server.Read(readBuf); err != nil {
			t.Fatal("read:", err)
		}
		relay(t, server, client, packet) // Acknowledgement.
	})
	if allocs != 0 {
		t.Errorf("congestion-controlled exchange allocated %v times, want 0", allocs)
	}
}

// TestCUBIC_ResumesAfterAcknowledgement verifies the hold is released once the
// peer acknowledges the outstanding data, so throttling is transient rather
// than a deadlock.
func TestCUBIC_ResumesAfterAcknowledgement(t *testing.T) {
	cubic := new(CUBIC)
	if err := cubic.Configure(CUBICConfig{InitialCwnd: 2}); err != nil {
		t.Fatal(err)
	}
	var clock int64
	client, server, packet := connPair(t, cubic, func() int64 {
		clock += int64(nanosPerSecond) / 1000
		return clock
	})

	data := make([]byte, connBuf/2)
	if _, err := client.Write(data); err != nil {
		t.Fatal("write:", err)
	}

	// Fill the window, delivering each segment so the server can acknowledge.
	var delivered int
	for range 32 {
		n := relay(t, client, server, packet)
		if n == 0 {
			break
		}
		delivered += n - tcpHeaderLen
	}
	if delivered == 0 {
		t.Fatal("no data reached the server")
	}
	heldBefore := client.BufferedUnsent()
	if heldBefore == 0 {
		t.Skip("all data fit within the initial window; nothing to resume")
	}

	// The server acknowledges, which advances snd.UNA and grows the window.
	if n := relay(t, server, client, packet); n == 0 {
		t.Fatal("expected an acknowledgement from the server")
	}
	if got := cubic.WindowSegments(); got <= 2 {
		t.Errorf("cwnd=%v after acknowledgement, want growth above the initial 2", got)
	}
	if n := sendOnly(t, client, packet); n == 0 {
		t.Error("flow did not resume after the window opened")
	}
	if client.BufferedUnsent() >= heldBefore {
		t.Error("expected previously withheld data to be sent after the ACK")
	}
}
