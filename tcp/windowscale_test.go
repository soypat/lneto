package tcp

import (
	"math"
	"math/rand"
	"testing"
)

func TestWindowScaleFor(t *testing.T) {
	for _, test := range []struct {
		wnd  Size
		want uint8
	}{
		{wnd: 0, want: 0},
		{wnd: 1024, want: 0},
		{wnd: math.MaxUint16, want: 0},
		{wnd: math.MaxUint16 + 1, want: 1},
		{wnd: 1 << 17, want: 2},
		{wnd: 1 << 20, want: 5},
		{wnd: math.MaxUint16 << maxWindShift, want: maxWindShift},
		{wnd: math.MaxUint32, want: maxWindShift}, // Capped, not grown further.
	} {
		if got := windowScaleFor(test.wnd); got != test.want {
			t.Errorf("windowScaleFor(%d) = %d, want %d", test.wnd, got, test.want)
		}
		if shift := windowScaleFor(test.wnd); test.wnd>>shift > math.MaxUint16 && shift != maxWindShift {
			t.Errorf("windowScaleFor(%d) = %d still does not fit the window field", test.wnd, shift)
		}
	}
}

// TestWindowScaleNegotiation verifies scaling is enabled only when both sides
// offer the option, which is what RFC 7323 §2.2 requires, and that neither
// direction is scaled on the strength of one side's offer alone.
func TestWindowScaleNegotiation(t *testing.T) {
	for _, test := range []struct {
		name      string
		weSent    bool
		peerSent  bool
		peerShift uint8
		ourShift  uint8
		wantSnd   uint8
		wantRcv   uint8
	}{
		{name: "neither offers"},
		{name: "only we offer", weSent: true, ourShift: 3},
		{name: "only peer offers", peerSent: true, peerShift: 5},
		{
			name: "both offer", weSent: true, ourShift: 3, peerSent: true, peerShift: 5,
			wantSnd: 5, wantRcv: 3,
		},
		{
			// RFC 7323 §2.3: a shift above the maximum is clamped, not rejected.
			name: "peer offers an oversized shift", weSent: true, ourShift: 2,
			peerSent: true, peerShift: 20,
			wantSnd: maxWindShift, wantRcv: 2,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var tcb ControlBlock
			// Order is deliberately peer-then-us here and us-then-peer below, since a
			// passive open sees the peer's SYN first and an active open its own.
			if test.peerSent {
				tcb.recvWindowScale(test.peerShift)
			}
			if test.weSent {
				tcb.sentWindowScale(test.ourShift)
			}
			if snd, rcv := tcb.WindowScales(); snd != test.wantSnd || rcv != test.wantRcv {
				t.Errorf("shifts after peer-first = (%d,%d), want (%d,%d)", snd, rcv, test.wantSnd, test.wantRcv)
			}

			var rev ControlBlock
			if test.weSent {
				rev.sentWindowScale(test.ourShift)
			}
			if test.peerSent {
				rev.recvWindowScale(test.peerShift)
			}
			if snd, rcv := rev.WindowScales(); snd != test.wantSnd || rcv != test.wantRcv {
				t.Errorf("shifts after us-first = (%d,%d), want (%d,%d)", snd, rcv, test.wantSnd, test.wantRcv)
			}
		})
	}
}

// TestAdvertisedWindowScalesDown verifies the window put on the wire is the true
// window shifted down, rounded down rather than up, and always inside the 16-bit
// field.
func TestAdvertisedWindowScalesDown(t *testing.T) {
	var tcb ControlBlock
	tcb.sentWindowScale(4)
	tcb.recvWindowScale(0)
	if _, rcv := tcb.WindowScales(); rcv != 4 {
		t.Fatalf("recv shift = %d, want 4", rcv)
	}
	for _, test := range []struct{ trueWnd, want Size }{
		{trueWnd: 0, want: 0},
		{trueWnd: 15, want: 0}, // Rounds down: advertising 1 would overstate space.
		{trueWnd: 16, want: 1},
		{trueWnd: 31, want: 1},
		{trueWnd: 1 << 20, want: math.MaxUint16}, // 1<<16 does not fit the field.
	} {
		if got := tcb.advertisedWindow(test.trueWnd); got != test.want {
			t.Errorf("advertisedWindow(%d) = %d, want %d", test.trueWnd, got, test.want)
		}
	}
	// A window too large for even the negotiated shift is clamped, never truncated
	// into a tiny one.
	if got := tcb.advertisedWindow(math.MaxUint32); got != math.MaxUint16 {
		t.Errorf("advertisedWindow(max) = %d, want it clamped to %d", got, math.MaxUint16)
	}
}

// TestWindowScaleEndToEnd verifies two handlers negotiate the option across a real
// handshake and that the sender's view of the peer's window is the scaled-up value,
// exceeding what the 16-bit field could have carried.
func TestWindowScaleEndToEnd(t *testing.T) {
	// A receive buffer past 64KiB is what forces a non-zero shift.
	const bufSize = 256 * 1024
	const mtu = 1500
	rng := rand.New(rand.NewSource(4))
	client, server := new(Handler), new(Handler)
	for _, h := range []*Handler{client, server} {
		if err := h.SetBuffers(make([]byte, bufSize), make([]byte, bufSize), 4); err != nil {
			t.Fatal(err)
		}
	}
	if err := server.OpenListen(uint16(rng.Uint32()), 0); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenActive(uint16(rng.Uint32()), server.LocalPort(), 0); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, mtu)
	relay := func(from, to *Handler) Segment {
		t.Helper()
		clear(buf)
		n, err := from.Send(buf)
		if err != nil {
			t.Fatal("send:", err)
		}
		if n == 0 {
			t.Fatal("expected a segment")
		}
		seg := mustSegment(t, buf[:n], n-sizeHeaderTCP)
		if err = to.Recv(buf[:n]); err != nil {
			t.Fatal("recv:", err)
		}
		return seg
	}
	syn := relay(client, server)
	synack := relay(server, client)
	ack := relay(client, server)

	// The handshake carries windows unscaled (RFC 7323 §2.2), so each must be the
	// receive buffer clamped to the header field, never the shifted-down value a
	// later segment would carry.
	wantSynWnd := Size(math.MaxUint16)
	if bufSize < math.MaxUint16 {
		wantSynWnd = bufSize
	}
	for name, seg := range map[string]Segment{"SYN": syn, "SYN-ACK": synack} {
		if seg.WND != wantSynWnd {
			t.Errorf("%s window = %d, want the unscaled %d", name, seg.WND, wantSynWnd)
		}
	}

	wantShift := windowScaleFor(bufSize)
	if wantShift == 0 {
		t.Fatal("fixture must force a non-zero shift")
	}
	for name, h := range map[string]*Handler{"client": client, "server": server} {
		snd, rcv := h.scb.WindowScales()
		if snd != wantShift || rcv != wantShift {
			t.Errorf("%s shifts = (%d,%d), want (%d,%d)", name, snd, rcv, wantShift, wantShift)
		}
	}

	// From the first post-handshake segment the advertised window is scaled, so the
	// sender sees more space than the field could express.
	if ack.WND > math.MaxUint16 {
		t.Errorf("ACK window %d exceeds the 16-bit field", ack.WND)
	}
	if got := server.scb.snd.WND; got <= math.MaxUint16 {
		t.Errorf("server's view of the peer window is %d, want a scaled window above %d",
			got, math.MaxUint16)
	}
	if got, want := server.scb.snd.WND, Size(ack.WND)<<wantShift; got != want {
		t.Errorf("server scaled the peer window to %d, want %d", got, want)
	}
}

// TestWindowScaleAllowsMoreThan64KInFlight is the property window scaling exists
// for: without it a sender can have at most 65535 octets outstanding, which caps
// throughput at that many octets per round trip no matter how much capacity the
// path has. With the option negotiated the receiver's advertised window, and so the
// data the sender may keep in flight, goes past that ceiling.
func TestWindowScaleAllowsMoreThan64KInFlight(t *testing.T) {
	const bufSize = 512 * 1024
	const mtu = 1500
	rng := rand.New(rand.NewSource(6))
	client, server := new(Handler), new(Handler)
	for _, h := range []*Handler{client, server} {
		if err := h.SetBuffers(make([]byte, bufSize), make([]byte, bufSize), 512); err != nil {
			t.Fatal(err)
		}
	}
	if err := server.OpenListen(uint16(rng.Uint32()), 0); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenActive(uint16(rng.Uint32()), server.LocalPort(), 0); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, mtu)
	relay := func(from, to *Handler) int {
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
	if client.State() != StateEstablished {
		t.Fatalf("handshake failed: %s", client.State())
	}

	payload := make([]byte, 300*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	if _, err := client.Write(payload); err != nil {
		t.Fatal("write:", err)
	}

	// The SYN-ACK carried an unscaled window, so the sender is still held to the
	// 16-bit ceiling until the receiver advertises a scaled one. Exchange one
	// segment to get that first post-handshake window across.
	inFlight := 0
	if n := relay(client, server); n > sizeHeaderTCP {
		inFlight += n - sizeHeaderTCP
	}
	relay(server, client) // Scaled window update.
	if client.scb.snd.WND <= math.MaxUint16 {
		t.Fatalf("peer window is %d after the first update, want it scaled past %d",
			client.scb.snd.WND, math.MaxUint16)
	}

	// Now emit without delivering, so everything sent stays outstanding and only
	// the peer's advertised window limits how much may be in flight.
	for range 1024 {
		n, err := client.Send(buf)
		if err != nil {
			t.Fatal("send data:", err)
		}
		if n == 0 {
			break // Window exhausted or nothing left to send.
		}
		inFlight += n - sizeHeaderTCP
	}
	if inFlight <= math.MaxUint16 {
		t.Fatalf("only %d octets in flight, want more than the unscaled ceiling of %d",
			inFlight, math.MaxUint16)
	}
	// Unacknowledged data must itself exceed the ceiling, which is the limit the
	// peer's advertised window imposes. The first segment was acknowledged, so this
	// is a little under the total emitted.
	if outstanding := Sizeof(client.scb.snd.UNA, client.scb.snd.NXT); outstanding <= math.MaxUint16 {
		t.Errorf("only %d octets outstanding, want more than %d", outstanding, math.MaxUint16)
	}
	t.Logf("%d octets in flight with shift %d, %.1fx the unscaled ceiling",
		inFlight, client.scb.rcvWindShift, float64(inFlight)/math.MaxUint16)
}
