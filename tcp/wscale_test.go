package tcp

import (
	"bytes"
	"math/rand"
	"testing"
)

// synOptions parses the option block of a raw TCP frame and returns the MSS
// and window-scale values found, with ok flags for presence.
func synOptions(t *testing.T, frame []byte) (mss uint16, mssOK bool, shift uint8, shiftOK bool) {
	t.Helper()
	tfrm, err := NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	var oc OptionCodec
	err = oc.ForEachOption(tfrm.Options(), func(kind OptionKind, data []byte) error {
		switch {
		case kind == OptMaxSegmentSize && len(data) == 2:
			mss = uint16(data[0])<<8 | uint16(data[1])
			mssOK = true
		case kind == OptWindowScale && len(data) == 1:
			shift = data[0]
			shiftOK = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return mss, mssOK, shift, shiftOK
}

// TestWindowScaleNegotiation walks the three-way handshake with asymmetric
// buffer sizes and verifies RFC 7323 §2 end to end on the wire: the SYN and
// SYN-ACK carry the shift derived from each side's receive buffer, SYN
// windows are never scaled (and saturate rather than wrap the 16-bit field),
// and the first post-handshake segment advertises the scaled window.
func TestWindowScaleNegotiation(t *testing.T) {
	const clientBuf = 256 << 10 // shift 3: 256KiB>>3 = 32Ki fits, >>2 does not.
	const serverBuf = 1 << 20   // shift 5: 1MiB>>5 = 32Ki fits, >>4 does not.
	rng := rand.New(rand.NewSource(1))
	client, server := new(Handler), new(Handler)
	err := client.SetBuffers(make([]byte, 2048), make([]byte, clientBuf), 32)
	if err != nil {
		t.Fatal(err)
	}
	err = server.SetBuffers(make([]byte, 2048), make([]byte, serverBuf), 32)
	if err != nil {
		t.Fatal(err)
	}
	setupClientServer(t, rng, client, server)

	packetBuf := make([]byte, 2048)

	// Client SYN: window-scale offer present, window field unscaled+saturated.
	n, err := client.Send(packetBuf)
	if err != nil {
		t.Fatal(err)
	}
	_, mssOK, shift, shiftOK := synOptions(t, packetBuf[:n])
	if !mssOK {
		t.Fatal("client SYN lacks MSS option")
	}
	if !shiftOK {
		t.Fatal("client SYN lacks window-scale option")
	}
	if shift != 3 {
		t.Errorf("client SYN shift = %d, want 3 (buffer %d)", shift, clientBuf)
	}
	tfrm, _ := NewFrame(packetBuf[:n])
	if got := tfrm.WindowSize(); got != 0xFFFF {
		t.Errorf("client SYN wire window = %d, want 65535 (saturated, never scaled)", got)
	}
	if err = server.Recv(packetBuf[:n]); err != nil {
		t.Fatal(err)
	}

	// Server SYN-ACK: echoes its own shift because the SYN offered scaling.
	clear(packetBuf)
	n, err = server.Send(packetBuf)
	if err != nil {
		t.Fatal(err)
	}
	_, _, shift, shiftOK = synOptions(t, packetBuf[:n])
	if !shiftOK {
		t.Fatal("server SYN-ACK lacks window-scale option")
	}
	if shift != 5 {
		t.Errorf("server SYN-ACK shift = %d, want 5 (buffer %d)", shift, serverBuf)
	}
	tfrm, _ = NewFrame(packetBuf[:n])
	if got := tfrm.WindowSize(); got != 0xFFFF {
		t.Errorf("server SYN-ACK wire window = %d, want 65535 (saturated, never scaled)", got)
	}
	if err = client.Recv(packetBuf[:n]); err != nil {
		t.Fatal(err)
	}

	// Client handshake ACK: the first scaled window on the wire. The client
	// advertises its whole free buffer, which only fits the field when
	// right-shifted by its offered shift.
	clear(packetBuf)
	n, err = client.Send(packetBuf)
	if err != nil {
		t.Fatal(err)
	}
	tfrm, _ = NewFrame(packetBuf[:n])
	wantWire := uint16(clientBuf >> 3)
	if got := tfrm.WindowSize(); got != wantWire {
		t.Errorf("client ACK wire window = %d, want %d (%d >> 3)", got, wantWire, clientBuf)
	}
	if err = server.Recv(packetBuf[:n]); err != nil {
		t.Fatal(err)
	}
	// The server must have scaled the advertisement back up to real octets.
	if got := server.scb.snd.WND; got != Size(clientBuf) {
		t.Errorf("server snd.WND = %d, want %d (scaled back up)", got, clientBuf)
	}
}

// TestWindowScaleBigTransfer proves the negotiated scale carries real data
// past the unscaled 64KiB ceiling: with 256KiB buffers on both sides the
// server streams segments without receiving a single ACK, and must be able
// to put more than 64KiB in flight before stalling on the send window. The
// client then receives everything intact.
func TestWindowScaleBigTransfer(t *testing.T) {
	const bufSize = 256 << 10
	const payload = 200 << 10
	const mtu = 2048
	rng := rand.New(rand.NewSource(2))
	client, server := new(Handler), new(Handler)
	err := client.SetBuffers(make([]byte, mtu), make([]byte, bufSize), 32)
	if err != nil {
		t.Fatal(err)
	}
	err = server.SetBuffers(make([]byte, bufSize), make([]byte, bufSize), 256)
	if err != nil {
		t.Fatal(err)
	}
	setupClientServer(t, rng, client, server)
	packetBuf := make([]byte, mtu)
	establish(t, client, server, packetBuf)

	data := make([]byte, payload)
	rng.Read(data)
	nw, err := server.Write(data)
	if err != nil {
		t.Fatal(err)
	} else if nw != payload {
		t.Fatalf("server buffered %d of %d", nw, payload)
	}

	// Stream server→client WITHOUT delivering anything back: no ACKs, so
	// everything sent stays in flight. Past 64KiB in flight is the proof
	// that the scaled window governs the sender.
	inFlight := 0
	frames := make([][]byte, 0, payload/1024)
	for {
		clear(packetBuf)
		n, err := server.Send(packetBuf)
		if err != nil {
			t.Fatal(err)
		}
		if n <= sizeHeaderTCP {
			break // window exhausted (or nothing left to send).
		}
		tfrm, _ := NewFrame(packetBuf[:n])
		inFlight += len(tfrm.Payload())
		frames = append(frames, append([]byte(nil), packetBuf[:n]...))
		if inFlight >= payload {
			break
		}
	}
	if inFlight <= 0xFFFF {
		t.Fatalf("server stalled at %d bytes in flight; scaled window should allow more than 65535", inFlight)
	}

	// Deliver the flight; the client must reassemble the stream intact.
	for _, frm := range frames {
		if err := client.Recv(frm); err != nil {
			t.Fatal(err)
		}
	}
	got := make([]byte, inFlight)
	nr, err := client.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if nr != inFlight {
		t.Fatalf("client read %d of %d in-flight bytes", nr, inFlight)
	}
	if !bytes.Equal(got[:nr], data[:nr]) {
		t.Fatal("received data differs from sent data")
	}
}

// TestWindowScaleWireSafety covers the wire-conversion corners without a
// peer: no echo of the offer when the peer never gave one, and saturation
// (not wrap-around) of oversized windows for both SYN and non-SYN segments
// when scaling is off. Before window scaling existed a 128KiB receive buffer
// wrapped to a near-zero wire window on the SYN; that regression stays pinned
// here.
func TestWindowScaleWireSafety(t *testing.T) {
	h := new(Handler)
	err := h.SetBuffers(make([]byte, 2048), make([]byte, 128<<10), 32)
	if err != nil {
		t.Fatal(err)
	}
	if h.wndShiftLocal != 2 {
		// 128KiB>>1 = 65536 still overflows the field; >>2 = 32768 fits.
		t.Errorf("wndShiftLocal = %d, want 2 for 128KiB buffer", h.wndShiftLocal)
	}

	var b [16]byte
	if words := h.putSynOptions(b[:], 1460, true); words != 1 {
		t.Errorf("SYN-ACK echoed window scale without a peer offer (words=%d)", words)
	}
	if words := h.putSynOptions(b[:], 1460, false); words != 2 {
		t.Errorf("active SYN did not offer window scale (words=%d)", words)
	}

	// Scaling off: oversized windows saturate the 16-bit field.
	if got := h.wireWnd(Segment{WND: 128 << 10, Flags: FlagACK}); got != 0xFFFF {
		t.Errorf("unscaled oversized window = %d, want 65535", got)
	}
	// SYN never scales, even with a negotiated peer shift.
	h.peerOfferedWS = true
	if got := h.wireWnd(Segment{WND: 128 << 10, Flags: FlagSYN}); got != 0xFFFF {
		t.Errorf("SYN window = %d, want 65535 (saturated, unscaled)", got)
	}
	// Established segment with negotiated scaling: shifted representation.
	if got := h.wireWnd(Segment{WND: 128 << 10, Flags: FlagACK}); got != (128<<10)>>2 {
		t.Errorf("scaled window = %d, want %d", got, (128<<10)>>2)
	}
}
