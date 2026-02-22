package tcp

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestHandler(t *testing.T) {
	const mtu = 1500
	const maxpackets = 3
	rng := rand.New(rand.NewSource(0))
	client, server := newHandler(t, mtu, maxpackets), newHandler(t, mtu, maxpackets)
	setupClientServer(t, rng, client, server)
	var rawbuf [mtu]byte
	establish(t, client, server, rawbuf[:])
	sendDataFull(t, client, server, []byte("hello"), rawbuf[:])
}

func sendDataFull(t *testing.T, client, server *Handler, data, packetBuf []byte) {
	n, err := client.Write(data)
	if err != nil {
		t.Fatal("client write:", err)
	} else if n != len(data) {
		t.Fatal("expected client to write full data packet")
	}
	n, err = client.Send(packetBuf)
	if err != nil {
		t.Fatal("client sending:", err)
	} else if n < len(data)+sizeHeaderTCP {
		t.Fatal("expected client to send full data packet", n, len(data)+sizeHeaderTCP)
	}
	err = server.Recv(packetBuf[:n])
	if err != nil {
		t.Fatal("server receiving:", err)
	} else if server.BufferedInput() != len(data) {
		t.Fatal("server did not receive full data packet", server.BufferedInput(), len(data))
	}
	clear(packetBuf)
	n, err = server.Read(packetBuf)
	if err != nil {
		t.Fatal("server read:", err)
	} else if n != len(data) {
		t.Fatal("expected server to read full data packet")
	} else if !bytes.Equal(packetBuf[:n], data) {
		t.Fatal("server received unexpected data")
	}
}

func newHandler(t *testing.T, mtu, mintaxpackets int) *Handler {
	h := new(Handler)
	err := h.SetBuffers(make([]byte, mtu), make([]byte, mtu), mintaxpackets)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func setupClientServer(t *testing.T, rng *rand.Rand, client, server *Handler) {
	// Ensure buffer sizes are OK with reused buffers.
	err := client.SetBuffers(nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = server.SetBuffers(nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = server.OpenListen(uint16(rng.Uint32()), 0)
	if err != nil {
		t.Fatal(err)
	}
	err = client.OpenActive(uint16(rng.Uint32()), server.LocalPort(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !client.AwaitingSynSend() {
		t.Fatal("client in wrong state")
	}
	if !server.AwaitingSynAck() {
		t.Fatal("server in wrong state")
	}
}

func establish(t *testing.T, client, server *Handler, packetBuf []byte) {
	if client.State() != StateClosed {
		t.Fatal("client in wrong state")
	} else if server.State() != StateListen {
		t.Fatal("server in wrong state")
	}
	clear(packetBuf)

	// Commence 3-way handshake: client sends SYN, server sends SYN-ACK, client sends ACK.

	// Client sends SYN.
	n, err := client.Send(packetBuf)
	if err != nil {
		t.Fatal("client sending:", err)
	} else if n < sizeHeaderTCP {
		t.Fatal("expected client to send SYN packet")
	} else if client.State() != StateSynSent {
		t.Fatal("client did not transition to SynSent state:", client.State().String())
	}
	err = server.Recv(packetBuf[:n]) // Server receives SYN.
	if err != nil {
		t.Fatal(err)
	} else if server.State() != StateSynRcvd {
		t.Fatal("server did not transition to SynReceived state:", server.State().String())
	}
	clear(packetBuf)
	// Server sends SYNACK response to client's SYN.
	n, err = server.Send(packetBuf)
	if err != nil {
		t.Fatal("server sending:", err)
	} else if n < sizeHeaderTCP {
		t.Fatal("expected server to send SYNACK packet")
	} else if server.State() != StateSynRcvd {
		t.Fatal("server should remain in SynReceived state:", server.State().String())
	}
	err = client.Recv(packetBuf[:n]) // Client receives SYNACK, is established but must send ACK.
	if err != nil {
		t.Fatal(err)
	} else if client.State() != StateEstablished {
		t.Fatal("client did not transition to Established state:", client.State().String())
	}

	clear(packetBuf)
	n, err = client.Send(packetBuf) // Client sends ACK.
	if err != nil {
		t.Fatal("client sending ACK:", err)
	} else if n < sizeHeaderTCP {
		t.Fatal("expected client to send ACK packet")
	} else if client.State() != StateEstablished {
		t.Fatal("client should remain in Established state:", client.State().String())
	}
	err = server.Recv(packetBuf[:n]) // Server receives ACK.
	if err != nil {
		t.Fatal(err)
	} else if server.State() != StateEstablished {
		t.Fatal("server did not transition to Established state on ACK receive:", server.State().String())
	}
}

func clear[E any, T []E](s T) {
	var zero E
	for i := range s {
		s[i] = zero
	}
}

// TestTxBufferFreedOnACK tests that the TX buffer is freed when ACKs are received.
// This is a regression test for https://github.com/soypat/lneto/issues/22
// where ringTx.sentoff and ringTx.sentend were not being updated when ACKs
// were received, causing AvailableOutput() to return 0 indefinitely after
// the initial buffer was consumed.
func TestTxBufferFreedOnACK(t *testing.T) {
	const mtu = 256
	const maxpackets = 4
	const txBufSize = 128 // Small TX buffer to easily fill it
	rng := rand.New(rand.NewSource(42))

	// Create handlers with small TX buffers to easily trigger the issue.
	client := new(Handler)
	server := new(Handler)
	err := client.SetBuffers(make([]byte, txBufSize), make([]byte, mtu), maxpackets)
	if err != nil {
		t.Fatal(err)
	}
	err = server.SetBuffers(make([]byte, txBufSize), make([]byte, mtu), maxpackets)
	if err != nil {
		t.Fatal(err)
	}

	// Setup and establish connection.
	err = server.OpenListen(uint16(rng.Uint32()), 0)
	if err != nil {
		t.Fatal(err)
	}
	err = client.OpenActive(uint16(rng.Uint32()), server.LocalPort(), 0)
	if err != nil {
		t.Fatal(err)
	}

	var rawbuf [mtu]byte
	establish(t, client, server, rawbuf[:])

	// Record initial available space.
	initialAvailable := client.AvailableOutput()
	if initialAvailable == 0 {
		t.Fatal("expected non-zero initial available output")
	}

	// Write data to fill a significant portion of the TX buffer.
	data := make([]byte, txBufSize/2)
	for i := range data {
		data[i] = byte(i)
	}
	n, err := client.Write(data)
	if err != nil {
		t.Fatal("client write:", err)
	} else if n != len(data) {
		t.Fatalf("expected to write %d bytes, wrote %d", len(data), n)
	}

	// Available space should have decreased.
	afterWriteAvailable := client.AvailableOutput()
	if afterWriteAvailable >= initialAvailable {
		t.Fatalf("expected available to decrease after write: before=%d, after=%d",
			initialAvailable, afterWriteAvailable)
	}

	// Client sends DATA packet.
	clear(rawbuf[:])
	n, err = client.Send(rawbuf[:])
	if err != nil {
		t.Fatal("client sending data:", err)
	}
	if n < len(data)+sizeHeaderTCP {
		t.Fatal("expected client to send full data packet")
	}
	dataPacket := append([]byte(nil), rawbuf[:n]...)

	// After sending, data moves from "unsent" to "sent" - available should still be reduced
	// until we receive an ACK.
	afterSendAvailable := client.AvailableOutput()

	// Server receives DATA.
	err = server.Recv(dataPacket)
	if err != nil {
		t.Fatal("server receiving data:", err)
	}

	// Server sends ACK.
	clear(rawbuf[:])
	n, err = server.Send(rawbuf[:])
	if err != nil {
		t.Fatal("server sending ACK:", err)
	}
	ackPacket := append([]byte(nil), rawbuf[:n]...)

	// Client receives ACK - this is where the bug manifests.
	// Without the fix, the TX buffer's sentoff/sentend are not updated,
	// so AvailableOutput() remains low.
	err = client.Recv(ackPacket)
	if err != nil {
		t.Fatal("client receiving ACK:", err)
	}

	// THE BUG: After receiving ACK, the TX buffer should be freed.
	// Without the fix, AvailableOutput() stays at the post-send value.
	afterAckAvailable := client.AvailableOutput()

	if afterAckAvailable <= afterSendAvailable {
		t.Fatalf("BUG (issue #22): TX buffer not freed after receiving ACK\n"+
			"AvailableOutput() after send: %d\n"+
			"AvailableOutput() after ACK:  %d\n"+
			"Expected available space to increase after ACK is received.\n"+
			"The ringTx.sentoff and ringTx.sentend fields are not being updated\n"+
			"because ringTx.RecvACK() is not called when ACKs are received.",
			afterSendAvailable, afterAckAvailable)
	}

	// Should be back to (approximately) initial available space.
	if afterAckAvailable < initialAvailable-10 { // Allow small margin for overhead
		t.Fatalf("expected available to return close to initial: initial=%d, afterAck=%d",
			initialAvailable, afterAckAvailable)
	}
}

// TestWindowUpdateAfterRead verifies that after the application reads data from
// a full receive buffer (Window=0), the TCP stack queues a window update ACK
// so the remote peer can resume sending. This is a regression test for a
// zero-window deadlock: without proactive window updates, the remote peer stays
// stuck at Window=0 indefinitely after the app frees buffer space via Read().
func TestWindowUpdateAfterRead(t *testing.T) {
	const rxBufSize = 256
	const mtu = 1500
	const maxpackets = 4
	rng := rand.New(rand.NewSource(99))

	client := new(Handler)
	server := new(Handler)
	// Server gets a small RX buffer so we can fill it easily.
	err := client.SetBuffers(make([]byte, mtu), make([]byte, mtu), maxpackets)
	if err != nil {
		t.Fatal(err)
	}
	err = server.SetBuffers(make([]byte, mtu), make([]byte, rxBufSize), maxpackets)
	if err != nil {
		t.Fatal(err)
	}

	err = server.OpenListen(uint16(rng.Uint32()), 0)
	if err != nil {
		t.Fatal(err)
	}
	err = client.OpenActive(uint16(rng.Uint32()), server.LocalPort(), 0)
	if err != nil {
		t.Fatal(err)
	}

	var rawbuf [mtu]byte
	establish(t, client, server, rawbuf[:])

	// Fill the server's RX buffer completely (without reading).
	fillData := make([]byte, server.FreeRx())
	n, err := client.Write(fillData)
	if err != nil {
		t.Fatal("client write:", err)
	} else if n != len(fillData) {
		t.Fatal("short write")
	}
	clear(rawbuf[:])
	n, err = client.Send(rawbuf[:])
	if err != nil {
		t.Fatal("client send:", err)
	}
	err = server.Recv(rawbuf[:n])
	if err != nil {
		t.Fatal("server recv:", err)
	}
	if server.FreeRx() != 0 {
		t.Fatalf("expected server RX buffer full, got %d free", server.FreeRx())
	}

	// Server sends ACK — should advertise Window=0.
	clear(rawbuf[:])
	n, err = server.Send(rawbuf[:])
	if err != nil {
		t.Fatal("server send ACK:", err)
	}
	if n == 0 {
		t.Fatal("expected server to send ACK for received data")
	}
	zeroWndFrm, _ := NewFrame(rawbuf[:n])
	if wnd := zeroWndFrm.WindowSize(); wnd != 0 {
		t.Fatalf("expected Window=0 in ACK, got %d", wnd)
	}

	// Verify no pending segment before Read (nothing to send).
	clear(rawbuf[:])
	n, err = server.Send(rawbuf[:])
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("expected no pending segment before Read")
	}

	// App reads ALL data from server, freeing the entire buffer.
	readBuf := make([]byte, rxBufSize)
	n, err = server.Read(readBuf)
	if err != nil {
		t.Fatal("server read:", err)
	}
	if n != len(fillData) {
		t.Fatalf("read %d, expected %d", n, len(fillData))
	}

	// Server should now have a pending window update ACK.
	clear(rawbuf[:])
	n, err = server.Send(rawbuf[:])
	if err != nil {
		t.Fatal("server send window update:", err)
	}
	if n == 0 {
		t.Fatal("BUG: no window update sent after Read() freed buffer space from Window=0")
	}
	wndFrm, _ := NewFrame(rawbuf[:n])
	if wnd := wndFrm.WindowSize(); wnd == 0 {
		t.Fatal("BUG: window update ACK still has Window=0")
	}
	t.Logf("window update sent: Window=%d (buffer free=%d)", wndFrm.WindowSize(), server.FreeRx())
}

// TestWindowUpdateSWSAvoidance verifies that small reads that free less than
// half the buffer do NOT trigger a window update (Silly Window Syndrome avoidance).
func TestWindowUpdateSWSAvoidance(t *testing.T) {
	const rxBufSize = 256
	const mtu = 1500
	const maxpackets = 4
	rng := rand.New(rand.NewSource(77))

	client := new(Handler)
	server := new(Handler)
	err := client.SetBuffers(make([]byte, mtu), make([]byte, mtu), maxpackets)
	if err != nil {
		t.Fatal(err)
	}
	err = server.SetBuffers(make([]byte, mtu), make([]byte, rxBufSize), maxpackets)
	if err != nil {
		t.Fatal(err)
	}

	err = server.OpenListen(uint16(rng.Uint32()), 0)
	if err != nil {
		t.Fatal(err)
	}
	err = client.OpenActive(uint16(rng.Uint32()), server.LocalPort(), 0)
	if err != nil {
		t.Fatal(err)
	}

	var rawbuf [mtu]byte
	establish(t, client, server, rawbuf[:])

	// Fill most of the server's RX buffer (leave a tiny amount free).
	fillSize := server.FreeRx() - 10
	fillData := make([]byte, fillSize)
	for i := range fillData {
		fillData[i] = byte(i)
	}
	n, err := client.Write(fillData)
	if err != nil {
		t.Fatal("client write:", err)
	} else if n != len(fillData) {
		t.Fatal("short write")
	}
	clear(rawbuf[:])
	n, err = client.Send(rawbuf[:])
	if err != nil {
		t.Fatal("client send:", err)
	}
	err = server.Recv(rawbuf[:n])
	if err != nil {
		t.Fatal("server recv:", err)
	}

	// Server sends ACK with small window.
	clear(rawbuf[:])
	n, err = server.Send(rawbuf[:])
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected ACK")
	}
	// Client receives the ACK so its send window is updated.
	err = client.Recv(rawbuf[:n])
	if err != nil {
		t.Fatal(err)
	}

	// App reads a small amount (less than half the buffer).
	smallRead := make([]byte, rxBufSize/4)
	n, err = server.Read(smallRead)
	if err != nil {
		t.Fatal("server read:", err)
	}
	if n == 0 {
		t.Fatal("expected to read data")
	}

	// Because freed space < bufSize/2, no window update should be queued.
	clear(rawbuf[:])
	n, err = server.Send(rawbuf[:])
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Logf("NOTE: window update sent after small read (freed %d of %d buffer)", len(smallRead), rxBufSize)
		// This is acceptable if the threshold is met, but for SWS avoidance
		// we expect no update when the freed increment is < bufSize/2.
		freeAfterRead := Size(server.FreeRx())
		if freeAfterRead < Size(rxBufSize/2) {
			t.Fatalf("SWS violation: window update sent when free=%d < bufSize/2=%d", freeAfterRead, rxBufSize/2)
		}
	}
}

// TestRSTinSynReceived verifies that a RST received during the SYN-RECEIVED
// state correctly reverts the connection to LISTEN per RFC 9293 §3.5.3.
// This is a regression test for a bug where RST segments in non-synchronized
// states were blocked by errRequireSequential, causing connection pool leaks.
func TestRSTinSynReceived(t *testing.T) {
	const mtu = 1500
	const maxpackets = 3
	rng := rand.New(rand.NewSource(2))
	client, server := newHandler(t, mtu, maxpackets), newHandler(t, mtu, maxpackets)
	setupClientServer(t, rng, client, server)
	var rawbuf [mtu]byte

	// Client sends SYN.
	clear(rawbuf[:])
	n, err := client.Send(rawbuf[:])
	if err != nil {
		t.Fatal("client sending SYN:", err)
	}
	if client.State() != StateSynSent {
		t.Fatal("client not in SynSent:", client.State())
	}

	// Server receives SYN → transitions to SYN-RECEIVED.
	err = server.Recv(rawbuf[:n])
	if err != nil {
		t.Fatal("server receiving SYN:", err)
	}
	if server.State() != StateSynRcvd {
		t.Fatal("server not in SynRcvd:", server.State())
	}

	// Server sends SYN,ACK.
	clear(rawbuf[:])
	n, err = server.Send(rawbuf[:])
	if err != nil {
		t.Fatal("server sending SYN,ACK:", err)
	}
	if n < sizeHeaderTCP {
		t.Fatal("expected SYN,ACK packet")
	}
	synackFrm, _ := NewFrame(rawbuf[:n])
	synackSeg := synackFrm.Segment(0)

	// Construct RST packet from client perspective (as if the remote peer
	// rejected the connection). SEQ = ACK from SYN,ACK, no ACK flag, no payload.
	clear(rawbuf[:])
	rstFrm, err := NewFrame(rawbuf[:])
	if err != nil {
		t.Fatal("new frame:", err)
	}
	rstSeg := Segment{
		SEQ:   synackSeg.ACK, // SEQ = server's ACK value = in window.
		Flags: FlagRST,
	}
	rstFrm.SetSourcePort(client.localPort)
	rstFrm.SetDestinationPort(server.localPort)
	rstFrm.SetSegment(rstSeg, 5)
	rstFrm.SetUrgentPtr(0)

	// Server receives RST → should revert to LISTEN per RFC 9293 §3.5.3.
	err = server.Recv(rawbuf[:sizeHeaderTCP])
	if !IsDroppedErr(err) {
		t.Fatal("expected drop segment error from RST recv, got:", err)
	}
	if server.State() != StateListen {
		t.Fatalf("expected server LISTEN after RST in SYN-RECEIVED, got %s", server.State())
	}
	if server.scb.HasPending() {
		t.Fatal("server should have no pending segments after RST")
	}
}

// TestBufferNotClearedOnPassiveClose tests that data remains readable after
// the TCP connection is closed by the remote peer. This is a regression test
// for a bug where the receive buffer was cleared when the connection transitioned
// to CLOSED state, causing data loss.
//
// The sequence is:
//  1. Server sends DATA + initiates close (FIN)
//  2. Client receives data, enters CLOSE_WAIT
//  3. Client sends ACK, then FIN+ACK (enters LAST_ACK)
//  4. Server sends final ACK
//  5. Client receives ACK in LAST_ACK -> state becomes CLOSED
//  6. At this point, client.Read() should still return the buffered data
//
// The bug was that reset() cleared bufRx when state became CLOSED.
func TestBufferNotClearedOnPassiveClose(t *testing.T) {
	const mtu = 1500
	const maxpackets = 3
	rng := rand.New(rand.NewSource(1))
	client, server := newHandler(t, mtu, maxpackets), newHandler(t, mtu, maxpackets)
	setupClientServer(t, rng, client, server)
	var rawbuf [mtu]byte
	establish(t, client, server, rawbuf[:])

	// Server writes data to be sent.
	data := []byte("hello world - this data should survive close")
	n, err := server.Write(data)
	if err != nil {
		t.Fatal("server write:", err)
	} else if n != len(data) {
		t.Fatal("expected server to write full data")
	}

	// Server sends DATA packet.
	clear(rawbuf[:])
	n, err = server.Send(rawbuf[:])
	if err != nil {
		t.Fatal("server sending data:", err)
	} else if n < len(data)+sizeHeaderTCP {
		t.Fatal("expected server to send full data packet")
	}
	dataPacket := append([]byte(nil), rawbuf[:n]...) // Save for later use.

	// Client receives DATA.
	err = client.Recv(dataPacket)
	if err != nil {
		t.Fatal("client receiving data:", err)
	}
	if client.BufferedInput() != len(data) {
		t.Fatalf("client did not buffer data: got %d, want %d", client.BufferedInput(), len(data))
	}

	// Server initiates close (will send FIN on next Send).
	err = server.Close()
	if err != nil {
		t.Fatal("server close:", err)
	}

	// Server sends FIN (enters FIN_WAIT_1).
	clear(rawbuf[:])
	n, err = server.Send(rawbuf[:])
	if err != nil {
		t.Fatal("server sending FIN:", err)
	}
	if server.State() != StateFinWait1 {
		t.Fatalf("expected server in FIN_WAIT_1, got %s", server.State())
	}
	finPacket := append([]byte(nil), rawbuf[:n]...)

	// Client receives FIN (enters CLOSE_WAIT).
	err = client.Recv(finPacket)
	if err != nil {
		t.Fatal("client receiving FIN:", err)
	}
	if client.State() != StateCloseWait {
		t.Fatalf("expected client in CLOSE_WAIT, got %s", client.State())
	}

	// Client sends ACK for FIN.
	clear(rawbuf[:])
	n, err = client.Send(rawbuf[:])
	if err != nil {
		t.Fatal("client sending ACK:", err)
	}
	ackPacket := append([]byte(nil), rawbuf[:n]...)

	// Server receives ACK (enters FIN_WAIT_2).
	err = server.Recv(ackPacket)
	if err != nil {
		t.Fatal("server receiving ACK:", err)
	}
	if server.State() != StateFinWait2 {
		t.Fatalf("expected server in FIN_WAIT_2, got %s", server.State())
	}

	// Client initiates its own close (will send FIN on next Send).
	err = client.Close()
	if err != nil {
		t.Fatal("client close:", err)
	}

	// Client sends FIN (enters LAST_ACK).
	clear(rawbuf[:])
	n, err = client.Send(rawbuf[:])
	if err != nil {
		t.Fatal("client sending FIN:", err)
	}
	if client.State() != StateLastAck {
		t.Fatalf("expected client in LAST_ACK, got %s", client.State())
	}
	clientFinPacket := append([]byte(nil), rawbuf[:n]...)

	// Server receives client's FIN (enters TIME_WAIT).
	err = server.Recv(clientFinPacket)
	if err != nil {
		t.Fatal("server receiving client FIN:", err)
	}
	if server.State() != StateTimeWait {
		t.Fatalf("expected server in TIME_WAIT, got %s", server.State())
	}

	// Server sends final ACK.
	clear(rawbuf[:])
	n, err = server.Send(rawbuf[:])
	if err != nil {
		t.Fatal("server sending final ACK:", err)
	}
	finalAckPacket := append([]byte(nil), rawbuf[:n]...)
	if client.BufferedInput() == 0 {
		t.Fatal("emptied buffer")
	}
	// Client receives final ACK (should enter CLOSED).
	// This is where the bug manifests: the buffer gets cleared.
	err = client.Recv(finalAckPacket)
	// Note: client.Recv returns net.ErrClosed when state becomes CLOSED, that's expected.
	if err != nil && err.Error() != "use of closed network connection" {
		t.Fatal("client receiving final ACK:", err)
	}
	if client.State() != StateClosed {
		t.Fatalf("expected client in CLOSED, got %s", client.State())
	}

	// THE BUG: At this point, the data should still be readable, but the
	// buffer was cleared by reset() when state transitioned to CLOSED.
	//
	// This test will FAIL until the bug is fixed.
	readBuf := make([]byte, mtu)
	n, err = client.Read(readBuf)
	if err != nil && n == 0 {
		t.Fatalf("BUG: Could not read buffered data after connection closed: %v\n"+
			"Expected to read %d bytes of data that was received before the connection closed.\n"+
			"The receive buffer was incorrectly cleared when the connection transitioned to CLOSED state.",
			err, len(data))
	}
	if n != len(data) {
		t.Fatalf("read wrong amount: got %d, want %d", n, len(data))
	}
	if !bytes.Equal(readBuf[:n], data) {
		t.Fatalf("read wrong data: got %q, want %q", readBuf[:n], data)
	}
}
