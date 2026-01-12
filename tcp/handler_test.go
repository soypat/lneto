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
