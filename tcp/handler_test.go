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
	} else if server.Buffered() != len(data) {
		t.Fatal("server did not receive full data packet", server.Buffered(), len(data))
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
