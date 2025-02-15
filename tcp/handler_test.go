package tcp

import (
	"math/rand"
	"testing"
)

func TestHandler(t *testing.T) {
	const mtu = 1500
	const maxpackets = 3
	rng := rand.New(rand.NewSource(0))
	client, server := setupClientServer(t, rng, mtu, mtu, maxpackets, mtu, mtu, maxpackets)
	var rawbuf [mtu]byte
	establish(t, client, server, rawbuf[:])
}

func setupClientServer(t *testing.T, rng *rand.Rand, clientTxSize, clientRxSize, clientPackets, serverTxSize, serverRxSize, serverPackets int) (client, server *Handler) {
	client = new(Handler)
	server = new(Handler)
	err := client.SetBuffers(make([]byte, clientTxSize), make([]byte, clientRxSize), clientPackets)
	if err != nil {
		t.Fatal(err)
	}
	err = server.SetBuffers(make([]byte, serverTxSize), make([]byte, serverRxSize), serverPackets)
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
	return client, server
}

func establish(t *testing.T, client, server *Handler, buf []byte) {
	if client.State() != StateClosed {
		t.Fatal("client in wrong state")
	} else if server.State() != StateListen {
		t.Fatal("server in wrong state")
	}
	clear(buf)

	// Commence 3-way handshake: client sends SYN, server sends SYN-ACK, client sends ACK.

	// Client sends SYN.
	n, err := client.Send(buf)
	if err != nil {
		t.Fatal("client sending:", err)
	} else if n < sizeHeaderTCP {
		t.Fatal("expected client to send SYN packet")
	} else if client.State() != StateSynSent {
		t.Fatal("client did not transition to SynSent state:", client.State().String())
	}
	err = server.Recv(buf[:n]) // Server receives SYN.
	if err != nil {
		t.Fatal(err)
	} else if server.State() != StateSynRcvd {
		t.Fatal("server did not transition to SynReceived state:", server.State().String())
	}
	clear(buf)
	// Server sends SYNACK response to client's SYN.
	n, err = server.Send(buf)
	if err != nil {
		t.Fatal("server sending:", err)
	} else if n < sizeHeaderTCP {
		t.Fatal("expected server to send SYNACK packet")
	} else if server.State() != StateSynRcvd {
		t.Fatal("server should remain in SynReceived state:", server.State().String())
	}
	err = client.Recv(buf[:n]) // Client receives SYNACK, is established but must send ACK.
	if err != nil {
		t.Fatal(err)
	} else if client.State() != StateEstablished {
		t.Fatal("client did not transition to Established state:", client.State().String())
	}

	clear(buf)
	n, err = client.Send(buf) // Client sends ACK.
	if err != nil {
		t.Fatal("client sending ACK:", err)
	} else if n < sizeHeaderTCP {
		t.Fatal("expected client to send ACK packet")
	} else if client.State() != StateEstablished {
		t.Fatal("client should remain in Established state:", client.State().String())
	}
	err = server.Recv(buf[:n]) // Server receives ACK.
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
