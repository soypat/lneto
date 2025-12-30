package internet

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/soypat/lneto/tcp"
)

func TestBasicStack(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var sbCl, sbSv StackIP
	var connCl, connSv tcp.Conn
	setupClientServer(t, rng, &sbCl, &sbSv, &connCl, &connSv)
	var buf [2048]byte
	nextToSend := &sbCl
	nextToRecv := &sbSv
	exchangeAndExpectStates := func(clState, svState tcp.State) {
		t.Helper()
		expectExchange(t, nextToSend, nextToRecv, buf[:])
		gotCl := connCl.State()
		gotSv := connSv.State()
		if gotCl != clState {
			t.Errorf("want client state %s, got %s", clState, gotCl)
		}
		if gotSv != svState {
			t.Errorf("want server state %s, got %s", svState, gotSv)
		}
		nextToSend, nextToRecv = nextToRecv, nextToSend
	}
	exchangeAndExpectStates(tcp.StateSynSent, tcp.StateSynRcvd)         // Client sends over first SYN and server receives it.
	exchangeAndExpectStates(tcp.StateEstablished, tcp.StateSynRcvd)     // server sends back SYNACK, establishing connection on client side.
	exchangeAndExpectStates(tcp.StateEstablished, tcp.StateEstablished) // Client sends ACK, establishing connection in full.
}

func TestBasicStack2(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var sbCl, sbSv StackIP
	var connCl, connSv tcp.Conn
	setupClientServerEstablished(t, rng, &sbCl, &sbSv, &connCl, &connSv)

}

func expectExchange(t *testing.T, from, to *StackIP, buf []byte) {
	t.Helper()
	n, err := from.Encapsulate(buf, -1, 0)
	if err != nil {
		t.Error("expectExchange:encapsulate:", err)
	} else if n == 0 {
		t.Error("expected data exchange")
		return
	}
	err = to.Demux(buf[:n], 0)
	if err != nil {
		t.Error("expectExchange:Recv:", err)
	}
}

func setupClientServerEstablished(t *testing.T, rng *rand.Rand, client, server *StackIP, connClient, connServer *tcp.Conn) {
	t.Helper()
	setupClientServer(t, rng, client, server, connClient, connServer)
	var buf [2048]byte
	nextToSend := client
	nextToRecv := server
	exchangeAndExpectStates := func(clState, svState tcp.State) {
		t.Helper()
		expectExchange(t, nextToSend, nextToRecv, buf[:])
		gotCl := connClient.State()
		gotSv := connServer.State()
		if gotCl != clState {
			t.Errorf("want client state %s, got %s", clState, gotCl)
		}
		if gotSv != svState {
			t.Errorf("want server state %s, got %s", svState, gotSv)
		}
		nextToSend, nextToRecv = nextToRecv, nextToSend
	}
	exchangeAndExpectStates(tcp.StateSynSent, tcp.StateSynRcvd)         // Client sends over first SYN and server receives it.
	exchangeAndExpectStates(tcp.StateEstablished, tcp.StateSynRcvd)     // server sends back SYNACK, establishing connection on client side.
	exchangeAndExpectStates(tcp.StateEstablished, tcp.StateEstablished) // Client sends ACK, establishing connection in full.
	if t.Failed() {
		t.Error("establishment failed")
		t.FailNow()
	}
}

func setupClientServer(t *testing.T, rng *rand.Rand, client, server *StackIP, connClient, connServer *tcp.Conn) {
	const maxNodes = 1
	bufsize := 2048
	// Ensure buffer sizes are OK with reused buffers.
	svip := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 0}), 80)
	clip := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 1}), 1337)
	server.Reset(svip.Addr(), maxNodes)
	client.Reset(clip.Addr(), maxNodes)

	err := connServer.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, bufsize),
		TxBuf:             make([]byte, bufsize),
		TxPacketQueueSize: 3,
		Logger:            nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = connClient.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, bufsize),
		TxBuf:             make([]byte, bufsize),
		TxPacketQueueSize: 3,
		Logger:            nil,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = connServer.OpenListen(svip.Port(), 200)
	if err != nil {
		t.Fatal(err)
	}
	err = connClient.OpenActive(clip.Port(), svip, 100)
	if err != nil {
		t.Fatal(err)
	}

	err = server.Register(connServer)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Register(connClient)
	if err != nil {
		t.Fatal(err)
	}
}
