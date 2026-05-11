package internet

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
)

func TestBasicStack(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var sbCl, sbSv StackIPv4
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
	var sbCl, sbSv StackIPv4
	var connCl, connSv tcp.Conn
	setupClientServerEstablished(t, rng, &sbCl, &sbSv, &connCl, &connSv)

}

func expectExchange(t *testing.T, from, to lneto.StackNode, buf []byte) {
	t.Helper()
	n, err := from.Encapsulate(buf, 0, 0)
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

func setupClientServerEstablished(t *testing.T, rng *rand.Rand, client, server *StackIPv4, connClient, connServer *tcp.Conn) {
	t.Helper()
	setupClientServer(t, rng, client, server, connClient, connServer)
	testClientServerEstablish(t, client, server, connClient, connServer)
}

func testClientServerEstablish(t *testing.T, client, server lneto.StackNode, connClient, connServer *tcp.Conn) {
	t.Helper()
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

func TestBasicStack6(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var sbCl, sbSv StackIPv6
	var connCl, connSv tcp.Conn
	setupClientServer6(t, rng, &sbCl, &sbSv, &connCl, &connSv)
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
	exchangeAndExpectStates(tcp.StateSynSent, tcp.StateSynRcvd)
	exchangeAndExpectStates(tcp.StateEstablished, tcp.StateSynRcvd)
	exchangeAndExpectStates(tcp.StateEstablished, tcp.StateEstablished)
}

func TestBasicStack6Established(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var sbCl, sbSv StackIPv6
	var connCl, connSv tcp.Conn
	setupClientServer6(t, rng, &sbCl, &sbSv, &connCl, &connSv)
	testClientServerEstablish(t, &sbCl, &sbSv, &connCl, &connSv)
}

func setupClientServer6(t *testing.T, rng *rand.Rand, client, server *StackIPv6, connClient, connServer *tcp.Conn) {
	t.Helper()
	_ = rng
	const maxNodes = 1
	bufsize := 2048
	svip6 := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) // 2001:db8::1
	clip6 := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}) // 2001:db8::2
	svip := netip.AddrPortFrom(svip6, 80)
	clip := netip.AddrPortFrom(clip6, 1337)
	if err := server.Reset(new(lneto.Validator), maxNodes); err != nil {
		t.Fatal(err)
	}
	if err := client.Reset(new(lneto.Validator), maxNodes); err != nil {
		t.Fatal(err)
	}
	server.SetAddr6(svip6.As16())
	client.SetAddr6(clip6.As16())
	err := connServer.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, bufsize),
		TxBuf:             make([]byte, bufsize),
		TxPacketQueueSize: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = connClient.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, bufsize),
		TxBuf:             make([]byte, bufsize),
		TxPacketQueueSize: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = connServer.OpenListen(svip.Port(), 200); err != nil {
		t.Fatal(err)
	}
	if err = connClient.OpenActive(clip.Port(), svip, 100); err != nil {
		t.Fatal(err)
	}
	if err = server.Register6(connServer); err != nil {
		t.Fatal(err)
	}
	if err = client.Register6(connClient); err != nil {
		t.Fatal(err)
	}
}

func setupClientServer(t *testing.T, rng *rand.Rand, client, server *StackIPv4, connClient, connServer *tcp.Conn) {
	const maxNodes = 1
	bufsize := 2048
	// Ensure buffer sizes are OK with reused buffers.
	svip := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 0}), 80)
	clip := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 1}), 1337)
	server.Reset(new(lneto.Validator), maxNodes)
	client.Reset(new(lneto.Validator), maxNodes)
	server.SetAddr4(svip.Addr().As4())
	client.SetAddr4(clip.Addr().As4())
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

	err = server.Register4(connServer)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Register4(connClient)
	if err != nil {
		t.Fatal(err)
	}
}
