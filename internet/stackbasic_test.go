package internet

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/soypat/lneto/tcp"
)

func TestBasicStack(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var sbCl, sbSv StackBasic
	var connCl, connSv TCPConn
	setupClientServer(t, rng, &sbCl, &sbSv, &connCl, &connSv)
	var buf [2048]byte
	exchangeAndExpectStates := func(clState, svState tcp.State) {
		t.Helper()
		expectExchange(t, &sbCl, &sbSv, buf[:])
		gotCl := connCl.State()
		gotSv := connSv.State()
		if gotCl != clState {
			t.Errorf("want client state %s, got %s", clState, gotCl)
		}
		if gotSv != svState {
			t.Errorf("want server state %s, got %s", svState, gotSv)
		}
	}
	exchangeAndExpectStates(tcp.StateSynSent, tcp.StateListen)
}

func expectExchange(t *testing.T, from, to *StackBasic, buf []byte) {
	n, err := from.Handle(buf)
	if err != nil {
		t.Error(err)
	} else if n == 0 {
		t.Error("expected data exchange")
	}
	err = to.Recv(buf[:n])
	if err != nil {
		t.Error(err)
	}
}

func setupClientServer(t *testing.T, rng *rand.Rand, client, server *StackBasic, connClient, connServer *TCPConn) {
	bufsize := 2048
	// Ensure buffer sizes are OK with reused buffers.
	svip := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 0}), 80)
	clip := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 1}), 1337)
	server.SetAddr(svip.Addr())
	client.SetAddr(clip.Addr())

	err := connServer.Configure(&TCPConnConfig{
		RxBuf:             make([]byte, bufsize),
		TxBuf:             make([]byte, bufsize),
		TxPacketQueueSize: 3,
		Logger:            nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = connClient.Configure(&TCPConnConfig{
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
	err = connClient.OpenActive(svip, clip.Port(), 100)
	if err != nil {
		t.Fatal(err)
	}

	err = server.RegisterTCPConn(connServer)
	if err != nil {
		t.Fatal(err)
	}
	err = client.RegisterTCPConn(connClient)
	if err != nil {
		t.Fatal(err)
	}
}
