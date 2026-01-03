package xnet

import (
	"net/netip"
	"testing"
	"time"

	"github.com/soypat/lneto/tcp"
)

func TestStackAsyncListener_SingleConnection(t *testing.T) {
	const seed int64 = 1234
	const MTU = 1500
	const svPort = 80
	const clPort = 1337

	// Create two stacks.
	client, sv := new(StackAsync), new(StackAsync)
	err := client.Reset(StackConfig{
		Hostname:        "Client",
		RandSeed:        seed,
		StaticAddress:   netip.AddrFrom4([4]byte{10, 0, 0, 1}),
		MaxTCPConns:     1,
		HardwareAddress: [6]byte{0xbe, 0xef, 0, 0, 0, 1},
		MTU:             MTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = sv.Reset(StackConfig{
		Hostname:        "Server",
		RandSeed:        ^seed,
		StaticAddress:   netip.AddrFrom4([4]byte{10, 0, 0, 2}),
		MaxTCPConns:     1, // Note: We use listener, not direct TCP conn registration.
		HardwareAddress: [6]byte{0xbe, 0xef, 0, 0, 0, 2},
		MTU:             MTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.SetGateway6(sv.HardwareAddress())
	sv.SetGateway6(client.HardwareAddress())

	// Create client connection.
	var clConn tcp.Conn
	err = clConn.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, MTU),
		TxBuf:             make([]byte, MTU),
		TxPacketQueueSize: 4,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create pool and listener for server.
	pool, err := NewTCPPool(TCPPoolConfig{
		PoolSize:           1,
		QueueSize:          4,
		BufferSize:         MTU,
		EstablishedTimeout: 10e9,
		ClosingTimeout:     10e9,
	})
	if err != nil {
		t.Fatal(err)
	}

	var listener tcp.Listener
	err = listener.Reset(svPort, pool)
	if err != nil {
		t.Fatal(err)
	}
	err = sv.RegisterListener(&listener)
	if err != nil {
		t.Fatal(err)
	}

	// Client dials server.
	err = client.DialTCP(&clConn, clPort, netip.AddrPortFrom(sv.Addr(), svPort))
	if err != nil {
		t.Fatal(err)
	}

	tst := testerFrom(t, MTU)

	// Complete TCP handshake.
	tst.TestTCPHandshake(client, sv)

	// After handshake, TryAccept should work.
	if listener.NumberOfReadyToAccept() != 1 {
		t.Fatalf("after handshake: expected 1 ready, got %d", listener.NumberOfReadyToAccept())
	}
	svConn, err := listener.TryAccept()
	if err != nil {
		t.Fatalf("TryAccept: %v", err)
	}
	if listener.NumberOfReadyToAccept() != 0 {
		t.Fatalf("after accept: expected 0 ready, got %d", listener.NumberOfReadyToAccept())
	}

	// Verify both connections are established.
	if clConn.State() != tcp.StateEstablished {
		t.Fatalf("client: expected StateEstablished, got %s", clConn.State())
	}
	if svConn.State() != tcp.StateEstablished {
		t.Fatalf("server: expected StateEstablished, got %s", svConn.State())
	}

	// Test data exchange: client -> server.
	sendData := []byte("hello from client")
	tst.TestTCPEstablishedSingleData(client, sv, &clConn, svConn, sendData)

	// Test data exchange: server -> client.
	replyData := []byte("hello from server")
	tst.TestTCPEstablishedSingleData(sv, client, svConn, &clConn, replyData)

	// Test close (client-initiated).
	tst.TestTCPClose(client, sv, &clConn, svConn)
}

func TestStackAsyncListener_Concurrent(t *testing.T) {
	const seed int64 = 1234
	const MTU = 1500
	const svPort = 80
	const clPort = 1337
	const poolsize = 10
	const bufsize = 128
	// Create two stacks.
	sv := new(StackAsync)
	err := sv.Reset(StackConfig{
		Hostname:        "Server",
		RandSeed:        ^seed,
		StaticAddress:   netip.AddrFrom4([4]byte{10, 0, 0, 2}),
		MaxTCPConns:     1, // Note: We use listener, not direct TCP conn registration.
		HardwareAddress: [6]byte{0xbe, 0xef, 0, 0, 0, 2},
		MTU:             MTU,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create pool and listener for server.
	pool, err := NewTCPPool(TCPPoolConfig{
		PoolSize:           poolsize,
		QueueSize:          4,
		BufferSize:         bufsize,
		EstablishedTimeout: 10e9,
		ClosingTimeout:     10e9,
	})
	if err != nil {
		t.Fatal(err)
	}

	var listener tcp.Listener
	err = listener.Reset(svPort, pool)
	if err != nil {
		t.Fatal(err)
	}
	err = sv.RegisterListener(&listener)
	if err != nil {
		t.Fatal(err)
	}
	caddr := netip.AddrFrom4([4]byte{10, 0, 0, 1})
	chw := [6]byte{0xbe, 0xef, 0, 0, 0, 1}
	sv.SetGateway6(chw)
	tst := testerFrom(t, MTU)
	doRequest := func(caddrp netip.AddrPort, sleep time.Duration, data []byte) {
		var client StackAsync
		err := client.Reset(StackConfig{
			Hostname:        "Client",
			RandSeed:        seed,
			StaticAddress:   caddrp.Addr(),
			MaxTCPConns:     1,
			HardwareAddress: chw,
			MTU:             MTU,
		})
		if err != nil {
			panic(err)
		}
		client.SetGateway6(sv.HardwareAddress())
		// Create client connection.
		var clConn tcp.Conn
		err = clConn.Configure(tcp.ConnConfig{
			RxBuf:             make([]byte, bufsize),
			TxBuf:             make([]byte, bufsize),
			TxPacketQueueSize: 4,
		})
		if err != nil {
			t.Fatal(err)
		}
		// Client dials server.
		err = client.DialTCP(&clConn, caddrp.Port(), netip.AddrPortFrom(sv.Addr(), svPort))
		if err != nil {
			t.Fatal(err)
		}
		// Complete TCP handshake.
		tst.TestTCPHandshake(&client, sv)
		// After handshake, TryAccept should work.
		if listener.NumberOfReadyToAccept() != 1 {
			t.Fatalf("after handshake: expected 1 ready, got %d", listener.NumberOfReadyToAccept())
		}
		svconn, err := listener.TryAccept()
		if err != nil {
			t.Fatal(err)
		} else if svconn.RemotePort() != clConn.LocalPort() ||
			[4]byte(svconn.RemoteAddr()) != client.Addr().As4() {
			t.Fatal("race condition to listener acquisition")
		}
		// Verify both connections are established.
		if clConn.State() != tcp.StateEstablished {
			t.Fatalf("client: expected StateEstablished, got %s", clConn.State())
		}
		if len(data) > 0 {
			tst.TestTCPEstablishedSingleData(&client, sv, &clConn, svconn, data)
		}
		if sleep > 0 {
			time.Sleep(sleep)
		}
		tst.TestTCPClose(&client, sv, &clConn, svconn)
	}
	t.Run("serial-conns", func(t *testing.T) {

		for range 100 {
			caddr := caddr.Next()
			doRequest(netip.AddrPortFrom(caddr, uint16(sv.Prand32())), 0, []byte("HTTP 1.0\r\n"))
		}
	})
	t.Run("concurrent-conns", func(t *testing.T) {
		const maxConcurrents = poolsize
		const sleep = time.Millisecond
		queue := make(chan struct{}, maxConcurrents)
		for range 1000 {
			caddr = caddr.Next()
			go func(caddrp netip.AddrPort) {
				queue <- struct{}{}
				doRequest(caddrp, sleep, []byte("HTTP 1.0\r\n"))
				<-queue
			}(netip.AddrPortFrom(caddr, uint16(sv.Prand32())))
		}
	})

}
