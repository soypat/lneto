package xnet

import (
	"net/netip"
	"testing"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/tcp"
)

func BenchmarkARPExchange(b *testing.B) {
	const MTU = 1500
	const frameSize = MTU + ethernet.MaxOverheadSize
	c1, c2 := new(StackAsync), new(StackAsync)
	queryAddr := netip.AddrFrom4([4]byte{192, 168, 1, 2})

	err := c1.Reset(StackConfig{
		Hostname:        "C1",
		RandSeed:        1,
		StaticAddress:   netip.AddrFrom4([4]byte{192, 168, 1, 1}),
		HardwareAddress: [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x00},
		MTU:             MTU,
	})
	if err != nil {
		b.Fatal(err)
	}
	err = c2.Reset(StackConfig{
		Hostname:        "C2",
		RandSeed:        2,
		StaticAddress:   queryAddr,
		HardwareAddress: [6]byte{0xc0, 0xff, 0xee, 0xc0, 0xff, 0xee},
		MTU:             MTU,
	})
	if err != nil {
		b.Fatal(err)
	}
	// Set gateways so ethernet frames are properly addressed.
	c1.SetGateway6(c2.HardwareAddress())
	c2.SetGateway6(c1.HardwareAddress())

	var buf [frameSize]byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = c1.StartResolveHardwareAddress6(queryAddr)
		if err != nil {
			b.Fatal(err)
		}
		n, err := c1.Encapsulate(buf[:], -1, 0) // Send Request.
		if err != nil {
			b.Fatal(err)
		} else if n == 0 {
			b.Fatal("expected send of data after first query")
		}
		err = c2.Demux(buf[:n], 0) // Receive request.
		if err != nil {
			b.Fatal(err)
		}
		n, err = c2.Encapsulate(buf[:], -1, 0) // Send response.
		if err != nil {
			b.Fatal(err)
		} else if n == 0 {
			b.Fatal("got no response to request")
		}
		err = c1.Demux(buf[:n], 0) // Receive response.
		if err != nil {
			b.Fatal(err)
		}
		_, err = c1.ResultResolveHardwareAddress6(queryAddr)
		if err != nil {
			b.Fatal("expected query result:", err)
		}
		// Discard query for next iteration.
		c1.DiscardResolveHardwareAddress6(queryAddr)
	}
}

func BenchmarkTCPHandshake(b *testing.B) {
	const MTU = 1500
	const frameSize = MTU + ethernet.MaxOverheadSize
	const svPort = 8080
	client, sv := new(StackAsync), new(StackAsync)
	clconn, svconn := new(tcp.Conn), new(tcp.Conn)

	err := sv.Reset(StackConfig{
		Hostname:        "Server",
		RandSeed:        1,
		StaticAddress:   netip.AddrFrom4([4]byte{10, 0, 0, 1}),
		MaxTCPConns:     1,
		HardwareAddress: [6]byte{0xbe, 0xef, 0, 0, 0, 1},
		MTU:             MTU,
	})
	if err != nil {
		b.Fatal(err)
	}
	err = client.Reset(StackConfig{
		Hostname:        "Client",
		RandSeed:        2,
		StaticAddress:   netip.AddrFrom4([4]byte{10, 0, 0, 2}),
		MaxTCPConns:     1,
		HardwareAddress: [6]byte{0xbe, 0xef, 0, 0, 0, 2},
		MTU:             MTU,
	})
	if err != nil {
		b.Fatal(err)
	}
	sv.SetGateway6(client.HardwareAddress())
	client.SetGateway6(sv.HardwareAddress())

	buf := make([]byte, MTU*4)
	err = clconn.Configure(tcp.ConnConfig{
		RxBuf:             buf[:MTU],
		TxBuf:             buf[MTU : MTU*2],
		TxPacketQueueSize: 4,
	})
	if err != nil {
		b.Fatal(err)
	}
	err = svconn.Configure(tcp.ConnConfig{
		RxBuf:             buf[2*MTU : 3*MTU],
		TxBuf:             buf[3*MTU : 4*MTU],
		TxPacketQueueSize: 4,
	})
	if err != nil {
		b.Fatal(err)
	}

	var pktbuf [frameSize]byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Setup connections.
		err = sv.ListenTCP(svconn, svPort)
		if err != nil {
			b.Fatal(err)
		}
		err = client.DialTCP(clconn, 1337, netip.AddrPortFrom(sv.Addr(), svPort))
		if err != nil {
			b.Fatal(err)
		}

		// SYN from client.
		n, err := client.Encapsulate(pktbuf[:], -1, 0)
		if err != nil {
			b.Fatal(err)
		}
		err = sv.Demux(pktbuf[:n], 0)
		if err != nil {
			b.Fatal(err)
		}

		// SYN-ACK from server.
		n, err = sv.Encapsulate(pktbuf[:], -1, 0)
		if err != nil {
			b.Fatal(err)
		}
		err = client.Demux(pktbuf[:n], 0)
		if err != nil {
			b.Fatal(err)
		}

		// ACK from client.
		n, err = client.Encapsulate(pktbuf[:], -1, 0)
		if err != nil {
			b.Fatal(err)
		}
		err = sv.Demux(pktbuf[:n], 0)
		if err != nil {
			b.Fatal(err)
		}

		// Abort connections for next iteration.
		clconn.Abort()
		svconn.Abort()
	}
}
