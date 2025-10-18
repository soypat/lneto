package xnet

import (
	"net/netip"
	"testing"

	"github.com/soypat/lneto/tcp"
)

func TestABC(t *testing.T) {
	const seed = 1234
	const MTU = 1500
	var mac = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	var client StackAsync
	err := client.Reset(StackConfig{
		StaticAddress:   netip.MustParseAddr("10.0.0.1"),
		MaxTCPConns:     1,
		MTU:             MTU,
		HardwareAddress: mac,
		Hostname:        "client",
		RandSeed:        seed,
	})
	if err != nil {
		t.Fatal(err)
	}

	var macsv = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	var sv StackAsync
	err = sv.Reset(StackConfig{
		StaticAddress:   netip.MustParseAddr("10.0.0.2"),
		MaxTCPConns:     1,
		MTU:             MTU,
		HardwareAddress: macsv,
		Hostname:        "server",
		RandSeed:        seed,
	})
	if err != nil {
		t.Fatal(err)
	}
	// IMG_1084.MOV

	const svPort = 80
	var clconn tcp.Conn
	err = clconn.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, MTU),
		TxBuf:             make([]byte, MTU),
		TxPacketQueueSize: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = client.DialTCP(&clconn, 1337, netip.AddrPortFrom(sv.Addr(), svPort))
	if err != nil {
		t.Fatal(err)
	}

	var svconn tcp.Conn
	err = svconn.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, MTU),
		TxBuf:             make([]byte, MTU),
		TxPacketQueueSize: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	// clconn.OpenListen()
}
