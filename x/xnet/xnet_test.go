package xnet

import (
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internet/pcap"
	"github.com/soypat/lneto/tcp"
)

const (
	synack = tcp.FlagSYN | tcp.FlagACK
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

	const svPort = 80
	var svconn tcp.Conn
	err = svconn.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, MTU),
		TxBuf:             make([]byte, MTU),
		TxPacketQueueSize: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = sv.ListenTCP(&svconn, svPort)
	if err != nil {
		t.Fatal(err)
	}

	var clconn tcp.Conn
	err = clconn.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, MTU),
		TxBuf:             make([]byte, MTU),
		TxPacketQueueSize: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.SetGateway6(sv.HardwareAddress())
	sv.SetGateway6(client.HardwareAddress())

	err = client.DialTCP(&clconn, 1337, netip.AddrPortFrom(sv.Addr(), svPort))
	if err != nil {
		t.Fatal(err)
	}

	var expected = []struct {
		fromClient bool
		flags      tcp.Flags
	}{
		{
			fromClient: true,
			flags:      tcp.FlagSYN,
		},
		{
			fromClient: false,
			flags:      synack,
		},
		{
			fromClient: true,
			flags:      tcp.FlagACK,
		},
	}
	var cap pcap.PacketBreakdown
	var frms []pcap.Frame
	var buf [MTU]byte
	for _, action := range expected {
		var n int
		switch action.fromClient {
		case true:
			n, err = client.Encapsulate(buf[:], 0)
		case false:
			n, err = sv.Encapsulate(buf[:], 0)
		}
		if err != nil {
			t.Fatal(err)
		} else if n == 0 {
			t.Error("zero bits sent")
		}
		frms, err = cap.CaptureEthernet(frms[:0], buf[:n], 0)
		if err != nil {
			t.Fatal(err)
		}
		tfrm := getProtoFrame(frms, lneto.IPProtoTCP)
		if tfrm == nil {
			t.Fatal("where's the TCP?")
		}
		fidx, _ := tfrm.FieldByClass(pcap.FieldClassFlags)
		flags, _ := tfrm.FieldAsUint(fidx, buf[:n])
		tflags := tcp.Flags(flags)
		if tflags != action.flags {
			t.Errorf("expected flags %s, got %s", action.flags.String(), tflags.String())
		}
		switch action.fromClient {
		case true:
			err = sv.Demux(buf[:], 0)
		case false:
			err = client.Demux(buf[:], 0)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func getProtoFrame(frms []pcap.Frame, proto any) *pcap.Frame {
	for i := range frms {
		if frms[i].Protocol == proto {
			return &frms[i]
		}
	}
	return nil
}
