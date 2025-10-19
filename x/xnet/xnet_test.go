package xnet

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internet/pcap"
	"github.com/soypat/lneto/tcp"
)

const (
	synack = tcp.FlagSYN | tcp.FlagACK
	pshack = tcp.FlagPSH | tcp.FlagACK
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

	tst := tester{
		t: t, buf: make([]byte, MTU),
	}
	const flagNoData = tcp.Flags(0)
	noMoreData := []tcpExpectExchange{{SourceIdx: 0, WantFlags: flagNoData}, {SourceIdx: 1, WantFlags: flagNoData}}
	expected := []tcpExpectExchange{
		{
			SourceIdx: 0,
			WantFlags: tcp.FlagSYN,
		},
		{
			SourceIdx: 1,
			WantFlags: synack,
		},
		{
			SourceIdx: 0,
			WantFlags: tcp.FlagACK,
		},
	}
	expected = append(expected, noMoreData...) // Ensure no data exchanged after expected.
	for _, wants := range expected {
		tst.TCPExchange(wants, &client, &sv)
	}
	sendData := []byte("hello")
	_, err = clconn.Write(sendData)
	if err != nil {
		t.Fatal(err)
	}
	expected = []tcpExpectExchange{
		{
			SourceIdx: 0,
			WantFlags: pshack,
			WantData:  sendData,
		},
		{
			SourceIdx: 1,
			WantFlags: tcp.FlagACK,
		},
	}
	expected = append(expected, noMoreData...) // Ensure no data exchanged after expected.
	for _, wants := range expected {
		tst.TCPExchange(wants, &client, &sv)
	}
}

type tester struct {
	t      *testing.T
	cap    pcap.PacketBreakdown
	frmbuf []pcap.Frame
	buf    []byte
}

type tcpExpectExchange struct {
	SourceIdx int
	WantFlags tcp.Flags
	WantData  []byte
}

func (tst *tester) TCPExchange(expect tcpExpectExchange, stack1, stack2 *StackAsync) {
	t := tst.t
	buf := tst.buf
	nodata := expect.WantFlags == 0
	var n int
	var err error
	switch expect.SourceIdx {
	case 0:
		n, err = stack1.Encapsulate(buf[:], 0)
	case 1:
		n, err = stack2.Encapsulate(buf[:], 0)
	default:
		panic("OOB")
	}
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		if nodata {
			return // No data sent and no data expected.
		}
		t.Error("zero bits sent")
	}
	tst.frmbuf, err = tst.cap.CaptureEthernet(tst.frmbuf[:0], buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}
	tfrm := getProtoFrame(tst.frmbuf, lneto.IPProtoTCP)
	if tfrm == nil {
		t.Fatal("where's the TCP?")
	}
	fidx, _ := tfrm.FieldByClass(pcap.FieldClassFlags)
	flags, _ := tfrm.FieldAsUint(fidx, buf[:n])
	tflags := tcp.Flags(flags)
	var payload []byte
	fidx, _ = tfrm.FieldByClass(pcap.FieldClassPayload)
	if fidx > 0 {
		fieldPayload := tfrm.Fields[fidx]
		payload = buf[fieldPayload.FrameBitOffset*8:]
	}
	if !bytes.Equal(payload, expect.WantData) {
		t.Errorf("mismatched data sent, \nwant=%q\ngot=%q\n", expect.WantData, payload)
	}
	if tflags != expect.WantFlags {
		t.Errorf("expected flags %s, got %s", expect.WantFlags.String(), tflags.String())
	}
	switch expect.SourceIdx {
	case 0:
		err = stack2.Demux(buf[:], 0)
	case 1:
		err = stack1.Demux(buf[:], 0)
	}
	if err != nil {
		t.Fatal(err)
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
