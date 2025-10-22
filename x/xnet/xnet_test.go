package xnet

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
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
	var src, dst *StackAsync
	switch expect.SourceIdx {
	case 0:
		src, dst = stack1, stack2
	case 1:
		src, dst = stack2, stack1
	default:
		panic("OOB")
	}
	n, err := src.Encapsulate(buf[:], 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		if nodata {
			return // No data sent and no data expected.
		}
		t.Error("zero bits sent")
	}

	tst.buf = tst.buf[:n]
	defer func() {
		tst.buf = tst.buf[:cap(tst.buf)]
	}()
	tst.frmbuf, err = tst.cap.CaptureEthernet(tst.frmbuf[:0], buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}
	srcEth := src.HardwareAddress()
	dstEth := dst.HardwareAddress()
	if !bytes.Equal(srcEth[:], tst.getData(pcap.ProtoEthernet, pcap.FieldClassSrc)) {
		t.Errorf("mismatched ethernet src addr %x", tst.getData(pcap.ProtoEthernet, pcap.FieldClassSrc))
	}
	if !bytes.Equal(dstEth[:], tst.getData(pcap.ProtoEthernet, pcap.FieldClassDst)) {
		t.Errorf("mismatched ethernet dst addr %x", tst.getData(pcap.ProtoEthernet, pcap.FieldClassDst))
	}
	if tst.getInt(ethernet.TypeIPv4, pcap.FieldClassVersion) != 4 {
		t.Errorf("did not get IP version=4, got=%d", tst.getInt(ethernet.TypeIPv4, pcap.FieldClassVersion))
	}
	srcAddr := src.Addr()
	dstAddr := dst.Addr()
	if !bytes.Equal(srcAddr.AsSlice(), tst.getData(ethernet.TypeIPv4, pcap.FieldClassSrc)) {
		t.Errorf("mismatched ip src addr %d", tst.getData(ethernet.TypeIPv4, pcap.FieldClassSrc))
	}
	if !bytes.Equal(dstAddr.AsSlice(), tst.getData(ethernet.TypeIPv4, pcap.FieldClassDst)) {
		t.Errorf("mismatched ip dst addr %d", tst.getData(ethernet.TypeIPv4, pcap.FieldClassDst))
	}
	tflags := tcp.Flags(tst.getInt(lneto.IPProtoTCP, pcap.FieldClassFlags))
	payload := tst.getPayload(lneto.IPProtoTCP)
	if !bytes.Equal(payload, expect.WantData) {
		t.Errorf("mismatched data sent, \nwant=%q\ngot=%q\n", expect.WantData, payload)
	}
	if tflags != expect.WantFlags {
		t.Errorf("expected flags %s, got %s", expect.WantFlags.String(), tflags.String())
	}
	err = dst.Demux(buf[:], 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := range buf[:n] {
		buf[i] = 0 // Set data sent to zero.
	}
}

func (tst *tester) getPayload(proto any) []byte {
	tst.t.Helper()
	i := 0
	for i = 0; i < len(tst.frmbuf); i++ {
		if tst.frmbuf[i].Protocol == proto {
			if i < len(tst.frmbuf)-1 {
				frm := &tst.frmbuf[i+1]
				bitOff := frm.PacketBitOffset
				if bitOff%8 != 0 {
					tst.t.Fatalf("proto %s bitoffset not multiple of 8: %d", proto, bitOff)
				}
				return tst.buf[bitOff/8:]
			}
		}
	}
	return tst.getData(proto, pcap.FieldClassPayload)
}

func (tst *tester) getData(proto any, field pcap.FieldClass) []byte {
	tst.t.Helper()
	frm := getProtoFrame(tst.frmbuf, proto)
	if frm == nil {
		tst.t.Fatalf("no frame for proto %s found in %s", proto, tst.frmbuf)
	}
	fidx, err := frm.FieldByClass(field)
	if err != nil {
		if errors.Is(err, pcap.ErrFieldByClassNotFound) {
			return nil
		}
		tst.t.Fatal(err)
	}
	bitoff := frm.PacketBitOffset + frm.Fields[fidx].FrameBitOffset
	bitlen := frm.Fields[fidx].BitLength
	if bitoff%8 != 0 || bitlen%8 != 0 {
		tst.t.Fatal("frame bitlength not multiple of 8")
	}
	return tst.buf[bitoff/8 : bitoff/8+bitlen/8]
}

func (tst *tester) getInt(proto any, field pcap.FieldClass) uint64 {
	tst.t.Helper()
	frm := getProtoFrame(tst.frmbuf, proto)
	if frm == nil {
		tst.t.Fatalf("no frame for proto %s found in %s", proto, tst.frmbuf)
	}
	fidx, err := frm.FieldByClass(field)
	if err != nil {
		tst.t.Fatal(err)
	}
	v, err := frm.FieldAsUint(fidx, tst.buf)
	if err != nil {
		tst.t.Fatal(err)
	}
	return v
}

func getProtoFrame(frms []pcap.Frame, proto any) *pcap.Frame {
	for i := range frms {
		if frms[i].Protocol == proto {
			return &frms[i]
		}
	}
	return nil
}
