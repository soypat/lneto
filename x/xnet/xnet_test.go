package xnet

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internet/pcap"
	"github.com/soypat/lneto/tcp"
)

const (
	synack = tcp.FlagSYN | tcp.FlagACK
	pshack = tcp.FlagPSH | tcp.FlagACK
	finack = tcp.FlagFIN | tcp.FlagACK
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
	sendData := []byte("hello")
	tst.TestTCPHandshake(&client, &sv)
	tst.TestTCPEstablishedSingleData(&client, &sv, &clconn, &svconn, sendData)
	tst.TestTCPClose(&client, &sv, &clconn, &svconn)
}

type tester struct {
	t       *testing.T
	cap     pcap.PacketBreakdown
	frmbuf  []pcap.Frame
	buf     []byte
	exch    []tcpExpectExchange
	lastSeg tcp.Segment
}

type tcpExpectExchange struct {
	SourceIdx int
	WantFlags tcp.Flags
	WantData  []byte
}

func noExchange(source int) tcpExpectExchange {
	return tcpExpectExchange{SourceIdx: source}
}

func (tst *tester) TestTCPHandshake(stack1, stack2 *StackAsync) {
	tst.t.Helper()
	tst.exch = append(tst.exch[:0], []tcpExpectExchange{
		{
			SourceIdx: 0,
			WantFlags: tcp.FlagSYN,
		},
		noExchange(0),
		{
			SourceIdx: 1,
			WantFlags: synack,
		},
		noExchange(1),
		{
			SourceIdx: 0,
			WantFlags: tcp.FlagACK,
		},
		noExchange(0),
		noExchange(1),
	}...)
	for _, wants := range tst.exch {
		tst.TCPExchange(wants, stack1, stack2)
	}
}

func (tst *tester) TestTCPEstablishedSingleData(stack1, stack2 *StackAsync, conn1, conn2 *tcp.Conn, sendData []byte) {
	tst.t.Helper()
	_, err := conn1.Write(sendData)
	if err != nil {
		tst.t.Fatal(err)
	}
	nprev := conn2.BufferedInput()
	tst.exch = append(tst.exch[:0], []tcpExpectExchange{
		{
			SourceIdx: 0,
			WantFlags: pshack,
			WantData:  sendData,
		},
		noExchange(0),
		{
			SourceIdx: 1,
			WantFlags: tcp.FlagACK,
		},
		noExchange(0),
		noExchange(1),
	}...)
	for _, wants := range tst.exch {
		tst.TCPExchange(wants, stack1, stack2)
	}
	n, err := conn2.Read(tst.buf)
	if err != nil {
		tst.t.Errorf("reading back data %q on conn2: %s", sendData, err)
	} else if n == len(tst.buf) {
		tst.t.Fatalf("buffer topped out in read!")
	}
	nread := n - nprev
	if nread != len(sendData) {
		tst.t.Errorf("expected to read %d bytes, got %d", len(sendData), nread)
	} else {
		got := tst.buf[n-nread : n]
		if !bytes.Equal(got, sendData) {
			tst.t.Errorf("expected to read back %q from conn, got %q", sendData, got)
		}
	}
	setzero(tst.buf[:n])
}

func (tst *tester) TestTCPClose(stack1, stack2 *StackAsync, conn1, conn2 *tcp.Conn) {
	t := tst.t
	t.Helper()
	cid1 := conn1.ConnectionID()
	cid2 := conn2.ConnectionID()
	cid1v := *cid1
	cid2v := *cid2
	err := conn1.Close()
	if err != nil {
		t.Fatal(err)
	}
	tst.exch = append(tst.exch[:0], []tcpExpectExchange{
		{
			SourceIdx: 0,
			WantFlags: finack, // Closer sends FINACK
		},
		noExchange(0),
		{
			SourceIdx: 1,
			WantFlags: tcp.FlagACK,
		},
		{
			SourceIdx: 1,
			WantFlags: finack,
		},
		noExchange(1),
		{
			SourceIdx: 0,
			WantFlags: tcp.FlagACK,
		},
		noExchange(0),
		noExchange(1),
	}...)
	t.Log(conn1.State().String(), conn2.State().String())
	for i, exch := range tst.exch {
		failed := t.Failed()
		tst.TCPExchange(exch, stack1, stack2)
		if !failed && t.Failed() {
			t.Error(i, exch.SourceIdx, "close failure")
		}
		if exch.WantFlags == 0 {
			continue
		}

		t.Log(i, tcp.StringExchange(tst.lastSeg, conn1.State(), conn2.State(), exch.SourceIdx != 0))
	}

	state1 := conn1.State()
	state2 := conn2.State()
	if !state1.IsClosed() {
		t.Errorf("expected closed state1, got %s", state1.String())
	}
	if !state2.IsClosed() {
		t.Errorf("expected closed state2, got %s", state2.String())
	}
	if cid1v == *cid1 {
		t.Error("no cid1 change")
	}
	if cid2v == *cid2 {
		t.Error("no cid2 change")
	}
}

func (tst *tester) TCPExchange(expect tcpExpectExchange, stack1, stack2 *StackAsync) {
	tst.lastSeg = tcp.Segment{}
	var src, dst *StackAsync
	defer func(failed bool) {
		if !failed && tst.t.Failed() {
			tst.t.Helper()
			tst.t.Logf("failed on idx=%d src=%s -->  dst=%s", expect.SourceIdx, src.Hostname(), dst.Hostname())
		}
	}(tst.t.Failed())
	t := tst.t
	t.Helper()
	buf := tst.buf[:cap(tst.buf)]
	nodata := expect.WantFlags == 0

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
	} else if nodata && n > 0 {
		t.Error("expected no data sent and got data")
		return
	}

	tst.buf = tst.buf[:n]
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
	tfrm := tst.getTCPFrame()

	payload := tfrm.Payload()
	seg := tfrm.Segment(len(payload))
	tst.lastSeg = seg
	if !bytes.Equal(payload, expect.WantData) {
		t.Errorf("mismatched data sent, \nwant=%q\ngot=%q\n", expect.WantData, payload)
	}
	if seg.Flags != expect.WantFlags {
		t.Errorf("expected flags %s, got %s", expect.WantFlags.String(), seg.Flags.String())
	}
	err = dst.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}
	setzero(buf[:n])
}

func (tst *tester) getTCPFrame() tcp.Frame {
	data := tst.getPayload(ethernet.TypeIPv4)
	frame, err := tcp.NewFrame(data)
	if err != nil {
		panic(err)
	}
	return frame
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

func setzero[T ~[]E, E any](s T) {
	var zero E
	for i := range s {
		s[i] = zero
	}
}
