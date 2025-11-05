package xnet

import (
	"bytes"
	"errors"
	"math/rand"
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

func TestStackAsyncTCP_multipacket(t *testing.T) {
	const seed = 1234
	const MTU = 512
	const svPort = 8080
	const maxPktLen = 30
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := tester{
		t: t, buf: make([]byte, MTU),
	}
	rng := rand.New(rand.NewSource(seed))
	client2, sv2, clconn2, svconn2 := newTCPStacks(t, seed, MTU)
	_, _, _, _ = client2, sv2, clconn2, svconn2
	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)
	tst.TestTCPClose(client, sv, clconn, svconn)
	var buf [MTU]byte
	for i := 0; i < 1; i++ {
		payloadSize := rng.Intn(maxPktLen) + 1
		tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)
		// npkt := rng.Intn(maxNPkt-1) + 2
		a, _ := rng.Read(buf[:payloadSize])
		tst.TestTCPEstablishedSingleData(sv, client, svconn, clconn, buf[:a])
		a, _ = rng.Read(buf[:payloadSize])
		tst.TestTCPEstablishedSingleData(sv, client, svconn, clconn, buf[:a])
		// for ipkt := 0; ipkt < npkt; ipkt++ {
		// 	a, _ := rng.Read(buf[:payloadSize])
		// 	tst.TestTCPEstablishedSingleData(sv, client, svconn, clconn, buf[:a])
		// }
		tst.TestTCPClose(client, sv, clconn, svconn)
		if t.Failed() {
			t.Error("multi failed")
			t.FailNow()
		}
	}
}

func TestStackAsyncTCP_singlepacket(t *testing.T) {
	const seed = 1234
	const MTU = 1500
	const svPort = 80
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)

	tst := tester{
		t: t, buf: make([]byte, MTU),
	}

	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)
	sendData := []byte("hello")
	tst.TestTCPEstablishedSingleData(client, sv, clconn, svconn, sendData)
	tst.TestTCPClose(client, sv, clconn, svconn)

	// Switch handles around, now server will be client and they will be registered to
	// a different stack.
	svconn, clconn = clconn, svconn
	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1234)
	sendData = []byte("olleh")
	tst.TestTCPEstablishedSingleData(client, sv, clconn, svconn, sendData)
	tst.TestTCPClose(client, sv, clconn, svconn)
}

func newTCPStacks(t *testing.T, randSeed int64, mtu int) (s1, s2 *StackAsync, c1, c2 *tcp.Conn) {
	s1, s2 = new(StackAsync), new(StackAsync)
	c1, c2 = new(tcp.Conn), new(tcp.Conn)
	byte1 := byte(randSeed) / 4
	err := s1.Reset(StackConfig{
		Hostname:        "Stack1",
		RandSeed:        randSeed,
		StaticAddress:   netip.AddrFrom4([4]byte{10, 0, 0, byte1}),
		MaxTCPConns:     1,
		HardwareAddress: [6]byte{0xbe, 0xef, 0, 0, 0, byte1},
		MTU:             uint16(mtu),
	})
	if err != nil {
		t.Fatal(err)
	}

	byte2 := byte1 + 1
	err = s2.Reset(StackConfig{
		Hostname:        "Stack2",
		RandSeed:        ^randSeed,
		StaticAddress:   netip.AddrFrom4([4]byte{10, 0, 0, byte2}),
		MaxTCPConns:     1,
		HardwareAddress: [6]byte{0xbe, 0xef, 0, 0, 0, byte2},
		MTU:             uint16(mtu),
	})
	if err != nil {
		t.Fatal(err)
	}
	s1.SetGateway6(s2.HardwareAddress())
	s2.SetGateway6(s1.HardwareAddress())
	buf := make([]byte, mtu*4)
	err = c1.Configure(tcp.ConnConfig{
		RxBuf:             buf[:mtu],
		TxBuf:             buf[mtu : mtu*2],
		TxPacketQueueSize: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = c2.Configure(tcp.ConnConfig{
		RxBuf:             buf[2*mtu : 3*mtu],
		TxBuf:             buf[3*mtu : 4*mtu],
		TxPacketQueueSize: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s1, s2, c1, c2
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

func (tst *tester) TestTCPSetupAndEstablish(svStack, clStack *StackAsync, svConn, clConn *tcp.Conn, svPort, clPort uint16) {
	t := tst.t
	// Attach server and client connections to stacks.
	err := svStack.ListenTCP(svConn, svPort)
	if err != nil {
		t.Fatal(err)
	}
	err = clStack.DialTCP(clConn, clPort, netip.AddrPortFrom(svStack.Addr(), svPort))
	if err != nil {
		t.Fatal(err)
	}
	tst.TestTCPHandshake(clStack, svStack)
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

func (tst *tester) TestTCPEstablishedSingleData(srcStack, dstStack *StackAsync, srcConn, dstConn *tcp.Conn, sendData []byte) {
	t := tst.t
	t.Helper()
	availTx := srcConn.AvailableOutput()
	availRx := dstConn.AvailableInput()
	if availTx < len(sendData) {
		t.Fatal("insufficient space for write call", availTx, len(sendData))
	} else if len(sendData) <= 0 {
		panic("empty data!")
	} else if availRx < len(sendData) {
		t.Fatal("insufficient space for dst read call", availRx, len(sendData))
	}
	_, err := srcConn.Write(sendData)
	if err != nil {
		t.Fatal(err)
	}
	nprev := dstConn.BufferedInput()
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
		tst.TCPExchange(wants, srcStack, dstStack)
	}
	n, err := dstConn.Read(tst.buf)
	if err != nil {
		t.Errorf("reading back data %q on conn2: %s", sendData, err)
	} else if n == len(tst.buf) {
		t.Fatalf("buffer topped out in read!")
	}
	nread := n - nprev
	if nread != len(sendData) {
		t.Errorf("expected to read %d bytes, got %d", len(sendData), nread)
	} else {
		got := tst.buf[n-nread : n]
		if !bytes.Equal(got, sendData) {
			t.Errorf("expected to read back %q from conn, got %q", sendData, got)
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
