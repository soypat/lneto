package xnet

import (
	"bytes"
	"errors"
	"math/rand"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internet/pcap"
	"github.com/soypat/lneto/tcp"
)

const (
	logExchange = false

	synack = tcp.FlagSYN | tcp.FlagACK
	pshack = tcp.FlagPSH | tcp.FlagACK
	finack = tcp.FlagFIN | tcp.FlagACK
)

func TestTCPConn_ReadBlocksUntilDataAvailable(t *testing.T) {
	const seed = 5678
	const MTU = 1500
	const svPort = 8080
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := testerFrom(t, MTU)

	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)

	// Verify no data buffered initially.
	if svconn.BufferedInput() != 0 {
		t.Fatal("expected no buffered input on server conn")
	}

	sendData := []byte("blocking test data")
	readDone := make(chan struct{})
	var readN int
	var readErr error
	var readBuf [64]byte

	// Start a goroutine to read from svconn - this should block since no data available.
	go func() {
		readN, readErr = svconn.Read(readBuf[:])
		close(readDone)
	}()

	// Give Read time to enter blocking state.
	select {
	case <-readDone:
		t.Fatal("Read returned immediately without data - expected blocking")
	case <-time.After(50 * time.Millisecond):
		// Good - Read is blocking as expected.
	}

	// Write data on client side.
	_, err := clconn.Write(sendData)
	if err != nil {
		t.Fatal(err)
	}

	// Perform packet exchange to deliver data.
	tst.bufmu.Lock()
	buf := tst.buf[:cap(tst.buf)]
	n, err := client.Encapsulate(buf, -1, 0)
	if err != nil {
		tst.bufmu.Unlock()
		t.Fatal(err)
	}
	if n == 0 {
		tst.bufmu.Unlock()
		t.Fatal("expected data packet from client")
	}
	err = sv.Demux(buf[:n], 0)
	tst.bufmu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	// Now Read should unblock and return data.
	select {
	case <-readDone:
		// Good - Read unblocked.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Read did not unblock after data became available")
	}

	if readErr != nil {
		t.Fatalf("Read returned error: %v", readErr)
	}
	if readN != len(sendData) {
		t.Fatalf("expected to read %d bytes, got %d", len(sendData), readN)
	}
	if !bytes.Equal(readBuf[:readN], sendData) {
		t.Fatalf("read data mismatch: got %q, want %q", readBuf[:readN], sendData)
	}
}

func TestStackAsyncTCP_multipacket(t *testing.T) {
	const seed = 1234
	const MTU = 512
	const svPort = 8080
	const maxPktLen = 30
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := testerFrom(t, MTU)
	rng := rand.New(rand.NewSource(seed))
	client2, sv2, clconn2, svconn2 := newTCPStacks(t, seed, MTU)

	for _, clientCloses := range []bool{true, false} {
		testClose := func() {
			t.Helper()
			if clientCloses {
				tst.TestTCPClose(client, sv, clconn, svconn)
			} else {
				tst.TestTCPClose(sv, client, svconn, clconn)
			}
		}
		tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)
		testClose()
		var buf [MTU]byte
		for i := 0; i < 20; i++ {
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
			testClose()
			if t.Failed() {
				t.Error("multi failed")
				t.FailNow()
			}
		}
	}
	_, _, _, _ = client2, sv2, clconn2, svconn2

}

func TestStackAsyncTCP_singlepacket(t *testing.T) {
	const seed = 1234
	const MTU = 1500
	const svPort = 80
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := testerFrom(t, MTU)

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

func newTCPStacks(t testing.TB, randSeed int64, mtu int) (s1, s2 *StackAsync, c1, c2 *tcp.Conn) {
	s1, s2 = new(StackAsync), new(StackAsync)
	c1, c2 = new(tcp.Conn), new(tcp.Conn)
	byte1 := byte(randSeed)/4 - 1
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

func testerFrom(t *testing.T, mtu int) *tester {
	carrierDataSize := mtu + ethernet.MaxOverheadSize
	return &tester{
		t:   t,
		buf: make([]byte, carrierDataSize),
	}
}

type tester struct {
	t *testing.T

	cap    pcap.PacketBreakdown
	frmbuf []pcap.Frame
	bufmu  sync.Mutex
	buf    []byte
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
	exch := [...]tcpExpectExchange{
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
	}
	for _, wants := range exch {
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
	exch := [...]tcpExpectExchange{
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
	}
	for _, wants := range exch {
		tst.TCPExchange(wants, srcStack, dstStack)
	}
	tst.bufmu.Lock()
	defer tst.bufmu.Unlock()
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
	err := conn1.Close()
	if err != nil {
		t.Fatal(err)
	}
	exch := [...]tcpExpectExchange{
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
	}
	if logExchange {
		t.Log(conn1.State().String(), conn2.State().String())
	}
	for i, exch := range exch {
		failed := t.Failed()
		seg := tst.TCPExchange(exch, stack1, stack2)
		if !failed && t.Failed() {
			t.Error(i, exch.SourceIdx, "close failure")
		}
		if exch.WantFlags == 0 {
			continue
		}
		if logExchange {
			t.Log(i, tcp.StringExchange(seg, conn1.State(), conn2.State(), exch.SourceIdx != 0))
		}
	}

	state1 := conn1.State()
	state2 := conn2.State()
	if !state1.IsClosed() {
		t.Errorf("expected closed state1, got %s", state1.String())
	}
	if !state2.IsClosed() {
		t.Errorf("expected closed state2, got %s", state2.String())
	}
}

func (tst *tester) TCPExchange(expect tcpExpectExchange, stack1, stack2 *StackAsync) tcp.Segment {
	tst.bufmu.Lock()
	defer tst.bufmu.Unlock()
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

	n, err := src.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		if nodata {
			return tcp.Segment{} // No data sent and no data expected.
		}
		t.Error("zero bits sent")
	} else if nodata && n > 0 {
		t.Error("expected no data sent and got data")
		return tcp.Segment{}
	}
	defer setzero(buf[:n])

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
	return seg
}

func (tst *tester) ARPExchangeOnly(querying, target *StackAsync) {
	t := tst.t
	t.Helper()
	tst.bufmu.Lock()
	defer tst.bufmu.Unlock()
	buf := tst.buf[:cap(tst.buf)]

	// === PHASE 1: ARP Request from querying stack ===
	n, err := querying.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Error("zero bits sent by ARP querying stack")
		return
	}

	tst.frmbuf, err = tst.cap.CaptureEthernet(tst.frmbuf[:0], buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}
	tst.buf = tst.buf[:n]

	qHw := querying.HardwareAddress()
	tgtHw := target.HardwareAddress()
	broadcast := ethernet.BroadcastAddr()
	qIP := querying.Addr()
	tgtIP := target.Addr()

	// Validate Ethernet layer (request is broadcast)
	if !bytes.Equal(qHw[:], tst.getData(pcap.ProtoEthernet, pcap.FieldClassSrc)) {
		t.Errorf("request: mismatched ethernet src addr %x", tst.getData(pcap.ProtoEthernet, pcap.FieldClassSrc))
	}
	if !bytes.Equal(broadcast[:], tst.getData(pcap.ProtoEthernet, pcap.FieldClassDst)) {
		t.Errorf("request: expected broadcast ethernet dst addr, got %x", tst.getData(pcap.ProtoEthernet, pcap.FieldClassDst))
	}

	// Validate ARP request fields
	// ARP fields: FieldClassSrc with 6 octets = HW addr, 4 octets = proto addr
	// occurrence 0 = sender, occurrence 1 = target
	if tst.getARPOperation() != arp.OpRequest {
		t.Errorf("request: expected ARP OpRequest, got %d", tst.getARPOperation())
	}
	if !bytes.Equal(qHw[:], tst.getFieldByClassLen(ethernet.TypeARP, pcap.FieldClassSrc, 6, 0)) {
		t.Errorf("request: mismatched ARP sender HW")
	}
	if !bytes.Equal(qIP.AsSlice(), tst.getFieldByClassLen(ethernet.TypeARP, pcap.FieldClassSrc, 4, 0)) {
		t.Errorf("request: mismatched ARP sender proto")
	}
	if !bytes.Equal(tgtIP.AsSlice(), tst.getFieldByClassLen(ethernet.TypeARP, pcap.FieldClassSrc, 4, 1)) {
		t.Errorf("request: mismatched ARP target proto")
	}

	// Deliver request to target
	err = target.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal("target demux request:", err)
	}
	setzero(buf[:n])

	// === PHASE 2: ARP Reply from target stack ===
	buf = tst.buf[:cap(tst.buf)]
	n, err = target.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Error("zero bits sent by ARP target stack (no reply)")
		return
	}

	tst.frmbuf, err = tst.cap.CaptureEthernet(tst.frmbuf[:0], buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}
	tst.buf = tst.buf[:n]

	// Validate Ethernet layer (reply is unicast to querying)
	if !bytes.Equal(tgtHw[:], tst.getData(pcap.ProtoEthernet, pcap.FieldClassSrc)) {
		t.Errorf("reply: mismatched ethernet src addr %x", tst.getData(pcap.ProtoEthernet, pcap.FieldClassSrc))
	}
	if !bytes.Equal(qHw[:], tst.getData(pcap.ProtoEthernet, pcap.FieldClassDst)) {
		t.Errorf("reply: expected unicast to querying, got %x", tst.getData(pcap.ProtoEthernet, pcap.FieldClassDst))
	}

	// Validate ARP reply fields
	if tst.getARPOperation() != arp.OpReply {
		t.Errorf("reply: expected ARP OpReply, got %d", tst.getARPOperation())
	}
	if !bytes.Equal(tgtHw[:], tst.getFieldByClassLen(ethernet.TypeARP, pcap.FieldClassSrc, 6, 0)) {
		t.Errorf("reply: mismatched ARP sender HW (should be target's MAC)")
	}
	if !bytes.Equal(tgtIP.AsSlice(), tst.getFieldByClassLen(ethernet.TypeARP, pcap.FieldClassSrc, 4, 0)) {
		t.Errorf("reply: mismatched ARP sender proto (should be target's IP)")
	}
	if !bytes.Equal(qHw[:], tst.getFieldByClassLen(ethernet.TypeARP, pcap.FieldClassSrc, 6, 1)) {
		t.Errorf("reply: mismatched ARP target HW (should be querying's MAC)")
	}
	if !bytes.Equal(qIP.AsSlice(), tst.getFieldByClassLen(ethernet.TypeARP, pcap.FieldClassSrc, 4, 1)) {
		t.Errorf("reply: mismatched ARP target proto (should be querying's IP)")
	}

	// Deliver reply to querying stack
	err = querying.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal("querying demux reply:", err)
	}
	setzero(buf[:n])

	// === PHASE 3: Verify querying stack learned target's MAC ===
	resolvedHw, err := querying.ResultResolveHardwareAddress6(tgtIP)
	if err != nil {
		t.Fatalf("ARP query result failed: %v", err)
	}
	if resolvedHw != tgtHw {
		t.Errorf("ARP resolved wrong MAC: got %x, want %x", resolvedHw, tgtHw)
	}
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

// getFieldByClassLen finds a field by protocol, class, and octet length.
// occurrence specifies which match to return (0 = first, 1 = second, etc.)
// This is needed for ARP where sender and target fields share the same class.
func (tst *tester) getFieldByClassLen(proto any, class pcap.FieldClass, octetLen, occurrence int) []byte {
	tst.t.Helper()
	frm := getProtoFrame(tst.frmbuf, proto)
	if frm == nil {
		tst.t.Fatalf("no frame for proto %v found", proto)
	}
	count := 0
	for _, field := range frm.Fields {
		if field.Class == class && field.BitLength == octetLen*8 {
			if count == occurrence {
				bitoff := frm.PacketBitOffset + field.FrameBitOffset
				return tst.buf[bitoff/8 : bitoff/8+field.BitLength/8]
			}
			count++
		}
	}
	tst.t.Fatalf("field (proto=%v, class=%v, octets=%d, occurrence=%d) not found", proto, class, octetLen, occurrence)
	return nil
}

func (tst *tester) getARPOperation() arp.Operation {
	tst.t.Helper()
	return arp.Operation(tst.getInt(ethernet.TypeARP, pcap.FieldClassOperation))
}

// TestTCPConn_BufferNotClearedOnPassiveClose tests that data remains readable after
// the TCP connection is closed by the remote peer. This is a regression test
// for a bug where the receive buffer was cleared when the connection transitioned
// to CLOSED state, causing data loss.
//
// The sequence is:
//  1. Server sends DATA then initiates close (FIN)
//  2. Client receives data, enters CLOSE_WAIT
//  3. Client sends ACK, then FIN+ACK (enters LAST_ACK)
//  4. Server sends final ACK
//  5. Client receives ACK in LAST_ACK -> state becomes CLOSED
//  6. At this point, client.Read() should still return the buffered data
//
// The bug was that reset() cleared bufRx when state became CLOSED.
func TestTCPConn_BufferNotClearedOnPassiveClose(t *testing.T) {
	const seed = 9999
	const MTU = 1500
	const svPort = 8080
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := testerFrom(t, MTU)

	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)

	// Server writes data to be sent.
	sendData := []byte("this data should survive close handshake")
	_, err := svconn.Write(sendData)
	if err != nil {
		t.Fatal("server write:", err)
	}

	// Server sends DATA packet to client.
	tst.bufmu.Lock()
	buf := tst.buf[:cap(tst.buf)]
	n, err := sv.Encapsulate(buf, -1, 0)
	if err != nil {
		tst.bufmu.Unlock()
		t.Fatal("server encapsulate data:", err)
	}
	if n == 0 {
		tst.bufmu.Unlock()
		t.Fatal("expected data packet from server")
	}
	err = client.Demux(buf[:n], 0)
	tst.bufmu.Unlock()
	if err != nil {
		t.Fatal("client demux data:", err)
	}

	// Verify client buffered the data.
	if clconn.BufferedInput() != len(sendData) {
		t.Fatalf("client did not buffer data: got %d, want %d", clconn.BufferedInput(), len(sendData))
	}

	// Client sends ACK for data.
	tst.bufmu.Lock()
	buf = tst.buf[:cap(tst.buf)]
	n, err = client.Encapsulate(buf, -1, 0)
	if err != nil {
		tst.bufmu.Unlock()
		t.Fatal("client encapsulate ACK:", err)
	}
	if n > 0 {
		err = sv.Demux(buf[:n], 0)
		if err != nil {
			tst.bufmu.Unlock()
			t.Fatal("server demux ACK:", err)
		}
	}
	tst.bufmu.Unlock()

	// Server initiates close.
	err = svconn.Close()
	if err != nil {
		t.Fatal("server close:", err)
	}

	// Server sends FIN (enters FIN_WAIT_1).
	tst.bufmu.Lock()
	buf = tst.buf[:cap(tst.buf)]
	n, err = sv.Encapsulate(buf, -1, 0)
	if err != nil {
		tst.bufmu.Unlock()
		t.Fatal("server encapsulate FIN:", err)
	}
	if n == 0 {
		tst.bufmu.Unlock()
		t.Fatal("expected FIN packet from server")
	}
	err = client.Demux(buf[:n], 0)
	tst.bufmu.Unlock()
	if err != nil {
		t.Fatal("client demux FIN:", err)
	}

	if svconn.State() != tcp.StateFinWait1 {
		t.Fatalf("expected server in FIN_WAIT_1, got %s", svconn.State())
	}
	if clconn.State() != tcp.StateCloseWait {
		t.Fatalf("expected client in CLOSE_WAIT, got %s", clconn.State())
	}

	// Client sends ACK for FIN.
	tst.bufmu.Lock()
	buf = tst.buf[:cap(tst.buf)]
	n, err = client.Encapsulate(buf, -1, 0)
	if err != nil {
		tst.bufmu.Unlock()
		t.Fatal("client encapsulate ACK:", err)
	}
	if n > 0 {
		err = sv.Demux(buf[:n], 0)
		if err != nil {
			tst.bufmu.Unlock()
			t.Fatal("server demux ACK:", err)
		}
	}
	tst.bufmu.Unlock()

	if svconn.State() != tcp.StateFinWait2 {
		t.Fatalf("expected server in FIN_WAIT_2, got %s", svconn.State())
	}

	// Client initiates its close.
	err = clconn.Close()
	if err != nil {
		t.Fatal("client close:", err)
	}

	// Client sends FIN (enters LAST_ACK).
	tst.bufmu.Lock()
	buf = tst.buf[:cap(tst.buf)]
	n, err = client.Encapsulate(buf, -1, 0)
	if err != nil {
		tst.bufmu.Unlock()
		t.Fatal("client encapsulate FIN:", err)
	}
	if n == 0 {
		tst.bufmu.Unlock()
		t.Fatal("expected FIN packet from client")
	}
	err = sv.Demux(buf[:n], 0)
	tst.bufmu.Unlock()
	if err != nil {
		t.Fatal("server demux client FIN:", err)
	}

	if clconn.State() != tcp.StateLastAck {
		t.Fatalf("expected client in LAST_ACK, got %s", clconn.State())
	}
	if svconn.State() != tcp.StateTimeWait {
		t.Fatalf("expected server in TIME_WAIT, got %s", svconn.State())
	}

	// Server sends final ACK.
	tst.bufmu.Lock()
	buf = tst.buf[:cap(tst.buf)]
	n, err = sv.Encapsulate(buf, -1, 0)
	if err != nil {
		tst.bufmu.Unlock()
		t.Fatal("server encapsulate final ACK:", err)
	}
	if n == 0 {
		tst.bufmu.Unlock()
		t.Fatal("expected final ACK from server")
	}
	err = client.Demux(buf[:n], 0)
	tst.bufmu.Unlock()
	if err != nil {
		t.Fatal("client demux final ACK:", err)
	}

	// Client should now be CLOSED.
	if clconn.State() != tcp.StateClosed {
		t.Fatalf("expected client in CLOSED, got %s", clconn.State())
	}

	// THE BUG: At this point, the data should still be readable, but the
	// buffer was cleared by reset() when state transitioned to CLOSED.
	//
	// This test will FAIL until the bug is fixed.
	readBuf := make([]byte, MTU)
	n, err = clconn.Read(readBuf)
	if err != nil && n == 0 {
		t.Fatalf("BUG: Could not read buffered data after connection closed: %v\n"+
			"Expected to read %d bytes of data that was received before the connection closed.\n"+
			"The receive buffer was incorrectly cleared when the connection transitioned to CLOSED state.",
			err, len(sendData))
	}
	if n != len(sendData) {
		t.Fatalf("read wrong amount: got %d, want %d", n, len(sendData))
	}
	if !bytes.Equal(readBuf[:n], sendData) {
		t.Fatalf("read wrong data: got %q, want %q", readBuf[:n], sendData)
	}
}
