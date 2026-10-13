package xnet

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internet/pcap"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
)

func newTestStack(t testing.TB, hostname string, randSeed int64, mtu, tcpPorts, udpPorts uint16) (s1 *StackAsync) {
	t.Helper()
	return newTestStackClock(t, hostname, randSeed, mtu, tcpPorts, udpPorts, nil)
}

// newTestStackClock is [newTestStack] with nanotime as the stack's monotonic clock.
func newTestStackClock(t testing.TB, hostname string, randSeed int64, mtu, tcpPorts, udpPorts uint16, nanotime func() int64) (s1 *StackAsync) {
	t.Helper()
	id := hostname[len(hostname)-1] - '0'
	if id > 9 {
		t.Fatal("test stack name must end with hex digit 0..9, got:", hostname)
	}
	var stack StackAsync
	err := stack.Reset(StackConfig{
		Hostname:          hostname,
		RandSeed:          randSeed,
		StaticAddress4:    [4]byte{10, 0, 0, id},
		HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, id},
		MTU:               uint16(mtu),
		ICMPQueueLimit:    2,
		MaxActiveTCPPorts: tcpPorts,
		MaxActiveUDPPorts: udpPorts,
		PassivePeers:      1, // put passive peers to test.
		Nanotime:          nanotime,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &stack
}

func newTestTCPConn(t testing.TB, bufsize, txpack int) *tcp.Conn {
	t.Helper()
	conn := new(tcp.Conn)
	buf := make([]byte, bufsize*2)
	err := conn.Configure(tcp.ConnConfig{
		RxBuf:             buf[0:bufsize],
		TxBuf:             buf[bufsize : 2*bufsize],
		TxPacketQueueSize: txpack,
		RWBackoff:         backoffYield,
	})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func newTCPStacks(t testing.TB, randSeed int64, mtu int) (s1, s2 *StackAsync, c1, c2 *tcp.Conn) {
	t.Helper()
	c1, c2 = new(tcp.Conn), new(tcp.Conn)
	s1 = newTestStack(t, "Stack1", randSeed, uint16(mtu), 1, 0)
	s2 = newTestStack(t, "Stack2", ^randSeed, uint16(mtu), 1, 0)
	s1.SetGatewayHardwareAddr(s2.HardwareAddr())
	s2.SetGatewayHardwareAddr(s1.HardwareAddr())
	c1 = newTestTCPConn(t, mtu, 4)
	c2 = newTestTCPConn(t, mtu, 4)
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

func (tst *tester) ensureQuiesce(s1, s2 *StackAsync, lim int) {
	tst.t.Helper()
	buf := tst.buf
	for range lim {
		sent := false
		for _, p := range [2][2]*StackAsync{{s1, s2}, {s2, s1}} {
			n, err := p[0].EgressEthernet(buf[:])
			if err != nil {
				tst.t.Fatal(err)
			} else if n > 0 {
				sent = true
				p[1].IngressEthernet(buf[:n])
			}
		}
		if !sent {
			return
		}
	}
	tst.t.Fatal("stacks did not quiesce after", lim)
}

// readyToAccept reports the connections ready on a listener returned by [StackGo.SocketNetip].
func readyToAccept(t *testing.T, l net.Listener) int {
	t.Helper()
	ll, ok := l.(interface{ LnetoListener() *tcp.Listener })
	if !ok {
		t.Fatalf("listener %T does not expose LnetoListener", l)
	}
	return ll.LnetoListener().NumberOfReadyToAccept()
}

func noExchange(source int) tcpExpectExchange {
	return tcpExpectExchange{SourceIdx: source}
}

func (tst *tester) TestTCPSetupAndEstablish(svStack, clStack *StackAsync, svConn, clConn *tcp.Conn, svPort, clPort uint16) {
	t := tst.t
	// Attach server and client connections to stacks.
	err := svStack.ListenTCP4(svConn, svPort)
	if err != nil {
		t.Fatal(err)
	}
	err = clStack.DialTCP(clConn, clPort, netip.AddrPortFrom(netip.AddrFrom4(svStack.Addr4()), svPort))
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
	var got [len(exch)]struct {
		seg tcp.Segment
	}
	for i, wants := range exch {
		haveFailed := tst.t.Failed()
		got[i].seg = tst.TCPExchange(wants, stack1, stack2)
		if haveFailed != tst.t.Failed() {
			tst.t.Logf("print out sent segments (%d):\n", i+1)
			for k := range i + 1 {
				str := tcp.StringExchange(got[k].seg, 255, 255, exch[k].SourceIdx == 0) // states unknown.
				tst.t.Log(str)
			}
		}
	}
}

func (tst *tester) TestTCPEstablishedSingleData(srcStack, dstStack *StackAsync, srcConn, dstConn *tcp.Conn, sendData []byte) {
	t := tst.t
	t.Helper()
	availTx := srcConn.FreeOutput()
	availRx := dstConn.FreeInput()
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
		if i == 2 {
			// Passive side in CLOSE-WAIT: FIN only leaves after its application closes.
			if err := conn2.Close(); err != nil {
				t.Fatal(err)
			}
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

	n, err := src.EgressEthernet(buf[:])
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
	srcEth := src.HardwareAddr()
	dstEth := dst.HardwareAddr()
	if !bytes.Equal(srcEth[:], tst.getData(protoEthernet, pcap.FieldClassSrc)) {
		t.Errorf("mismatched ethernet src addr %x", tst.getData(protoEthernet, pcap.FieldClassSrc))
	}
	if !bytes.Equal(dstEth[:], tst.getData(protoEthernet, pcap.FieldClassDst)) {
		t.Errorf("mismatched ethernet dst addr %x", tst.getData(protoEthernet, pcap.FieldClassDst))
	}
	if tst.getInt(protoIPv4, pcap.FieldClassVersion) != 4 {
		t.Errorf("did not get IP version=4, got=%d", tst.getInt(protoIPv4, pcap.FieldClassVersion))
	}
	srcAddr := src.Addr4()
	dstAddr := dst.Addr4()
	if !bytes.Equal(srcAddr[:], tst.getData(protoIPv4, pcap.FieldClassSrc)) {
		t.Errorf("mismatched ip src addr %d", tst.getData(protoIPv4, pcap.FieldClassSrc))
	}
	if !bytes.Equal(dstAddr[:], tst.getData(protoIPv4, pcap.FieldClassDst)) {
		t.Errorf("mismatched ip dst addr %d", tst.getData(protoIPv4, pcap.FieldClassDst))
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
	err = dst.IngressEthernet(buf[:n])
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
	n, err := querying.EgressEthernet(buf[:])
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

	qHw := querying.HardwareAddr()
	tgtHw := target.HardwareAddr()
	broadcast := ethernet.BroadcastAddr()
	qIP := querying.Addr4()
	tgtIP := target.Addr4()

	// Validate Ethernet layer (request is broadcast)
	if !bytes.Equal(qHw[:], tst.getData(protoEthernet, pcap.FieldClassSrc)) {
		t.Errorf("request: mismatched ethernet src addr %x", tst.getData(protoEthernet, pcap.FieldClassSrc))
	}
	if !bytes.Equal(broadcast[:], tst.getData(protoEthernet, pcap.FieldClassDst)) {
		t.Errorf("request: expected broadcast ethernet dst addr, got %x", tst.getData(protoEthernet, pcap.FieldClassDst))
	}

	// Validate ARP request fields
	// ARP fields: FieldClassSrc with 6 octets = HW addr, 4 octets = proto addr
	// occurrence 0 = sender, occurrence 1 = target
	if tst.getARPOperation() != arp.OpRequest {
		t.Errorf("request: expected ARP OpRequest, got %d", tst.getARPOperation())
	}
	if !bytes.Equal(qHw[:], tst.getFieldByClassLen(protoARP, pcap.FieldClassSrc, 6, 0)) {
		t.Errorf("request: mismatched ARP sender HW")
	}
	if !bytes.Equal(qIP[:], tst.getFieldByClassLen(protoARP, pcap.FieldClassSrc, 4, 0)) {
		t.Errorf("request: mismatched ARP sender proto")
	}
	if !bytes.Equal(tgtIP[:], tst.getFieldByClassLen(protoARP, pcap.FieldClassSrc, 4, 1)) {
		t.Errorf("request: mismatched ARP target proto")
	}

	// Deliver request to target
	err = target.IngressEthernet(buf[:n])
	if err != nil {
		t.Fatal("target demux request:", err)
	}
	setzero(buf[:n])

	// === PHASE 2: ARP Reply from target stack ===
	buf = tst.buf[:cap(tst.buf)]
	n, err = target.EgressEthernet(buf[:])
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
	if !bytes.Equal(tgtHw[:], tst.getData(protoEthernet, pcap.FieldClassSrc)) {
		t.Errorf("reply: mismatched ethernet src addr %x", tst.getData(protoEthernet, pcap.FieldClassSrc))
	}
	if !bytes.Equal(qHw[:], tst.getData(protoEthernet, pcap.FieldClassDst)) {
		t.Errorf("reply: expected unicast to querying, got %x", tst.getData(protoEthernet, pcap.FieldClassDst))
	}

	// Validate ARP reply fields
	if tst.getARPOperation() != arp.OpReply {
		t.Errorf("reply: expected ARP OpReply, got %d", tst.getARPOperation())
	}
	if !bytes.Equal(tgtHw[:], tst.getFieldByClassLen(protoARP, pcap.FieldClassSrc, 6, 0)) {
		t.Errorf("reply: mismatched ARP sender HW (should be target's MAC)")
	}
	if !bytes.Equal(tgtIP[:], tst.getFieldByClassLen(protoARP, pcap.FieldClassSrc, 4, 0)) {
		t.Errorf("reply: mismatched ARP sender proto (should be target's IP)")
	}
	if !bytes.Equal(qHw[:], tst.getFieldByClassLen(protoARP, pcap.FieldClassSrc, 6, 1)) {
		t.Errorf("reply: mismatched ARP target HW (should be querying's MAC)")
	}
	if !bytes.Equal(qIP[:], tst.getFieldByClassLen(protoARP, pcap.FieldClassSrc, 4, 1)) {
		t.Errorf("reply: mismatched ARP target proto (should be querying's IP)")
	}

	// Deliver reply to querying stack
	err = querying.IngressEthernet(buf[:n])
	if err != nil {
		t.Fatal("querying demux reply:", err)
	}
	setzero(buf[:n])

	// === PHASE 3: Verify querying stack learned target's MAC ===
	resolvedHw, err := querying.ResultResolveHardwareAddress6(netip.AddrFrom4(tgtIP))
	if err != nil {
		t.Errorf("ARP query result failed: %v", err)
	} else if resolvedHw != tgtHw {
		t.Errorf("ARP resolved wrong MAC: got %x, want %x", resolvedHw, tgtHw)
	}
}

func (tst *tester) getTCPFrame() tcp.Frame {
	tst.t.Helper()
	// Find the IP frame's position in the captured packet buffer.
	ipFrm := getProtoFrame(tst.frmbuf, protoIPv4)
	if ipFrm == nil {
		tst.t.Fatal("no IP frame in capture")
	}
	ipStart := ipFrm.PacketBitOffset / 8
	// Use IP TotalLength to correctly bound the frame, stripping any
	// Ethernet runt-frame padding (802.3 §3.2.7). This mirrors what
	// StackIP.Demux does before passing data to TCP.
	ifrm, err := ipv4.NewFrame(tst.buf[ipStart:])
	if err != nil {
		tst.t.Fatal("parsing IP frame:", err)
	}
	totalLen := int(ifrm.TotalLength())
	ihl := ifrm.HeaderLength()
	data := tst.buf[ipStart+ihl : ipStart+totalLen]
	frame, err := tcp.NewFrame(data)
	if err != nil {
		panic(err)
	}
	return frame
}

func (tst *tester) getPayload(proto string) []byte {
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

func (tst *tester) getData(proto string, field pcap.FieldClass) []byte {
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

func (tst *tester) getInt(proto string, field pcap.FieldClass) uint64 {
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

func getProtoFrame(frms []pcap.Frame, proto string) *pcap.Frame {
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
func (tst *tester) getFieldByClassLen(proto string, class pcap.FieldClass, octetLen, occurrence int) []byte {
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
	return arp.Operation(tst.getInt(protoARP, pcap.FieldClassOperation))
}

func getTCPFrame(etherFrame []byte) (tcp.Frame, bool) {
	efrm, err := ethernet.NewFrame(etherFrame)
	if err != nil || efrm.EtherTypeOrSize() != ethernet.TypeIPv4 {
		return tcp.Frame{}, false
	}
	ifrm, err := ipv4.NewFrame(efrm.Payload())
	if err != nil || ifrm.Protocol() != lneto.IPProtoTCP {
		return tcp.Frame{}, false
	}
	tfrm, err := tcp.NewFrame(ifrm.Payload())
	if err != nil {
		return tcp.Frame{}, false
	}
	return tfrm, true
}

func newBackoffYield() lneto.BackoffStrategy { return backoffYield }

func backoffYield(consecutiveBackoffs uint) time.Duration {
	return lneto.BackoffFlagGosched
}

func at(frames [][]byte, i int) []byte {
	if i < len(frames) {
		return frames[i]
	}
	return nil
}

// dnsRR is an answer record: a CNAME to cname when set, else an A record with addr.
type dnsRR struct {
	owner string
	cname string
	addr  netip.Addr
}

func rrA(owner, addr string) dnsRR { return dnsRR{owner: owner, addr: netip.MustParseAddr(addr)} }

func rrCNAME(owner, target string) dnsRR { return dnsRR{owner: owner, cname: target} }

// dnsTestServer answers the client's pending query from zone, echoing
// the question back as a recursive resolver would.
type dnsTestServer struct {
	t       *testing.T
	client  *StackAsync
	zone    map[string][]dnsRR // Answer section keyed by queried name.
	queries int
	buf     [ethernet.MaxFrameLength]byte
}

// respond answers one query and reports whether the client had one pending.
// A query for a name not in the zone fails the test.
func (s *dnsTestServer) respond() bool {
	t := s.t
	t.Helper()
	n, err := s.client.EgressEthernet(s.buf[:])
	if err != nil || n == 0 {
		return false
	}
	txid, port, err := extractDNSTxIDAndPort(s.buf[:n])
	if err != nil {
		t.Fatal("failed to extract DNS txid:", err)
	}
	var q dns.Question
	if _, err = q.Decode(extractDNSPayload(s.buf[:n]), dns.SizeHeader); err != nil {
		t.Fatal("failed to decode question:", err)
	}
	s.queries++
	msg := dns.Message{Questions: []dns.Question{q}}
	for owner, rrs := range s.zone {
		if !q.Name.EqualString(owner) {
			continue
		}
		for _, rr := range rrs {
			msg.Answers = append(msg.Answers, rr.resource(t))
		}
	}
	if len(msg.Answers) == 0 {
		t.Fatalf("query #%d for %s not in zone", s.queries, q.Name.String())
	}
	pkt, err := buildDNSMsgResponsePacket(t, txid, port, msg,
		dnsTestServerAddr, dnsTestServerMAC, dnsTestClientAddr, dnsTestClientMAC, s.buf[:])
	if err != nil {
		t.Fatal("failed to build response packet:", err)
	}
	if err = s.client.IngressEthernet(pkt); err != nil {
		t.Fatal("client Demux failed:", err)
	}
	return true
}

func newDNSTestClient(t *testing.T) *StackAsync {
	t.Helper()
	client := new(StackAsync)
	err := client.Reset(StackConfig{
		Hostname:        "DNSClient",
		RandSeed:        9876,
		StaticAddress4:  dnsTestClientAddr.As4(),
		DNSServer:       dnsTestServerAddr,
		HardwareAddress: dnsTestClientMAC,
		MTU:             uint16(ethernet.MaxMTU),
	})
	if err != nil {
		t.Fatal("client Reset failed:", err)
	}
	client.SetGatewayHardwareAddr(dnsTestServerMAC)
	return client
}

// exchangeEthernetOnce sends one Ethernet frame from src to dst if available.
func exchangeEthernetOnce(t *testing.T, src, dst *StackAsync, buf []byte) int {
	t.Helper()
	n, err := src.EgressEthernet(buf)
	if err != nil {
		t.Error(err)
	}
	if n == 0 {
		return 0
	}
	if err := dst.IngressEthernet(buf[:n]); err != nil {
		t.Error(err)
	}
	return n
}
