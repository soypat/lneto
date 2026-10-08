package xnet

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/udp"
)

var (
	dnsTestServerAddr = netip.AddrFrom4([4]byte{8, 8, 8, 8})
	dnsTestServerMAC  = [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dnsTestClientAddr = netip.AddrFrom4([4]byte{10, 0, 0, 100})
	dnsTestClientMAC  = [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
)

// dnsRR is an answer record: a CNAME to cname when set, else an A record with addr.
type dnsRR struct {
	owner string
	cname string
	addr  netip.Addr
}

func rrA(owner, addr string) dnsRR       { return dnsRR{owner: owner, addr: netip.MustParseAddr(addr)} }
func rrCNAME(owner, target string) dnsRR { return dnsRR{owner: owner, cname: target} }

func (rr dnsRR) resource(t *testing.T) dns.Resource {
	t.Helper()
	owner := dns.MustNewName(rr.owner)
	if rr.cname == "" {
		return dns.NewResource(owner, dns.TypeA, dns.ClassINET, 300, rr.addr.AsSlice())
	}
	target := dns.MustNewName(rr.cname)
	wire, err := target.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	return dns.NewResource(owner, dns.TypeCNAME, dns.ClassINET, 300, wire)
}

// cnameChain returns a zone where host is a CNAME-only answer followed by hops-1
// more CNAME-only answers, the last alias holding the A record addr.
// Resolving it one query per answer takes hops+1 queries.
func cnameChain(host string, hops int, addr string) map[string][]dnsRR {
	zone := make(map[string][]dnsRR, hops+1)
	owner := host
	for i := 1; i <= hops; i++ {
		alias := fmt.Sprintf("cdn%d.example.net", i)
		zone[owner] = []dnsRR{rrCNAME(owner, alias)}
		owner = alias
	}
	zone[owner] = []dnsRR{rrA(owner, addr)}
	return zone
}

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

// TestDNS_LookupIP resolves a host against a zone through the async API
// (StartLookupIP+ResultLookupIP, a single query) or the blocking API
// (DoLookupIP, which queries again for the canonical name of CNAME-only answers,
// at most maxCNAMEqueries times).
func TestDNS_LookupIP(t *testing.T) {
	const host = "www.example.com"
	tests := []struct {
		name        string
		blocking    bool
		zone        map[string][]dnsRR
		wantAddr    string // Empty when wantErr is set.
		wantErr     error
		wantQueries int
	}{
		{
			name:     "A",
			zone:     map[string][]dnsRR{host: {rrA(host, "93.184.216.34")}},
			wantAddr: "93.184.216.34", wantQueries: 1,
		},
		{
			name: "A blocking", blocking: true,
			zone:     map[string][]dnsRR{host: {rrA(host, "93.184.216.35")}},
			wantAddr: "93.184.216.35", wantQueries: 1,
		},
		{
			// CNAME RDATA must not be misinterpreted as an IP address.
			name:     "CNAME and A",
			zone:     map[string][]dnsRR{host: {rrCNAME(host, "cdn.example.net"), rrA("cdn.example.net", "192.0.2.200")}},
			wantAddr: "192.0.2.200", wantQueries: 1,
		},
		{
			// Async API does not requery.
			name:    "CNAME only",
			zone:    cnameChain(host, 1, "192.0.2.201"),
			wantErr: errDNSOnlyCNAME, wantQueries: 1,
		},
		{
			name: "CNAME only requery", blocking: true,
			zone:     cnameChain(host, 1, "192.0.2.202"),
			wantAddr: "192.0.2.202", wantQueries: 2,
		},
		{
			// Address arrives on the last query allowed.
			name: "CNAME chain at query limit", blocking: true,
			zone:     cnameChain(host, maxCNAMEqueries-1, "192.0.2.203"),
			wantAddr: "192.0.2.203", wantQueries: maxCNAMEqueries,
		},
		{
			// One hop more than the limit allows: gives up without exceeding it.
			name: "CNAME chain past query limit", blocking: true,
			zone:    cnameChain(host, maxCNAMEqueries, "192.0.2.204"),
			wantErr: errDNSOnlyCNAME, wantQueries: maxCNAMEqueries,
		},
	}
	// Shared client: each lookup must not see the previous one's result, so wantAddr is unique per case.
	client := newDNSTestClient(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := &dnsTestServer{t: t, client: client, zone: tc.zone}
			var addrs []netip.Addr
			var err error
			if tc.blocking {
				pump := func(uint) time.Duration {
					srv.respond()
					return lneto.BackoffFlagNop
				}
				var dst [4]netip.Addr
				var n int
				n, err = client.StackBlocking(pump).DoLookupIP(dst[:], dns.MustNewName(host), time.Second)
				addrs = dst[:n]
			} else {
				txid, serr := client.LookupIPStart(dns.MustNewName(host), dns.TypeA, 4)
				if serr != nil {
					t.Fatal("LookupIPStart failed:", serr)
				}
				if !srv.respond() {
					t.Fatal("expected DNS query packet from client")
				}
				var dst [4]netip.Addr
				n, done, rerr := client.LookupIPResult(txid, dst[:])
				if !done {
					t.Fatal("DNS lookup not done after response")
				}
				if completed, ok := client.LookupIPPop(txid); !completed || !ok {
					t.Fatalf("pop: completed=%v ok=%v", completed, ok)
				}
				addrs, err = dst[:n], rerr
			}
			if err != tc.wantErr {
				t.Fatalf("got err=%v, want %v", err, tc.wantErr)
			}
			if tc.wantAddr != "" && !slices.Contains(addrs, netip.MustParseAddr(tc.wantAddr)) {
				t.Errorf("expected address %s not found in result %v", tc.wantAddr, addrs)
			}
			if srv.queries != tc.wantQueries {
				t.Errorf("got %d queries, want %d", srv.queries, tc.wantQueries)
			}
		})
	}
}

// lookupTestResult polls lookup txid once and fails the test unless it is done.
func lookupTestResult(t *testing.T, client *StackAsync, txid uint16, dst []netip.Addr) ([]netip.Addr, error) {
	t.Helper()
	n, done, err := client.LookupIPResult(txid, dst)
	if !done {
		t.Fatalf("lookup %#x not done", txid)
	}
	return dst[:n], err
}

func TestDNS_LookupIPConcurrent(t *testing.T) {
	const hostA, hostB = "a.example.com", "b.example.org"
	client := newDNSTestClient(t)
	srv := &dnsTestServer{t: t, client: client, zone: map[string][]dnsRR{
		hostA: {rrA(hostA, "192.0.2.1")},
		hostB: {rrA(hostB, "198.51.100.1")},
	}}
	txidA, err := client.LookupIPStart(dns.MustNewName(hostA), dns.TypeA, 4)
	if err != nil {
		t.Fatal(err)
	}
	txidB, err := client.LookupIPStart(dns.MustNewName(hostB), dns.TypeA, 4)
	if err != nil {
		t.Fatal(err)
	}
	if txidA == 0 || txidB == 0 || txidA == txidB {
		t.Fatalf("txids must be distinct and non-zero: %#x %#x", txidA, txidB)
	}
	if n, done, _ := client.LookupIPResult(txidA, make([]netip.Addr, 1)); done || n != 0 {
		t.Fatal("lookup done before any response")
	}
	for i := range 2 {
		if !srv.respond() {
			t.Fatalf("expected query %d", i)
		}
	}
	var dst [4]netip.Addr
	addrs, err := lookupTestResult(t, client, txidA, dst[:])
	if err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("lookup A: %v %v", addrs, err)
	}
	addrs, err = lookupTestResult(t, client, txidB, dst[:])
	if err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("198.51.100.1") {
		t.Fatalf("lookup B: %v %v", addrs, err)
	}
	for _, txid := range []uint16{txidA, txidB} {
		if completed, ok := client.LookupIPPop(txid); !completed || !ok {
			t.Fatalf("pop %#x: completed=%v ok=%v", txid, completed, ok)
		}
		if _, ok := client.LookupIPPop(txid); ok {
			t.Fatalf("second pop of %#x succeeded", txid)
		}
	}
}

func TestDNS_LookupIPManyAddresses(t *testing.T) {
	const host = "many.example.com"
	zone := map[string][]dnsRR{}
	var want []netip.Addr
	for i := 1; i <= 8; i++ {
		addr := fmt.Sprintf("192.0.2.%d", i)
		zone[host] = append(zone[host], rrA(host, addr))
		want = append(want, netip.MustParseAddr(addr))
	}
	client := newDNSTestClient(t)
	srv := &dnsTestServer{t: t, client: client, zone: zone}
	txid, err := client.LookupIPStart(dns.MustNewName(host), dns.TypeA, 8)
	if err != nil {
		t.Fatal(err)
	}
	srv.respond()
	var dst [8]netip.Addr
	addrs, err := lookupTestResult(t, client, txid, dst[:])
	if err != nil || !slices.Equal(addrs, want) {
		t.Fatalf("got %v err=%v, want %v", addrs, err, want)
	}
}

func TestDNS_LookupIPFollowCNAME(t *testing.T) {
	const host = "www.example.com"
	client := newDNSTestClient(t)
	srv := &dnsTestServer{t: t, client: client, zone: cnameChain(host, 1, "192.0.2.77")}
	txid, err := client.LookupIPStart(dns.MustNewName(host), dns.TypeA, 4)
	if err != nil {
		t.Fatal(err)
	}
	srv.respond()
	var dst [4]netip.Addr
	if _, err = lookupTestResult(t, client, txid, dst[:]); err != errDNSOnlyCNAME {
		t.Fatalf("got err=%v, want %v", err, errDNSOnlyCNAME)
	}
	hopTxid, err := client.LookupIPFollowCNAME(txid)
	if err != nil {
		t.Fatal("follow CNAME:", err)
	} else if hopTxid == 0 || hopTxid == txid {
		t.Fatalf("hop txid %#x must differ from %#x and be non-zero", hopTxid, txid)
	}
	if _, ok := client.LookupIPPop(txid); ok {
		t.Fatal("old txid still active after following CNAME")
	}
	if n, done, _ := client.LookupIPResult(hopTxid, dst[:]); done || n != 0 {
		t.Fatal("hop done before its response")
	}
	srv.respond()
	addrs, err := lookupTestResult(t, client, hopTxid, dst[:])
	if err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("192.0.2.77") {
		t.Fatalf("got %v err=%v", addrs, err)
	}
	if srv.queries != 2 {
		t.Fatalf("got %d queries, want 2", srv.queries)
	}
}

func TestDNS_LookupIPExhausted(t *testing.T) {
	client := newDNSTestClient(t) // Default of 2 concurrent lookups.
	var txids []uint16
	for i := range 2 {
		txid, err := client.LookupIPStart(dns.MustNewName(fmt.Sprintf("h%d.example.com", i)), dns.TypeA, 4)
		if err != nil {
			t.Fatal(err)
		}
		txids = append(txids, txid)
	}
	if _, err := client.LookupIPStart(dns.MustNewName("h2.example.com"), dns.TypeA, 4); !errors.Is(err, lneto.ErrExhausted) {
		t.Fatalf("got err=%v, want ErrExhausted", err)
	}
	if completed, ok := client.LookupIPPop(txids[0]); completed || !ok {
		t.Fatalf("pop pending: completed=%v ok=%v", completed, ok)
	}
	if _, err := client.LookupIPStart(dns.MustNewName("h2.example.com"), dns.TypeA, 4); err != nil {
		t.Fatal("start after pop:", err)
	}
}

func TestDNS_DoLookupIPFreesLookupOnTimeout(t *testing.T) {
	client := newDNSTestClient(t)
	silent := client.StackBlocking(func(uint) time.Duration { return lneto.BackoffFlagNop })
	// More timed out lookups than concurrent lookups allowed: each must free its slot.
	var dst [4]netip.Addr
	for i := range 3 {
		_, err := silent.DoLookupIP(dst[:], dns.MustNewName("timeout.example.com"), time.Millisecond)
		if err != errDeadlineExceed {
			t.Fatalf("lookup %d: got err=%v, want %v", i, err, errDeadlineExceed)
		}
	}
	const host = "www.example.com"
	srv := &dnsTestServer{t: t, client: client, zone: map[string][]dnsRR{host: {rrA(host, "192.0.2.9")}}}
	pump := client.StackBlocking(func(uint) time.Duration {
		srv.respond()
		return lneto.BackoffFlagNop
	})
	n, err := pump.DoLookupIP(dst[:], dns.MustNewName(host), time.Second)
	if err != nil || n != 1 || dst[0] != netip.MustParseAddr("192.0.2.9") {
		t.Fatalf("lookup after timeouts: %v %v", dst[:n], err)
	}
}

// TestDNS_DoLookupIPCNAMEHeadroom checks a destination sized for the addresses alone still
// resolves an answer whose CNAME records precede the address in a single query.
func TestDNS_DoLookupIPCNAMEHeadroom(t *testing.T) {
	const host = "www.example.com"
	client := newDNSTestClient(t)
	srv := &dnsTestServer{t: t, client: client, zone: map[string][]dnsRR{host: {
		rrCNAME(host, "cdn1.example.net"),
		rrCNAME("cdn1.example.net", "cdn2.example.net"),
		rrA("cdn2.example.net", "192.0.2.10"),
	}}}
	pump := client.StackBlocking(func(uint) time.Duration {
		srv.respond()
		return lneto.BackoffFlagNop
	})
	var dst [1]netip.Addr
	n, err := pump.DoLookupIP(dst[:], dns.MustNewName(host), time.Second)
	if err != nil || n != 1 || dst[0] != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("got %v err=%v", dst[:n], err)
	}
	if srv.queries != 1 {
		t.Fatalf("got %d queries, want 1: CNAME records must not crowd out the address", srv.queries)
	}
}

func TestDNS_DoLookupIPEmptyDst(t *testing.T) {
	client := newDNSTestClient(t)
	pump := client.StackBlocking(func(uint) time.Duration { return lneto.BackoffFlagNop })
	if _, err := pump.DoLookupIP(nil, dns.MustNewName("www.example.com"), time.Second); !errors.Is(err, lneto.ErrShortBuffer) {
		t.Fatalf("got err=%v, want ErrShortBuffer", err)
	}
}

// egressDNSTestPort sends the client's next pending query to nowhere and returns its source port.
func egressDNSTestPort(t *testing.T, client *StackAsync) uint16 {
	t.Helper()
	var buf [ethernet.MaxFrameLength]byte
	n, err := client.EgressEthernet(buf[:])
	if err != nil || n == 0 {
		t.Fatalf("no query egressed: n=%d err=%v", n, err)
	}
	_, port, err := extractDNSTxIDAndPort(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestDNS_LookupIPPort(t *testing.T) {
	client := newDNSTestClient(t)
	txidA, err := client.LookupIPStart(dns.MustNewName("a.example.com"), dns.TypeA, 4)
	if err != nil {
		t.Fatal(err)
	}
	portA := egressDNSTestPort(t, client)
	txidB, err := client.LookupIPStart(dns.MustNewName("b.example.com"), dns.TypeA, 4)
	if err != nil {
		t.Fatal(err)
	}
	portB := egressDNSTestPort(t, client)
	if portA != portB {
		t.Fatalf("concurrent lookups use ports %d and %d, want shared port", portA, portB)
	}
	client.LookupIPPop(txidA)
	client.LookupIPPop(txidB)
	if _, err = client.LookupIPStart(dns.MustNewName("c.example.com"), dns.TypeA, 4); err != nil {
		t.Fatal(err)
	}
	if portC := egressDNSTestPort(t, client); portC == portA {
		t.Fatalf("idle client kept port %d for a new lookup", portC)
	}
}

// extractDNSTxIDAndPort extracts the DNS transaction ID and source port from an Ethernet+IP+UDP+DNS packet.
func extractDNSTxIDAndPort(pkt []byte) (txid uint16, srcPort uint16, err error) {
	const ethHdrLen = 14
	if len(pkt) < ethHdrLen+20+8+dns.SizeHeader {
		return 0, 0, errBaseLenDNS
	}

	// Parse ethernet to find IP header length.
	ethHdr, err := ethernet.NewFrame(pkt)
	if err != nil {
		return 0, 0, err
	}
	etherType := ethHdr.EtherTypeOrSize()
	if etherType != ethernet.TypeIPv4 {
		return 0, 0, errInvalidEtherType
	}

	ipHdrLen := int(pkt[ethHdrLen]&0x0f) * 4
	udpStart := ethHdrLen + ipHdrLen
	dnsStart := udpStart + 8

	if len(pkt) < dnsStart+dns.SizeHeader {
		return 0, 0, errBaseLenDNS
	}

	// Extract UDP source port.
	udpFrame, err := udp.NewFrame(pkt[udpStart:])
	if err != nil {
		return 0, 0, err
	}
	srcPort = udpFrame.SourcePort()

	dnsFrame, err := dns.NewFrame(pkt[dnsStart:])
	if err != nil {
		return 0, 0, err
	}
	return dnsFrame.TxID(), srcPort, nil
}

// extractDNSPayload returns the DNS message of an Ethernet+IPv4+UDP+DNS packet
// already validated by extractDNSTxIDAndPort.
func extractDNSPayload(pkt []byte) []byte {
	const ethHdrLen = 14
	ipHdrLen := int(pkt[ethHdrLen]&0x0f) * 4
	return pkt[ethHdrLen+ipHdrLen+8:]
}

// buildDNSMsgResponsePacket wraps a DNS response message into a complete
// Ethernet+IP+UDP packet with valid checksums.
func buildDNSMsgResponsePacket(t *testing.T, txid uint16, dstPort uint16, msg dns.Message,
	srcIP netip.Addr, srcMAC [6]byte, dstIP netip.Addr, dstMAC [6]byte, buf []byte) ([]byte, error) {
	t.Helper()

	// Response flags: QR=1 (response), RD=1 (recursion desired), RA=1 (recursion available).
	responseFlags := dns.HeaderFlags(1<<15 | 1<<8 | 1<<7)

	var dnsBuf [512]byte
	dnsPayload, err := msg.AppendTo(dnsBuf[:0], txid, responseFlags)
	if err != nil {
		return nil, err
	}

	// Build packet: Ethernet + IP + UDP + DNS.
	const ethHdrLen = 14
	const ipHdrLen = 20
	const udpHdrLen = 8

	totalLen := ethHdrLen + ipHdrLen + udpHdrLen + len(dnsPayload)
	if len(buf) < totalLen {
		return nil, errBaseLenDNS
	}
	pkt := buf[:totalLen]

	// Ethernet header.
	ethFrame, err := ethernet.NewFrame(pkt)
	if err != nil {
		return nil, err
	}
	*ethFrame.DestinationHardwareAddr() = dstMAC
	*ethFrame.SourceHardwareAddr() = srcMAC
	ethFrame.SetEtherType(ethernet.TypeIPv4)

	// IP header using ipv4.Frame for correct CRC calculation.
	ipStart := ethHdrLen
	ifrm, err := ipv4.NewFrame(pkt[ipStart:])
	if err != nil {
		return nil, err
	}
	ifrm.SetVersionAndIHL(4, 5) // Version 4, IHL 5 (20 bytes)
	ifrm.SetTotalLength(uint16(ipHdrLen + udpHdrLen + len(dnsPayload)))
	ifrm.SetID(0)
	ifrm.SetFlags(0)
	ifrm.SetTTL(64)
	ifrm.SetProtocol(lneto.IPProtoUDP)
	*ifrm.SourceAddr() = srcIP.As4()
	*ifrm.DestinationAddr() = dstIP.As4()
	// Zero the CRC field so its value does not add to the final result.
	ifrm.SetCRC(0)
	crcValue := ifrm.CalculateHeaderCRC()
	ifrm.SetCRC(crcValue)

	// UDP header.
	udpStart := ipStart + ipHdrLen
	udpFrame, err := udp.NewFrame(pkt[udpStart:])
	if err != nil {
		return nil, err
	}
	udpFrame.SetSourcePort(dns.ServerPort)
	udpFrame.SetDestinationPort(dstPort)
	udpLen := udpHdrLen + len(dnsPayload)
	udpFrame.SetLength(uint16(udpLen))

	// Copy DNS payload before calculating checksum.
	dnsStart := udpStart + udpHdrLen
	copy(pkt[dnsStart:], dnsPayload)

	// Calculate UDP checksum using pseudo header.
	var crc lneto.CRC791
	ifrm.CRCWriteUDPPseudo(&crc, uint16(udpLen))
	// Zero the CRC field so its value does not add to the final result.
	udpFrame.SetCRC(0)
	crcValue = crc.PayloadSum16(udpFrame.RawData())
	udpFrame.SetCRC(crcValue)

	return pkt, nil
}

var errBaseLenDNS = func() error {
	_, err := dns.NewFrame(nil)
	return err
}()

var errInvalidEtherType = errors.New("invalid ethernet type")
