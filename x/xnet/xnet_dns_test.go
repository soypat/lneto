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
				addrs, err = client.StackBlocking(pump).DoLookupIP(dns.MustNewName(host), time.Second)
			} else {
				if err = client.StartLookupIP(dns.MustNewName(host)); err != nil {
					t.Fatal("StartLookupIP failed:", err)
				}
				if !srv.respond() {
					t.Fatal("expected DNS query packet from client")
				}
				var done bool
				addrs, done, err = client.ResultLookupIP(dns.MustNewName(host))
				if !done {
					t.Fatal("DNS lookup not done after response")
				}
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
