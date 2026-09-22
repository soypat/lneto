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

func TestDNS_QueryReceivesAnswer(t *testing.T) {
	const seed = 9876
	const MTU = ethernet.MaxMTU

	// Create client stack with DNS server configured.
	client := new(StackAsync)
	dnsServerAddr := netip.AddrFrom4([4]byte{8, 8, 8, 8})
	clientAddr := netip.AddrFrom4([4]byte{10, 0, 0, 100})
	clientMAC := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	dnsServerMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	err := client.Reset(StackConfig{
		Hostname:        "DNSClient",
		RandSeed:        seed,
		StaticAddress4:  clientAddr.As4(),
		DNSServer:       dnsServerAddr,
		HardwareAddress: clientMAC,
		MTU:             uint16(MTU),
	})
	if err != nil {
		t.Fatal("client Reset failed:", err)
	}
	client.SetGatewayHardwareAddr(dnsServerMAC)

	// The IP address we expect to receive from the DNS response.
	wantAddr := netip.MustParseAddr("93.184.216.34") // example.com's IP

	// Start DNS lookup on the client.
	const hostname = "example.com"
	err = client.StartLookupIP(dns.MustNewName(hostname))
	if err != nil {
		t.Fatal("StartLookupIP failed:", err)
	}

	// Client sends DNS query.
	const carrierDataSize = ethernet.MaxFrameLength
	var buf [carrierDataSize]byte
	n, err := client.EgressEthernet(buf[:])
	if err != nil {
		t.Fatal("client Encapsulate failed:", err)
	}
	if n == 0 {
		t.Fatal("expected DNS query packet from client")
	}

	// Parse the DNS query to get the transaction ID and client port.
	txid, clientPort, err := extractDNSTxIDAndPort(buf[:n])
	if err != nil {
		t.Fatal("failed to extract DNS txid:", err)
	}

	// Build and wrap DNS response manually.
	responsePkt, err := buildDNSResponsePacket(t, txid, clientPort, hostname, wantAddr, dnsServerAddr, dnsServerMAC, clientAddr, clientMAC, buf[:])
	if err != nil {
		t.Fatal("failed to build DNS response packet:", err)
	}

	// Deliver response to client.
	err = client.IngressEthernet(responsePkt)
	if err != nil {
		t.Fatal("client Demux failed:", err)
	}

	// Check the result.
	addrs, done, err := client.ResultLookupIP(dns.MustNewName(hostname))
	if err != nil {
		t.Fatal("ResultLookupIP error:", err)
	}
	if !done {
		t.Fatal("DNS lookup not done after receiving response")
	}
	if len(addrs) == 0 {
		t.Fatal("no addresses returned from DNS lookup")
	}

	found := slices.Contains(addrs, wantAddr)
	if !found {
		t.Errorf("expected address %s not found in result %v", wantAddr, addrs)
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

// buildDNSResponsePacket builds a complete Ethernet+IP+UDP+DNS response packet.
func buildDNSResponsePacket(t *testing.T, txid uint16, dstPort uint16, hostname string, addr netip.Addr,
	srcIP netip.Addr, srcMAC [6]byte, dstIP netip.Addr, dstMAC [6]byte, buf []byte) ([]byte, error) {
	t.Helper()

	var name dns.Name

	err := name.Parse(hostname)
	if err != nil {
		return nil, err
	}

	// Build DNS response message.
	msg := dns.Message{
		Questions: []dns.Question{
			{
				Name:  name,
				Type:  dns.TypeA,
				Class: dns.ClassINET,
			},
		},
		Answers: []dns.Resource{
			dns.NewResource(name, dns.TypeA, dns.ClassINET, 300, addr.AsSlice()),
		},
	}
	return buildDNSMsgResponsePacket(t, txid, dstPort, msg, srcIP, srcMAC, dstIP, dstMAC, buf)
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

// TestDNS_CNAMEResponse verifies that a DNS response containing a CNAME record
// followed by an A record for the canonical name resolves to the A record's
// address: the CNAME RDATA must not be misinterpreted as an IP address.
func TestDNS_CNAMEResponse(t *testing.T) {
	const seed = 9876
	const MTU = ethernet.MaxMTU

	client := new(StackAsync)
	dnsServerAddr := netip.AddrFrom4([4]byte{8, 8, 8, 8})
	clientAddr := netip.AddrFrom4([4]byte{10, 0, 0, 100})
	clientMAC := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	dnsServerMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	err := client.Reset(StackConfig{
		Hostname:        "DNSClient",
		RandSeed:        seed,
		StaticAddress4:  clientAddr.As4(),
		DNSServer:       dnsServerAddr,
		HardwareAddress: clientMAC,
		MTU:             uint16(MTU),
	})
	if err != nil {
		t.Fatal("client Reset failed:", err)
	}
	client.SetGatewayHardwareAddr(dnsServerMAC)

	const hostname = "www.example.com"
	const alias = "cdn.example.net"
	wantAddr := netip.MustParseAddr("192.0.2.200")

	err = client.StartLookupIP(dns.MustNewName(hostname))
	if err != nil {
		t.Fatal("StartLookupIP failed:", err)
	}

	const carrierDataSize = ethernet.MaxFrameLength
	var buf [carrierDataSize]byte

	// Client sends DNS query for www.example.com.
	n, err := client.EgressEthernet(buf[:])
	if err != nil || n == 0 {
		t.Fatal("expected DNS query packet from client:", err, n)
	}
	txid, clientPort, err := extractDNSTxIDAndPort(buf[:n])
	if err != nil {
		t.Fatal("failed to extract DNS txid:", err)
	}

	// Respond with a CNAME record www.example.com -> cdn.example.net
	// followed by the A record for cdn.example.net.
	var owner dns.Name
	err = owner.Parse(hostname)
	if err != nil {
		t.Fatal(err)
	}
	var aliasName dns.Name
	err = aliasName.Parse(alias)
	if err != nil {
		t.Fatal(err)
	}
	aliasWire, err := aliasName.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := dns.Message{
		Questions: []dns.Question{{
			Name:  owner,
			Type:  dns.TypeA,
			Class: dns.ClassINET,
		}},
		Answers: []dns.Resource{
			dns.NewResource(owner, dns.TypeCNAME, dns.ClassINET, 300, aliasWire),
			dns.NewResource(aliasName, dns.TypeA, dns.ClassINET, 300, wantAddr.AsSlice()),
		},
	}
	responsePkt, err := buildDNSMsgResponsePacket(t, txid, clientPort, msg,
		dnsServerAddr, dnsServerMAC, clientAddr, clientMAC, buf[:])
	if err != nil {
		t.Fatal("failed to build CNAME response packet:", err)
	}
	if err = client.IngressEthernet(responsePkt); err != nil {
		t.Fatal("client Demux of CNAME response failed:", err)
	}

	addrs, done, err := client.ResultLookupIP(dns.MustNewName(hostname))
	if err != nil {
		t.Fatal("ResultLookupIP error:", err)
	}
	if !done {
		t.Fatal("DNS lookup not done after receiving CNAME response")
	}
	if !slices.Contains(addrs, wantAddr) {
		t.Errorf("expected address %s not found in result %v", wantAddr, addrs)
	}
}

// TestDNS_CNAMEOnlyResult verifies a response with only a CNAME is reported by
// ResultLookupIP as errDNSOnlyCNAME. See TestDNS_CNAMEChainQueryLimit for requeries.
func TestDNS_CNAMEOnlyResult(t *testing.T) {
	const hostname = "www.example.com"
	const alias = "cdn.example.net"
	dnsServerAddr := netip.AddrFrom4([4]byte{8, 8, 8, 8})
	clientAddr := netip.AddrFrom4([4]byte{10, 0, 0, 100})
	clientMAC := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	dnsServerMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	client := new(StackAsync)
	err := client.Reset(StackConfig{
		Hostname:        "DNSClient",
		RandSeed:        9876,
		StaticAddress4:  clientAddr.As4(),
		DNSServer:       dnsServerAddr,
		HardwareAddress: clientMAC,
		MTU:             uint16(ethernet.MaxMTU),
	})
	if err != nil {
		t.Fatal("client Reset failed:", err)
	}
	client.SetGatewayHardwareAddr(dnsServerMAC)

	owner := dns.MustNewName(hostname)
	aliasName := dns.MustNewName(alias)
	aliasWire, err := aliasName.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.StartLookupIP(owner); err != nil {
		t.Fatal("StartLookupIP failed:", err)
	}
	var buf [ethernet.MaxFrameLength]byte
	n, err := client.EgressEthernet(buf[:])
	if err != nil || n == 0 {
		t.Fatal("expected DNS query packet from client:", err, n)
	}
	txid, port, err := extractDNSTxIDAndPort(buf[:n])
	if err != nil {
		t.Fatal("failed to extract DNS txid:", err)
	}
	msg := dns.Message{
		Questions: []dns.Question{{Name: owner, Type: dns.TypeA, Class: dns.ClassINET}},
		Answers:   []dns.Resource{dns.NewResource(owner, dns.TypeCNAME, dns.ClassINET, 300, aliasWire)},
	}
	pkt, err := buildDNSMsgResponsePacket(t, txid, port, msg, dnsServerAddr, dnsServerMAC, clientAddr, clientMAC, buf[:])
	if err != nil {
		t.Fatal("failed to build response packet:", err)
	}
	if err = client.IngressEthernet(pkt); err != nil {
		t.Fatal("client Demux failed:", err)
	}
	_, done, err := client.ResultLookupIP(dns.MustNewName(hostname))
	if !done || err != errDNSOnlyCNAME {
		t.Errorf("expected done with %v, got done=%v err=%v", errDNSOnlyCNAME, done, err)
	}
}

// TestDNS_CNAMEChainQueryLimit verifies DoLookupIP follows chains of CNAME-only
// answers one query per hop, succeeds when the address arrives on the last
// allowed query and fails with errDNSOnlyCNAME without exceeding maxCNAMEqueries.
func TestDNS_CNAMEChainQueryLimit(t *testing.T) {
	wantAddr := netip.MustParseAddr("192.0.2.200")
	dnsServerAddr := netip.AddrFrom4([4]byte{8, 8, 8, 8})
	clientAddr := netip.AddrFrom4([4]byte{10, 0, 0, 100})
	clientMAC := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	dnsServerMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	// A chain of n hops needs n+1 queries: one per CNAME-only answer plus the final A query.
	for hops := 1; hops <= maxCNAMEqueries; hops++ {
		wantErr := error(nil)
		wantQueries := hops + 1
		if wantQueries > maxCNAMEqueries {
			wantErr = errDNSOnlyCNAME
			wantQueries = maxCNAMEqueries
		}
		t.Run(fmt.Sprintf("hops=%d", hops), func(t *testing.T) {
			client := new(StackAsync)
			err := client.Reset(StackConfig{
				Hostname:        "DNSClient",
				RandSeed:        9876,
				StaticAddress4:  clientAddr.As4(),
				DNSServer:       dnsServerAddr,
				HardwareAddress: clientMAC,
				MTU:             uint16(ethernet.MaxMTU),
			})
			if err != nil {
				t.Fatal("client Reset failed:", err)
			}
			client.SetGatewayHardwareAddr(dnsServerMAC)

			// chain[i] is a CNAME to chain[i+1]; the last name has the A record.
			chain := make([]dns.Name, hops+1)
			chain[0] = dns.MustNewName("www.example.com")
			for i := 1; i <= hops; i++ {
				chain[i] = dns.MustNewName(fmt.Sprintf("cdn%d.example.net", i))
			}

			var buf [ethernet.MaxFrameLength]byte
			var q dns.Question
			queries := 0
			// Server answers query i for chain[i] with a CNAME to chain[i+1], or with the A record at the chain end.
			pump := func(uint) time.Duration {
				n, err := client.EgressEthernet(buf[:])
				if err != nil || n == 0 {
					return lneto.BackoffFlagNop
				}
				txid, port, err := extractDNSTxIDAndPort(buf[:n])
				if err != nil {
					t.Fatal("failed to extract DNS txid:", err)
				}
				if queries >= len(chain) {
					t.Fatalf("unexpected query #%d past chain end", queries+1)
				}
				if _, err = q.Decode(extractDNSPayload(buf[:n]), dns.SizeHeader); err != nil {
					t.Fatal("failed to decode question:", err)
				}
				owner := chain[queries]
				if !q.Name.EqualString(owner.String()) {
					t.Fatalf("query #%d: want name %s, got %s", queries+1, owner.String(), q.Name.String())
				}
				var ans dns.Resource
				if queries < hops {
					target, err := chain[queries+1].AppendTo(nil)
					if err != nil {
						t.Fatal(err)
					}
					ans = dns.NewResource(owner, dns.TypeCNAME, dns.ClassINET, 300, target)
				} else {
					ans = dns.NewResource(owner, dns.TypeA, dns.ClassINET, 300, wantAddr.AsSlice())
				}
				queries++
				msg := dns.Message{
					Questions: []dns.Question{{Name: owner, Type: dns.TypeA, Class: dns.ClassINET}},
					Answers:   []dns.Resource{ans},
				}
				pkt, err := buildDNSMsgResponsePacket(t, txid, port, msg, dnsServerAddr, dnsServerMAC, clientAddr, clientMAC, buf[:])
				if err != nil {
					t.Fatal("failed to build response packet:", err)
				}
				if err = client.IngressEthernet(pkt); err != nil {
					t.Fatal("client Demux failed:", err)
				}
				return lneto.BackoffFlagNop
			}

			addrs, err := client.StackBlocking(pump).DoLookupIP(chain[0], time.Second)
			if err != wantErr {
				t.Fatalf("want err %v, got %v", wantErr, err)
			}
			if wantErr == nil && !slices.Contains(addrs, wantAddr) {
				t.Errorf("expected address %s not found in result %v", wantAddr, addrs)
			}
			if queries != wantQueries {
				t.Errorf("want %d queries, got %d", wantQueries, queries)
			}
		})
	}
}
