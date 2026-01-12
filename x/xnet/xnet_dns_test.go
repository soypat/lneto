package xnet

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/udp"
)

func TestDNS_QueryReceivesAnswer(t *testing.T) {
	const seed = 9876
	const MTU = 1500

	// Create client stack with DNS server configured.
	client := new(StackAsync)
	dnsServerAddr := netip.AddrFrom4([4]byte{8, 8, 8, 8})
	clientAddr := netip.AddrFrom4([4]byte{10, 0, 0, 100})
	clientMAC := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	dnsServerMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	err := client.Reset(StackConfig{
		Hostname:        "DNSClient",
		RandSeed:        seed,
		StaticAddress:   clientAddr,
		DNSServer:       dnsServerAddr,
		HardwareAddress: clientMAC,
		MTU:             uint16(MTU),
	})
	if err != nil {
		t.Fatal("client Reset failed:", err)
	}
	client.SetGateway6(dnsServerMAC)

	// The IP address we expect to receive from the DNS response.
	wantAddr := netip.MustParseAddr("93.184.216.34") // example.com's IP

	// Start DNS lookup on the client.
	const hostname = "example.com"
	err = client.StartLookupIP(hostname)
	if err != nil {
		t.Fatal("StartLookupIP failed:", err)
	}

	// Client sends DNS query.
	var buf [MTU]byte
	n, err := client.Encapsulate(buf[:], -1, 0)
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
	err = client.Demux(responsePkt, 0)
	if err != nil {
		t.Fatal("client Demux failed:", err)
	}

	// Verify our DNS response is valid by decoding it separately.
	var testMsg dns.Message
	testMsg.LimitResourceDecoding(1, 1, 0, 0)
	// Find DNS payload offset in response packet.
	const ethLen, ipLen, udpLen = 14, 20, 8
	dnsOffset := ethLen + ipLen + udpLen
	_, _, decodeErr := testMsg.Decode(responsePkt[dnsOffset:])
	if decodeErr != nil {
		t.Logf("DNS decode error: %v", decodeErr)
	}
	t.Logf("Test decode: questions=%d, answers=%d", len(testMsg.Questions), len(testMsg.Answers))
	if len(testMsg.Answers) > 0 {
		data := testMsg.Answers[0].RawData()
		t.Logf("Answer data: %v (len=%d)", data, len(data))
	}

	// Also verify DNS header flags in the packet.
	dnsFrame, _ := dns.NewFrame(responsePkt[dnsOffset:])
	t.Logf("DNS Frame: txid=%d, flags=%s, QD=%d, AN=%d", dnsFrame.TxID(), dnsFrame.Flags(), dnsFrame.QDCount(), dnsFrame.ANCount())

	// Check the result.
	addrs, done, err := client.ResultLookupIP(hostname)
	if err != nil {
		t.Fatal("ResultLookupIP error:", err)
	}
	if !done {
		t.Fatal("DNS lookup not done after receiving response")
	}
	if len(addrs) == 0 {
		t.Fatal("no addresses returned from DNS lookup")
	}

	found := false
	for _, addr := range addrs {
		if addr == wantAddr {
			found = true
			break
		}
	}
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

// buildDNSResponsePacket builds a complete Ethernet+IP+UDP+DNS response packet.
func buildDNSResponsePacket(t *testing.T, txid uint16, dstPort uint16, hostname string, addr netip.Addr,
	srcIP netip.Addr, srcMAC [6]byte, dstIP netip.Addr, dstMAC [6]byte, buf []byte) ([]byte, error) {
	t.Helper()

	name, err := dns.NewName(hostname)
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
	ifrm.SetCRC(ifrm.CalculateHeaderCRC())

	// UDP header.
	udpStart := ipStart + ipHdrLen
	udpFrame, err := udp.NewFrame(pkt[udpStart:])
	if err != nil {
		return nil, err
	}
	udpFrame.SetSourcePort(dns.ServerPort)
	udpFrame.SetDestinationPort(dstPort)
	udpFrame.SetLength(uint16(udpHdrLen + len(dnsPayload)))

	// Copy DNS payload before calculating checksum.
	dnsStart := udpStart + udpHdrLen
	copy(pkt[dnsStart:], dnsPayload)

	// Calculate UDP checksum using pseudo header.
	var crc lneto.CRC791
	ifrm.CRCWriteUDPPseudo(&crc)
	udpFrame.CRCWriteIPv4(&crc)
	udpFrame.SetCRC(crc.Sum16())

	return pkt, nil
}

var errBaseLenDNS = func() error {
	_, err := dns.NewFrame(nil)
	return err
}()

var errInvalidEtherType = errors.New("invalid ethernet type")
