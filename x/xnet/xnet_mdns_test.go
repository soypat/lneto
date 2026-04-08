package xnet

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/mdns"
	"github.com/soypat/lneto/udp"
)

func TestMDNS_QueryResponse(t *testing.T) {
	const MTU = 1500
	svcName, err := dns.NewName("My Web._http._tcp.local")
	if err != nil {
		t.Fatal(err)
	}
	hostName, err := dns.NewName("mydevice.local")
	if err != nil {
		t.Fatal(err)
	}
	svcType, err := dns.NewName("_http._tcp.local")
	if err != nil {
		t.Fatal(err)
	}
	svc := mdns.Service{
		Name: svcName,
		Host: hostName,
		Addr: []byte{192, 168, 1, 50},
		Port: 80,
	}

	responderAddr := netip.AddrFrom4([4]byte{192, 168, 1, 50})
	responderMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}
	querierAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
	querierMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02}
	mcastAddr := []byte{224, 0, 0, 251}

	// Setup responder stack with mDNS service.
	responderStack := new(StackAsync)
	err = responderStack.Reset(StackConfig{
		Hostname:        "responder",
		RandSeed:        1234,
		StaticAddress:   responderAddr,
		HardwareAddress: responderMAC,
		MTU:             MTU,
		MaxUDPConns:     1,
		AcceptMulticast: true,
	})
	if err != nil {
		t.Fatal("responder reset:", err)
	}
	responderStack.SetGateway6(querierMAC)

	var responderClient mdns.Client
	err = responderClient.Configure(mdns.ClientConfig{
		LocalPort:     mdns.Port,
		Services:      []mdns.Service{svc},
		MulticastAddr: mcastAddr,
	})
	if err != nil {
		t.Fatal("responder configure:", err)
	}
	err = responderStack.RegisterUDP(&responderClient, mcastAddr, mdns.Port)
	if err != nil {
		t.Fatal("responder register:", err)
	}

	// Setup querier stack.
	querierStack := new(StackAsync)
	err = querierStack.Reset(StackConfig{
		Hostname:        "querier",
		RandSeed:        5678,
		StaticAddress:   querierAddr,
		HardwareAddress: querierMAC,
		MTU:             MTU,
		MaxUDPConns:     1,
		AcceptMulticast: true,
	})
	if err != nil {
		t.Fatal("querier reset:", err)
	}
	querierStack.SetGateway6(responderMAC)

	var querierClient mdns.Client
	err = querierClient.Configure(mdns.ClientConfig{
		LocalPort:     mdns.Port,
		MulticastAddr: mcastAddr,
	})
	if err != nil {
		t.Fatal("querier configure:", err)
	}
	err = querierClient.StartResolve(mdns.ResolveConfig{
		Questions: []dns.Question{{
			Name:  svcType,
			Type:  dns.TypePTR,
			Class: dns.ClassINET,
		}},
		MaxResponseAnswers: 4,
	})
	if err != nil {
		t.Fatal("start resolve:", err)
	}
	err = querierStack.RegisterUDP(&querierClient, mcastAddr, mdns.Port)
	if err != nil {
		t.Fatal("querier register:", err)
	}

	const carrierDataSize = MTU + ethernet.MaxOverheadSize
	var buf [carrierDataSize]byte

	// Querier encapsulates query through full stack (Ethernet+IP+UDP+mDNS).
	n, err := querierStack.SendEthernet(buf[:])
	if err != nil || n == 0 {
		t.Fatal("querier encapsulate:", err, n)
	}

	// Verify mDNS query wire format at DNS layer.
	const ethHdrLen = 14
	ipIHL := int(buf[ethHdrLen]&0x0f) * 4
	dnsStart := ethHdrLen + ipIHL + 8
	dnsFrame, err := dns.NewFrame(buf[dnsStart:n])
	if err != nil {
		t.Fatal("parse query dns frame:", err)
	}
	if dnsFrame.TxID() != 0 {
		t.Errorf("mDNS query txid=%d, want 0", dnsFrame.TxID())
	}
	if dnsFrame.Flags() != 0 {
		t.Errorf("mDNS query flags=%d, want 0", dnsFrame.Flags())
	}

	// Responder demuxes the query (multicast MAC+IP accepted via AcceptMulticast).
	err = responderStack.RecvEthernet(buf[:n])
	if err != nil {
		t.Fatal("responder demux:", err)
	}

	// Responder encapsulates response.
	n, err = responderStack.SendEthernet(buf[:])
	if err != nil || n == 0 {
		t.Fatal("responder encapsulate:", err, n)
	}

	// Verify response DNS flags.
	ipIHL = int(buf[ethHdrLen]&0x0f) * 4
	dnsStart = ethHdrLen + ipIHL + 8
	dnsFrame, err = dns.NewFrame(buf[dnsStart:n])
	if err != nil {
		t.Fatal("parse response dns frame:", err)
	}
	flags := dnsFrame.Flags()
	if !flags.IsResponse() {
		t.Error("mDNS response missing QR bit")
	}
	if !flags.IsAuthorativeAnswer() {
		t.Error("mDNS response missing AA bit")
	}
	if dnsFrame.ANCount() == 0 {
		t.Fatal("mDNS response has 0 answers")
	}

	// Querier demuxes response.
	err = querierStack.RecvEthernet(buf[:n])
	if err != nil {
		t.Fatal("querier demux:", err)
	}

	// Read answers.
	var answers [4]dns.Resource
	nans, done, err := querierClient.AnswersCopyTo(answers[:])
	if err != nil {
		t.Fatal("answers:", err)
	}
	if !done {
		t.Fatal("expected done")
	}
	if nans == 0 {
		t.Fatal("got 0 answers")
	}

	// Verify PTR answer points to our service instance name.
	ptrData := answers[0].RawData()
	var ptrTarget dns.Name
	_, err = ptrTarget.Decode(ptrData, 0)
	if err != nil {
		t.Fatal("decode PTR target:", err)
	}
	if !dns.NamesEqual(ptrTarget, svcName) {
		t.Errorf("PTR target=%q, want %q", ptrTarget.String(), svcName.String())
	}
}

func TestMDNS_SRVThroughStack(t *testing.T) {
	const MTU = 1500
	svcName, err := dns.NewName("My Web._http._tcp.local")
	if err != nil {
		t.Fatal(err)
	}
	hostName, err := dns.NewName("mydevice.local")
	if err != nil {
		t.Fatal(err)
	}
	svc := mdns.Service{
		Name: svcName,
		Host: hostName,
		Addr: []byte{192, 168, 1, 50},
		Port: 80,
	}
	mcastAddr := []byte{224, 0, 0, 251}

	responderMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x01}
	querierMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x02}

	// Create responder.
	responderStack, _ := newMDNSStack(t, "responder", 1111,
		netip.AddrFrom4([4]byte{192, 168, 1, 50}), responderMAC, querierMAC,
		mdns.ClientConfig{LocalPort: mdns.Port, Services: []mdns.Service{svc}, MulticastAddr: mcastAddr},
	)

	// Create querier.
	querierStack, querierClient := newMDNSStack(t, "querier", 2222,
		netip.AddrFrom4([4]byte{192, 168, 1, 100}), querierMAC, responderMAC,
		mdns.ClientConfig{LocalPort: mdns.Port, MulticastAddr: mcastAddr},
	)
	err = querierClient.StartResolve(mdns.ResolveConfig{
		Questions: []dns.Question{{
			Name:  svcName,
			Type:  dns.TypeSRV,
			Class: dns.ClassINET,
		}},
		MaxResponseAnswers: 4,
	})
	if err != nil {
		t.Fatal("start resolve:", err)
	}

	// Full round-trip through both stacks.
	var buf [MTU + ethernet.MaxOverheadSize]byte
	mdnsQueryRespond(t, querierStack, responderStack, buf[:])

	var answers [4]dns.Resource
	nans, done, err := querierClient.AnswersCopyTo(answers[:])
	if err != nil || !done {
		t.Fatal("expected done:", err)
	}
	if nans < 2 {
		t.Fatalf("expected at least 2 answers (SRV+A), got %d", nans)
	}

	// Verify SRV port.
	srvData := answers[0].RawData()
	if len(srvData) < 6 {
		t.Fatalf("SRV data too short: %d", len(srvData))
	}
	gotPort := binary.BigEndian.Uint16(srvData[4:6])
	if gotPort != svc.Port {
		t.Errorf("SRV port=%d, want %d", gotPort, svc.Port)
	}

	// Verify A record.
	aData := answers[1].RawData()
	if [4]byte(aData) != [4]byte(svc.Addr) {
		t.Errorf("A record addr=%v, want %v", aData, svc.Addr)
	}
}

// newMDNSStack creates a StackAsync with an mDNS client registered on its UDP ports.
func newMDNSStack(t *testing.T, hostname string, seed int64,
	addr netip.Addr, mac, gatewayMAC [6]byte,
	mdnsCfg mdns.ClientConfig,
) (*StackAsync, *mdns.Client) {
	t.Helper()
	const MTU = 1500
	stack := new(StackAsync)
	err := stack.Reset(StackConfig{
		Hostname:        hostname,
		RandSeed:        seed,
		StaticAddress:   addr,
		HardwareAddress: mac,
		MTU:             MTU,
		MaxUDPConns:     1,
		AcceptMulticast: true,
	})
	if err != nil {
		t.Fatal(hostname, "reset:", err)
	}
	stack.SetGateway6(gatewayMAC)

	var client mdns.Client
	err = client.Configure(mdnsCfg)
	if err != nil {
		t.Fatal(hostname, "mdns configure:", err)
	}

	err = stack.RegisterUDP(&client, mdnsCfg.MulticastAddr, mdns.Port)
	if err != nil {
		t.Fatal(hostname, "register udp:", err)
	}
	return stack, &client
}

// mdnsQueryRespond performs a full Ethernet+IP+UDP+mDNS query→response cycle
// between two stacks with AcceptMulticast enabled.
func mdnsQueryRespond(t *testing.T, querier, responder *StackAsync, buf []byte) {
	t.Helper()

	// Querier encapsulates query.
	n, err := querier.SendEthernet(buf)
	if err != nil || n == 0 {
		t.Fatal("querier encapsulate:", err, n)
	}

	// Responder demuxes multicast query directly.
	err = responder.RecvEthernet(buf[:n])
	if err != nil {
		t.Fatal("responder demux:", err)
	}

	// Responder encapsulates response.
	n, err = responder.SendEthernet(buf)
	if err != nil || n == 0 {
		t.Fatal("responder encapsulate:", err, n)
	}

	// Querier demuxes multicast response.
	err = querier.RecvEthernet(buf[:n])
	if err != nil {
		t.Fatal("querier demux:", err)
	}
}

func TestMDNS_RealWorldQueries(t *testing.T) {
	const MTU = 1500

	responderMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}
	querierMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02}

	responderIP := netip.AddrFrom4([4]byte{192, 168, 50, 81})
	querierIP := netip.AddrFrom4([4]byte{192, 168, 50, 213})

	mcastAddr := mdns.IPv4MulticastAddr()

	// Service hosted by responder.
	hostName := dns.MustNewName("server.local")
	svc := mdns.Service{
		Name: hostName,
		Host: hostName,
		Addr: []byte{192, 168, 50, 81},
		Port: 80,
	}

	responderStack, _ := newMDNSStack(t, "responder", 1,
		responderIP, responderMAC, querierMAC,
		mdns.ClientConfig{
			LocalPort:     mdns.Port,
			Services:      []mdns.Service{svc},
			MulticastAddr: mcastAddr[:],
		},
	)

	pkts := []struct {
		name    string
		qname   string
		qtype   dns.Type
		unicast bool // QU bit
	}{
		// Frame 1: QM multicast A server.local
		{"QM_A_server", "server.local", dns.TypeA, false},

		// Frame 2: QU unicast AAAA random.local
		{"QU_AAAA_random", "rds-th-TH010-e6614864d3511735.local", dns.TypeAAAA, true},

		// Frame 3: QU unicast A random.local
		{"QU_A_random", "rds-th-TH010-e6614864d3511735.local", dns.TypeA, true},
	}

	var buf [MTU + ethernet.MaxOverheadSize]byte
	checkNoData := func(msg string) {
		t.Helper()
		n, err := responderStack.SendEthernet(buf[:])
		if err != nil {
			t.Fatal(err)
		} else if n != 0 {
			t.Errorf(" %s: expected no data sent: %d", msg, n)
		}
	}
	checkNoData("before transaction")
	var msg dns.Message
	for _, q := range pkts {
		msg.Reset()
		msg.AddQuestions([]dns.Question{
			{
				Name:  dns.MustNewName(q.qname),
				Type:  q.qtype,
				Class: withQU(q.unicast),
			},
		})
		efrm, _ := ethernet.NewFrame(buf[:])
		*efrm.DestinationHardwareAddr(), _ = ethernet.MulticastAddrFrom4(mdns.IPv4MulticastAddr())
		*efrm.SourceHardwareAddr() = querierMAC
		efrm.SetEtherType(ethernet.TypeIPv4)

		ifrm, _ := ipv4.NewFrame(efrm.Payload())
		ifrm.SetVersionAndIHL(4, 5) // No options. IHL=5, IPLEN=4*IHL=20
		ifrm.SetToS(ipv4.NewToS(0, 0))
		ifrm.SetTotalLength(20 + 8 + msg.Len())
		ifrm.SetID(1337)
		ifrm.SetFlags(ipv4.FlagDontFragment)
		ifrm.SetTTL(64)
		ifrm.SetProtocol(lneto.IPProtoUDP)

		*ifrm.SourceAddr() = querierIP.As4()
		*ifrm.DestinationAddr() = mdns.IPv4MulticastAddr()

		ifrm.SetCRC(0) // Zero CRC before calculating CRC, as custom with lneto.
		ifrm.SetCRC(ifrm.CalculateHeaderCRC())

		ufrm, _ := udp.NewFrame(ifrm.Payload())
		ufrm.SetSourcePort(mdns.Port)
		ufrm.SetDestinationPort(mdns.Port)
		ufrm.SetLength(8 + msg.Len())

		mdnsPayload, _ := msg.AppendTo(ufrm.Payload()[:0], 0, 0)
		if len(mdnsPayload) != int(msg.Len()) {
			t.Fatal("unreachable")
		}
		var crc lneto.CRC791
		ufrm.SetCRC(0)
		ifrm.CRCWriteUDPPseudo(&crc, ufrm.Length())
		got := crc.PayloadSum16(ifrm.Payload())
		ufrm.SetCRC(got)
		err := responderStack.RecvEthernet(buf[:14+20+8+msg.Len()])
		if err != nil {
			t.Fatal(err)
		}
	}
	n, err := responderStack.SendEthernet(buf[:])
	if err != nil {
		t.Fatal(err)
	} else if n < 14+20+8+dns.SizeHeader {
		t.Error("expected response", n)
	}
	n, err = responderStack.SendEthernet(buf[:])
	if err != nil {
		t.Fatal(err)
	} else if n != 0 {
		t.Error("expected single response")
	}
}

func withQU(unicast bool) dns.Class {
	if !unicast {
		return dns.ClassINET
	}
	return dns.ClassINET | (1 << 15) // QU bit
}
