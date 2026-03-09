package mdns

import (
	"encoding/binary"
	"testing"

	"github.com/soypat/lneto/dns"
)

func mustNewName(s string) dns.Name {
	n, err := dns.NewName(s)
	if err != nil {
		panic(err)
	}
	return n
}

func testService() Service {
	return Service{
		Name: mustNewName("My Web._http._tcp.local"),
		Host: mustNewName("mydevice.local"),
		Addr: [4]byte{192, 168, 1, 50},
		Port: 80,
	}
}

func TestQuerierResponder(t *testing.T) {
	svc := testService()

	// Configure responder with one service.
	var resp Responder
	err := resp.Configure([]Service{svc})
	if err != nil {
		t.Fatal(err)
	}
	if resp.State() != responderReady {
		t.Fatalf("want responder state ready, got %d", resp.State())
	}

	// Set up querier to ask for the PTR record of the service type.
	var querier Querier
	err = querier.StartQuery(QueryConfig{
		Questions: []dns.Question{{
			Name:  mustNewName("_http._tcp.local"),
			Type:  dns.TypePTR,
			Class: dns.ClassINET,
		}},
		MaxAnswers: 8,
	})
	if err != nil {
		t.Fatal(err)
	}

	var buf [1024]byte

	// QUERIER: Encapsulate query.
	n, err := querier.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal("querier encapsulate:", err)
	} else if n == 0 {
		t.Fatal("querier wrote 0 bytes")
	}

	// Verify query wire format: txid=0, flags=0.
	f, _ := dns.NewFrame(buf[:n])
	if f.TxID() != 0 {
		t.Errorf("mDNS query txid=%d, want 0", f.TxID())
	}
	if f.Flags() != 0 {
		t.Errorf("mDNS query flags=%d, want 0", f.Flags())
	}
	if f.QDCount() != 1 {
		t.Errorf("mDNS query QDCount=%d, want 1", f.QDCount())
	}

	// RESPONDER: Demux the query.
	err = resp.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal("responder demux:", err)
	}

	// RESPONDER: Encapsulate response.
	n, err = resp.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal("responder encapsulate:", err)
	} else if n == 0 {
		t.Fatal("responder wrote 0 bytes")
	}

	// Verify response wire format: QR=1, AA=1.
	f, _ = dns.NewFrame(buf[:n])
	flags := f.Flags()
	if !flags.IsResponse() {
		t.Error("mDNS response missing QR bit")
	}
	if !flags.IsAuthorativeAnswer() {
		t.Error("mDNS response missing AA bit")
	}
	if f.ANCount() == 0 {
		t.Fatal("mDNS response has 0 answers")
	}

	// QUERIER: Demux the response.
	err = querier.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal("querier demux:", err)
	}

	answers := querier.Answers()
	if len(answers) == 0 {
		t.Fatal("querier got 0 answers")
	}

	// The PTR answer data should contain the instance name in wire format.
	ptrData := answers[0].RawData()
	if len(ptrData) == 0 {
		t.Fatal("PTR answer has no data")
	}
	// Decode the name from the PTR data.
	var ptrName dns.Name
	_, err = ptrName.Decode(ptrData, 0)
	if err != nil {
		t.Fatal("decode PTR name:", err)
	}
	if ptrName.String() != svc.Name.String() {
		t.Errorf("PTR target=%q, want %q", ptrName.String(), svc.Name.String())
	}
}

func TestQuerierResponderSRV(t *testing.T) {
	svc := testService()
	var resp Responder
	resp.Configure([]Service{svc})

	// Query for SRV record by instance name.
	var querier Querier
	querier.StartQuery(QueryConfig{
		Questions: []dns.Question{{
			Name:  mustNewName("My Web._http._tcp.local"),
			Type:  dns.TypeSRV,
			Class: dns.ClassINET,
		}},
		MaxAnswers: 8,
	})

	var buf [1024]byte

	// Query -> Responder -> Response -> Querier.
	n, err := querier.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatal("querier encapsulate:", err, n)
	}
	if err = resp.Demux(buf[:n], 0); err != nil {
		t.Fatal("responder demux:", err)
	}
	n, err = resp.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatal("responder encapsulate:", err, n)
	}
	if err = querier.Demux(buf[:n], 0); err != nil {
		t.Fatal("querier demux:", err)
	}

	answers := querier.Answers()
	// SRV query should return SRV + A record.
	if len(answers) < 2 {
		t.Fatalf("expected at least 2 answers (SRV+A), got %d", len(answers))
	}

	// First answer should be SRV. Parse priority(2)+weight(2)+port(2)+target.
	srvData := answers[0].RawData()
	if len(srvData) < 6 {
		t.Fatalf("SRV data too short: %d bytes", len(srvData))
	}
	gotPort := binary.BigEndian.Uint16(srvData[4:6])
	if gotPort != svc.Port {
		t.Errorf("SRV port=%d, want %d", gotPort, svc.Port)
	}
	var srvTarget dns.Name
	_, err = srvTarget.Decode(srvData, 6)
	if err != nil {
		t.Fatal("decode SRV target:", err)
	}
	if srvTarget.String() != svc.Host.String() {
		t.Errorf("SRV target=%q, want %q", srvTarget.String(), svc.Host.String())
	}

	// Second answer should be A record with 4-byte IP.
	aData := answers[1].RawData()
	if len(aData) != 4 {
		t.Fatalf("A record data length=%d, want 4", len(aData))
	}
	if [4]byte(aData) != svc.Addr {
		t.Errorf("A record addr=%v, want %v", aData, svc.Addr)
	}
}

func TestQuerierResponderARecord(t *testing.T) {
	svc := testService()
	var resp Responder
	resp.Configure([]Service{svc})

	// Query for A record by hostname.
	var querier Querier
	querier.StartQuery(QueryConfig{
		Questions: []dns.Question{{
			Name:  mustNewName("mydevice.local"),
			Type:  dns.TypeA,
			Class: dns.ClassINET,
		}},
		MaxAnswers: 4,
	})

	var buf [1024]byte
	n, err := querier.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatal("querier encapsulate:", err, n)
	}
	if err = resp.Demux(buf[:n], 0); err != nil {
		t.Fatal("responder demux:", err)
	}
	n, err = resp.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatal("responder encapsulate:", err, n)
	}
	if err = querier.Demux(buf[:n], 0); err != nil {
		t.Fatal("querier demux:", err)
	}

	answers := querier.Answers()
	if len(answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(answers))
	}
	aData := answers[0].RawData()
	if [4]byte(aData) != svc.Addr {
		t.Errorf("A record addr=%v, want %v", aData, svc.Addr)
	}
}

func TestResponderAnnounce(t *testing.T) {
	svc := testService()
	var resp Responder
	resp.Configure([]Service{svc})
	resp.Announce()

	var buf [1024]byte
	n, err := resp.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("announce wrote 0 bytes")
	}

	// Decode and verify announcement contains PTR+SRV+TXT+A.
	f, _ := dns.NewFrame(buf[:n])
	if !f.Flags().IsResponse() {
		t.Error("announcement missing QR bit")
	}
	ancount := f.ANCount()
	if ancount != 4 {
		t.Errorf("announcement ANCount=%d, want 4 (PTR+SRV+TXT+A)", ancount)
	}
}

func TestResponderProbeFinish(t *testing.T) {
	svc := testService()
	var resp Responder
	resp.Configure([]Service{svc})

	resp.Probe()
	if resp.State() != responderProbing {
		t.Fatalf("expected probing state, got %d", resp.State())
	}

	var buf [1024]byte
	n, err := resp.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("probe wrote 0 bytes")
	}

	// Probe should be a query (QR=0).
	f, _ := dns.NewFrame(buf[:n])
	if f.Flags().IsResponse() {
		t.Error("probe should be a query, not a response")
	}
	if f.QDCount() != 1 {
		t.Errorf("probe QDCount=%d, want 1", f.QDCount())
	}

	// Finish probing should transition to ready and trigger announcement.
	resp.FinishProbe()
	if resp.State() != responderReady {
		t.Fatalf("expected ready state after FinishProbe, got %d", resp.State())
	}

	// Should have a pending announcement.
	n, err = resp.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("expected announcement after FinishProbe")
	}
}

func TestQuerierIgnoresQueries(t *testing.T) {
	// Querier should ignore non-response packets.
	var querier Querier
	querier.StartQuery(QueryConfig{
		Questions: []dns.Question{{
			Name:  mustNewName("_http._tcp.local"),
			Type:  dns.TypePTR,
			Class: dns.ClassINET,
		}},
		MaxAnswers: 4,
	})

	// Encapsulate the query first.
	var buf [512]byte
	n, _ := querier.Encapsulate(buf[:], -1, 0)

	// Feed the query back into the querier — it should be ignored (not a response).
	err := querier.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal("demux query:", err)
	}
	if len(querier.Answers()) != 0 {
		t.Error("querier should ignore queries")
	}
}

func TestResponderIgnoresResponses(t *testing.T) {
	svc := testService()
	var resp Responder
	resp.Configure([]Service{svc})

	// Build a response packet (QR=1).
	var msg dns.Message
	var buf [512]byte
	const responseFlags = dns.HeaderFlags(1 << 15)
	data, err := msg.AppendTo(buf[:0], 0, responseFlags)
	if err != nil {
		t.Fatal(err)
	}

	// Feed a response to the responder — should be ignored.
	err = resp.Demux(data, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Nothing should be pending.
	n, _ := resp.Encapsulate(buf[:], -1, 0)
	if n != 0 {
		t.Error("responder should not respond to responses")
	}
}

func TestQuerierFinish(t *testing.T) {
	var querier Querier
	querier.StartQuery(QueryConfig{
		Questions: []dns.Question{{
			Name:  mustNewName("_http._tcp.local"),
			Type:  dns.TypePTR,
			Class: dns.ClassINET,
		}},
		MaxAnswers: 4,
	})

	var buf [512]byte
	querier.Encapsulate(buf[:], -1, 0)

	if querier.Done() {
		t.Error("querier should not be done before Finish")
	}
	querier.Finish()
	if !querier.Done() {
		t.Error("querier should be done after Finish")
	}
}

func TestResponderUnmatchedQuery(t *testing.T) {
	svc := testService()
	var resp Responder
	resp.Configure([]Service{svc})

	// Query for a name the responder doesn't know.
	var querier Querier
	querier.StartQuery(QueryConfig{
		Questions: []dns.Question{{
			Name:  mustNewName("_ftp._tcp.local"),
			Type:  dns.TypePTR,
			Class: dns.ClassINET,
		}},
		MaxAnswers: 4,
	})

	var buf [1024]byte
	n, _ := querier.Encapsulate(buf[:], -1, 0)
	resp.Demux(buf[:n], 0)

	// Responder should have nothing pending.
	n, _ = resp.Encapsulate(buf[:], -1, 0)
	if n != 0 {
		t.Error("responder should not respond to unmatched query")
	}
}

func TestQuerierMultipleResponses(t *testing.T) {
	// Two responders advertising different instances of the same service type.
	svc1 := Service{
		Name: mustNewName("Device A._http._tcp.local"),
		Host: mustNewName("device-a.local"),
		Addr: [4]byte{192, 168, 1, 10},
		Port: 80,
	}
	svc2 := Service{
		Name: mustNewName("Device B._http._tcp.local"),
		Host: mustNewName("device-b.local"),
		Addr: [4]byte{192, 168, 1, 11},
		Port: 8080,
	}

	var resp1, resp2 Responder
	resp1.Configure([]Service{svc1})
	resp2.Configure([]Service{svc2})

	var querier Querier
	querier.StartQuery(QueryConfig{
		Questions: []dns.Question{{
			Name:  mustNewName("_http._tcp.local"),
			Type:  dns.TypePTR,
			Class: dns.ClassINET,
		}},
		MaxAnswers: 8,
	})

	var buf [1024]byte

	// Querier sends query.
	n, _ := querier.Encapsulate(buf[:], -1, 0)
	query := make([]byte, n)
	copy(query, buf[:n])

	// Both responders process the query.
	resp1.Demux(query, 0)
	resp2.Demux(query, 0)

	// Querier receives response from responder 1.
	n, _ = resp1.Encapsulate(buf[:], -1, 0)
	querier.Demux(buf[:n], 0)

	// Querier receives response from responder 2.
	n, _ = resp2.Encapsulate(buf[:], -1, 0)
	querier.Demux(buf[:n], 0)

	answers := querier.Answers()
	if len(answers) < 2 {
		t.Fatalf("expected at least 2 answers from 2 responders, got %d", len(answers))
	}
}

func TestResponderConfigureErrors(t *testing.T) {
	var resp Responder
	err := resp.Configure(nil)
	if err == nil {
		t.Error("expected error for nil services")
	}
	err = resp.Configure([]Service{})
	if err == nil {
		t.Error("expected error for empty services")
	}
}

func TestQuerierStartQueryErrors(t *testing.T) {
	var querier Querier
	err := querier.StartQuery(QueryConfig{})
	if err == nil {
		t.Error("expected error for empty questions")
	}
}

func TestResponderReset(t *testing.T) {
	svc := testService()
	var resp Responder
	resp.Configure([]Service{svc})
	if resp.State() != responderReady {
		t.Fatal("expected ready")
	}
	resp.Reset()
	if resp.State() != responderIdle {
		t.Fatalf("expected idle after reset, got %d", resp.State())
	}

	// Demux on idle responder should return ErrClosed.
	var buf [512]byte
	var msg dns.Message
	msg.AddQuestions([]dns.Question{{
		Name:  mustNewName("_http._tcp.local"),
		Type:  dns.TypePTR,
		Class: dns.ClassINET,
	}})
	data, _ := msg.AppendTo(buf[:0], 0, 0)
	err := resp.Demux(data, 0)
	if err == nil {
		t.Error("expected error on idle responder demux")
	}
}
