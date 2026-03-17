package mdns

import (
	"encoding/binary"
	"net"
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
		Addr: []byte{192, 168, 1, 50},
		Port: 80,
	}
}

func newQuerier(t *testing.T, questions []dns.Question, maxAnswers uint16) *Client {
	t.Helper()
	var c Client
	err := c.Configure(ClientConfig{LocalPort: Port})
	if err != nil {
		t.Fatal(err)
	}
	err = c.StartResolve(ResolveConfig{
		Questions:          questions,
		MaxResponseAnswers: maxAnswers,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &c
}

func newResponder(t *testing.T, services []Service) *Client {
	t.Helper()
	var c Client
	err := c.Configure(ClientConfig{
		LocalPort: Port,
		Services:  services,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &c
}

// queryRespond performs the full query->demux->encapsulate->demux cycle
// between a querier and responder, returning the response length.
func queryRespond(t *testing.T, querier, responder *Client, buf []byte) int {
	t.Helper()
	n, err := querier.Encapsulate(buf, -1, 0)
	if err != nil || n == 0 {
		t.Fatal("querier encapsulate:", err, n)
	}
	if err = responder.Demux(buf[:n], 0); err != nil {
		t.Fatal("responder demux:", err)
	}
	n, err = responder.Encapsulate(buf, -1, 0)
	if err != nil {
		t.Fatal("responder encapsulate:", err)
	}
	if n > 0 {
		if err = querier.Demux(buf[:n], 0); err != nil {
			t.Fatal("querier demux:", err)
		}
	}
	return n
}

func TestClientQueryPTR(t *testing.T) {
	svc := testService()
	responder := newResponder(t, []Service{svc})
	querier := newQuerier(t, []dns.Question{{
		Name:  mustNewName("_http._tcp.local"),
		Type:  dns.TypePTR,
		Class: dns.ClassINET,
	}}, 8)

	var buf [1024]byte

	// Querier encapsulates query.
	n, err := querier.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatal("querier encapsulate:", err, n)
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

	// Responder demuxes and encapsulates response.
	if err = responder.Demux(buf[:n], 0); err != nil {
		t.Fatal("responder demux:", err)
	}
	n, err = responder.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatal("responder encapsulate:", err, n)
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

	// Querier demuxes response and reads answers.
	if err = querier.Demux(buf[:n], 0); err != nil {
		t.Fatal("querier demux:", err)
	}
	var answers [8]dns.Resource
	nans, done, err := querier.AnswersCopyTo(answers[:])
	if err != nil {
		t.Fatal(err)
	} else if !done {
		t.Fatal("expected done")
	} else if nans == 0 {
		t.Fatal("querier got 0 answers")
	}

	// The PTR answer data should contain the instance name in wire format.
	ptrData := answers[0].RawData()
	if len(ptrData) == 0 {
		t.Fatal("PTR answer has no data")
	}
	var ptrName dns.Name
	_, err = ptrName.Decode(ptrData, 0)
	if err != nil {
		t.Fatal("decode PTR name:", err)
	}
	if ptrName.String() != svc.Name.String() {
		t.Errorf("PTR target=%q, want %q", ptrName.String(), svc.Name.String())
	}
}

func TestClientQuerySRV(t *testing.T) {
	svc := testService()
	responder := newResponder(t, []Service{svc})
	querier := newQuerier(t, []dns.Question{{
		Name:  mustNewName("My Web._http._tcp.local"),
		Type:  dns.TypeSRV,
		Class: dns.ClassINET,
	}}, 8)

	var buf [1024]byte
	queryRespond(t, querier, responder, buf[:])

	var answers [8]dns.Resource
	nans, done, err := querier.AnswersCopyTo(answers[:])
	if err != nil || !done {
		t.Fatal("expected done without error:", err)
	}
	// SRV query should return SRV + A record.
	if nans < 2 {
		t.Fatalf("expected at least 2 answers (SRV+A), got %d", nans)
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
	if [4]byte(aData) != [4]byte(svc.Addr) {
		t.Errorf("A record addr=%v, want %v", aData, svc.Addr)
	}
}

func TestClientQueryARecord(t *testing.T) {
	svc := testService()
	responder := newResponder(t, []Service{svc})
	querier := newQuerier(t, []dns.Question{{
		Name:  mustNewName("mydevice.local"),
		Type:  dns.TypeA,
		Class: dns.ClassINET,
	}}, 4)

	var buf [1024]byte
	queryRespond(t, querier, responder, buf[:])

	var answers [4]dns.Resource
	nans, done, err := querier.AnswersCopyTo(answers[:])
	if err != nil || !done {
		t.Fatal("expected done without error:", err)
	}
	if nans != 1 {
		t.Fatalf("expected 1 answer, got %d", nans)
	}
	aData := answers[0].RawData()
	if [4]byte(aData) != [4]byte(svc.Addr) {
		t.Errorf("A record addr=%v, want %v", aData, svc.Addr)
	}
}

// TODO: TestClientAnnounce — test unsolicited announcement of all registered services.
// func TestClientAnnounce(t *testing.T) { ... }

// TODO: TestClientProbeFinish — test probing sequence for name uniqueness (RFC 6762 §8.1).
// func TestClientProbeFinish(t *testing.T) { ... }

func TestClientIgnoresQueriesWithoutServices(t *testing.T) {
	// A querier-only client should ignore incoming queries.
	querier := newQuerier(t, []dns.Question{{
		Name:  mustNewName("_http._tcp.local"),
		Type:  dns.TypePTR,
		Class: dns.ClassINET,
	}}, 4)

	// Encapsulate query, then feed it back — should be ignored (not a response).
	var buf [512]byte
	n, _ := querier.Encapsulate(buf[:], -1, 0)
	err := querier.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal("demux query:", err)
	}
	// No response should be pending.
	n, _ = querier.Encapsulate(buf[:], -1, 0)
	if n != 0 {
		t.Error("querier without services should not respond to queries")
	}
}

func TestClientResponderIgnoresResponses(t *testing.T) {
	svc := testService()
	responder := newResponder(t, []Service{svc})

	// Build a response packet (QR=1).
	var msg dns.Message
	var buf [512]byte
	const responseFlags = dns.HeaderFlags(1 << 15)
	data, err := msg.AppendTo(buf[:0], 0, responseFlags)
	if err != nil {
		t.Fatal(err)
	}

	// Feed a response to the responder — should be ignored.
	err = responder.Demux(data, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Nothing should be pending.
	n, _ := responder.Encapsulate(buf[:], -1, 0)
	if n != 0 {
		t.Error("responder should not respond to responses")
	}
}

func TestClientUnmatchedQuery(t *testing.T) {
	svc := testService()
	responder := newResponder(t, []Service{svc})

	// Query for a name the responder doesn't know.
	querier := newQuerier(t, []dns.Question{{
		Name:  mustNewName("_ftp._tcp.local"),
		Type:  dns.TypePTR,
		Class: dns.ClassINET,
	}}, 4)

	var buf [1024]byte
	n, _ := querier.Encapsulate(buf[:], -1, 0)
	responder.Demux(buf[:n], 0)

	// Responder should have nothing pending.
	n, _ = responder.Encapsulate(buf[:], -1, 0)
	if n != 0 {
		t.Error("responder should not respond to unmatched query")
	}
}

func TestClientMultipleResponders(t *testing.T) {
	// Two responder clients advertising different instances of the same service type.
	svc1 := Service{
		Name: mustNewName("Device A._http._tcp.local"),
		Host: mustNewName("device-a.local"),
		Addr: []byte{192, 168, 1, 10},
		Port: 80,
	}
	svc2 := Service{
		Name: mustNewName("Device B._http._tcp.local"),
		Host: mustNewName("device-b.local"),
		Addr: []byte{192, 168, 1, 11},
		Port: 8080,
	}

	responder1 := newResponder(t, []Service{svc1})
	responder2 := newResponder(t, []Service{svc2})
	querier := newQuerier(t, []dns.Question{{
		Name:  mustNewName("_http._tcp.local"),
		Type:  dns.TypePTR,
		Class: dns.ClassINET,
	}}, 8)

	var buf [1024]byte

	// Querier sends query.
	n, _ := querier.Encapsulate(buf[:], -1, 0)
	query := make([]byte, n)
	copy(query, buf[:n])

	// Both responders process the query.
	responder1.Demux(query, 0)
	responder2.Demux(query, 0)

	// Querier receives response from responder 1.
	n, _ = responder1.Encapsulate(buf[:], -1, 0)
	querier.Demux(buf[:n], 0)

	var answers [8]dns.Resource
	nans, _, err := querier.AnswersCopyTo(answers[:])
	if err != nil {
		t.Fatal(err)
	}
	if nans < 1 {
		t.Fatalf("expected at least 1 answer from first responder, got %d", nans)
	}

	// Start a new resolve to receive from responder 2.
	querier.StartResolve(ResolveConfig{
		Questions: []dns.Question{{
			Name:  mustNewName("_http._tcp.local"),
			Type:  dns.TypePTR,
			Class: dns.ClassINET,
		}},
		MaxResponseAnswers: 8,
	})
	// Re-send query for second responder.
	n, _ = querier.Encapsulate(buf[:], -1, 0)

	n, _ = responder2.Encapsulate(buf[:], -1, 0)
	querier.Demux(buf[:n], 0)

	nans, _, err = querier.AnswersCopyTo(answers[:])
	if err != nil {
		t.Fatal(err)
	}
	if nans < 1 {
		t.Fatalf("expected at least 1 answer from second responder, got %d", nans)
	}
}

func TestClientResponderSendsOnce(t *testing.T) {
	svc := testService()
	responder := newResponder(t, []Service{svc})
	querier := newQuerier(t, []dns.Question{{
		Name:  mustNewName("_http._tcp.local"),
		Type:  dns.TypePTR,
		Class: dns.ClassINET,
	}}, 8)

	var buf [1024]byte

	// Querier sends query, responder processes it.
	n, err := querier.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatal("querier encapsulate:", err, n)
	}
	if err = responder.Demux(buf[:n], 0); err != nil {
		t.Fatal("responder demux:", err)
	}

	// First Encapsulate should produce a response.
	n, err = responder.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatal("responder first encapsulate:", err, n)
	}

	// Subsequent Encapsulate calls without new queries must produce nothing.
	const maxSpurious = 5
	for i := range maxSpurious {
		n, err = responder.Encapsulate(buf[:], -1, 0)
		if err != nil {
			t.Fatal("responder encapsulate:", err)
		}
		if n != 0 {
			t.Fatalf("responder sent spurious response on call %d (got %d bytes); expected silence after first response", i+1, n)
		}
	}
}

func TestClientResponderHandlesQueryWithKnownAnswers(t *testing.T) {
	// RFC 6762 §7.1: mDNS queries may include known-answer records.
	// The responder must not return an error when decoding such queries.
	svc := testService()
	responder := newResponder(t, []Service{svc})

	// Build an mDNS query with a known-answer record (QDCount=1, ANCount=1).
	ptrName := mustNewName("Other Device._http._tcp.local")
	ptrData, perr := ptrName.AppendTo(nil)
	if perr != nil {
		t.Fatal("encode PTR name:", perr)
	}
	var msg dns.Message
	msg.Questions = []dns.Question{{
		Name:  mustNewName("_http._tcp.local"),
		Type:  dns.TypePTR,
		Class: dns.ClassINET,
	}}
	msg.Answers = []dns.Resource{
		dns.NewResource(mustNewName("_http._tcp.local"), dns.TypePTR, dns.ClassINET, 120, ptrData),
	}
	var buf [1024]byte
	data, err := msg.AppendTo(buf[:0], 0, 0) // txid=0, flags=0 (query).
	if err != nil {
		t.Fatal("build query with known-answer:", err)
	}

	// Demux must not return an error.
	err = responder.Demux(data, 0)
	if err != nil {
		t.Fatalf("responder demux returned error on query with known-answers: %v", err)
	}

	// Responder should still generate a response for its service.
	n, err := responder.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal("responder encapsulate:", err)
	}
	if n == 0 {
		t.Fatal("responder should respond to query even when known-answers are present")
	}
}

func TestClientAbort(t *testing.T) {
	svc := testService()
	responder := newResponder(t, []Service{svc})

	responder.Abort()

	// Demux on aborted client should return ErrClosed.
	var buf [512]byte
	var msg dns.Message
	msg.AddQuestions([]dns.Question{{
		Name:  mustNewName("_http._tcp.local"),
		Type:  dns.TypePTR,
		Class: dns.ClassINET,
	}})
	data, _ := msg.AppendTo(buf[:0], 0, 0)
	err := responder.Demux(data, 0)
	if err != net.ErrClosed {
		t.Errorf("expected net.ErrClosed, got %v", err)
	}

	// Encapsulate on aborted client should return ErrClosed.
	_, err = responder.Encapsulate(buf[:], -1, 0)
	if err != net.ErrClosed {
		t.Errorf("expected net.ErrClosed, got %v", err)
	}
}
