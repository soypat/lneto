package dns

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
)

// clientTestResponseFlags are QR=1 (response), RD=1, RA=1.
const clientTestResponseFlags = HeaderFlags(1<<15 | 1<<8 | 1<<7)

func newTestClient(t testing.TB, maxQueries int) *Client {
	t.Helper()
	var client Client
	err := client.Configure(ClientConfig{LocalPort: 54321, MaxQueries: maxQueries})
	if err != nil {
		t.Fatal(err)
	}
	return &client
}

func startTestResolve(t testing.TB, client *Client, txid uint16, host string, maxAnswers uint16) {
	t.Helper()
	err := client.StartResolve(txid, ResolveConfig{
		Questions:          []Question{{Name: MustNewName(host), Type: TypeA, Class: ClassINET}},
		EnableRecursion:    true,
		MaxResponseAnswers: maxAnswers,
	})
	if err != nil {
		t.Fatal("start resolve:", err)
	}
}

// encapsulateTestQuery sends one pending query and returns its txid.
func encapsulateTestQuery(t testing.TB, client *Client) uint16 {
	t.Helper()
	var buf [512]byte
	n, err := client.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal("encapsulate:", err)
	} else if n == 0 {
		t.Fatal("no query encapsulated")
	}
	frm, err := NewFrame(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return frm.TxID()
}

func testAnswers(host string, firstOctet byte, n int) ([]Resource, []netip.Addr) {
	name := MustNewName(host)
	rsc := make([]Resource, n)
	addrs := make([]netip.Addr, n)
	for i := range rsc {
		ip := [4]byte{firstOctet, 0, 2, byte(i + 1)}
		rsc[i] = NewResource(name, TypeA, ClassINET, 300, ip[:])
		addrs[i] = netip.AddrFrom4(ip)
	}
	return rsc, addrs
}

func testResponse(t testing.TB, txid uint16, flags HeaderFlags, host string, qtype Type, answers []Resource) []byte {
	t.Helper()
	msg := Message{
		Questions: []Question{{Name: MustNewName(host), Type: qtype, Class: ClassINET}},
		Answers:   answers,
	}
	wire, err := msg.AppendTo(nil, txid, flags)
	if err != nil {
		t.Fatal("encode response:", err)
	}
	return wire
}

// checkTestAnswers checks the response to txid holds exactly want for host.
func checkTestAnswers(t testing.TB, client *Client, txid uint16, host string, want []netip.Addr) {
	t.Helper()
	completed, ok := client.ResolvePeek(txid)
	if !ok || !completed {
		t.Fatalf("txid %#x: completed=%v ok=%v", txid, completed, ok)
	}
	resp, flags, ok := client.Response(txid)
	if !ok {
		t.Fatalf("txid %#x: no response", txid)
	} else if flags != clientTestResponseFlags {
		t.Fatalf("txid %#x: flags %v", txid, flags)
	}
	dst := make([]netip.Addr, len(want)+1)
	n, err := resp.WriteAnswers(dst, MustNewName(host))
	if err != nil || int(n) != len(want) {
		t.Fatalf("txid %#x: n=%d err=%v, want %d", txid, n, err, len(want))
	}
	for i := range want {
		if dst[i] != want[i] {
			t.Errorf("txid %#x: addr %d=%v, want %v", txid, i, dst[i], want[i])
		}
	}
}

func TestClient_ConcurrentQueries(t *testing.T) {
	const hostA, hostB = "a.example.com", "b.example.org"
	const txidA, txidB = 0x1111, 0x2222
	client := newTestClient(t, 2)
	startTestResolve(t, client, txidA, hostA, 4)
	startTestResolve(t, client, txidB, hostB, 4)
	if client.NumQueries() != 2 {
		t.Fatalf("NumQueries=%d, want 2", client.NumQueries())
	}
	sent := [2]uint16{encapsulateTestQuery(t, client), encapsulateTestQuery(t, client)}
	if sent != [2]uint16{txidA, txidB} && sent != [2]uint16{txidB, txidA} {
		t.Fatalf("sent txids %#x, want both of %#x and %#x", sent, txidA, txidB)
	}
	var buf [512]byte
	if n, err := client.Encapsulate(buf[:], -1, 0); n != 0 || err != nil {
		t.Fatalf("third encapsulate n=%d err=%v, want 0 and nil", n, err)
	}
	rscA, wantA := testAnswers(hostA, 10, 2)
	rscB, wantB := testAnswers(hostB, 20, 3)
	// Responses arrive in reverse order.
	if err := client.Demux(testResponse(t, txidB, clientTestResponseFlags, hostB, TypeA, rscB), 0); err != nil {
		t.Fatal(err)
	}
	if completed, ok := client.ResolvePeek(txidA); completed || !ok {
		t.Fatalf("A completed=%v ok=%v before its response", completed, ok)
	}
	if err := client.Demux(testResponse(t, txidA, clientTestResponseFlags, hostA, TypeA, rscA), 0); err != nil {
		t.Fatal(err)
	}
	checkTestAnswers(t, client, txidA, hostA, wantA)
	checkTestAnswers(t, client, txidB, hostB, wantB)
}

func TestClient_Exhausted(t *testing.T) {
	client := newTestClient(t, 2)
	if client.QueryCapacity() != 2 {
		t.Fatalf("QueryCapacity=%d, want 2", client.QueryCapacity())
	}
	startTestResolve(t, client, 1, "a.com", 1)
	startTestResolve(t, client, 2, "b.com", 1)
	cfg := ResolveConfig{Questions: []Question{{Name: MustNewName("c.com"), Type: TypeA, Class: ClassINET}}}
	if err := client.StartResolve(3, cfg); !errors.Is(err, lneto.ErrExhausted) {
		t.Fatalf("err=%v, want ErrExhausted", err)
	}
	if completed, ok := client.ResolvePop(1); completed || !ok {
		t.Fatalf("pop pending: completed=%v ok=%v", completed, ok)
	}
	if err := client.StartResolve(3, cfg); err != nil {
		t.Fatal("start after pop:", err)
	}
	// Remaining queries are intact after the pop.
	if _, ok := client.ResolvePeek(2); !ok {
		t.Fatal("query 2 lost after popping query 1")
	}
}

func TestClient_StartResolveInvalid(t *testing.T) {
	client := newTestClient(t, 2)
	startTestResolve(t, client, 7, "a.com", 1)
	cfg := ResolveConfig{Questions: []Question{{Name: MustNewName("b.com"), Type: TypeA, Class: ClassINET}}}
	if err := client.StartResolve(7, cfg); err == nil {
		t.Fatal("duplicate active txid accepted")
	}
	if err := client.StartResolve(8, ResolveConfig{}); err == nil {
		t.Fatal("zero questions accepted")
	}
	if err := client.StartResolve(8, ResolveConfig{Questions: []Question{{Type: TypeA, Class: ClassINET}}}); err == nil {
		t.Fatal("empty question name accepted")
	}
	// Failed starts do not hold a slot.
	if client.NumQueries() != 1 {
		t.Fatalf("NumQueries=%d after failed starts, want 1", client.NumQueries())
	}
	if err := client.StartResolve(8, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestClient_RejectsMismatchedResponse(t *testing.T) {
	const host = "example.com"
	const txid = 0x1234
	rsc, want := testAnswers(host, 30, 1)
	good := testResponse(t, txid, clientTestResponseFlags, host, TypeA, rsc)
	tests := []struct {
		name string
		resp []byte
	}{
		{name: "wrong txid", resp: testResponse(t, txid+1, clientTestResponseFlags, host, TypeA, rsc)},
		{name: "not a response", resp: testResponse(t, txid, NewClientHeaderFlags(OpCodeQuery, true), host, TypeA, rsc)},
		{name: "other name", resp: testResponse(t, txid, clientTestResponseFlags, "example.org", TypeA, rsc)},
		{name: "other type", resp: testResponse(t, txid, clientTestResponseFlags, host, TypeAAAA, rsc)},
		{name: "longer name", resp: testResponse(t, txid, clientTestResponseFlags, "www.example.com", TypeA, rsc)},
		{name: "header only", resp: good[:SizeHeader]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestClient(t, 1)
			startTestResolve(t, client, txid, host, 1)
			encapsulateTestQuery(t, client)
			client.Demux(tt.resp, 0)
			if completed, ok := client.ResolvePeek(txid); completed || !ok {
				t.Fatalf("completed=%v ok=%v after mismatched response", completed, ok)
			}
			if _, _, ok := client.Response(txid); ok {
				t.Fatal("response available after mismatched response")
			}
			if err := client.Demux(good, 0); err != nil {
				t.Fatal(err)
			}
			checkTestAnswers(t, client, txid, host, want)
		})
	}
	t.Run("before query sent", func(t *testing.T) {
		client := newTestClient(t, 1)
		startTestResolve(t, client, txid, host, 1)
		client.Demux(good, 0)
		if completed, _ := client.ResolvePeek(txid); completed {
			t.Fatal("completed by response to unsent query")
		}
	})
}

func TestClient_CaseRandomizedQuestion(t *testing.T) {
	const txid = 0x0420
	client := newTestClient(t, 1)
	startTestResolve(t, client, txid, "www.example.com", 1)
	encapsulateTestQuery(t, client)
	rsc, want := testAnswers("www.example.com", 40, 1)
	// Server echoes the question with DNS 0x20 randomized case.
	resp := testResponse(t, txid, clientTestResponseFlags, "wWw.ExAmPlE.CoM", TypeA, rsc)
	if err := client.Demux(resp, 0); err != nil {
		t.Fatal(err)
	}
	checkTestAnswers(t, client, txid, "www.example.com", want)
}

func TestClient_PopSemantics(t *testing.T) {
	const host = "example.com"
	const txid = 0x5555
	client := newTestClient(t, 1)
	if completed, ok := client.ResolvePeek(txid); completed || ok {
		t.Fatalf("unknown txid: completed=%v ok=%v", completed, ok)
	}
	startTestResolve(t, client, txid, host, 1)
	encapsulateTestQuery(t, client)
	rsc, _ := testAnswers(host, 50, 1)
	if err := client.Demux(testResponse(t, txid, clientTestResponseFlags, host, TypeA, rsc), 0); err != nil {
		t.Fatal(err)
	}
	if completed, ok := client.ResolvePop(txid); !completed || !ok {
		t.Fatalf("pop: completed=%v ok=%v", completed, ok)
	}
	if completed, ok := client.ResolvePeek(txid); completed || ok {
		t.Fatalf("peek after pop: completed=%v ok=%v", completed, ok)
	}
	if completed, ok := client.ResolvePop(txid); completed || ok {
		t.Fatalf("second pop: completed=%v ok=%v", completed, ok)
	}
	if _, _, ok := client.Response(txid); ok {
		t.Fatal("response after pop")
	}
	if client.NumQueries() != 0 {
		t.Fatalf("NumQueries=%d after pop, want 0", client.NumQueries())
	}
}

func TestClient_ManyAnswers(t *testing.T) {
	const host = "example.com"
	const txid = 0x0808
	client := newTestClient(t, 1)
	startTestResolve(t, client, txid, host, 8)
	encapsulateTestQuery(t, client)
	rsc, want := testAnswers(host, 60, 8)
	if err := client.Demux(testResponse(t, txid, clientTestResponseFlags, host, TypeA, rsc), 0); err != nil {
		t.Fatal(err)
	}
	checkTestAnswers(t, client, txid, host, want)
}

func TestClient_ZeroAllocReuse(t *testing.T) {
	const host = "example.com"
	const txid = 0x3333
	client := newTestClient(t, 2)
	name := MustNewName(host)
	cfg := ResolveConfig{
		Questions:          []Question{{Name: name, Type: TypeA, Class: ClassINET}},
		EnableRecursion:    true,
		MaxResponseAnswers: 4,
	}
	rsc, _ := testAnswers(host, 70, 4)
	resp := testResponse(t, txid, clientTestResponseFlags, host, TypeA, rsc)
	var buf [512]byte
	var dst [4]netip.Addr
	// Keep another query active so popping exercises removal of a non-last slot.
	if err := client.StartResolve(txid+1, cfg); err != nil {
		t.Fatal(err)
	}
	cycle := func() {
		if err := client.StartResolve(txid, cfg); err != nil {
			panic(err)
		}
		for {
			n, err := client.Encapsulate(buf[:], -1, 0)
			if err != nil {
				panic(err)
			} else if n == 0 {
				break
			}
		}
		if err := client.Demux(resp, 0); err != nil {
			panic(err)
		}
		msg, _, ok := client.Response(txid)
		if !ok {
			panic("no response")
		}
		if n, err := msg.WriteAnswers(dst[:], name); err != nil || n != 4 {
			panic(err)
		}
		if completed, ok := client.ResolvePop(txid); !completed || !ok {
			panic("pop failed")
		}
	}
	cycle() // Warm up slot buffers.
	if allocs := testing.AllocsPerRun(100, cycle); allocs != 0 {
		t.Fatalf("got %v allocations per query cycle, want 0", allocs)
	}
}

func TestClient_SetLocalPort(t *testing.T) {
	client := newTestClient(t, 1)
	connID := *client.ConnectionID()
	startTestResolve(t, client, 1, "a.com", 1)
	if err := client.SetLocalPort(1000); !errors.Is(err, lneto.ErrBadState) {
		t.Fatalf("SetLocalPort with active query: err=%v, want ErrBadState", err)
	}
	client.ResolvePop(1)
	if err := client.SetLocalPort(1000); err != nil {
		t.Fatal(err)
	}
	if client.LocalPort() != 1000 {
		t.Fatalf("LocalPort=%d, want 1000", client.LocalPort())
	}
	if *client.ConnectionID() == connID {
		t.Fatal("connection ID unchanged after port change")
	}
}

func TestClient_AbortAndIdle(t *testing.T) {
	client := newTestClient(t, 2)
	var buf [512]byte
	if n, err := client.Encapsulate(buf[:], -1, 0); n != 0 || err != nil {
		t.Fatalf("idle encapsulate n=%d err=%v, want 0 and nil", n, err)
	}
	startTestResolve(t, client, 1, "a.com", 1)
	startTestResolve(t, client, 2, "b.com", 1)
	connID := *client.ConnectionID()
	client.Abort()
	if *client.ConnectionID() == connID {
		t.Fatal("connection ID unchanged after Abort")
	}
	if client.NumQueries() != 0 {
		t.Fatalf("NumQueries=%d after Abort", client.NumQueries())
	}
	if _, ok := client.ResolvePeek(1); ok {
		t.Fatal("query survived Abort")
	}
}

func TestClient_ReceivesDNSResponse(t *testing.T) {
	const hostname = "example.com"
	const txid = uint16(12345)
	const clientPort = uint16(54321)
	const maxAnswers = 4
	allIPs := [5][4]byte{
		{192, 0, 2, 1},
		{192, 0, 2, 2},
		{192, 0, 2, 3},
		{192, 0, 2, 4},
		{192, 0, 2, 5},
	}
	tests := []struct {
		name        string
		responseIPs [][4]byte
		wantAnswers int // Addresses returned by ResponseAnswerLookup and copied by ResponseCopyTo.
	}{
		{name: "single_answer", responseIPs: allIPs[:1], wantAnswers: 1},
		{name: "multiple_answers", responseIPs: allIPs[:4], wantAnswers: 4},
		{name: "answer_limit", responseIPs: allIPs[:5], wantAnswers: maxAnswers},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := MustNewName(hostname)
			responseMsg := Message{
				Questions: []Question{{
					Name:  name,
					Type:  TypeA,
					Class: ClassINET,
				}},
				Answers: make([]Resource, len(tt.responseIPs)),
			}
			for i := range tt.responseIPs {
				responseMsg.Answers[i] = NewResource(name, TypeA, ClassINET, 300, tt.responseIPs[i][:])
			}

			// Response flags: QR=1 (response), RD=1, RA=1.
			responseFlags := HeaderFlags(1<<15 | 1<<8 | 1<<7)
			var responseBuf [512]byte
			dnsPayload, err := responseMsg.AppendTo(responseBuf[:0], txid, responseFlags)
			if err != nil {
				t.Fatal("failed to build DNS response:", err)
			}

			var client Client
			err = client.Configure(ClientConfig{LocalPort: clientPort, MaxQueries: 1})
			if err != nil {
				t.Fatal(err)
			}
			err = client.StartResolve(txid, ResolveConfig{
				Questions: []Question{{
					Name:  name,
					Type:  TypeA,
					Class: ClassINET,
				}},
				EnableRecursion:    true,
				MaxResponseAnswers: maxAnswers,
			})
			if err != nil {
				t.Fatal("failed to start DNS resolve:", err)
			}

			// Encapsulate the query to move the client into the outstanding state.
			var queryBuf [512]byte
			_, err = client.Encapsulate(queryBuf[:], 0, 0)
			if err != nil {
				t.Fatal("failed to encapsulate DNS query:", err)
			}
			if err := client.Demux(dnsPayload, 0); err != nil {
				t.Fatal("failed to demux DNS response:", err)
			}

			resp, _, ok := client.Response(txid)
			if !ok {
				t.Fatal("no response")
			}
			var addrs [maxAnswers]netip.Addr
			answers, err := resp.WriteAnswers(addrs[:], name)
			if err != nil {
				t.Fatal("failed to look up DNS response answers:", err)
			}
			if int(answers) != tt.wantAnswers {
				t.Fatalf("expected %d answers, got %d", tt.wantAnswers, answers)
			}
			for i := 0; i < tt.wantAnswers; i++ {
				addr := addrs[i]
				if !addr.Is4() {
					t.Errorf("answer %d: expected IPv4 address, got %v", i, addr)
					continue
				}
				if addr.As4() != tt.responseIPs[i] {
					t.Errorf("answer %d: expected IP %v, got %v", i, tt.responseIPs[i], addr)
				}
			}

			if len(resp.Answers) != tt.wantAnswers {
				t.Fatalf("expected %d decoded answers, got %d", tt.wantAnswers, len(resp.Answers))
			}
		})
	}
}

func testCNAME(t testing.TB, owner, target string) Resource {
	t.Helper()
	wire, err := (&Question{Name: MustNewName(target)}).Name.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	return NewResource(MustNewName(owner), TypeCNAME, ClassINET, 300, wire)
}

func TestClient_ResolveCanonical(t *testing.T) {
	const host, alias = "a.example.com", "edge.cdn.example.net"
	const txid, hopTxid = 0x1000, 0x2000

	var edns Resource
	setEDNS0(&edns, 1232, nil)
	client := newTestClient(t, 1)
	err := client.StartResolve(txid, ResolveConfig{
		Questions:          []Question{{Name: MustNewName(host), Type: TypeA, Class: ClassINET}},
		Additional:         []Resource{edns},
		EnableRecursion:    true,
		MaxResponseAnswers: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	encapsulateTestQuery(t, client)
	cnameOnly := testResponse(t, txid, clientTestResponseFlags, host, TypeA, []Resource{testCNAME(t, host, alias)})
	if err = client.Demux(cnameOnly, 0); err != nil {
		t.Fatal(err)
	}
	if err = client.ResolveCanonical(txid, hopTxid); err != nil {
		t.Fatal("hop:", err)
	}
	if _, ok := client.ResolvePeek(txid); ok {
		t.Fatal("old txid still active after hop")
	}
	if completed, ok := client.ResolvePeek(hopTxid); completed || !ok {
		t.Fatalf("hop query: completed=%v ok=%v, want pending", completed, ok)
	}
	if client.NumQueries() != 1 {
		t.Fatalf("NumQueries=%d after hop, want 1", client.NumQueries())
	}
	// The hop query asks for the alias and keeps the EDNS0 record.
	var buf [512]byte
	n, err := client.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatalf("encapsulate hop: n=%d err=%v", n, err)
	}
	var sent Message
	sent.LimitResourceDecoding(1, 0, 0, 1)
	if _, incomplete, err := sent.Decode(buf[:n]); err != nil || incomplete {
		t.Fatalf("decode hop query: incomplete=%v err=%v", incomplete, err)
	}
	frm, _ := NewFrame(buf[:n])
	if frm.TxID() != hopTxid {
		t.Errorf("hop txid=%#x, want %#x", frm.TxID(), hopTxid)
	}
	if !sent.Questions[0].Name.EqualString(alias) || sent.Questions[0].Type != TypeA {
		t.Errorf("hop question %s, want %s A", sent.Questions[0].String(), alias)
	}
	if len(sent.Additionals) != 1 || sent.Additionals[0].Header().Type != TypeOPT {
		t.Errorf("hop query lost EDNS0 record: %v", sent.Additionals)
	}
	rsc, want := testAnswers(alias, 80, 1)
	if err = client.Demux(testResponse(t, hopTxid, clientTestResponseFlags, alias, TypeA, rsc), 0); err != nil {
		t.Fatal(err)
	}
	checkTestAnswers(t, client, hopTxid, alias, want)
}

func TestClient_ResolveCanonicalErrors(t *testing.T) {
	const host = "a.example.com"
	const txid = 0x1000
	rsc, _ := testAnswers(host, 90, 1)
	cname := []Resource{testCNAME(t, host, "b.example.net")}
	tests := []struct {
		name    string
		resp    []byte // Nil leaves the query pending.
		newTxid uint16
	}{
		{name: "pending", newTxid: 0x2000},
		{name: "rcode", resp: testResponse(t, txid, clientTestResponseFlags|HeaderFlags(RCodeServerFailure), host, TypeA, nil), newTxid: 0x2000},
		{name: "no CNAME", resp: testResponse(t, txid, clientTestResponseFlags, host, TypeA, rsc), newTxid: 0x2000},
		{name: "zero txid", resp: testResponse(t, txid, clientTestResponseFlags, host, TypeA, cname), newTxid: 0},
		{name: "txid in use", resp: testResponse(t, txid, clientTestResponseFlags, host, TypeA, cname), newTxid: 0x3000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestClient(t, 2)
			startTestResolve(t, client, txid, host, 4)
			startTestResolve(t, client, 0x3000, "other.example.com", 4)
			encapsulateTestQuery(t, client)
			if tt.resp != nil {
				if err := client.Demux(tt.resp, 0); err != nil {
					t.Fatal(err)
				}
			}
			completed, _ := client.ResolvePeek(txid)
			if err := client.ResolveCanonical(txid, tt.newTxid); err == nil {
				t.Fatal("hop succeeded")
			}
			// Failed hop leaves the query as it was.
			if c, ok := client.ResolvePeek(txid); !ok || c != completed {
				t.Fatalf("query changed by failed hop: completed=%v ok=%v", c, ok)
			}
		})
	}
	t.Run("unknown txid", func(t *testing.T) {
		client := newTestClient(t, 1)
		if err := client.ResolveCanonical(1, 2); err == nil {
			t.Fatal("hop of unknown txid succeeded")
		}
	})
}

func TestClient_ResolveCanonicalZeroAlloc(t *testing.T) {
	const host, alias = "a.example.com", "edge.cdn.example.net"
	const txid, hopTxid = 0x1000, 0x2000
	var edns Resource
	setEDNS0(&edns, 1232, nil)
	client := newTestClient(t, 1)
	cfg := ResolveConfig{
		Questions:          []Question{{Name: MustNewName(host), Type: TypeA, Class: ClassINET}},
		Additional:         []Resource{edns},
		EnableRecursion:    true,
		MaxResponseAnswers: 4,
	}
	cnameOnly := testResponse(t, txid, clientTestResponseFlags, host, TypeA, []Resource{testCNAME(t, host, alias)})
	rsc, _ := testAnswers(alias, 100, 2)
	final := testResponse(t, hopTxid, clientTestResponseFlags, alias, TypeA, rsc)
	aliasName := MustNewName(alias)
	var buf [512]byte
	var dst [4]netip.Addr
	cycle := func() {
		if err := client.StartResolve(txid, cfg); err != nil {
			panic(err)
		}
		if n, err := client.Encapsulate(buf[:], -1, 0); err != nil || n == 0 {
			panic("encapsulate")
		}
		if err := client.Demux(cnameOnly, 0); err != nil {
			panic(err)
		}
		if err := client.ResolveCanonical(txid, hopTxid); err != nil {
			panic(err)
		}
		if n, err := client.Encapsulate(buf[:], -1, 0); err != nil || n == 0 {
			panic("encapsulate hop")
		}
		if err := client.Demux(final, 0); err != nil {
			panic(err)
		}
		resp, _, ok := client.Response(hopTxid)
		if !ok {
			panic("no response")
		}
		if n, err := resp.WriteAnswers(dst[:], aliasName); err != nil || n != 2 {
			panic(err)
		}
		if completed, ok := client.ResolvePop(hopTxid); !completed || !ok {
			panic("pop")
		}
	}
	cycle() // Warm up slot buffers.
	if allocs := testing.AllocsPerRun(100, cycle); allocs != 0 {
		t.Fatalf("got %v allocations per hop cycle, want 0", allocs)
	}
}

// Regression test for CNAME-following: a response for www.yahoo.co.jp
// contains a CNAME record to edge12.g.yimg.jp (with compressed labels in its
// RDATA) followed by the A record for the canonical name. The CNAME RDATA
// must not be interpreted as an IP address and the A record must be returned.
func TestClient_CNAMEResponse(t *testing.T) {
	const hostname = "www.yahoo.co.jp"
	const txid = uint16(0x1234)
	const clientPort = uint16(54321)
	response := []byte{
		// Header: txid 0x1234, QR|RD|RA, QD=1 AN=2 NS=0 AR=0.
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		// Question: www.yahoo.co.jp A IN.
		0x03, 'w', 'w', 'w', 0x05, 'y', 'a', 'h', 'o', 'o', 0x02, 'c', 'o', 0x02, 'j', 'p', 0x00,
		0x00, 0x01, 0x00, 0x01,
		// Answer 1: (ptr to question) CNAME IN ttl=842 rdlen=16
		// rdata: edge12.g.yimg.jp with "jp" as compression pointer to offset 0x19.
		0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x03, 0x4a, 0x00, 0x10,
		0x06, 'e', 'd', 'g', 'e', '1', '2', 0x01, 'g', 0x04, 'y', 'i', 'm', 'g', 0xc0, 0x19,
		// Answer 2: (ptr into CNAME rdata) A IN ttl=36 rdlen=4 182.22.23.124.
		0xc0, 0x2d, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00, 0x04, 0xb6, 0x16, 0x17, 0x7c,
	}
	name := MustNewName(hostname)
	var client Client
	err := client.Configure(ClientConfig{LocalPort: clientPort, MaxQueries: 1})
	if err != nil {
		t.Fatal(err)
	}
	err = client.StartResolve(txid, ResolveConfig{
		Questions: []Question{{
			Name:  name,
			Type:  TypeA,
			Class: ClassINET,
		}},
		EnableRecursion:    true,
		MaxResponseAnswers: 6,
	})
	if err != nil {
		t.Fatal("failed to start DNS resolve:", err)
	}
	var queryBuf [512]byte
	_, err = client.Encapsulate(queryBuf[:], 0, 0)
	if err != nil {
		t.Fatal("failed to encapsulate DNS query:", err)
	}
	if err := client.Demux(response, 0); err != nil {
		t.Fatal("failed to demux DNS response:", err)
	}
	resp, _, ok := client.Response(txid)
	if !ok {
		t.Fatal("no response")
	}
	var addrs [4]netip.Addr
	n, err := resp.WriteAnswers(addrs[:], name)
	if err != nil {
		t.Fatal("failed to look up DNS response answers:", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 answer, got %d: %v", n, addrs[:n])
	}
	if addrs[0] != (netip.AddrFrom4([4]byte{182, 22, 23, 124})) {
		t.Fatalf("expected 182.22.23.124, got %v", addrs[0])
	}
}
