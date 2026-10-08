package dns

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
)

func newTestClient(t testing.TB, maxLookups int) *Client {
	t.Helper()
	var client Client
	err := client.Configure(ClientConfig{LocalPort: 54321, MaxLookups: maxLookups})
	if err != nil {
		t.Fatal(err)
	}
	return &client
}

func startTestLookup(t testing.TB, client *Client, txid uint16, host string, maxAnswers uint16) {
	t.Helper()
	err := client.LookupStart(txid, LookupConfig{
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
	rsc := make([]Resource, n)
	addrs := make([]netip.Addr, n)
	for i := range rsc {
		ip := [4]byte{firstOctet, 0, 2, byte(i + 1)}
		rsc[i] = testA(host, ip)
		addrs[i] = netip.AddrFrom4(ip)
	}
	return rsc, addrs
}

// checkTestAnswers checks the response to txid holds exactly want for host.
func checkTestAnswers(t testing.TB, client *Client, txid uint16, host string, want []netip.Addr) {
	t.Helper()
	state, ok := client.LookupPeek(txid)
	if !ok || state.InProgress() {
		t.Fatalf("txid %#x: state=%v ok=%v", txid, state, ok)
	}
	resp, flags, ok := client.LookupResponse(txid)
	if !ok {
		t.Fatalf("txid %#x: no response", txid)
	} else if flags != testResponseFlags {
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

func TestClient_ConcurrentLookups(t *testing.T) {
	const hostA, hostB = "a.example.com", "b.example.org"
	const txidA, txidB = 0x1111, 0x2222
	client := newTestClient(t, 2)
	startTestLookup(t, client, txidA, hostA, 4)
	startTestLookup(t, client, txidB, hostB, 4)
	if client.NumLookups() != 2 {
		t.Fatalf("NumLookups=%d, want 2", client.NumLookups())
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
	if err := client.Demux(testResponse(t, txidB, testResponseFlags, hostB, TypeA, rscB), 0); err != nil {
		t.Fatal(err)
	}
	if state, ok := client.LookupPeek(txidA); !state.InProgress() || !ok {
		t.Fatalf("A state=%v ok=%v before its response", state, ok)
	}
	if err := client.Demux(testResponse(t, txidA, testResponseFlags, hostA, TypeA, rscA), 0); err != nil {
		t.Fatal(err)
	}
	checkTestAnswers(t, client, txidA, hostA, wantA)
	checkTestAnswers(t, client, txidB, hostB, wantB)
}

func TestClient_Exhausted(t *testing.T) {
	client := newTestClient(t, 2)
	if client.MaxLookups() != 2 {
		t.Fatalf("MaxLookups=%d, want 2", client.MaxLookups())
	}
	startTestLookup(t, client, 1, "a.com", 1)
	startTestLookup(t, client, 2, "b.com", 1)
	cfg := LookupConfig{Questions: []Question{{Name: MustNewName("c.com"), Type: TypeA, Class: ClassINET}}}
	if err := client.LookupStart(3, cfg); !errors.Is(err, lneto.ErrExhausted) {
		t.Fatalf("err=%v, want ErrExhausted", err)
	}
	if state, ok := client.LookupPop(1); !state.InProgress() || !ok {
		t.Fatalf("pop pending: state=%v ok=%v", state, ok)
	}
	if err := client.LookupStart(3, cfg); err != nil {
		t.Fatal("start after pop:", err)
	}
	// Remaining lookups are intact after the pop.
	if _, ok := client.LookupPeek(2); !ok {
		t.Fatal("lookup 2 lost after popping lookup 1")
	}
}

func TestClient_LookupStartInvalid(t *testing.T) {
	client := newTestClient(t, 2)
	startTestLookup(t, client, 7, "a.com", 1)
	cfg := LookupConfig{Questions: []Question{{Name: MustNewName("b.com"), Type: TypeA, Class: ClassINET}}}
	if err := client.LookupStart(7, cfg); err == nil {
		t.Fatal("duplicate active txid accepted")
	}
	if err := client.LookupStart(8, LookupConfig{}); err == nil {
		t.Fatal("zero questions accepted")
	}
	if err := client.LookupStart(8, LookupConfig{Questions: []Question{{Type: TypeA, Class: ClassINET}}}); err == nil {
		t.Fatal("empty question name accepted")
	}
	// Failed starts do not hold a slot.
	if client.NumLookups() != 1 {
		t.Fatalf("NumLookups=%d after failed starts, want 1", client.NumLookups())
	}
	if err := client.LookupStart(8, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestClient_RejectsMismatchedResponse(t *testing.T) {
	const host = "example.com"
	const txid = 0x1234
	rsc, want := testAnswers(host, 30, 1)
	good := testResponse(t, txid, testResponseFlags, host, TypeA, rsc)
	tests := []struct {
		name string
		resp []byte
	}{
		{name: "wrong txid", resp: testResponse(t, txid+1, testResponseFlags, host, TypeA, rsc)},
		{name: "not a response", resp: testResponse(t, txid, NewClientHeaderFlags(OpCodeQuery, true), host, TypeA, rsc)},
		{name: "other name", resp: testResponse(t, txid, testResponseFlags, "example.org", TypeA, rsc)},
		{name: "other type", resp: testResponse(t, txid, testResponseFlags, host, TypeAAAA, rsc)},
		{name: "longer name", resp: testResponse(t, txid, testResponseFlags, "www.example.com", TypeA, rsc)},
		{name: "header only", resp: good[:SizeHeader]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestClient(t, 1)
			startTestLookup(t, client, txid, host, 1)
			encapsulateTestQuery(t, client)
			client.Demux(tt.resp, 0)
			if state, ok := client.LookupPeek(txid); !state.InProgress() || !ok {
				t.Fatalf("state=%v ok=%v after mismatched response", state, ok)
			}
			if _, _, ok := client.LookupResponse(txid); ok {
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
		startTestLookup(t, client, txid, host, 1)
		client.Demux(good, 0)
		if state, _ := client.LookupPeek(txid); !state.InProgress() {
			t.Fatal("completed by response to unsent query")
		}
	})
}

func TestClient_CaseRandomizedQuestion(t *testing.T) {
	const txid = 0x0420
	client := newTestClient(t, 1)
	startTestLookup(t, client, txid, "www.example.com", 1)
	encapsulateTestQuery(t, client)
	rsc, want := testAnswers("www.example.com", 40, 1)
	// Server echoes the question with DNS 0x20 randomized case.
	resp := testResponse(t, txid, testResponseFlags, "wWw.ExAmPlE.CoM", TypeA, rsc)
	if err := client.Demux(resp, 0); err != nil {
		t.Fatal(err)
	}
	checkTestAnswers(t, client, txid, "www.example.com", want)
}

func TestClient_PopSemantics(t *testing.T) {
	const host = "example.com"
	const txid = 0x5555
	client := newTestClient(t, 1)
	if state, ok := client.LookupPeek(txid); state.InProgress() || ok {
		t.Fatalf("unknown txid: state=%v ok=%v", state, ok)
	}
	startTestLookup(t, client, txid, host, 1)
	encapsulateTestQuery(t, client)
	rsc, _ := testAnswers(host, 50, 1)
	if err := client.Demux(testResponse(t, txid, testResponseFlags, host, TypeA, rsc), 0); err != nil {
		t.Fatal(err)
	}
	if state, ok := client.LookupPop(txid); !state.InProgress() || !ok {
		t.Fatalf("pop: state=%v ok=%v", state, ok)
	}
	if state, ok := client.LookupPeek(txid); state.InProgress() || ok {
		t.Fatalf("peek after pop: state=%v ok=%v", state, ok)
	}
	if state, ok := client.LookupPop(txid); state.InProgress() || ok {
		t.Fatalf("second pop: state=%v ok=%v", state, ok)
	}
	if _, _, ok := client.LookupResponse(txid); ok {
		t.Fatal("response after pop")
	}
	if client.NumLookups() != 0 {
		t.Fatalf("NumLookups=%d after pop, want 0", client.NumLookups())
	}
}

func TestClient_ResponseStableAcrossPop(t *testing.T) {
	const hostA, hostB, hostC = "a.example.com", "b.example.org", "c.example.net"
	const txidA, txidB, txidC = 0x1111, 0x2222, 0x3333
	client := newTestClient(t, 2)
	startTestLookup(t, client, txidA, hostA, 4)
	startTestLookup(t, client, txidB, hostB, 4)
	encapsulateTestQuery(t, client)
	encapsulateTestQuery(t, client)
	rscA, _ := testAnswers(hostA, 10, 2)
	rscB, wantB := testAnswers(hostB, 20, 3)
	if err := client.Demux(testResponse(t, txidA, testResponseFlags, hostA, TypeA, rscA), 0); err != nil {
		t.Fatal(err)
	}
	if err := client.Demux(testResponse(t, txidB, testResponseFlags, hostB, TypeA, rscB), 0); err != nil {
		t.Fatal(err)
	}
	respB, _, ok := client.LookupResponse(txidB)
	if !ok {
		t.Fatal("no response for B")
	}
	checkResp := func(when string) {
		t.Helper()
		got, _, ok := client.LookupResponse(txidB)
		if !ok || got != respB {
			t.Fatalf("%s: B response pointer changed", when)
		}
		dst := make([]netip.Addr, len(wantB)+1)
		n, err := respB.WriteAnswers(dst, MustNewName(hostB))
		if err != nil || int(n) != len(wantB) {
			t.Fatalf("%s: n=%d err=%v, want %d", when, n, err, len(wantB))
		}
		for i := range wantB {
			if dst[i] != wantB[i] {
				t.Fatalf("%s: addr %d=%v, want %v", when, i, dst[i], wantB[i])
			}
		}
	}
	if _, ok := client.LookupPop(txidA); !ok {
		t.Fatal("pop A failed")
	}
	checkResp("after pop A")
	startTestLookup(t, client, txidC, hostC, 4)
	encapsulateTestQuery(t, client)
	rscC, _ := testAnswers(hostC, 30, 1)
	if err := client.Demux(testResponse(t, txidC, testResponseFlags, hostC, TypeA, rscC), 0); err != nil {
		t.Fatal(err)
	}
	checkResp("after C completes")
}

func TestClient_ManyAnswers(t *testing.T) {
	const host = "example.com"
	const txid = 0x0808
	client := newTestClient(t, 1)
	startTestLookup(t, client, txid, host, 8)
	encapsulateTestQuery(t, client)
	rsc, want := testAnswers(host, 60, 8)
	if err := client.Demux(testResponse(t, txid, testResponseFlags, host, TypeA, rsc), 0); err != nil {
		t.Fatal(err)
	}
	checkTestAnswers(t, client, txid, host, want)
}

func TestClient_ZeroAllocReuse(t *testing.T) {
	const host = "example.com"
	const txid = 0x3333
	client := newTestClient(t, 2)
	name := MustNewName(host)
	cfg := LookupConfig{
		Questions:          []Question{{Name: name, Type: TypeA, Class: ClassINET}},
		EnableRecursion:    true,
		MaxResponseAnswers: 4,
	}
	rsc, _ := testAnswers(host, 70, 4)
	resp := testResponse(t, txid, testResponseFlags, host, TypeA, rsc)
	var buf [512]byte
	var dst [4]netip.Addr
	// Keep another lookup active so popping exercises removal of a non-last slot.
	if err := client.LookupStart(txid+1, cfg); err != nil {
		t.Fatal(err)
	}
	cycle := func() {
		if err := client.LookupStart(txid, cfg); err != nil {
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
		msg, _, ok := client.LookupResponse(txid)
		if !ok {
			panic("no response")
		}
		if n, err := msg.WriteAnswers(dst[:], name); err != nil || n != 4 {
			panic(err)
		}
		if state, ok := client.LookupPop(txid); !state.InProgress() || !ok {
			panic("pop failed")
		}
	}
	cycle() // Warm up slot buffers.
	if allocs := testing.AllocsPerRun(100, cycle); allocs != 0 {
		t.Fatalf("got %v allocations per lookup cycle, want 0", allocs)
	}
}

func TestClient_AbortAndIdle(t *testing.T) {
	client := newTestClient(t, 2)
	var buf [512]byte
	if n, err := client.Encapsulate(buf[:], -1, 0); n != 0 || err != nil {
		t.Fatalf("idle encapsulate n=%d err=%v, want 0 and nil", n, err)
	}
	startTestLookup(t, client, 1, "a.com", 1)
	startTestLookup(t, client, 2, "b.com", 1)
	connID := *client.ConnectionID()
	client.Abort()
	if *client.ConnectionID() == connID {
		t.Fatal("connection ID unchanged after Abort")
	}
	if client.NumLookups() != 0 {
		t.Fatalf("NumLookups=%d after Abort", client.NumLookups())
	}
	if _, ok := client.LookupPeek(1); ok {
		t.Fatal("lookup survived Abort")
	}
}

func TestClient_ReceivesDNSResponse(t *testing.T) {
	const hostname = "example.com"
	const txid = uint16(12345)
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
			rsc := make([]Resource, len(tt.responseIPs))
			for i, ip := range tt.responseIPs {
				rsc[i] = testA(hostname, ip)
			}
			dnsPayload := testResponse(t, txid, testResponseFlags, hostname, TypeA, rsc)

			client := newTestClient(t, 1)
			startTestLookup(t, client, txid, hostname, maxAnswers)
			// Encapsulate the query to move the client into the outstanding state.
			encapsulateTestQuery(t, client)
			if err := client.Demux(dnsPayload, 0); err != nil {
				t.Fatal("failed to demux DNS response:", err)
			}

			resp, _, ok := client.LookupResponse(txid)
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

func TestClient_LookupCanonical(t *testing.T) {
	const host, alias = "a.example.com", "edge.cdn.example.net"
	const txid, hopTxid = 0x1000, 0x2000

	var edns Resource
	setEDNS0(&edns, 1232, nil)
	client := newTestClient(t, 1)
	err := client.LookupStart(txid, LookupConfig{
		Questions:          []Question{{Name: MustNewName(host), Type: TypeA, Class: ClassINET}},
		Additional:         []Resource{edns},
		EnableRecursion:    true,
		MaxResponseAnswers: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	encapsulateTestQuery(t, client)
	cnameOnly := testResponse(t, txid, testResponseFlags, host, TypeA, []Resource{testCNAME(t, host, alias)})
	if err = client.Demux(cnameOnly, 0); err != nil {
		t.Fatal(err)
	}
	if err = client.LookupCanonicalRestart(txid, hopTxid); err != nil {
		t.Fatal("hop:", err)
	}
	if _, ok := client.LookupPeek(txid); ok {
		t.Fatal("old txid still active after hop")
	}
	if state, ok := client.LookupPeek(hopTxid); state.InProgress() || !ok {
		t.Fatalf("hop lookup: state=%v ok=%v, want pending", state, ok)
	}
	if client.NumLookups() != 1 {
		t.Fatalf("NumLookups=%d after hop, want 1", client.NumLookups())
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
	if err = client.Demux(testResponse(t, hopTxid, testResponseFlags, alias, TypeA, rsc), 0); err != nil {
		t.Fatal(err)
	}
	checkTestAnswers(t, client, hopTxid, alias, want)
}

func TestClient_LookupCanonicalErrors(t *testing.T) {
	const host = "a.example.com"
	const txid = 0x1000
	rsc, _ := testAnswers(host, 90, 1)
	cname := []Resource{testCNAME(t, host, "b.example.net")}
	tests := []struct {
		name    string
		resp    []byte // Nil leaves the lookup pending.
		newTxid uint16
	}{
		{name: "pending", newTxid: 0x2000},
		{name: "rcode", resp: testResponse(t, txid, testResponseFlags|HeaderFlags(RCodeServerFailure), host, TypeA, nil), newTxid: 0x2000},
		{name: "no CNAME", resp: testResponse(t, txid, testResponseFlags, host, TypeA, rsc), newTxid: 0x2000},
		{name: "zero txid", resp: testResponse(t, txid, testResponseFlags, host, TypeA, cname), newTxid: 0},
		{name: "txid in use", resp: testResponse(t, txid, testResponseFlags, host, TypeA, cname), newTxid: 0x3000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestClient(t, 2)
			startTestLookup(t, client, txid, host, 4)
			startTestLookup(t, client, 0x3000, "other.example.com", 4)
			encapsulateTestQuery(t, client)
			if tt.resp != nil {
				if err := client.Demux(tt.resp, 0); err != nil {
					t.Fatal(err)
				}
			}
			completed, _ := client.LookupPeek(txid)
			if err := client.LookupCanonicalRestart(txid, tt.newTxid); err == nil {
				t.Fatal("hop succeeded")
			}
			// Failed hop leaves the lookup as it was.
			if c, ok := client.LookupPeek(txid); !ok || c != completed {
				t.Fatalf("lookup changed by failed hop: completed=%v ok=%v", c, ok)
			}
		})
	}
	t.Run("unknown txid", func(t *testing.T) {
		client := newTestClient(t, 1)
		if err := client.LookupCanonicalRestart(1, 2); err == nil {
			t.Fatal("hop of unknown txid succeeded")
		}
	})
}

func TestClient_LookupCanonicalZeroAlloc(t *testing.T) {
	const host, alias = "a.example.com", "edge.cdn.example.net"
	const txid, hopTxid = 0x1000, 0x2000
	var edns Resource
	setEDNS0(&edns, 1232, nil)
	client := newTestClient(t, 1)
	cfg := LookupConfig{
		Questions:          []Question{{Name: MustNewName(host), Type: TypeA, Class: ClassINET}},
		Additional:         []Resource{edns},
		EnableRecursion:    true,
		MaxResponseAnswers: 4,
	}
	cnameOnly := testResponse(t, txid, testResponseFlags, host, TypeA, []Resource{testCNAME(t, host, alias)})
	rsc, _ := testAnswers(alias, 100, 2)
	final := testResponse(t, hopTxid, testResponseFlags, alias, TypeA, rsc)
	aliasName := MustNewName(alias)
	var buf [512]byte
	var dst [4]netip.Addr
	cycle := func() {
		if err := client.LookupStart(txid, cfg); err != nil {
			panic(err)
		}
		if n, err := client.Encapsulate(buf[:], -1, 0); err != nil || n == 0 {
			panic("encapsulate")
		}
		if err := client.Demux(cnameOnly, 0); err != nil {
			panic(err)
		}
		if err := client.LookupCanonicalRestart(txid, hopTxid); err != nil {
			panic(err)
		}
		if n, err := client.Encapsulate(buf[:], -1, 0); err != nil || n == 0 {
			panic("encapsulate hop")
		}
		if err := client.Demux(final, 0); err != nil {
			panic(err)
		}
		resp, _, ok := client.LookupResponse(hopTxid)
		if !ok {
			panic("no response")
		}
		if n, err := resp.WriteAnswers(dst[:], aliasName); err != nil || n != 2 {
			panic(err)
		}
		if state, ok := client.LookupPop(hopTxid); !state.InProgress() || !ok {
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
	err := client.Configure(ClientConfig{LocalPort: clientPort, MaxLookups: 1})
	if err != nil {
		t.Fatal(err)
	}
	err = client.LookupStart(txid, LookupConfig{
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
	resp, _, ok := client.LookupResponse(txid)
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
