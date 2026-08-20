package dns

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

var defaultMessageFlags = NewClientHeaderFlags(OpCodeQuery, true)

func TestNameString(t *testing.T) {
	var name Name
	domain := "foo.bar.org"
	domainSplit := strings.Split(domain, ".")
	for i, label := range domainSplit {
		name.AddLabel(label)
		s := name.String()
		if s != strings.Join(domainSplit[:i+1], ".")+"." {
			t.Fatalf("unexpected name string %q", s)
		}
	}
}

func TestNameAppendDecode(t *testing.T) {
	const domain = "foo.bar.org"
	name, err := NewName(domain)
	if err != nil {
		t.Fatal(err)
	} else if name.String() != domain+"." {
		t.Fatalf("unexpected name string %q", name.String())
	}
	var buf [512]byte
	b, err := name.AppendTo(buf[:0])
	if err != nil {
		t.Fatal(err)
	}
	if uint16(len(b)) != name.Len() {
		t.Fatalf("unexpected name length %d", len(b))
	}
	if b[len(b)-1] != 0 {
		t.Fatalf("unexpected name terminator byte after construction: %q", b[len(b)-1])
	}

	var name2 Name
	n, err := name2.Decode(b, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != name.Len() {
		t.Errorf("unexpected name parsed length %q (%d), want %q (%d)", name.data, n, b, name.Len())
	}
	if name2.String() != name.String() {
		t.Errorf("unexpected name string %q, want %q", name2.String(), name.String())
	}

	// Re-decode.
	const okvalidName = "\x03www\x02go\x03dev\x00"
	_, err = name.Decode([]byte(okvalidName), 0)
	if err != nil {
		t.Error("got error decoding valid name", err)
	} else if name.String() != "www.go.dev." {
		t.Error("unexpected name string", name.String())
	}
	b, err = name.AppendTo(buf[:0])
	if err != nil {
		t.Fatal(err)
	}
	if b[len(b)-1] != 0 {
		t.Fatalf("unexpected name terminator byte after decoding: %q", b[len(b)-1])
	}
	if string(b) != okvalidName {
		t.Errorf("unexpected name bytes after decode %q, want %q", b, okvalidName)
	}
	// Decode invalid name.
	const invalidName = "\x03w.w\x02go\x03dev\x00"
	_, err = name.Decode([]byte(invalidName), 0)
	if err == nil {
		t.Error("expected error for invalid name")
	} else if err != errInvalidName {
		t.Errorf("unexpected error %v, want %v", err, errInvalidName)
	}
}

func TestMessageAppendEncode(t *testing.T) {
	var tests = []struct {
		Message Message
		error   error
	}{
		{
			Message: Message{
				Questions: []Question{
					{
						Name:  MustNewName("."),
						Type:  TypeA,
						Class: ClassINET,
					},
				},
				Answers: []Resource{
					{
						header: ResourceHeader{
							Name:   MustNewName("."),
							Type:   TypeA,
							Class:  ClassINET,
							TTL:    256,
							Length: 3,
						},
						data: []byte{1, 2, 3},
					},
				},
			},
		},
	}
	var buf [512]byte
	for _, tt := range tests {
		b, err := tt.Message.AppendTo(buf[:0], 123, defaultMessageFlags)
		if err != nil {
			t.Fatal(err)
		}

		var msg Message
		msg.LimitResourceDecoding(uint16(len(tt.Message.Questions)), uint16(len(tt.Message.Answers)), uint16(len(tt.Message.Authorities)), uint16(len(tt.Message.Additionals)))
		_, incomplete, err := msg.Decode(b)
		if err != nil {
			t.Fatal(err)
		} else if incomplete {
			t.Fatal("incomplete parse")
		}
		if msg.String() != tt.Message.String() {
			t.Errorf("mismatch message strings after append/decode:\n%s\n%s", tt.Message.String(), msg.String())
		}
	}
}

func TestMessageAppendEncodeIncompleteOK(t *testing.T) {
	var tests = []struct {
		Message Message
		error   error
	}{
		{
			Message: Message{
				Questions: []Question{
					{
						Name:  MustNewName("."),
						Type:  TypeA,
						Class: ClassINET,
					},
				},
				Answers: []Resource{
					{
						header: ResourceHeader{
							Name:   MustNewName("."),
							Type:   TypeA,
							Class:  ClassINET,
							TTL:    256,
							Length: 3,
						},
						data: []byte{1, 2, 3},
					},
					{
						header: ResourceHeader{
							Name:   MustNewName("."),
							Type:   TypeA,
							Class:  ClassINET,
							TTL:    256,
							Length: 3,
						},
						data: []byte{1, 2, 3},
					},
				},
			},
		},
	}
	var buf [512]byte
	for _, tt := range tests {
		b, err := tt.Message.AppendTo(buf[:0], 123, defaultMessageFlags)
		if err != nil {
			t.Fatal(err)
		}

		var msg Message
		// Limit answers to 1 to test incomplete parsing (message has 2 answers).
		msg.LimitResourceDecoding(uint16(len(tt.Message.Questions)), 1, uint16(len(tt.Message.Authorities)), uint16(len(tt.Message.Additionals)))
		_, incomplete, err := msg.Decode(b)
		if err != nil && !incomplete {
			t.Fatal(err)
		} else if !incomplete {
			t.Fatal("expected incomplete parse")
		}
		tt.Message.Answers = tt.Message.Answers[:1] // Trim to match the limited decode.
		if msg.String() != tt.Message.String() {
			t.Errorf("mismatch message strings after append/decode:\n%s\n%s", tt.Message.String(), msg.String())
		}
	}
}

func (m *Message) String() string {
	// s := fmt.Sprintf("Message: %#v\n", &m.Header)
	var s strings.Builder
	if len(m.Questions) > 0 {
		s.WriteString("-- Questions\n")
		for _, q := range m.Questions {
			s.WriteString(fmt.Sprintf("%#v\n", q))
		}
	}
	if len(m.Answers) > 0 {
		s.WriteString("-- Answers\n")
		for _, a := range m.Answers {
			s.WriteString(fmt.Sprintf("%#v\n", a))
		}
	}
	if len(m.Authorities) > 0 {
		s.WriteString("-- Authorities\n")
		for _, ns := range m.Authorities {
			s.WriteString(fmt.Sprintf("%#v\n", ns))
		}
	}
	if len(m.Additionals) > 0 {
		s.WriteString("-- Additionals\n")
		for _, e := range m.Additionals {
			s.WriteString(fmt.Sprintf("%#v\n", e))
		}
	}
	return s.String()
}

func TestDecodeMessage(t *testing.T) {
	var data = []byte{
		0x84, 0x05, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0b, 0x77, 0x68, 0x69,
		0x74, 0x74, 0x69, 0x6c, 0x65, 0x61, 0x6b, 0x73, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
		0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x1e, 0xaf, 0x00, 0x04, 0xc6, 0x31, 0x17,
		0x91, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	var msg Message
	msg.LimitResourceDecoding(5, 5, 5, 5)
	off, incomplete, err := msg.Decode(data)
	if incomplete || err != nil {
		t.Fatal(incomplete, err, off)
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
	err := client.StartResolve(clientPort, txid, ResolveConfig{
		Questions: []Question{{
			Name:  name,
			Type:  TypeA,
			Class: ClassINET,
		}},
		EnableRecursion: true,
		MaxIPs:          4,
		MaxCNAMEs:       2,
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
	var addrs [4]netip.Addr
	n, err := client.ResponseAnswerLookup(addrs[:], hostname)
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

// Table-driven tests for Message.WriteAnswers covering answer reordering,
// non-address record types and cyclic CNAME aliases.
func TestMessage_WriteAnswers(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		response []byte
		want     []netip.Addr
	}{
		{
			name: "A record before its CNAME",
			host: "www.yahoo.co.jp",
			// Answer 1 is the A record for edge12.g.yimg.jp, spelled out with
			// a trailing compression pointer to "jp" in the question. Answer 2
			// is the CNAME from www.yahoo.co.jp whose RDATA is a single
			// backward compression pointer to answer 1's owner name.
			response: []byte{
				// Header: txid 0x1234, QR|RD|RA, QD=1 AN=2 NS=0 AR=0.
				0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
				// Question: www.yahoo.co.jp A IN.
				0x03, 'w', 'w', 'w', 0x05, 'y', 'a', 'h', 'o', 'o', 0x02, 'c', 'o', 0x02, 'j', 'p', 0x00,
				0x00, 0x01, 0x00, 0x01,
				// Answer 1: edge12.g.yimg.jp A IN ttl=36 rdlen=4 182.22.23.124.
				0x06, 'e', 'd', 'g', 'e', '1', '2', 0x01, 'g', 0x04, 'y', 'i', 'm', 'g', 0xc0, 0x19,
				0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00, 0x04, 0xb6, 0x16, 0x17, 0x7c,
				// Answer 2: (ptr to question) CNAME IN ttl=842 rdlen=2, target
				// is a pointer to answer 1's owner name at offset 0x21.
				0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x03, 0x4a, 0x00, 0x02, 0xc0, 0x21,
			},
			want: []netip.Addr{netip.AddrFrom4([4]byte{182, 22, 23, 124})},
		},
		{
			name: "ignores non-address records",
			host: "example.com",
			response: []byte{
				// Header: txid 0x5678, QR|RD|RA, QD=1 AN=2 NS=0 AR=0.
				0x56, 0x78, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
				// Question: example.com A IN.
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
				0x00, 0x01, 0x00, 0x01,
				// Answer 1: (ptr to question) TXT IN ttl=60 rdlen=6 "hello".
				0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x06, 0x05, 'h', 'e', 'l', 'l', 'o',
				// Answer 2: (ptr to question) A IN ttl=300 rdlen=4 192.0.2.1.
				0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x01,
			},
			want: []netip.Addr{netip.AddrFrom4([4]byte{192, 0, 2, 1})},
		},
		{
			name: "CNAME cycle terminates",
			host: "a.com",
			response: []byte{
				// Header: txid 0xabcd, QR|RD|RA, QD=1 AN=2 NS=0 AR=0.
				0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
				// Question: a.com A IN.
				0x01, 'a', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
				// Answer 1: a.com CNAME b.com.
				0x01, 'a', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x07, 0x01, 'b', 0x03, 'c', 'o', 'm', 0x00,
				// Answer 2: b.com CNAME a.com.
				0x01, 'b', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x07, 0x01, 'a', 0x03, 'c', 'o', 'm', 0x00,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var msg Message
			msg.LimitResourceDecoding(1, 4, 0, 0)
			_, incomplete, err := msg.Decode(tt.response)
			if incomplete || err != nil {
				t.Fatal("decode:", incomplete, err)
			}
			var addrs [4]netip.Addr
			n, err := msg.WriteAnswers(addrs[:], tt.host)
			if err != nil {
				t.Fatal("write answers:", err)
			}
			if n != uint16(len(tt.want)) {
				t.Fatalf("expected %d addresses, got %d: %v", len(tt.want), n, addrs[:n])
			}
			for i, want := range tt.want {
				if addrs[i] != want {
					t.Errorf("address %d: expected %v, got %v", i, want, addrs[i])
				}
			}
		})
	}
}

func TestClient_ReceivesDNSResponse(t *testing.T) {
	const hostname = "example.com"
	const txid = uint16(12345)
	const clientPort = uint16(54321)
	const maxIPs = 4
	const maxCNAMEs = 2
	const maxDecoded = maxIPs + maxCNAMEs
	allIPs := [8][4]byte{
		{192, 0, 2, 1},
		{192, 0, 2, 2},
		{192, 0, 2, 3},
		{192, 0, 2, 4},
		{192, 0, 2, 5},
		{192, 0, 2, 6},
		{192, 0, 2, 7},
		{192, 0, 2, 8},
	}
	tests := []struct {
		name        string
		responseIPs [][4]byte
		wantDecoded int // Answers decoded (and copied by ResponseCopyTo).
		wantAnswers int // Addresses returned by ResponseAnswerLookup.
	}{
		{name: "single_answer", responseIPs: allIPs[:1], wantDecoded: 1, wantAnswers: 1},
		{name: "multiple_answers", responseIPs: allIPs[:4], wantDecoded: 4, wantAnswers: 4},
		{name: "answer_limit", responseIPs: allIPs[:5], wantDecoded: 5, wantAnswers: maxIPs},
		{name: "decode_limit", responseIPs: allIPs[:8], wantDecoded: maxDecoded, wantAnswers: maxIPs},
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
			err = client.StartResolve(clientPort, txid, ResolveConfig{
				Questions: []Question{{
					Name:  name,
					Type:  TypeA,
					Class: ClassINET,
				}},
				EnableRecursion: true,
				MaxIPs:          maxIPs,
				MaxCNAMEs:       maxCNAMEs,
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

			var addrs [maxIPs]netip.Addr
			answers, err := client.ResponseAnswerLookup(addrs[:], hostname)
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

			var lookup Message
			done, err := client.ResponseCopyTo(&lookup)
			if err != nil {
				t.Fatal("failed to copy DNS response:", err)
			}
			if !done {
				t.Fatal("expected done=true")
			}
			if len(lookup.Answers) != tt.wantDecoded {
				t.Fatalf("expected %d copied answers, got %d", tt.wantDecoded, len(lookup.Answers))
			}
		})
	}
}
