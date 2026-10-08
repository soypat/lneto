package dns

import (
	"math"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/soypat/lneto"
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
	var name Name
	err := name.Parse(domain)
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
	b, _ := m.AppendText(nil)
	return string(b)
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
	var vld lneto.Validator
	msg.Validate(&vld)
	if err := vld.ErrPop(); err != nil {
		t.Fatal("decoded message failed validation:", err)
	}
}

func TestMessage_Validate(t *testing.T) {
	name := MustNewName("example.com")

	// EDNS options.
	var opt Resource
	setEDNS0(&opt, 512, nil)
	tests := []struct {
		desc    string
		msg     Message
		wantErr bool
	}{
		{desc: "ok", msg: Message{
			Questions:   []Question{{Name: name, Type: TypeA, Class: ClassINET}},
			Answers:     []Resource{NewResource(name, TypeA, ClassINET, 60, []byte{1, 2, 3, 4})},
			Additionals: []Resource{opt},
		}},
		{desc: "empty name", wantErr: true, msg: Message{
			Questions: []Question{{Type: TypeA, Class: ClassINET}},
		}},
		{desc: "compressed name", wantErr: true, msg: Message{
			Questions: []Question{{Name: Name{data: []byte{0xc0, 0x00}}, Type: TypeA, Class: ClassINET}},
		}},
		{desc: "trailing name data", wantErr: true, msg: Message{
			Questions: []Question{{Name: Name{data: append(slices.Clone(name.data), 0)}, Type: TypeA, Class: ClassINET}},
		}},
		{desc: "bad A length", wantErr: true, msg: Message{
			Answers: []Resource{NewResource(name, TypeA, ClassINET, 60, []byte{1, 2, 3})},
		}},
		{desc: "length mismatch", wantErr: true, msg: Message{
			Answers: []Resource{{header: ResourceHeader{Name: name, Type: TypeA, Class: ClassINET, Length: 5}, data: []byte{1, 2, 3, 4}}},
		}},
		{desc: "OPT in answers", wantErr: true, msg: Message{
			Answers: []Resource{opt},
		}},
		{desc: "two OPT", wantErr: true, msg: Message{
			Additionals: []Resource{opt, opt},
		}},
		{desc: "max rdata overflows message", wantErr: true, msg: Message{
			// RDLENGTH fits uint16 but name+10+RDLENGTH does not.
			Answers: []Resource{NewResource(name, TypeTXT, ClassINET, 60, make([]byte, math.MaxUint16))},
		}},
	}
	for _, tt := range tests {
		var vld lneto.Validator
		tt.msg.Validate(&vld)
		err := vld.ErrPop()
		if (err != nil) != tt.wantErr {
			t.Errorf("%s: got err=%v, wantErr=%v", tt.desc, err, tt.wantErr)
		}
	}
}

// TestDecodeMessageSkipTruncated
func TestDecodeMessageSkipTruncated(t *testing.T) {
	// Header with ANCount=1 followed by a root name and a resource header cut short.
	hdr := []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0}
	for missing := 1; missing <= 10; missing++ {
		msg := append(hdr[:len(hdr):len(hdr)], make([]byte, 10-missing)...)
		var ans []Resource // Zero capacity: answer is skipped.
		_, incomplete, err := DecodeMessage(nil, &ans, nil, nil, msg)
		if err != lneto.ErrTruncatedFrame || incomplete {
			t.Errorf("missing=%d: want truncated error, got incomplete=%v err=%v", missing, incomplete, err)
		}
		_, incomplete, err = DecodeMessage(nil, nil, nil, nil, msg)
		if err != lneto.ErrTruncatedFrame || incomplete {
			t.Errorf("missing=%d nil dst: want truncated error, got incomplete=%v err=%v", missing, incomplete, err)
		}
	}
	// Resource data length exceeding message.
	msg := append(hdr[:len(hdr):len(hdr)], 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 1, 2, 3)
	_, _, err := DecodeMessage(nil, nil, nil, nil, msg)
	if err != lneto.ErrTruncatedFrame {
		t.Errorf("short data: want truncated error, got %v", err)
	}
	// Complete resource skipped with nil dst decodes up to message end.
	msg = append(msg, 4)
	off, incomplete, _ := DecodeMessage(nil, nil, nil, nil, msg)
	if int(off) != len(msg) || !incomplete {
		t.Errorf("complete: want off=%d incomplete, got off=%d incomplete=%v", len(msg), off, incomplete)
	}
}

// testResponseFlags are QR=1 (response), RD=1, RA=1.
const testResponseFlags = HeaderFlags(1<<15 | 1<<8 | 1<<7)

func testA(owner string, ip [4]byte) Resource {
	return NewResource(MustNewName(owner), TypeA, ClassINET, 300, ip[:])
}

func testCNAME(t testing.TB, owner, target string) Resource {
	t.Helper()
	tname := MustNewName(target)
	wire, err := tname.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	return NewResource(MustNewName(owner), TypeCNAME, ClassINET, 300, wire)
}

// testResponse encodes a response to a single question for host with the given answers.
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

// decodeTestMessage decodes a message of one question, up to 4 answers and up to 1 additional.
func decodeTestMessage(t testing.TB, wire []byte) *Message {
	t.Helper()
	var msg Message
	msg.LimitResourceDecoding(1, 4, 0, 1)
	_, incomplete, err := msg.Decode(wire)
	if incomplete || err != nil {
		t.Fatalf("decode: incomplete=%v err=%v", incomplete, err)
	}
	return &msg
}

// Table-driven tests for Message.WriteAnswers covering answer reordering
// and cyclic CNAME aliases.
func TestMessage_WriteAnswers(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		response []byte     // Raw wire response, for cases exercising name compression.
		answers  []Resource // Encoded into a response for host when response is nil.
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
			name:    "CNAME cycle terminates",
			host:    "a.com",
			answers: []Resource{testCNAME(t, "a.com", "b.com"), testCNAME(t, "b.com", "a.com")},
			want:    nil,
		},
		{
			name: "CNAME target case differs from owner name",
			host: "a.com",
			// A server picks the case of both the CNAME target and the owner
			// name of the record it aliases, and may randomize it (DNS 0x20),
			// so the two must compare under ASCII case folding.
			answers: []Resource{testCNAME(t, "a.com", "B.CoM"), testA("b.com", [4]byte{1, 2, 3, 4})},
			want:    []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := tt.response
			if wire == nil {
				wire = testResponse(t, 0xabcd, testResponseFlags, tt.host, TypeA, tt.answers)
			}
			msg := decodeTestMessage(t, wire)
			var addrs [4]netip.Addr
			n, err := msg.WriteAnswers(addrs[:], MustNewName(tt.host))
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

func TestMessage_CanonicalName(t *testing.T) {
	const host = "a.com"
	cname := func(owner, target string) Resource { return testCNAME(t, owner, target) }
	a := func(owner string) Resource { return testA(owner, [4]byte{1, 2, 3, 4}) }
	tests := []struct {
		name    string
		answers []Resource
		want    string // Empty means zero Name.
		anyWant bool   // Only check termination.
	}{
		{name: "no CNAME", answers: []Resource{a("a.com")}},
		{name: "CNAME only", answers: []Resource{cname("a.com", "b.com")}, want: "b.com"},
		{name: "CNAME chain", answers: []Resource{cname("a.com", "b.com"), cname("b.com", "c.com")}, want: "c.com"},
		{name: "CNAME target case differs", answers: []Resource{cname("a.com", "B.CoM"), cname("b.com", "c.com")}, want: "c.com"},
		{name: "CNAME cycle terminates", answers: []Resource{cname("a.com", "b.com"), cname("b.com", "a.com")}, anyWant: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := decodeTestMessage(t, testResponse(t, 0xabcd, testResponseFlags, host, TypeA, tt.answers))
			got := msg.CanonicalName(MustNewName(host))
			if tt.anyWant {
				return
			}
			if tt.want == "" {
				if got.Len() != 0 {
					t.Fatalf("expected zero Name, got %q", got.String())
				}
				return
			}
			if !NamesEqualFold(got, MustNewName(tt.want)) {
				t.Fatalf("expected %q, got %q", tt.want, got.String())
			}
		})
	}
}

func setEDNS0(opt *Resource, udplen uint16, ednsData []byte) {
	const rcode = 0
	const zflags = 0
	opt.RawSet(ResourceHeader{
		Name:   MustNewName("."),
		Type:   TypeOPT,
		Class:  Class(udplen), // udp length
		TTL:    uint32(rcode)<<24 | 0<<16 | uint32(zflags),
		Length: uint16(len(ednsData)),
	}, append(opt.RawData()[:0], ednsData...))
}
