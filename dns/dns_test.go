package dns

import (
	"fmt"
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
	var s string
	if len(m.Questions) > 0 {
		s += "-- Questions\n"
		for _, q := range m.Questions {
			s += fmt.Sprintf("%#v\n", q)
		}
	}
	if len(m.Answers) > 0 {
		s += "-- Answers\n"
		for _, a := range m.Answers {
			s += fmt.Sprintf("%#v\n", a)
		}
	}
	if len(m.Authorities) > 0 {
		s += "-- Authorities\n"
		for _, ns := range m.Authorities {
			s += fmt.Sprintf("%#v\n", ns)
		}
	}
	if len(m.Additionals) > 0 {
		s += "-- Additionals\n"
		for _, e := range m.Additionals {
			s += fmt.Sprintf("%#v\n", e)
		}
	}
	return s
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
