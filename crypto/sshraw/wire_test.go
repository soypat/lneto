package sshraw_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/soypat/lneto"
	ssh "github.com/soypat/lneto/crypto/sshraw"
)

func TestValidateNameList(t *testing.T) {
	long := strings.Repeat("a", ssh.MaxNameLen)
	for _, tc := range []struct {
		list string
		want error
	}{
		{"", nil}, // Empty list is legal, RFC 4251 5.
		{"a", nil},
		{"curve25519-sha256,kex-strict-c-v00@openssh.com", nil},
		{long, nil},
		{long + "a", lneto.ErrInvalidLengthField},
		{"a," + long + "a", lneto.ErrInvalidLengthField},
		{",a", lneto.ErrInvalidField}, // Zero length name.
		{"a,", lneto.ErrInvalidField},
		{"a,,b", lneto.ErrInvalidField},
		{",", lneto.ErrInvalidField},
		{"a b", lneto.ErrInvalidField}, // Whitespace.
		{"a\x00", lneto.ErrInvalidField},
		{"a\x7f", lneto.ErrInvalidField},
		{"\xc3\xa9", lneto.ErrInvalidField}, // Not US-ASCII.
	} {
		got := ssh.ValidateNameList([]byte(tc.list))
		if !errors.Is(got, tc.want) {
			t.Errorf("ValidateNameList(%q)=%v, want %v", tc.list, got, tc.want)
		}
	}
}

func TestNextName(t *testing.T) {
	for _, tc := range []struct {
		list string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a,bc,d", []string{"a", "bc", "d"}},
	} {
		var got []string
		for list := []byte(tc.list); len(list) > 0; {
			var name []byte
			name, list = ssh.NextName(list)
			got = append(got, string(name))
		}
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("NextName walk of %q=%q, want %q", tc.list, got, tc.want)
		}
	}
}

func TestNegotiate(t *testing.T) {
	for _, tc := range []struct {
		client, server string
		want           string // "" for no match.
	}{
		{"a,b,c", "c,b", "b"}, // Client preference wins, RFC 4253 7.1.
		{"a", "a", "a"},
		{"a,b", "c,d", ""},
		{"", "a", ""},
		{"a", "", ""},
		{"aes128", "aes128-gcm@openssh.com", ""}, // Prefix is not a match.
		{"aes128-gcm@openssh.com", "aes128", ""},
		{",a", ",b", ""}, // Empty names of unvalidated lists never agree.
		{"a,,b", ",b", "b"},
	} {
		got := ssh.Negotiate([]byte(tc.client), []byte(tc.server))
		if string(got) != tc.want {
			t.Errorf("Negotiate(%q,%q)=%q, want %q", tc.client, tc.server, got, tc.want)
		} else if tc.want == "" && got != nil {
			t.Errorf("Negotiate(%q,%q) no match returned non-nil", tc.client, tc.server)
		}
	}
	for _, tc := range []struct {
		list, name string
		want       bool
	}{
		{"a,bc", "bc", true},
		{"a,bc", "b", false},
		{"a,bc", "a,bc", false},
		{"", "", false},
		{"a,,b", "", false},
		{",", "", false},
		{ssh.KexCurve25519SHA256 + "," + ssh.KexStrictServer, ssh.KexStrictServer, true},
	} {
		if got := ssh.HasName([]byte(tc.list), tc.name); got != tc.want {
			t.Errorf("HasName(%q,%q)=%v, want %v", tc.list, tc.name, got, tc.want)
		}
	}
}

func TestEncoderNameList(t *testing.T) {
	var e ssh.Encoder
	buf := make([]byte, 64)
	e.Reset(buf, 0)
	e.NameList("a", "bc")
	e.NameList()
	want := []byte{0, 0, 0, 4, 'a', ',', 'b', 'c', 0, 0, 0, 0}
	if e.Err() != nil {
		t.Fatal(e.Err())
	} else if !bytes.Equal(buf[:e.Len()], want) {
		t.Fatalf("name-lists=%x, want %x", buf[:e.Len()], want)
	}
	for _, names := range [][]string{{""}, {"a,b"}, {"a", ""}} {
		e.Reset(buf, 0)
		if e.NameList(names...); !errors.Is(e.Err(), lneto.ErrInvalidField) {
			t.Errorf("NameList(%q) err=%v, want %v", names, e.Err(), lneto.ErrInvalidField)
		}
	}
}

// RFC 4251 5 mpint examples, positive values only; this encoder writes unsigned magnitudes.
func TestEncoderMPInt(t *testing.T) {
	for _, tc := range []struct {
		mag  []byte
		want []byte
	}{
		{nil, []byte{0, 0, 0, 0}},
		{[]byte{0, 0}, []byte{0, 0, 0, 0}}, // Zero is the empty string.
		{
			[]byte{0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7},
			[]byte{0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7},
		},
		{[]byte{0x80}, []byte{0, 0, 0, 2, 0x00, 0x80}},        // High bit set needs a zero byte.
		{[]byte{0x00, 0x00, 0x7f}, []byte{0, 0, 0, 1, 0x7f}}, // Leading zeros stripped.
		{[]byte{0x00, 0xff}, []byte{0, 0, 0, 2, 0x00, 0xff}},
	} {
		var e ssh.Encoder
		buf := make([]byte, 32)
		e.Reset(buf, 0)
		e.MPInt(tc.mag)
		if e.Err() != nil {
			t.Fatal(e.Err())
		} else if !bytes.Equal(buf[:e.Len()], tc.want) {
			t.Errorf("MPInt(%x)=%x, want %x", tc.mag, buf[:e.Len()], tc.want)
		}
	}
}

func TestEncoderShortBuffer(t *testing.T) {
	var e ssh.Encoder
	buf := make([]byte, 6)
	e.Reset(buf, 0)
	e.String([]byte("hello"))
	e.Uint32(1) // Dropped after the failure.
	if !errors.Is(e.Err(), lneto.ErrShortBuffer) {
		t.Fatalf("err=%v, want %v", e.Err(), lneto.ErrShortBuffer)
	}
}
