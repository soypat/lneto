package sshraw_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/soypat/lneto"
	ssh "github.com/soypat/lneto/crypto/sshraw"
)

func TestNextIdentLine(t *testing.T) {
	long := "SSH-2.0-" + strings.Repeat("x", ssh.MaxIdentLen)
	for _, tc := range []struct {
		name     string
		buf      string
		wantLine string
		wantN    int
		wantErr  error
	}{
		{"crlf", "SSH-2.0-OpenSSH_9.6\r\nrest", "SSH-2.0-OpenSSH_9.6", 21, nil},
		{"lf only", "SSH-2.0-OpenSSH_9.6\nrest", "SSH-2.0-OpenSSH_9.6", 20, nil},
		{"preamble", "hello there\r\nSSH-2.0-x\r\n", "hello there", 13, nil},
		{"incomplete", "SSH-2.0-OpenSSH", "", 0, lneto.ErrTruncatedFrame},
		{"empty", "", "", 0, lneto.ErrTruncatedFrame},
		{"max length", long[:ssh.MaxIdentLen-2] + "\r\n", long[:ssh.MaxIdentLen-2], ssh.MaxIdentLen, nil},
		{"too long", long[:ssh.MaxIdentLen-1] + "\r\n", "", 0, lneto.ErrInvalidLengthField},
		{"too long no lf", long, "", 0, lneto.ErrInvalidLengthField},
		// Only the identification string must not contain null, RFC 4253 4.2.
		{"null byte preamble", "a\x00b\r\n", "a\x00b", 5, nil},
	} {
		line, n, err := ssh.NextIdentLine([]byte(tc.buf))
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: err=%v, want %v", tc.name, err, tc.wantErr)
		} else if string(line) != tc.wantLine || n != tc.wantN {
			t.Errorf("%s: line=%q n=%d, want %q n=%d", tc.name, line, n, tc.wantLine, tc.wantN)
		}
	}
}

func TestParseIdent(t *testing.T) {
	for _, tc := range []struct {
		line     string
		software string
		comments string
		wantErr  error
	}{
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", "OpenSSH_9.6p1", "Ubuntu-3ubuntu13", nil},
		{"SSH-2.0-OpenSSH_9.6", "OpenSSH_9.6", "", nil},
		{"SSH-2.0-Cisco-1.25", "Cisco-1.25", "", nil}, // Violates RFC 4253 4.2 but seen in the wild.
		{"SSH-1.99-srv", "srv", "", nil},              // Server compatible with both versions, RFC 4253 5.1.
		{"SSH-2.0-a b c", "a", "b c", nil},
		{"SSH-1.5-old", "", "", lneto.ErrUnsupported},
		{"SSH-2.0-", "", "", lneto.ErrInvalidField},
		{"SSH-2.0- comment", "", "", lneto.ErrInvalidField},
		{"SSH-2.0-a\tb", "", "", lneto.ErrInvalidField},
		{"hello there", "", "", lneto.ErrInvalidField}, // Preamble line, not an identification.
		{"SSH-2.0", "", "", lneto.ErrInvalidField},
		{"SSH-2.0-a b\x00c", "", "", lneto.ErrInvalidField},
	} {
		software, comments, err := ssh.ParseIdent([]byte(tc.line))
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("ParseIdent(%q) err=%v, want %v", tc.line, err, tc.wantErr)
		} else if string(software) != tc.software || string(comments) != tc.comments {
			t.Errorf("ParseIdent(%q)=%q,%q want %q,%q", tc.line, software, comments, tc.software, tc.comments)
		}
	}
}

func TestEncoderIdent(t *testing.T) {
	var e ssh.Encoder
	buf := make([]byte, ssh.MaxIdentLen)
	for _, tc := range []struct {
		software, comments string
		want               string
	}{
		{"lneto_0.1", "", "SSH-2.0-lneto_0.1\r\n"},
		{"lneto_0.1", "tinygo", "SSH-2.0-lneto_0.1 tinygo\r\n"},
	} {
		e.Reset(buf, 0)
		e.Ident(tc.software, tc.comments)
		if e.Err() != nil {
			t.Fatal(e.Err())
		} else if got := buf[:e.Len()]; !bytes.Equal(got, []byte(tc.want)) {
			t.Errorf("Ident=%q, want %q", got, tc.want)
		}
		line, _, err := ssh.NextIdentLine(buf[:e.Len()])
		if err != nil {
			t.Fatal(err)
		}
		software, comments, err := ssh.ParseIdent(line)
		if err != nil || string(software) != tc.software || string(comments) != tc.comments {
			t.Errorf("round trip=%q,%q,%v want %q,%q", software, comments, err, tc.software, tc.comments)
		}
	}
	e.Reset(buf, 0)
	if e.Ident(strings.Repeat("x", ssh.MaxIdentLen), ""); !errors.Is(e.Err(), lneto.ErrInvalidLengthField) {
		t.Errorf("long Ident err=%v, want %v", e.Err(), lneto.ErrInvalidLengthField)
	}
	e.Reset(buf, 0)
	if e.Ident("a b", ""); !errors.Is(e.Err(), lneto.ErrInvalidField) {
		t.Errorf("Ident with space err=%v, want %v", e.Err(), lneto.ErrInvalidField)
	}
}
