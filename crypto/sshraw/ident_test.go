package sshraw

import (
	"errors"
	"strings"
	"testing"

	"github.com/soypat/lneto"
)

func TestNextIdentLine(t *testing.T) {
	for _, tc := range []struct {
		buf     string
		line    string
		n       int
		wantErr error
	}{
		{buf: "SSH-2.0-x\r\nrest", line: "SSH-2.0-x", n: 11},
		{buf: "banner\nSSH-2.0-x\r\n", line: "banner", n: 7},
		{buf: "\n", line: "", n: 1},
		{buf: "SSH-2.0-x", wantErr: lneto.ErrTruncatedFrame},
		{buf: strings.Repeat("a", maxIdentLen), wantErr: lneto.ErrInvalidLengthField},
		{buf: strings.Repeat("a", maxIdentLen-1) + "\n", line: strings.Repeat("a", maxIdentLen-1), n: maxIdentLen},
	} {
		line, n, err := NextIdentLine([]byte(tc.buf))
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("%q: err=%v, want %v", tc.buf, err, tc.wantErr)
		} else if string(line) != tc.line || n != tc.n {
			t.Errorf("%q: line=%q n=%d, want %q n=%d", tc.buf, line, n, tc.line, tc.n)
		}
	}
}

func TestParseIdent(t *testing.T) {
	for _, tc := range []struct {
		line              string
		rejectNon2        bool
		proto, sw, coment string
		wantErr           error
	}{
		{line: "SSH-2.0-OpenSSH_9.6", rejectNon2: true, proto: "2.0", sw: "OpenSSH_9.6"},
		{line: "SSH-1.99-srv cmt with spaces", rejectNon2: true, proto: "1.99", sw: "srv", coment: "cmt with spaces"},
		{line: "SSH-2.0-dropbear-2024.85", rejectNon2: true, proto: "2.0", sw: "dropbear-2024.85"},
		{line: "SSH-2.0-x ", proto: "2.0", sw: "x", coment: ""},
		{line: "SSH-1.5-old", proto: "1.5", sw: "old"},
		{line: "SSH-1.5-old", rejectNon2: true, wantErr: lneto.ErrUnsupported},
		{line: "SSH-3.0-new", rejectNon2: true, wantErr: lneto.ErrUnsupported},
		{line: "SSH--x", wantErr: lneto.ErrInvalidField},
		{line: "SSH-2 .0-x", wantErr: lneto.ErrInvalidField},
		{line: "SSH-2.0-", wantErr: lneto.ErrInvalidField},
		{line: "SSH-2.0- cmt", wantErr: lneto.ErrInvalidField},
		{line: "SSH-2.0-x\x7f", wantErr: lneto.ErrInvalidField},
		{line: "SSH-2.0-x \x00", wantErr: lneto.ErrInvalidField},
		{line: "SSH-2.0", wantErr: lneto.ErrInvalidField},
		{line: "ssh-2.0-x", wantErr: lneto.ErrInvalidField},
		{line: "", wantErr: lneto.ErrInvalidField},
	} {
		proto, sw, comments, err := ParseIdent([]byte(tc.line), tc.rejectNon2)
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("%q: err=%v, want %v", tc.line, err, tc.wantErr)
		} else if string(proto) != tc.proto || string(sw) != tc.sw || string(comments) != tc.coment {
			t.Errorf("%q: got %q %q %q, want %q %q %q", tc.line, proto, sw, comments, tc.proto, tc.sw, tc.coment)
		}
	}
}

// TestValidateIdentFormat checks the strict RFC 4253 4.2 form of an identification string we send.
func TestValidateIdentFormat(t *testing.T) {
	for _, tc := range []struct {
		proto, software, comments string
		wantErr                   error
	}{
		{proto: "2.0", software: "lneto_1"},
		{proto: "2.0", software: "lneto_1", comments: "tiny go ~!"},
		{proto: "", software: "a", wantErr: lneto.ErrInvalidField},
		{proto: "2.0", software: "", wantErr: lneto.ErrInvalidField},
		{proto: "2-0", software: "a", wantErr: lneto.ErrInvalidField},
		{proto: "2.0", software: "a-b", wantErr: lneto.ErrInvalidField},
		{proto: "2.0", software: "a b", wantErr: lneto.ErrInvalidField},
		{proto: "2.0", software: "a\x7f", wantErr: lneto.ErrInvalidField},
		{proto: "2.0", software: "a", comments: "\r", wantErr: lneto.ErrInvalidField},
		{proto: "2.0", software: "a", comments: "x\x00", wantErr: lneto.ErrInvalidField},
	} {
		err := ValidateIdentFormat([]byte(tc.proto), []byte(tc.software), []byte(tc.comments))
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("%q %q %q: err=%v, want %v", tc.proto, tc.software, tc.comments, err, tc.wantErr)
		}
	}
}

func TestEncoderIdent(t *testing.T) {
	for _, tc := range []struct {
		software, comments string
		want               string
		wantErr            error
	}{
		{software: "lneto_1", want: "SSH-2.0-lneto_1\r\n"},
		{software: "lneto_1", comments: "tiny go", want: "SSH-2.0-lneto_1 tiny go\r\n"},
		{software: "", wantErr: lneto.ErrInvalidField},
		{software: strings.Repeat("a", maxIdentLen), wantErr: lneto.ErrInvalidLengthField},
	} {
		if err := ValidateIdentFormat([]byte("2.0"), []byte(tc.software), []byte(tc.comments)); err != nil && tc.wantErr == nil {
			t.Fatalf("test case %q %q not valid format: %v", tc.software, tc.comments, err)
		}
		var e Encoder
		buf := make([]byte, 2*maxIdentLen)
		e.Reset(buf, 0)
		e.Ident("2.0", tc.software, tc.comments)
		if !errors.Is(e.Err(), tc.wantErr) {
			t.Errorf("%q %q: err=%v, want %v", tc.software, tc.comments, e.Err(), tc.wantErr)
			continue
		} else if tc.wantErr != nil {
			continue
		}
		got := buf[:e.Len()]
		if string(got) != tc.want {
			t.Errorf("Ident=%q, want %q", got, tc.want)
		}
		line, _, err := NextIdentLine(got)
		if err != nil {
			t.Fatal(err)
		}
		_, sw, comments, err := ParseIdent(line, true)
		if err != nil || string(sw) != tc.software || string(comments) != tc.comments {
			t.Errorf("round trip %q %q err=%v", sw, comments, err)
		}
	}
}
