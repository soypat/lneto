package sshraw_test

import (
	"errors"
	"go/build"
	"strings"
	"testing"

	"github.com/soypat/lneto"
	ssh "github.com/soypat/lneto/crypto/sshraw"
)

// TestNoCryptoImports guards against linking Go's crypto packages, as tlsraw
// does: their init functions carry FIPS self-tests TinyGo cannot eliminate.
func TestNoCryptoImports(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range pkg.Imports {
		if imp == "crypto" || strings.HasPrefix(imp, "crypto/") {
			t.Errorf("sshraw must not import %q; take the primitive from the caller instead", imp)
		}
	}
}

// payload encodes a message of type typ whose fields are written by fields.
func payload(t *testing.T, typ ssh.MsgType, fields func(e *ssh.Encoder)) []byte {
	t.Helper()
	var e ssh.Encoder
	buf := make([]byte, 256)
	e.Reset(buf, 0)
	e.Uint8(uint8(typ))
	fields(&e)
	if e.Err() != nil {
		t.Fatal(e.Err())
	}
	return buf[:e.Len()]
}

func TestParseDisconnect(t *testing.T) {
	full := payload(t, ssh.MsgDisconnect, func(e *ssh.Encoder) {
		e.Uint32(uint32(ssh.DisconnectByApplication))
		e.Str("bye")
		e.Str("en")
	})
	reason, desc, err := ssh.ParseDisconnect(full)
	if err != nil {
		t.Fatal(err)
	} else if reason != ssh.DisconnectByApplication || string(desc) != "bye" {
		t.Errorf("got %v %q, want %v %q", reason, desc, ssh.DisconnectByApplication, "bye")
	}
	// The connection ends either way, so a missing language tag is tolerated.
	noLang := full[:len(full)-4-2]
	if _, desc, err = ssh.ParseDisconnect(noLang); err != nil || string(desc) != "bye" {
		t.Errorf("no language tag: %q %v", desc, err)
	}
	for _, tc := range []struct {
		name    string
		payload []byte
		want    error
	}{
		{"empty", nil, lneto.ErrTruncatedFrame},
		{"wrong type", append([]byte{byte(ssh.MsgIgnore)}, full[1:]...), lneto.ErrInvalidField},
		{"no description", full[:1+4], lneto.ErrTruncatedFrame},
		{"short description", full[:1+4+4+1], lneto.ErrTruncatedFrame},
	} {
		if _, _, err := ssh.ParseDisconnect(tc.payload); !errors.Is(err, tc.want) {
			t.Errorf("%s: err=%v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestParseServiceName(t *testing.T) {
	for _, typ := range []ssh.MsgType{ssh.MsgServiceRequest, ssh.MsgServiceAccept} {
		p := payload(t, typ, func(e *ssh.Encoder) { e.Str(ssh.ServiceUserauth) })
		name, err := ssh.ParseServiceName(p)
		if err != nil || string(name) != ssh.ServiceUserauth {
			t.Errorf("%v: got %q %v", typ, name, err)
		}
		if _, err = ssh.ParseServiceName(append(p, 0)); !errors.Is(err, lneto.ErrInvalidLengthField) {
			t.Errorf("%v trailing byte: err=%v, want %v", typ, err, lneto.ErrInvalidLengthField)
		}
		if _, err = ssh.ParseServiceName(p[:len(p)-1]); !errors.Is(err, lneto.ErrTruncatedFrame) {
			t.Errorf("%v truncated: err=%v, want %v", typ, err, lneto.ErrTruncatedFrame)
		}
	}
	p := payload(t, ssh.MsgIgnore, func(e *ssh.Encoder) { e.Str(ssh.ServiceUserauth) })
	if _, err := ssh.ParseServiceName(p); !errors.Is(err, lneto.ErrInvalidField) {
		t.Errorf("wrong type: err=%v, want %v", err, lneto.ErrInvalidField)
	}
}

func TestParseUnimplemented(t *testing.T) {
	p := payload(t, ssh.MsgUnimplemented, func(e *ssh.Encoder) { e.Uint32(0xdeadbeef) })
	seq, err := ssh.ParseUnimplemented(p)
	if err != nil || seq != 0xdeadbeef {
		t.Errorf("got %#x %v", seq, err)
	}
	if _, err = ssh.ParseUnimplemented(p[:4]); !errors.Is(err, lneto.ErrTruncatedFrame) {
		t.Errorf("truncated: err=%v", err)
	}
	if _, err = ssh.ParseUnimplemented(append(p, 0)); !errors.Is(err, lneto.ErrInvalidLengthField) {
		t.Errorf("trailing: err=%v", err)
	}
}

func TestParseDebug(t *testing.T) {
	p := payload(t, ssh.MsgDebug, func(e *ssh.Encoder) {
		e.Bool(true)
		e.Str("hi")
		e.Str("")
	})
	display, msg, err := ssh.ParseDebug(p)
	if err != nil || !display || string(msg) != "hi" {
		t.Errorf("got %v %q %v", display, msg, err)
	}
	if _, _, err = ssh.ParseDebug(p[:1+1+2]); !errors.Is(err, lneto.ErrTruncatedFrame) {
		t.Errorf("truncated: err=%v", err)
	}
}

func TestParseKexECDHInit(t *testing.T) {
	share := make([]byte, 32)
	share[0] = 9
	p := payload(t, ssh.MsgKexECDHInit, func(e *ssh.Encoder) { e.String(share) })
	qc, err := ssh.ParseKexECDHInit(p)
	if err != nil || len(qc) != 32 || qc[0] != 9 {
		t.Errorf("got %x %v", qc, err)
	}
	if _, err = ssh.ParseKexECDHInit(append(p, 0)); !errors.Is(err, lneto.ErrInvalidLengthField) {
		t.Errorf("trailing: err=%v", err)
	}
	if _, err = ssh.ParseKexECDHInit(p[:len(p)-1]); !errors.Is(err, lneto.ErrTruncatedFrame) {
		t.Errorf("truncated: err=%v", err)
	}
	if _, err = ssh.ParseKexECDHInit([]byte{byte(ssh.MsgKexECDHReply), 0, 0, 0, 0}); !errors.Is(err, lneto.ErrInvalidField) {
		t.Errorf("wrong type: err=%v", err)
	}
}
