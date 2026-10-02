package sshraw

import (
	"errors"
	"testing"

	"github.com/soypat/lneto"
)

// encode returns the payload written by fn.
func encode(t *testing.T, fn func(e *Encoder)) []byte {
	t.Helper()
	var e Encoder
	e.Reset(make([]byte, 128), 0)
	fn(&e)
	if e.Err() != nil {
		t.Fatal(e.Err())
	}
	return e.Since(0)
}

func TestParseDisconnect(t *testing.T) {
	payload := encode(t, func(e *Encoder) {
		e.Uint8(uint8(MsgDisconnect))
		e.Uint32(uint32(DisconnectHostNotAllowedToConnect))
		e.Str("bye")
		e.Str("en")
	})
	var vld lneto.Validator
	reason, desc, lang, err := ParseDisconnect(&vld, payload)
	if err != nil || reason != DisconnectHostNotAllowedToConnect || string(desc) != "bye" || string(lang) != "en" {
		t.Fatalf("got %v %q %q err=%v", reason, desc, lang, err)
	}
	// Lenient: the connection ends, so trailing bytes are fine.
	if _, _, _, err = ParseDisconnect(&vld, append(payload, 0)); err != nil {
		t.Fatal(err)
	}
	checkParseErrs(t, payload, func(p []byte) error { _, _, _, err := ParseDisconnect(&vld, p); return err }, false)
}

func TestParseServiceName(t *testing.T) {
	for _, typ := range []MsgType{MsgServiceRequest, MsgServiceAccept} {
		payload := encode(t, func(e *Encoder) { e.Uint8(uint8(typ)); e.Str("ssh-userauth") })
		var vld lneto.Validator
		if name, err := ParseServiceName(&vld, payload); err != nil || string(name) != "ssh-userauth" {
			t.Fatalf("%v: got %q err=%v", typ, name, err)
		}
		checkParseErrs(t, payload, func(p []byte) error { _, err := ParseServiceName(&vld, p); return err }, true)
	}
}

func TestParseUnimplemented(t *testing.T) {
	payload := encode(t, func(e *Encoder) { e.Uint8(uint8(MsgUnimplemented)); e.Uint32(0xdeadbeef) })
	var vld lneto.Validator
	if seq, err := ParseUnimplemented(&vld, payload); err != nil || seq != 0xdeadbeef {
		t.Fatalf("got %#x err=%v", seq, err)
	}
	checkParseErrs(t, payload, func(p []byte) error { _, err := ParseUnimplemented(&vld, p); return err }, true)
}

func TestParseDebug(t *testing.T) {
	payload := encode(t, func(e *Encoder) { e.Uint8(uint8(MsgDebug)); e.Bool(true); e.Str("hi"); e.Str("en") })
	var vld lneto.Validator
	if display, msg, lang, err := ParseDebug(&vld, payload); err != nil || !display || string(msg) != "hi" || string(lang) != "en" {
		t.Fatalf("got %v %q %q err=%v", display, msg, lang, err)
	}
	checkParseErrs(t, payload, func(p []byte) error { _, _, _, err := ParseDebug(&vld, p); return err }, true)
}

func TestParseKexECDHInit(t *testing.T) {
	payload := encode(t, func(e *Encoder) { e.Uint8(uint8(MsgKexECDHInit)); e.String(make([]byte, 32)) })
	var vld lneto.Validator
	if qc, err := ParseKexECDHInit(&vld, payload); err != nil || len(qc) != 32 {
		t.Fatalf("got %d bytes err=%v", len(qc), err)
	}
	checkParseErrs(t, payload, func(p []byte) error { _, err := ParseKexECDHInit(&vld, p); return err }, true)
}

// checkParseErrs checks parse rejects payload truncated, with a wrong message type and,
// when strict, with a trailing byte. It also checks a failed parse leaves no error behind.
func checkParseErrs(t *testing.T, payload []byte, parse func([]byte) error, strict bool) {
	t.Helper()
	wrongType := append([]byte{byte(MsgIgnore)}, payload[1:]...)
	trailing := append(append([]byte{}, payload...), 0)
	cases := []struct {
		name string
		p    []byte
		want error
	}{
		{"truncated", payload[:len(payload)-1], lneto.ErrTruncatedFrame},
		{"empty", nil, lneto.ErrTruncatedFrame},
		{"wrong type", wrongType, lneto.ErrInvalidField},
	}
	if strict {
		cases = append(cases, struct {
			name string
			p    []byte
			want error
		}{"trailing", trailing, lneto.ErrInvalidLengthField})
	}
	for _, c := range cases {
		if err := parse(c.p); !errors.Is(err, c.want) {
			t.Errorf("%s: err=%v, want %v", c.name, err, c.want)
		}
	}
	if err := parse(payload); err != nil {
		t.Errorf("valid after errors: %v", err)
	}
}
