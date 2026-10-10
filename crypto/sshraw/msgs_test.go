package sshraw

import "testing"

// encode returns the payload written by fn.
func encode(t *testing.T, fn func(e *Encoder)) []byte {
	t.Helper()
	var e Encoder
	e.Reset(make([]byte, 128), 0)
	fn(&e)
	if e.IsFailed() {
		t.Fatal("encode failed")
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
	reason, desc, lang, err := ParseDisconnect(payload)
	if err != nil || reason != DisconnectHostNotAllowedToConnect || string(desc) != "bye" || string(lang) != "en" {
		t.Fatalf("got %v %q %q err=%v", reason, desc, lang, err)
	}
	// Lenient: the connection ends, so trailing bytes are fine.
	if _, _, _, err = ParseDisconnect(append(payload, 0)); err != nil {
		t.Fatal(err)
	}
	checkParseErrs(t, payload, func(p []byte) error { _, _, _, err := ParseDisconnect(p); return err }, false)
}

func TestParseServiceName(t *testing.T) {
	for _, typ := range []MsgType{MsgServiceRequest, MsgServiceAccept} {
		payload := encode(t, func(e *Encoder) { e.Uint8(uint8(typ)); e.Str("ssh-userauth") })
		if name, err := ParseServiceName(payload); err != nil || string(name) != "ssh-userauth" {
			t.Fatalf("%v: got %q err=%v", typ, name, err)
		}
		checkParseErrs(t, payload, func(p []byte) error { _, err := ParseServiceName(p); return err }, true)
	}
}

func TestParseUnimplemented(t *testing.T) {
	payload := encode(t, func(e *Encoder) { e.Uint8(uint8(MsgUnimplemented)); e.Uint32(0xdeadbeef) })
	if seq, err := ParseUnimplemented(payload); err != nil || seq != 0xdeadbeef {
		t.Fatalf("got %#x err=%v", seq, err)
	}
	checkParseErrs(t, payload, func(p []byte) error { _, err := ParseUnimplemented(p); return err }, true)
}

func TestParseDebug(t *testing.T) {
	payload := encode(t, func(e *Encoder) { e.Uint8(uint8(MsgDebug)); e.Bool(true); e.Str("hi"); e.Str("en") })
	if display, msg, lang, err := ParseDebug(payload); err != nil || !display || string(msg) != "hi" || string(lang) != "en" {
		t.Fatalf("got %v %q %q err=%v", display, msg, lang, err)
	}
	checkParseErrs(t, payload, func(p []byte) error { _, _, _, err := ParseDebug(p); return err }, true)
}

func TestMsgTypeRanges(t *testing.T) {
	type ranges struct{ transport, kex, userauth, connection, channel, local bool }
	for _, tc := range []struct {
		typ  MsgType
		want ranges
	}{
		{0, ranges{}},
		{MsgDisconnect, ranges{transport: true}},
		{19, ranges{transport: true}},
		{MsgKexInit, ranges{transport: true, kex: true}},
		{MsgNewKeys, ranges{transport: true, kex: true}},
		{MsgKexECDHInit, ranges{transport: true, kex: true}},
		{49, ranges{transport: true, kex: true}},
		{MsgUserauthRequest, ranges{userauth: true}},
		{79, ranges{userauth: true}},
		{MsgGlobalRequest, ranges{connection: true}},
		{89, ranges{connection: true}},
		{MsgChannelOpen, ranges{connection: true, channel: true}},
		{127, ranges{connection: true, channel: true}},
		{128, ranges{}},
		{191, ranges{}},
		{192, ranges{local: true}},
		{255, ranges{local: true}},
	} {
		got := ranges{tc.typ.IsTransport(), tc.typ.IsKex(), tc.typ.IsUserauth(), tc.typ.IsConnection(), tc.typ.IsChannel(), tc.typ.IsLocal()}
		if got != tc.want {
			t.Errorf("%d: got %+v, want %+v", tc.typ, got, tc.want)
		}
	}
}

func TestParseIgnore(t *testing.T) {
	payload := encode(t, func(e *Encoder) { e.Uint8(uint8(MsgIgnore)); e.Str("pad") })
	if data, err := ParseIgnore(payload); err != nil || string(data) != "pad" {
		t.Fatalf("got %q err=%v", data, err)
	}
	checkParseErrs(t, payload, func(p []byte) error { _, err := ParseIgnore(p); return err }, true)
}

func TestParseNewKeys(t *testing.T) {
	payload := []byte{byte(MsgNewKeys)}
	if err := ParseNewKeys(payload); err != nil {
		t.Fatal(err)
	}
	checkParseErrs(t, payload, func(p []byte) error { return ParseNewKeys(p) }, true)
}

func TestParseKexECDHInit(t *testing.T) {
	payload := encode(t, func(e *Encoder) { e.Uint8(uint8(MsgKexECDHInit)); e.String(make([]byte, 32)) })
	if qc, err := ParseKexECDHInit(payload); err != nil || len(qc) != 32 {
		t.Fatalf("got %d bytes err=%v", len(qc), err)
	}
	checkParseErrs(t, payload, func(p []byte) error { _, err := ParseKexECDHInit(p); return err }, true)
}

func TestParseKexECDHReply(t *testing.T) {
	payload := encode(t, func(e *Encoder) {
		e.Uint8(uint8(MsgKexECDHReply))
		e.Str("hostkey")
		e.String(make([]byte, 32))
		e.Str("signature")
	})
	hostKey, qs, sig, err := ParseKexECDHReply(payload)
	if err != nil || string(hostKey) != "hostkey" || len(qs) != 32 || string(sig) != "signature" {
		t.Fatalf("got %q %d bytes %q err=%v", hostKey, len(qs), sig, err)
	}
	checkParseErrs(t, payload, func(p []byte) error { _, _, _, err := ParseKexECDHReply(p); return err }, true)
}

// checkParseErrs checks parse rejects payload truncated, with a wrong message type and,
// when strict, with a trailing byte. It also checks a failed parse leaves no error behind.
func checkParseErrs(t *testing.T, payload []byte, parse func([]byte) error, strict bool) {
	t.Helper()
	wrong := MsgIgnore
	if len(payload) > 0 && MsgType(payload[0]) == MsgIgnore {
		wrong = MsgDebug
	}
	wrongType := append([]byte{byte(wrong)}, payload[1:]...)
	trailing := append(append([]byte{}, payload...), 0)
	cases := []struct {
		name string
		p    []byte
	}{
		{"truncated", payload[:len(payload)-1]},
		{"empty", nil},
		{"wrong type", wrongType},
	}
	if strict {
		cases = append(cases, struct {
			name string
			p    []byte
		}{"trailing", trailing})
	}
	for _, c := range cases {
		if err := parse(c.p); err == nil {
			t.Errorf("%s: no error", c.name)
		}
	}
	if err := parse(payload); err != nil {
		t.Errorf("valid after errors: %v", err)
	}
}
