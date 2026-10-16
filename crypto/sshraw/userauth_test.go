package sshraw

import (
	"bytes"
	"errors"
	"testing"

	"github.com/soypat/lneto"
)

// TestPublicKeyAuthData checks the signed data against bytes encoded by hand.
func TestPublicKeyAuthData(t *testing.T) {
	sid := []byte{0xaa, 0xbb}
	want := []byte{
		0, 0, 0, 2, 0xaa, 0xbb,
		byte(MsgUserauthRequest),
		0, 0, 0, 1, 'u',
		0, 0, 0, 14, 's', 's', 'h', '-', 'c', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n',
		0, 0, 0, 9, 'p', 'u', 'b', 'l', 'i', 'c', 'k', 'e', 'y',
		1,
		0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9',
		0, 0, 0, 3, 'k', 'e', 'y',
	}
	var e Encoder
	e.Reset(make([]byte, 128), 0)
	e.PublicKeyAuthData(sid, []byte("u"), []byte("ssh-connection"), []byte("ssh-ed25519"), []byte("key"))
	if err := e.Err(); err != nil {
		t.Fatal(err)
	} else if got := e.Since(0); !bytes.Equal(got, want) {
		t.Fatalf("signed data %x, want %x", got, want)
	}

	for _, tc := range []struct {
		name    string
		sid     []byte
		alg     string
		bufLen  int
		wantErr error
	}{
		{"no session id", nil, "ssh-ed25519", 128, lneto.ErrBadState},
		{"bad alg", sid, "ssh ed25519", 128, lneto.ErrInvalidField},
		{"short buffer", sid, "ssh-ed25519", len(want) - 1, lneto.ErrShortBuffer},
	} {
		e.Reset(make([]byte, tc.bufLen), 0)
		e.PublicKeyAuthData(tc.sid, []byte("u"), []byte("ssh-connection"), []byte(tc.alg), []byte("key"))
		if err := e.Err(); !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: err=%v, want %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestParseUserauthRequest(t *testing.T) {
	payload := encode(t, func(e *Encoder) {
		e.Uint8(uint8(MsgUserauthRequest))
		e.Str("u")
		e.Str("ssh-connection")
		e.Str(MethodNone)
	})
	user, service, method, data, err := ParseUserauthRequest(payload)
	if err != nil || string(user) != "u" || string(service) != "ssh-connection" || string(method) != MethodNone || len(data) != 0 {
		t.Fatalf("got %q %q %q %x err=%v", user, service, method, data, err)
	}
	checkParseErrs(t, payload, func(p []byte) error { _, _, _, _, err := ParseUserauthRequest(p); return err }, false)
	withData := append(bytes.Clone(payload), 1, 2)
	if _, _, _, data, err = ParseUserauthRequest(withData); err != nil || !bytes.Equal(data, []byte{1, 2}) {
		t.Fatalf("methodData=%x err=%v, want 0102", data, err)
	}
	bad := encode(t, func(e *Encoder) { e.Uint8(uint8(MsgUserauthRequest)); e.Str("u"); e.Str("s"); e.Str("bad method") })
	if _, _, _, _, err = ParseUserauthRequest(bad); !errors.Is(err, lneto.ErrInvalidField) {
		t.Fatalf("bad method err=%v, want %v", err, lneto.ErrInvalidField)
	}
}

func TestParsePublicKeyAuth(t *testing.T) {
	unsigned := encode(t, func(e *Encoder) { e.Bool(false); e.Str("ssh-ed25519"); e.Str("key") })
	signed, alg, key, sig, err := ParsePublicKeyAuth(unsigned)
	if err != nil || signed || string(alg) != "ssh-ed25519" || string(key) != "key" || sig != nil {
		t.Fatalf("unsigned: got %v %q %q %q err=%v", signed, alg, key, sig, err)
	}
	checkDataErrs(t, unsigned, func(p []byte) error { _, _, _, _, err := ParsePublicKeyAuth(p); return err })
	withSig := encode(t, func(e *Encoder) { e.Bool(true); e.Str("ssh-ed25519"); e.Str("key"); e.Str("sig") })
	if signed, _, _, sig, err = ParsePublicKeyAuth(withSig); err != nil || !signed || string(sig) != "sig" {
		t.Fatalf("signed: got %v %q err=%v", signed, sig, err)
	}
	checkDataErrs(t, withSig, func(p []byte) error { _, _, _, _, err := ParsePublicKeyAuth(p); return err })
	if _, _, _, _, err = ParsePublicKeyAuth(withSig[:len(withSig)-7]); err == nil {
		t.Fatal("signed without signature: no error")
	}
	badAlg := encode(t, func(e *Encoder) { e.Bool(false); e.Str("ssh ed25519"); e.Str("key") })
	if _, _, _, _, err = ParsePublicKeyAuth(badAlg); !errors.Is(err, lneto.ErrInvalidField) {
		t.Fatalf("bad alg err=%v, want %v", err, lneto.ErrInvalidField)
	}
}

func TestParsePasswordAuth(t *testing.T) {
	plain := encode(t, func(e *Encoder) { e.Bool(false); e.Str("pw") })
	change, pw, newPw, err := ParsePasswordAuth(plain)
	if err != nil || change || string(pw) != "pw" || newPw != nil {
		t.Fatalf("got %v %q %q err=%v", change, pw, newPw, err)
	}
	checkDataErrs(t, plain, func(p []byte) error { _, _, _, err := ParsePasswordAuth(p); return err })
	changing := encode(t, func(e *Encoder) { e.Bool(true); e.Str("old"); e.Str("new") })
	if change, pw, newPw, err = ParsePasswordAuth(changing); err != nil || !change || string(pw) != "old" || string(newPw) != "new" {
		t.Fatalf("change: got %v %q %q err=%v", change, pw, newPw, err)
	}
	checkDataErrs(t, changing, func(p []byte) error { _, _, _, err := ParsePasswordAuth(p); return err })
}

func TestParseKeyboardInteractiveAuth(t *testing.T) {
	data := encode(t, func(e *Encoder) { e.Str(""); e.Str("pam") })
	lang, submethods, err := ParseKeyboardInteractiveAuth(data)
	if err != nil || len(lang) != 0 || string(submethods) != "pam" {
		t.Fatalf("got %q %q err=%v", lang, submethods, err)
	}
	checkDataErrs(t, data, func(p []byte) error { _, _, err := ParseKeyboardInteractiveAuth(p); return err })
}

func TestParseUserauthFailure(t *testing.T) {
	payload := encode(t, func(e *Encoder) {
		e.Uint8(uint8(MsgUserauthFailure))
		e.NameList(MethodPublicKey, MethodPassword)
		e.Bool(true)
	})
	methods, partial, err := ParseUserauthFailure(payload)
	if err != nil || string(methods) != "publickey,password" || !partial {
		t.Fatalf("got %q %v err=%v", methods, partial, err)
	}
	checkParseErrs(t, payload, func(p []byte) error { _, _, err := ParseUserauthFailure(p); return err }, true)
	bad := encode(t, func(e *Encoder) { e.Uint8(uint8(MsgUserauthFailure)); e.Str("public key"); e.Bool(false) })
	if _, _, err = ParseUserauthFailure(bad); !errors.Is(err, lneto.ErrInvalidField) {
		t.Fatalf("bad name-list err=%v, want %v", err, lneto.ErrInvalidField)
	}
}

func TestParseUserauthSmall(t *testing.T) {
	success := []byte{byte(MsgUserauthSuccess)}
	if err := ParseUserauthSuccess(success); err != nil {
		t.Fatal(err)
	} else if err = ParseUserauthSuccess(append(bytes.Clone(success), 0)); err == nil {
		t.Fatal("success with trailing byte: no error")
	} else if err = ParseUserauthSuccess([]byte{byte(MsgUserauthFailure)}); err == nil {
		t.Fatal("success with wrong type: no error")
	}

	banner := encode(t, func(e *Encoder) { e.Uint8(uint8(MsgUserauthBanner)); e.Str("hi"); e.Str("en") })
	if msg, lang, err := ParseUserauthBanner(banner); err != nil || string(msg) != "hi" || string(lang) != "en" {
		t.Fatalf("banner: got %q %q err=%v", msg, lang, err)
	}
	checkParseErrs(t, banner, func(p []byte) error { _, _, err := ParseUserauthBanner(p); return err }, true)

	pkok := encode(t, func(e *Encoder) { e.Uint8(uint8(MsgUserauthPKOK)); e.Str("ssh-ed25519"); e.Str("key") })
	if alg, key, err := ParseUserauthPKOK(pkok); err != nil || string(alg) != "ssh-ed25519" || string(key) != "key" {
		t.Fatalf("pk_ok: got %q %q err=%v", alg, key, err)
	}
	checkParseErrs(t, pkok, func(p []byte) error { _, _, err := ParseUserauthPKOK(p); return err }, true)

	changeReq := encode(t, func(e *Encoder) { e.Uint8(uint8(MsgUserauthPasswdChangeReq)); e.Str("expired"); e.Str("") })
	if prompt, lang, err := ParseUserauthPasswdChangeReq(changeReq); err != nil || string(prompt) != "expired" || len(lang) != 0 {
		t.Fatalf("passwd_changereq: got %q %q err=%v", prompt, lang, err)
	}
	checkParseErrs(t, changeReq, func(p []byte) error { _, _, err := ParseUserauthPasswdChangeReq(p); return err }, true)
}

func TestUserauthInfoRequest(t *testing.T) {
	infoRequest := func(count uint32, prompts ...string) []byte {
		return encode(t, func(e *Encoder) {
			e.Uint8(uint8(MsgUserauthInfoRequest))
			e.Str("name")
			e.Str("instr")
			e.Str("")
			e.Uint32(count)
			for i, p := range prompts {
				e.Str(p)
				e.Bool(i == 0)
			}
		})
	}
	payload := infoRequest(2, "Password: ", "OTP: ")
	name, instruction, lang, prompts, err := ValidateUserauthInfoRequest(payload)
	if err != nil || string(name) != "name" || string(instruction) != "instr" || len(lang) != 0 {
		t.Fatalf("got %q %q %q err=%v", name, instruction, lang, err)
	}
	for i, want := range []string{"Password: ", "OTP: "} {
		prompt, echo, n, err := NextUserauthPrompt(prompts)
		if err != nil || string(prompt) != want || echo != (i == 0) {
			t.Fatalf("prompt %d: got %q echo=%v err=%v", i, prompt, echo, err)
		}
		prompts = prompts[n:]
	}
	if len(prompts) != 0 {
		t.Fatalf("%d bytes left after prompts", len(prompts))
	}
	checkParseErrs(t, payload, func(p []byte) error { _, _, _, _, err := ValidateUserauthInfoRequest(p); return err }, true)
	for name, p := range map[string][]byte{
		"count over":  infoRequest(3, "a", "b"),
		"count under": infoRequest(1, "a", "b"),
		"huge count":  infoRequest(^uint32(0), "a"),
	} {
		if _, _, _, _, err := ValidateUserauthInfoRequest(p); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, _, _, prompts, err = ValidateUserauthInfoRequest(infoRequest(0)); err != nil || len(prompts) != 0 {
		t.Fatalf("no prompts: %x err=%v", prompts, err)
	}
}

func TestUserauthInfoResponse(t *testing.T) {
	infoResponse := func(count uint32, responses ...string) []byte {
		return encode(t, func(e *Encoder) {
			e.Uint8(uint8(MsgUserauthInfoResponse))
			e.Uint32(count)
			for _, r := range responses {
				e.Str(r)
			}
		})
	}
	payload := infoResponse(2, "pw", "123456")
	responses, err := ValidateUserauthInfoResponse(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pw", "123456"} {
		resp, n, err := NextUserauthResponse(responses)
		if err != nil || string(resp) != want {
			t.Fatalf("got %q err=%v, want %q", resp, err, want)
		}
		responses = responses[n:]
	}
	if len(responses) != 0 {
		t.Fatalf("%d bytes left after responses", len(responses))
	}
	checkParseErrs(t, payload, func(p []byte) error { _, err := ValidateUserauthInfoResponse(p); return err }, true)
	for name, p := range map[string][]byte{
		"count over":  infoResponse(3, "a", "b"),
		"count under": infoResponse(1, "a", "b"),
		"huge count":  infoResponse(^uint32(0), "a"),
	} {
		if _, err := ValidateUserauthInfoResponse(p); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// checkDataErrs checks parse rejects message data, such as method or request data,
// empty, truncated or with a trailing byte.
func checkDataErrs(t *testing.T, data []byte, parse func([]byte) error) {
	t.Helper()
	if err := parse(data[:len(data)-1]); err == nil {
		t.Error("truncated: no error")
	} else if err = parse(append(bytes.Clone(data), 0)); err == nil {
		t.Error("trailing: no error")
	} else if err = parse(nil); err == nil {
		t.Error("empty: no error")
	}
}
