package sshraw

import (
	"math"
	"testing"
)

// newExtInfo encodes an EXT_INFO payload declaring n extensions followed by fields
// written as strings, so n may disagree with the fields actually present.
func newExtInfo(t *testing.T, n uint32, fields ...string) []byte {
	t.Helper()
	return encode(t, func(e *Encoder) {
		e.Uint8(uint8(MsgExtInfo))
		e.Uint32(n)
		for _, f := range fields {
			e.Str(f)
		}
	})
}

func TestValidateExtInfo(t *testing.T) {
	want := []string{
		ExtServerSigAlgs, "ssh-ed25519,rsa-sha2-256",
		"no-flow-control", "p",
		"ping@openssh.com", "0",
	}
	payload := newExtInfo(t, 3, want...)
	exts, err := ValidateExtInfo(payload)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for len(exts) > 0 {
		name, value, n, err := NextExtInfo(exts)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, string(name), string(value))
		exts = exts[n:]
	}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d=%q, want %q", i, got[i], want[i])
		}
	}

	if exts, err := ValidateExtInfo(newExtInfo(t, 0)); err != nil || len(exts) != 0 {
		t.Errorf("no extensions: %d bytes err=%v", len(exts), err)
	}
	validate := func(p []byte) error { _, err := ValidateExtInfo(p); return err }
	checkParseErrs(t, payload, validate, true)
	checkRejects(t, validate, map[string][]byte{
		"huge count":    newExtInfo(t, math.MaxUint32, ExtServerSigAlgs, "ssh-ed25519"),
		"count short":   newExtInfo(t, 2, ExtServerSigAlgs, "ssh-ed25519"),
		"count long":    newExtInfo(t, 1, ExtServerSigAlgs, "ssh-ed25519", "ping@openssh.com", "0"),
		"no value":      newExtInfo(t, 1, ExtServerSigAlgs),
		"space in name": newExtInfo(t, 1, "server sig-algs", "ssh-ed25519"),
		"empty name":    newExtInfo(t, 1, "", "ssh-ed25519"),
	})
}

func TestNextExtInfo(t *testing.T) {
	ext := encode(t, func(e *Encoder) { e.Str(ExtServerSigAlgs); e.Str("ssh-ed25519") })
	rest := append(append([]byte{}, ext...), 0xff) // Next extension's bytes are not looked at.
	name, value, n, err := NextExtInfo(rest)
	if err != nil || string(name) != ExtServerSigAlgs || string(value) != "ssh-ed25519" || n != len(ext) {
		t.Fatalf("got %q %q n=%d err=%v, want n=%d", name, value, n, err, len(ext))
	}
	next := func(p []byte) error { _, _, _, err := NextExtInfo(p); return err }
	checkRejects(t, next, map[string][]byte{
		"empty":         nil,
		"truncated":     ext[:len(ext)-1],
		"no value":      encode(t, func(e *Encoder) { e.Str(ExtServerSigAlgs) }),
		"space in name": encode(t, func(e *Encoder) { e.Str("server sig-algs"); e.Str("x") }),
		"empty name":    encode(t, func(e *Encoder) { e.Str(""); e.Str("x") }),
	})
}
