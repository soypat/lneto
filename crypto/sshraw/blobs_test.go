package sshraw

import (
	"bytes"
	"testing"
)

func TestParseSignature(t *testing.T) {
	blob := encode(t, func(e *Encoder) { e.Str("ssh-ed25519"); e.String(bytes.Repeat([]byte{0xab}, 64)) })
	alg, sig, err := ParseSignature(blob)
	if err != nil || string(alg) != "ssh-ed25519" || len(sig) != 64 || sig[0] != 0xab {
		t.Fatalf("got %q %d bytes err=%v", alg, len(sig), err)
	}
	checkBlobErrs(t, blob, func(p []byte) error { _, _, err := ParseSignature(p); return err })
}

func TestParseECDSASignature(t *testing.T) {
	r := []byte{0x80, 1, 2} // High bit set: encoded with a leading zero.
	s := []byte{0x7f, 3}
	sig := encode(t, func(e *Encoder) { e.MPInt(r); e.MPInt(s) })
	gotR, gotS, err := ParseECDSASignature(sig)
	if err != nil || !bytes.Equal(gotR, r) || !bytes.Equal(gotS, s) {
		t.Fatalf("got r=%x s=%x err=%v", gotR, gotS, err)
	}
	parse := func(p []byte) error { _, _, err := ParseECDSASignature(p); return err }
	checkBlobErrs(t, sig, parse)
	checkRejects(t, parse, map[string][]byte{
		"negative r":     encode(t, func(e *Encoder) { e.String([]byte{0x80}); e.MPInt(s) }),
		"leading zero s": encode(t, func(e *Encoder) { e.MPInt(r); e.String([]byte{0, 0x7f}) }),
		"lone zero byte": encode(t, func(e *Encoder) { e.String([]byte{0}); e.MPInt(s) }),
	})
}

func TestParseEd25519PublicKey(t *testing.T) {
	blob := encode(t, func(e *Encoder) { e.Str("ssh-ed25519"); e.String(bytes.Repeat([]byte{0xcd}, 32)) })
	key, err := ParseEd25519PublicKey(blob)
	if err != nil || len(key) != 32 || key[0] != 0xcd {
		t.Fatalf("got %x err=%v", key, err)
	}
	parse := func(p []byte) error { _, err := ParseEd25519PublicKey(p); return err }
	checkBlobErrs(t, blob, parse)
	checkRejects(t, parse, map[string][]byte{
		"wrong name": encode(t, func(e *Encoder) { e.Str("ssh-rsa"); e.String(make([]byte, 32)) }),
		"short key":  encode(t, func(e *Encoder) { e.Str("ssh-ed25519"); e.String(make([]byte, 31)) }),
		"long key":   encode(t, func(e *Encoder) { e.Str("ssh-ed25519"); e.String(make([]byte, 33)) }),
	})
}

func TestParseECDSAPublicKey(t *testing.T) {
	q := append([]byte{4}, bytes.Repeat([]byte{0xef}, 64)...)
	blob := encode(t, func(e *Encoder) { e.Str("ecdsa-sha2-nistp256"); e.Str("nistp256"); e.String(q) })
	curve, gotQ, err := ParseECDSAPublicKey(blob)
	if err != nil || string(curve) != "nistp256" || !bytes.Equal(gotQ, q) {
		t.Fatalf("got %q %x err=%v", curve, gotQ, err)
	}
	parse := func(p []byte) error { _, _, err := ParseECDSAPublicKey(p); return err }
	checkBlobErrs(t, blob, parse)
	checkRejects(t, parse, map[string][]byte{
		"curve mismatch": encode(t, func(e *Encoder) { e.Str("ecdsa-sha2-nistp256"); e.Str("nistp384"); e.String(q) }),
		"bare prefix":    encode(t, func(e *Encoder) { e.Str("ecdsa-sha2-"); e.Str(""); e.String(q) }),
		"not ecdsa":      encode(t, func(e *Encoder) { e.Str("ssh-ed25519"); e.Str("ssh-ed25519"); e.String(q) }),
		"prefix only":    encode(t, func(e *Encoder) { e.Str("ecdsa-sha2"); e.Str("nistp256"); e.String(q) }),
	})
}

func TestParseRSAPublicKey(t *testing.T) {
	pubE := []byte{1, 0, 1}
	n := append([]byte{0xc1}, bytes.Repeat([]byte{0x55}, 31)...) // High bit set: encoded with a leading zero.
	blob := encode(t, func(e *Encoder) { e.Str("ssh-rsa"); e.MPInt(pubE); e.MPInt(n) })
	gotE, gotN, err := ParseRSAPublicKey(blob)
	if err != nil || !bytes.Equal(gotE, pubE) || !bytes.Equal(gotN, n) {
		t.Fatalf("got e=%x n=%x err=%v", gotE, gotN, err)
	}
	parse := func(p []byte) error { _, _, err := ParseRSAPublicKey(p); return err }
	checkBlobErrs(t, blob, parse)
	checkRejects(t, parse, map[string][]byte{
		"wrong name":   encode(t, func(e *Encoder) { e.Str("rsa-sha2-256"); e.MPInt(pubE); e.MPInt(n) }),
		"zero e":       encode(t, func(e *Encoder) { e.Str("ssh-rsa"); e.MPInt(nil); e.MPInt(n) }),
		"zero n":       encode(t, func(e *Encoder) { e.Str("ssh-rsa"); e.MPInt(pubE); e.MPInt(nil) }),
		"negative n":   encode(t, func(e *Encoder) { e.Str("ssh-rsa"); e.MPInt(pubE); e.String(n) }),
		"leading zero": encode(t, func(e *Encoder) { e.Str("ssh-rsa"); e.String([]byte{0, 1, 0, 1}); e.MPInt(n) }),
	})
}

// checkBlobErrs checks parse rejects blob truncated, empty and with a trailing
// byte, then still accepts blob.
func checkBlobErrs(t *testing.T, blob []byte, parse func([]byte) error) {
	t.Helper()
	checkRejects(t, parse, map[string][]byte{
		"truncated": blob[:len(blob)-1],
		"empty":     nil,
		"trailing":  append(append([]byte{}, blob...), 0),
	})
	if err := parse(blob); err != nil {
		t.Errorf("valid after errors: %v", err)
	}
}

// checkRejects checks parse fails on every blob of bad.
func checkRejects(t *testing.T, parse func([]byte) error, bad map[string][]byte) {
	t.Helper()
	for name, p := range bad {
		if err := parse(p); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
