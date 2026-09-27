package sshraw_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/soypat/lneto"
	ssh "github.com/soypat/lneto/crypto/sshraw"
)

func sshString(b []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) }

// refExchange computes H of RFC 4253 8 / RFC 5656 4 with the standard library.
func refExchange(fields [][]byte, k []byte) []byte {
	h := sha256.New()
	for _, f := range fields {
		h.Write(sshString(f))
	}
	h.Write(k)
	return h.Sum(nil)
}

// refDerive computes RFC 4253 7.2 key derivation of n bytes.
func refDerive(k, h []byte, letter byte, sid []byte, n int) []byte {
	sum := sha256.Sum256(append(append(append(append([]byte{}, k...), h...), letter), sid...))
	out := append([]byte{}, sum[:]...)
	for len(out) < n {
		sum = sha256.Sum256(append(append(append([]byte{}, k...), h...), out...))
		out = append(out, sum[:]...)
	}
	return out[:n]
}

func TestKeySchedule(t *testing.T) {
	var ks ssh.KeySchedule
	if err := ks.Configure(sha256.New()); err != nil {
		t.Fatal(err)
	}
	fields := [][]byte{[]byte("SSH-2.0-client"), []byte("SSH-2.0-server"), {20, 1}, {20, 2}, {0xaa}, {0xbb}, {0xcc}}
	shared := bytes.Repeat([]byte{0x80}, 32) // High bit set: mpint gains a zero byte.
	mpintK := append([]byte{0, 0, 0, 33, 0}, shared...)

	exchange := func(shared []byte, hashed bool) []byte {
		t.Helper()
		if err := ks.SetSecret(shared, hashed); err != nil {
			t.Fatal(err)
		}
		ks.StartExchange()
		for _, f := range fields {
			ks.HashString(f)
		}
		ks.FinishExchange()
		return ks.ExchangeHash()
	}

	h1 := exchange(shared, false)
	if want := refExchange(fields, mpintK); !bytes.Equal(h1, want) {
		t.Fatalf("H=%x, want %x", h1, want)
	} else if !bytes.Equal(ks.SessionID(), h1) {
		t.Fatalf("session id=%x, want first H %x", ks.SessionID(), h1)
	}
	h1 = append([]byte{}, h1...)
	for _, n := range []int{12, 32, 64, 80} {
		dst := make([]byte, n)
		ks.Derive(dst, 'C')
		if want := refDerive(mpintK, h1, 'C', h1, n); !bytes.Equal(dst, want) {
			t.Errorf("Derive %d=%x, want %x", n, dst, want)
		}
	}

	// A rekey computes a new H but keeps the session id, RFC 4253 7.2.
	sum := sha256.Sum256(shared[:31])
	stringK := sshString(sum[:])
	h2 := exchange(shared[:31], true)
	if want := refExchange(fields, stringK); !bytes.Equal(h2, want) {
		t.Fatalf("rekey H=%x, want %x", h2, want)
	} else if !bytes.Equal(ks.SessionID(), h1) {
		t.Fatalf("rekey changed session id")
	}
	dst := make([]byte, 16)
	ks.Derive(dst, 'A')
	if want := refDerive(stringK, h2, 'A', h1, 16); !bytes.Equal(dst, want) {
		t.Errorf("rekey Derive=%x, want %x", dst, want)
	}

	// InstallKeys keys a HalfConn as if key and IV were derived and set by hand.
	var got, want ssh.HalfConn
	if err := ks.InstallKeys(&got, newGCM(t, make([]byte, 32)), 32, 'C', 'A'); err != nil {
		t.Fatal(err)
	}
	var iv [12]byte
	copy(iv[:], refDerive(stringK, h2, 'A', h1, 12))
	if err := want.SetAEAD(newGCM(t, refDerive(stringK, h2, 'C', h1, 32)), &iv); err != nil {
		t.Fatal(err)
	}
	a, _ := got.Seal(encodePacket(t, []byte("x"), 16, true))
	b, _ := want.Seal(encodePacket(t, []byte("x"), 16, true))
	if !bytes.Equal(a, b) {
		t.Errorf("InstallKeys packet=%x, want %x", a, b)
	}

	ks.WipeExchange()
	if len(ks.ExchangeHash()) != 0 || !bytes.Equal(ks.SessionID(), h1) {
		t.Error("WipeExchange must drop H and keep the session id")
	}
	// A rekey may negotiate a method of another hash; the session id stays.
	if err := ks.UseHash(sha512.New()); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(ks.SessionID(), h1) || ks.Size() != 64 {
		t.Error("UseHash must keep the session id")
	}
	ks.Zeroize()
	if len(ks.SessionID()) != 0 {
		t.Error("Zeroize kept the session id")
	}

	allocs := testing.AllocsPerRun(10, func() {
		ks.SetSecret(shared, false)
		ks.StartExchange()
		for _, f := range fields {
			ks.HashString(f)
		}
		ks.FinishExchange()
		ks.Derive(dst, 'A')
		ks.Zeroize()
	})
	if allocs != 0 {
		t.Errorf("key schedule allocs=%v, want 0", allocs)
	}
}

func TestKeyScheduleErrors(t *testing.T) {
	var ks ssh.KeySchedule
	if err := ks.Configure(sha512.New()); err != nil {
		t.Fatalf("sha512: %v", err)
	}
	if err := ks.SetSecret(make([]byte, 65), false); !errors.Is(err, lneto.ErrUnsupported) {
		t.Errorf("oversized secret err=%v, want %v", err, lneto.ErrUnsupported)
	}
	var hc ssh.HalfConn
	if err := ks.InstallKeys(&hc, newGCM(t, make([]byte, 16)), 65, 'C', 'A'); !errors.Is(err, lneto.ErrInvalidConfig) {
		t.Errorf("oversized key err=%v, want %v", err, lneto.ErrInvalidConfig)
	}
}
