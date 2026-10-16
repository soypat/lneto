package sshraw

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/rfc8448"
)

// newExchangedSchedule returns a KeySchedule past FinishExchange, ready to derive keys.
func newExchangedSchedule(t *testing.T) *KeySchedule {
	t.Helper()
	ks := new(KeySchedule)
	if err := ks.Configure(sha256.New()); err != nil {
		t.Fatal(err)
	} else if err = ks.SetSecret(bytes.Repeat([]byte{0x80}, 32), false); err != nil {
		t.Fatal(err)
	}
	ks.StartExchange()
	ks.HashString([]byte("SSH-2.0-test"))
	ks.FinishExchange()
	return ks
}

// TestInstallKeysState checks installers refuse to derive outside a key exchange or past scratch.
func TestInstallKeysState(t *testing.T) {
	var ks KeySchedule
	if err := ks.Configure(sha256.New()); err != nil {
		t.Fatal(err)
	}
	var hc HalfConn
	if err := ks.InstallCipherFrameKeys(&hc, new(ctrHMAC), 64, true, false); !errors.Is(err, lneto.ErrBadState) {
		t.Fatalf("before exchange err=%v, want %v", err, lneto.ErrBadState)
	}
	if err := newExchangedSchedule(t).InstallCipherFrameKeys(&hc, new(ctrHMAC), 65, true, false); !errors.Is(err, lneto.ErrInvalidConfig) {
		t.Fatalf("oversized key err=%v, want %v", err, lneto.ErrInvalidConfig)
	}
}

// TestInstallKeysRekeySeq checks rekeying through installers keeps seq unless strict, RFC 4253 6.4.
func TestInstallKeysRekeySeq(t *testing.T) {
	for _, tc := range []struct {
		mode    string
		install func(ks *KeySchedule, hc *HalfConn, strict bool) error
	}{
		{"aead", func(ks *KeySchedule, hc *HalfConn, strict bool) error {
			return ks.InstallCipherAEADKeys(hc, rfc8448.NewAES128GCM(), 16, true, strict)
		}},
		{"frame", func(ks *KeySchedule, hc *HalfConn, strict bool) error {
			return ks.InstallCipherFrameKeys(hc, new(ctrHMAC), 64, true, strict)
		}},
	} {
		for _, strict := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/strict=%v", tc.mode, strict), func(t *testing.T) {
				var hc HalfConn
				for range 2 { // Initial key exchange, then a rekey.
					mustSeal(t, &hc, byte(MsgIgnore))
					mustSeal(t, &hc, byte(MsgNewKeys))
					before := hc.Seq()
					hc.WipeKeys()
					if err := tc.install(newExchangedSchedule(t), &hc, strict); err != nil {
						t.Fatal(err)
					}
					if want := before * uint32(b2i(!strict)); hc.Seq() != want {
						t.Fatalf("seq=%d after installing keys, want %d", hc.Seq(), want)
					}
				}
				mustSeal(t, &hc, byte(MsgIgnore))
			})
		}
	}
}

// TestInstallKeysFailClosed checks a failed install blocks Seal/Open instead of falling back to plaintext.
func TestInstallKeysFailClosed(t *testing.T) {
	ks := newExchangedSchedule(t)
	var hc HalfConn
	// canInstall accepts a 32 byte key but ctrHMAC.Rekey wants 64.
	if err := ks.InstallCipherFrameKeys(&hc, new(ctrHMAC), 32, true, false); err == nil {
		t.Fatal("install succeeded with bad key length")
	}
	checkFailClosed(t, &hc)
}

// checkFailClosed checks hc refuses to Seal and Open.
func checkFailClosed(t *testing.T, hc *HalfConn) {
	t.Helper()
	if _, err := hc.Seal(newPacket(t, []byte{byte(MsgIgnore)}, hc.Overhead(), hc.BlockSize())); !errors.Is(err, lneto.ErrBadState) {
		t.Errorf("Seal err=%v, want %v", err, lneto.ErrBadState)
	}
	if _, err := hc.Open(newPacket(t, []byte{byte(MsgIgnore)}, hc.Overhead(), hc.BlockSize())); !errors.Is(err, lneto.ErrBadState) {
		t.Errorf("Open err=%v, want %v", err, lneto.ErrBadState)
	}
}

// TestInstallKeysDirection checks installers key hc with the letters of the
// direction given, as deriving and rekeying by hand does, RFC 4253 7.2.
func TestInstallKeysDirection(t *testing.T) {
	for _, clientToServer := range []bool{true, false} {
		ivLetter, keyLetter := IVServerToClient, KeyServerToClient
		if clientToServer {
			ivLetter, keyLetter = IVClientToServer, KeyClientToServer
		}
		t.Run(fmt.Sprintf("aead/clientToServer=%v", clientToServer), func(t *testing.T) {
			const keyLen = 16
			ks := newExchangedSchedule(t)
			var got, want HalfConn
			if err := ks.InstallCipherAEADKeys(&got, rfc8448.NewAES128GCM(), keyLen, clientToServer, false); err != nil {
				t.Fatal(err)
			}
			var iv [12]byte
			key := make([]byte, keyLen)
			ks.Derive(iv[:], ivLetter)
			ks.Derive(key, keyLetter)
			aead := rfc8448.NewAES128GCM()
			if err := aead.Rekey(key); err != nil {
				t.Fatal(err)
			} else if err = want.SetCipherAEAD(aead, &iv, false); err != nil {
				t.Fatal(err)
			}
			checkSameSeal(t, &got, &want)
		})
		t.Run(fmt.Sprintf("frame/clientToServer=%v", clientToServer), func(t *testing.T) {
			const keyLen = 64 // chacha20-poly1305@openssh.com: two 256 bit keys.
			ks := newExchangedSchedule(t)
			var got, want HalfConn
			if err := ks.InstallCipherFrameKeys(&got, new(ctrHMAC), keyLen, clientToServer, false); err != nil {
				t.Fatal(err)
			}
			key := make([]byte, keyLen)
			ks.Derive(key, keyLetter)
			pc := new(ctrHMAC)
			if err := pc.Rekey(key); err != nil {
				t.Fatal(err)
			} else if err = want.SetCipherFrame(pc, false); err != nil {
				t.Fatal(err)
			}
			checkSameSeal(t, &got, &want)
		})
	}
}

// checkSameSeal checks got and want seal the same packet identically.
func checkSameSeal(t *testing.T, got, want *HalfConn) {
	t.Helper()
	payload := []byte{byte(MsgIgnore), 'k'}
	a := newPacket(t, payload, got.Overhead(), got.BlockSize())
	b := newPacket(t, payload, want.Overhead(), want.BlockSize())
	if _, err := got.Seal(a); err != nil {
		t.Fatal(err)
	} else if _, err = want.Seal(b); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(a.RawData(), b.RawData()) {
		t.Fatalf("installed packet %x, want %x", a.RawData(), b.RawData())
	}
}
