package sshraw

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
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

// TestSetSecretExchanger checks server and client reach the same H and keys
// through an Exchanger, as feeding the shared secret to SetSecret by hand does.
func TestSetSecretExchanger(t *testing.T) {
	for _, hashed := range []bool{false, true} {
		t.Run(fmt.Sprintf("hashed=%v", hashed), func(t *testing.T) {
			var exC, exS x25519Exchanger
			var qc, qs [32]byte
			if _, err := exC.ClientGenerateRekey(qc[:], rand.Reader); err != nil {
				t.Fatal(err)
			}
			priv := exC.priv // Kept to compute the shared secret by hand.
			var server, client, manual KeySchedule
			for _, ks := range []*KeySchedule{&server, &client, &manual} {
				if err := ks.Configure(sha256.New()); err != nil {
					t.Fatal(err)
				}
			}
			n, err := server.SetServerSecret(&exS, qs[:], qc[:], hashed, rand.Reader)
			if err != nil || n != len(qs) {
				t.Fatalf("SetServerSecret n=%d err=%v", n, err)
			} else if err = client.SetClientSecret(&exC, qs[:], hashed); err != nil {
				t.Fatal(err)
			} else if exS.zeroized != 1 || exC.zeroized != 1 {
				t.Fatalf("Zeroize calls server=%d client=%d, want 1", exS.zeroized, exC.zeroized)
			}
			peer, err := ecdh.X25519().NewPublicKey(qs[:])
			if err != nil {
				t.Fatal(err)
			}
			shared, err := priv.ECDH(peer)
			if err != nil {
				t.Fatal(err)
			} else if err = manual.SetSecret(shared, hashed); err != nil {
				t.Fatal(err)
			}
			var wantH, wantKey []byte
			for i, ks := range []*KeySchedule{&server, &client, &manual} {
				ks.StartExchange()
				ks.HashString(qc[:])
				ks.HashString(qs[:])
				ks.FinishExchange()
				key := make([]byte, 16)
				ks.Derive(key, KeyClientToServer)
				if i == 0 {
					wantH, wantKey = ks.ExchangeHash(), key
				} else if !bytes.Equal(ks.ExchangeHash(), wantH) || !bytes.Equal(key, wantKey) {
					t.Fatalf("schedule %d: H=%x key=%x, want H=%x key=%x", i, ks.ExchangeHash(), key, wantH, wantKey)
				}
			}
		})
	}
}

// TestSetSecretExchangerZeroize checks the Exchanger is zeroized once even when the exchange fails.
func TestSetSecretExchangerZeroize(t *testing.T) {
	errFake := errors.New("fake exchanger failure")
	var qc [32]byte
	var exC x25519Exchanger
	if _, err := exC.ClientGenerateRekey(qc[:], rand.Reader); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		ex      x25519Exchanger
		dstQS   int
		server  bool
		wantErr error
	}{
		{"server error", x25519Exchanger{err: errFake}, 32, true, errFake},
		{"server short share", x25519Exchanger{}, 8, true, lneto.ErrShortBuffer},
		{"client error", x25519Exchanger{priv: exC.priv, err: errFake}, 0, false, errFake},
		{"client unkeyed", x25519Exchanger{}, 0, false, lneto.ErrBadState},
	} {
		var ks KeySchedule
		if err := ks.Configure(sha256.New()); err != nil {
			t.Fatal(err)
		}
		var err error
		if tc.server {
			var n int
			n, err = ks.SetServerSecret(&tc.ex, make([]byte, tc.dstQS), qc[:], false, rand.Reader)
			if n != 0 {
				t.Errorf("%s: n=%d on error, want 0", tc.name, n)
			}
		} else {
			err = ks.SetClientSecret(&tc.ex, qc[:], false)
		}
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: err=%v, want %v", tc.name, err, tc.wantErr)
		} else if tc.ex.zeroized != 1 {
			t.Errorf("%s: Zeroize calls=%d, want 1", tc.name, tc.ex.zeroized)
		}
	}
}

// x25519Exchanger is an Exchanger over crypto/ecdh X25519 that counts Zeroize calls.
type x25519Exchanger struct {
	priv     *ecdh.PrivateKey
	err      error // Returned by every method when set.
	zeroized int
}

func (x *x25519Exchanger) ClientGenerateRekey(dst []byte, rand io.Reader) (int, error) {
	if x.err != nil {
		return 0, x.err
	}
	priv, err := ecdh.X25519().GenerateKey(rand)
	if err != nil {
		return 0, err
	}
	pub := priv.PublicKey().Bytes()
	if len(dst) < len(pub) {
		return 0, lneto.ErrShortBuffer
	}
	x.priv = priv
	return copy(dst, pub), nil
}

func (x *x25519Exchanger) ServerSharedRekey(dstShare, dstShared, clientShare []byte, rand io.Reader) (int, int, error) {
	n, err := x.ClientGenerateRekey(dstShare, rand)
	if err != nil {
		return 0, 0, err
	}
	nShared, err := x.ClientShared(dstShared, clientShare)
	if err != nil {
		return 0, 0, err
	}
	return n, nShared, nil
}

func (x *x25519Exchanger) ClientShared(dst, serverShare []byte) (int, error) {
	if x.err != nil {
		return 0, x.err
	} else if x.priv == nil {
		return 0, lneto.ErrBadState
	}
	pub, err := ecdh.X25519().NewPublicKey(serverShare)
	if err != nil {
		return 0, err
	}
	shared, err := x.priv.ECDH(pub)
	if err != nil {
		return 0, err
	} else if len(dst) < len(shared) {
		return 0, lneto.ErrShortBuffer
	}
	return copy(dst, shared), nil
}

func (x *x25519Exchanger) Zeroize() { x.priv = nil; x.zeroized++ }

// TestHashECDH checks HashECDH hashes the fields in RFC 5656 4 order followed by K,
// against a digest computed independently of HashString.
func TestHashECDH(t *testing.T) {
	shared := bytes.Repeat([]byte{0x80}, 32)
	fields := [][]byte{
		[]byte("SSH-2.0-client"), []byte("SSH-2.0-server"),
		{byte(MsgKexInit), 'c'}, {byte(MsgKexInit), 's'},
		[]byte("hostkey"), bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32),
	}
	var e Encoder
	e.Reset(make([]byte, 512), 0)
	for _, f := range fields {
		e.String(f)
	}
	e.MPInt(shared)
	if e.IsFailed() {
		t.Fatal("encode failed")
	}
	want := sha256.Sum256(e.Since(0))

	var ks KeySchedule
	if err := ks.Configure(sha256.New()); err != nil {
		t.Fatal(err)
	} else if err = ks.SetSecret(shared, false); err != nil {
		t.Fatal(err)
	} else if err = ks.HashECDH(fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6]); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(ks.ExchangeHash(), want[:]) {
		t.Fatalf("H=%x, want %x", ks.ExchangeHash(), want)
	} else if !bytes.Equal(ks.SessionID(), want[:]) {
		t.Fatalf("session id=%x, want first H %x", ks.SessionID(), want)
	}
}

// TestHashECDHState checks HashECDH refuses to compute H without a hash or a shared secret,
// which would derive keys from public data alone.
func TestHashECDHState(t *testing.T) {
	var ks KeySchedule
	if err := ks.HashECDH(nil, nil, nil, nil, nil, nil, nil); !errors.Is(err, lneto.ErrBadState) {
		t.Fatalf("unconfigured err=%v, want %v", err, lneto.ErrBadState)
	} else if err = ks.Configure(sha256.New()); err != nil {
		t.Fatal(err)
	} else if err = ks.HashECDH(nil, nil, nil, nil, nil, nil, nil); !errors.Is(err, lneto.ErrBadState) {
		t.Fatalf("no secret err=%v, want %v", err, lneto.ErrBadState)
	} else if len(ks.ExchangeHash()) != 0 || len(ks.SessionID()) != 0 {
		t.Fatal("H or session id set after failed HashECDH")
	}
}
