package tls

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/soypat/lneto"
)

var (
	vecClientHello = mustHex(`
01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83
02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01
00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 33 00
26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69
1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01
05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01`)
	vecServerPriv = mustHex(`b1 58 0e ea df 6d d5 89 b8 ef 4f 2d 56 52 57 8c c8 10 e9 98 01 91 ec 8d 05 83 08 ce a2 16 a2 1e`)
	vecServerPub  = mustHex(`c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f`)
	vecWantShared = mustHex(`8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d`)
)

// TestHandshakeRFC8448 walks the Simple 1-RTT Handshake of RFC 8448 3 from the server side.
func TestHandshakeRFC8448(t *testing.T) {

	// ClientHello.
	var vld lneto.Validator
	body := vecClientHello[SizeHeaderHandshake:]
	var ch HelloClientMsg
	n, err := ch.Decode(body, &vld)
	if err != nil {
		t.Fatal(err)
	} else if n != len(body) {
		t.Fatalf("Decode consumed %d bytes, want %d", n, len(body))
	}
	const extsOff = 2 + SizeHelloRandom + 1 + 2 + 6 + 1 + 1 + 2
	var clientShare []byte
	for exts := body[extsOff:]; len(exts) > 0; {
		ef, err := NewExtensionFrame(exts)
		if err != nil {
			t.Fatal(err)
		}
		ef.ValidateType(&vld, false)
		if err := vld.ErrPop(); err != nil {
			t.Fatalf("extension %d: %v", ef.Type(), err)
		}
		if ef.Type() == ExtKeyShare {
			for shares := ef.Data()[2:]; len(shares) > 0; {
				group, key, n, err := NextKeyShare(shares, false)
				if err != nil {
					t.Fatal(err)
				} else if group == GroupX25519 {
					clientShare = key
				}
				shares = shares[n:]
			}
		}
		exts = exts[len(ef.RawData()):]
	}
	if clientShare == nil {
		t.Fatal("no x25519 key share")
	}

	// Key exchange.
	priv, err := ecdh.X25519().NewPrivateKey(vecServerPriv)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(priv.PublicKey().Bytes(), vecServerPub) {
		t.Fatalf("server public key=%x, want %x", priv.PublicKey().Bytes(), vecServerPub)
	}
	peer, err := ecdh.X25519().NewPublicKey(clientShare)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(shared, vecWantShared) {
		t.Fatalf("shared secret=%x, want %x", shared, vecWantShared)
	}

	// TODO: ServerHello, key schedule, EncryptedExtensions, Certificate, CertificateVerify, Finished.
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		panic(err)
	}
	return b
}
