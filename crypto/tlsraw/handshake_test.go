package tlsraw

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/rfc8448"
)

// TestHandshakeRFC8448 walks the Simple 1-RTT Handshake of RFC 8448 3 from the server side.
func TestHandshakeRFC8448(t *testing.T) {
	const paranoid = true
	// ClientHello sent by client.
	var scratch [32]byte
	var vld lneto.Validator
	body := rfc8448.ClientHello[SizeHeaderHandshake:]
	var ch HelloClientMsg
	n, err := ch.Decode(body, &vld)
	if err != nil {
		t.Fatal(err)
	} else if n != len(body) {
		t.Fatalf("Decode consumed %d bytes, want %d", n, len(body))
	}
	var clientShare []byte
	walkExtensions(t, ch.Extensions(), false, func(ef ExtensionFrame) {
		if ef.Type() != ExtKeyShare {
			return
		}
		for shares := ef.Data()[2:]; len(shares) > 0; {
			group, key, n, err := NextKeyShare(shares, false)
			if err != nil {
				t.Fatal(err)
			} else if group == GroupX25519 {
				clientShare = key
			}
			shares = shares[n:]
		}
	})
	if clientShare == nil {
		t.Fatal("no x25519 key share")
	}

	// Key exchange.
	priv, err := ecdh.X25519().NewPrivateKey(rfc8448.ServerPriv)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(priv.PublicKey().Bytes(), rfc8448.ServerPub) {
		t.Fatalf("server public key=%x, want %x", priv.PublicKey().Bytes(), rfc8448.ServerPub)
	}
	peer, err := ecdh.X25519().NewPublicKey(clientShare)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(shared, rfc8448.WantShared) {
		t.Fatalf("shared secret=%x, want %x", shared, rfc8448.WantShared)
	}

	// ServerHello.
	body = rfc8448.ServerHello[SizeHeaderHandshake:]
	var sh HelloServerMsg
	n, err = sh.Decode(body, &vld)
	if err != nil {
		t.Fatal(err)
	} else if n != len(body) {
		t.Fatalf("Decode consumed %d bytes, want %d", n, len(body))
	}
	if len(sh.SessionID()) != int(ch.SIDLen()) {
		t.Errorf("session ID echo len=%d, want %d", len(sh.SessionID()), ch.SIDLen())
	}
	if sh.CipherSuite() != SuiteAES128GCMSHA256 {
		t.Errorf("cipher suite=%#x, want %#x", sh.CipherSuite(), SuiteAES128GCMSHA256)
	}
	if sh.Compression() != 0 {
		t.Errorf("compression=%d, want 0", sh.Compression())
	}
	var serverShare []byte
	var version uint16
	walkExtensions(t, sh.Extensions(), true, func(ef ExtensionFrame) {
		switch ef.Type() {
		case ExtKeyShare:
			group, key, _, err := NextKeyShare(ef.Data(), true)
			if err != nil {
				t.Fatal(err)
			} else if group != GroupX25519 {
				t.Fatalf("key share group=%#x, want x25519", group)
			}
			serverShare = key
		case ExtSupportedVersions:
			version = binary.BigEndian.Uint16(ef.Data())
		}
	})
	if !bytes.Equal(serverShare, priv.PublicKey().Bytes()) {
		t.Errorf("server key share=%x, want %x", serverShare, priv.PublicKey().Bytes())
	}
	if version != VersionTLS13 {
		t.Errorf("selected version=%#x, want %#x", version, VersionTLS13)
	}

	// Key schedule, handshake stage.
	// We use bytes.Equal but should use subtle package for constant time comparisons to prevent timing attacks!
	var ks KeySchedule
	ks.Reset(sha256.New(), sha256.New(), paranoid)
	ks.AddMessage(rfc8448.ClientHello)
	ks.AddMessage(rfc8448.ServerHello)
	if ks.TranscriptHash(&scratch); !bytes.Equal(scratch[:], rfc8448.HelloHash) {
		t.Fatalf("transcript hash=%x, want %x", scratch, rfc8448.HelloHash)
	}
	var cHS, sHS [32]byte
	ks.Handshake(&cHS, &sHS, shared)
	if !bytes.Equal(ks.secret[:], rfc8448.HandshakeSecret) {
		t.Fatalf("handshake secret=%x, want %x", ks.secret, rfc8448.HandshakeSecret)
	} else if !bytes.Equal(cHS[:], rfc8448.ClientHSTraffic) {
		t.Fatalf("c hs traffic=%x, want %x", cHS, rfc8448.ClientHSTraffic)
	} else if !bytes.Equal(sHS[:], rfc8448.ServerHSTraffic) {
		t.Fatalf("s hs traffic=%x, want %x", sHS, rfc8448.ServerHSTraffic)
	}
	var sKey, cKey [16]byte
	var sIV, cIV [12]byte
	ks.Keys(&sKey, &sIV, &sHS)
	if !bytes.Equal(sKey[:], rfc8448.ServerHSKey) || !bytes.Equal(sIV[:], rfc8448.ServerHSIV) {
		t.Fatalf("server hs key=%x iv=%x, want %x %x", sKey, sIV, rfc8448.ServerHSKey, rfc8448.ServerHSIV)
	}

	// Server Finished over EncryptedExtensions, Certificate and CertificateVerify.
	ks.AddMessage(rfc8448.EncryptedExtensions)
	ks.AddMessage(rfc8448.Certificate)
	ks.AddMessage(rfc8448.CertificateVerify)
	sFin := rfc8448.ServerFinished[SizeHeaderHandshake:]
	if ks.Finished(&scratch, &sHS); !bytes.Equal(scratch[:], sFin) {
		t.Fatalf("server finished=%x, want %x", scratch, sFin)
	}
	ks.AddMessage(rfc8448.ServerFinished)

	// Client Finished and master stage both cover the transcript up to server Finished.
	if ks.TranscriptHash(&scratch); !bytes.Equal(scratch[:], rfc8448.ServerFinHash) {
		t.Fatalf("transcript hash=%x, want %x", scratch, rfc8448.ServerFinHash)
	}
	if ks.Finished(&scratch, &cHS); !bytes.Equal(scratch[:], rfc8448.ClientVerify) {
		t.Fatalf("client finished=%x, want %x", scratch, rfc8448.ClientVerify)
	}
	var cAP, sAP [32]byte
	ks.Master(&cAP, &sAP)
	if !bytes.Equal(cAP[:], rfc8448.ClientAPTraffic) {
		t.Fatalf("c ap traffic=%x, want %x", cAP, rfc8448.ClientAPTraffic)
	} else if !bytes.Equal(sAP[:], rfc8448.ServerAPTraffic) {
		t.Fatalf("s ap traffic=%x, want %x", sAP, rfc8448.ServerAPTraffic)
	}

	// Server seals its encrypted flight into a single record.
	var sConn HalfConn
	if err := sConn.SetAEAD(newGCM(t, sKey[:]), sIV); err != nil {
		t.Fatal(err)
	}
	flight := make([]byte, SizeHeaderRecord, MaxRecord)
	for _, msg := range [][]byte{rfc8448.EncryptedExtensions, rfc8448.Certificate, rfc8448.CertificateVerify, rfc8448.ServerFinished} {
		flight = append(flight, msg...)
	}
	rec, err := sConn.Seal(flight, ContentTypeHandshake)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(rec, rfc8448.ServerRecord) {
		t.Fatalf("server record=%x, want %x", rec, rfc8448.ServerRecord)
	}

	// Server opens the client Finished record.
	var cConn HalfConn
	ks.Keys(&cKey, &cIV, &cHS)
	if err := cConn.SetAEAD(newGCM(t, cKey[:]), cIV); err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(10, func() {
		ks.Reset(ks.transcript, ks.mac, paranoid)
		ks.AddMessage(rfc8448.ClientHello)
		ks.AddMessage(rfc8448.ServerHello)
		ks.Handshake(&cHS, &sHS, shared)
		ks.Finished(&scratch, &sHS)
		ks.Master(&cAP, &sAP)
		ks.Zeroize()
	})
	if allocs != 0 {
		t.Errorf("key schedule allocs=%v, want 0", allocs)
	}
	rec = append(make([]byte, 0, len(rfc8448.ClientRecord)), rfc8448.ClientRecord...)
	content, ct, err := cConn.Open(rec)
	if err != nil {
		t.Fatal(err)
	} else if ct != ContentTypeHandshake {
		t.Fatalf("content type=%d, want handshake", ct)
	} else if HandshakeType(content[0]) != HandshakeTypeFinished || !bytes.Equal(content[SizeHeaderHandshake:], rfc8448.ClientVerify) {
		t.Fatalf("client finished=%x, want verify_data %x", content, rfc8448.ClientVerify)
	}

	allocs = testing.AllocsPerRun(10, func() {
		sConn.seq = 0
		flight = append(flight[:SizeHeaderRecord], content...)
		rec, _ := sConn.Seal(flight, ContentTypeHandshake)
		sConn.seq = 0
		sConn.Open(rec)
	})
	if allocs != 0 {
		t.Errorf("record protection allocs=%v, want 0", allocs)
	}

	// TODO: application data records with application traffic keys.
}

// walkExtensions validates each extension in exts and passes it to fn.
func walkExtensions(t *testing.T, exts []byte, sentByServer bool, fn func(ExtensionFrame)) {
	t.Helper()
	var vld lneto.Validator
	for len(exts) > 0 {
		ef, err := NewExtensionFrame(exts)
		if err != nil {
			t.Fatal(err)
		}
		ef.ValidateType(&vld, sentByServer)
		if err := vld.ErrPop(); err != nil {
			t.Fatalf("extension %d: %v", ef.Type(), err)
		}
		fn(ef)
		exts = exts[len(ef.RawData()):]
	}
}

func newGCM(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}
