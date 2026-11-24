package tlsauto

import (
	"bytes"
	"testing"

	"github.com/soypat/lneto/crypto/tlsraw"
)

// TestHandshakeCommonRoles runs the key schedule and the authentication
// messages of RFC 8446 4.4 as client and as server against each other, so the
// server side of handshakeCommon is checked before a server handshake drives it.
func TestHandshakeCommonRoles(t *testing.T) {
	p := newPKI(t)
	ccfg := p.clientConfig(t)
	ccfg.Schemes = DefaultSchemes
	scfg := ccfg
	scfg.Credential = &ecdsaCredential{derChain: derChain{p.serverDER}, key: p.serverKey}
	var client, server handshakeCommon
	var crk, srk recordKeys
	client.configure(&ccfg, true)
	client.peerName = []byte(ccfg.ServerName)
	server.configure(&scfg, false)
	for _, side := range []struct {
		hs *handshakeCommon
		rk *recordKeys
	}{{&client, &crk}, {&server, &srk}} {
		side.hs.reset(make([]byte, 4096))
		if err := side.hs.useSuite(side.rk, 0); err != nil {
			t.Fatal(err)
		}
		side.hs.ks.AddMessage([]byte("hellos")) // Stands in for ClientHello and ServerHello.
		copy(side.hs.shared[:], bytes.Repeat([]byte{7}, 32))
		if err := side.hs.installHandshakeKeys(side.rk, 32); err != nil {
			t.Fatal(err)
		}
		side.hs.nPeerScheme = uint8(copy(side.hs.peerSchemes[:], DefaultSchemes))
	}
	size := client.ks.Size()
	if !bytes.Equal(client.ownHS[:size], server.peerHS[:size]) || !bytes.Equal(client.peerHS[:size], server.ownHS[:size]) {
		t.Fatal("handshake secrets do not mirror")
	}
	sealOpen(t, &crk.out, &srk.in, "client to server")
	sealOpen(t, &srk.out, &crk.in, "server to client")

	authenticate(t, &server, &client)
	server.deriveMaster()
	client.deriveMaster()
	if !bytes.Equal(client.ownAP[:size], server.peerAP[:size]) || !bytes.Equal(client.peerAP[:size], server.ownAP[:size]) {
		t.Fatal("application secrets do not mirror")
	}
	authenticate(t, &client, &server)

	var ch, sh [maxHashSize]byte
	client.ks.TranscriptHash(ch[:size])
	server.ks.TranscriptHash(sh[:size])
	if ch != sh {
		t.Fatal("transcripts differ")
	}
}

// authenticate has from write Certificate, CertificateVerify and Finished and to read them.
func authenticate(t *testing.T, from, to *handshakeCommon) {
	t.Helper()
	buf := make([]byte, 2048)
	var e tlsraw.Encoder
	e.Reset(buf, 0)
	scheme := from.ownScheme()
	if scheme == 0 {
		t.Fatal("no signature scheme")
	} else if err := from.writeCertificate(&e, nil, true); err != nil {
		t.Fatal(err)
	} else if err = from.writeCertificateVerify(&e, scheme); err != nil {
		t.Fatal(err)
	}
	from.writeFinished(&e)
	if err := e.Err(); err != nil {
		t.Fatal(err)
	}
	var msgs [][]byte
	for b := buf[:e.Len()]; len(b) > 0; {
		n := tlsraw.SizeHeaderHandshake + int(uint24(b[1:]))
		msgs, b = append(msgs, b[:n]), b[n:]
	}
	if len(msgs) != 3 {
		t.Fatalf("got %d messages", len(msgs))
	} else if err := to.readCertificate(msgs[0]); err != nil {
		t.Fatal("Certificate:", err)
	} else if err = to.readCertificateVerify(msgs[1]); err != nil {
		t.Fatal("CertificateVerify:", err)
	} else if err = to.readFinished(msgs[2]); err != nil {
		t.Fatal("Finished:", err)
	}
}

// sealOpen seals payload with out and checks in opens it.
func sealOpen(t *testing.T, out, in *tlsraw.HalfConn, payload string) {
	t.Helper()
	buf := make([]byte, 256)
	var e tlsraw.Encoder
	e.Reset(buf, 0)
	rec := e.StartRecord(tlsraw.ContentTypeApplicationData)
	e.Bytes([]byte(payload))
	e.SealRecord(out, rec, tlsraw.ContentTypeApplicationData)
	if err := e.Err(); err != nil {
		t.Fatal(err)
	}
	content, ct, err := in.Open(buf[:e.Len()])
	if err != nil {
		t.Fatal("open:", err)
	} else if ct != tlsraw.ContentTypeApplicationData || string(content) != payload {
		t.Fatalf("opened %v %q", ct, content)
	}
}
