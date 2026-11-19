package tlsauto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/soypat/lneto/crypto/tlsraw"
)

type pki struct {
	rootDER   []byte
	rootKey   *ecdsa.PrivateKey
	root      *x509.Certificate
	serverDER []byte
	serverKey *ecdsa.PrivateKey
	clientDER []byte
	clientKey *ecdsa.PrivateKey
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	now := time.Now()
	p := &pki{}
	var err error
	p.rootKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	p.rootDER, err = x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &p.rootKey.PublicKey, p.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	p.root, _ = x509.ParseCertificate(p.rootDER)
	leaf := func(serial int64, eku x509.ExtKeyUsage) ([]byte, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "leaf"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku},
			DNSNames: []string{"server"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, p.root, &key.PublicKey, p.rootKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, key
	}
	p.serverDER, p.serverKey = leaf(2, x509.ExtKeyUsageServerAuth)
	p.clientDER, p.clientKey = leaf(3, x509.ExtKeyUsageClientAuth)
	return p
}

func (p *pki) clientConfig(t *testing.T) Config {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(p.root)
	return Config{
		Rand:         rand.Reader,
		Suites:       []Suite{aes128GCMSHA256()},
		KeyExchanges: []KeyExchange{x25519(), p256()},
		Credential:   &ecdsaCredential{derChain: derChain{p.clientDER}, key: p.clientKey},
		Verifier:     &x509Verifier{roots: roots},
		ServerName:   "server",
		ALPN:         "test/1",
	}
}

func (p *pki) serverConfig(curves ...tls.CurveID) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(p.root)
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{{Certificate: [][]byte{p.serverDER}, PrivateKey: p.serverKey}},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        pool,
		NextProtos:       []string{"test/1"},
		CurvePreferences: curves,
	}
}

// serve runs one TLS server connection that echoes what it reads.
func serve(t *testing.T, cfg *tls.Config) (net.Conn, chan error) {
	t.Helper()
	if runtime.Compiler == "tinygo" {
		t.Skip("TinyGo's crypto/tls performs no handshake")
	}
	ss, cs := bufPipe()
	done := make(chan error, 1)
	go func() {
		srv := tls.Server(ss, cfg)
		defer srv.Close()
		if err := srv.Handshake(); err != nil {
			done <- err
			return
		}
		if srv.ConnectionState().NegotiatedProtocol != "test/1" {
			done <- errors.New("server: wrong ALPN")
			return
		}
		if len(srv.ConnectionState().PeerCertificates) != 1 {
			done <- errors.New("server: no client cert")
			return
		}
		buf := make([]byte, 64<<10)
		for {
			n, err := srv.Read(buf)
			if err == io.EOF {
				done <- nil
				return
			} else if err != nil {
				done <- err
				return
			}
			if _, err := srv.Write(buf[:n]); err != nil {
				done <- err
				return
			}
		}
	}()
	return cs, done
}

func TestHandshakeMutual(t *testing.T) {
	p := newPKI(t)
	for _, tc := range []struct {
		name  string
		curve tls.CurveID
	}{{"x25519", tls.X25519}, {"p256", tls.CurveP256}} {
		t.Run(tc.name, func(t *testing.T) {
			cs, done := serve(t, p.serverConfig(tc.curve))
			var c Conn
			if err := c.Configure(p.clientConfig(t)); err != nil {
				t.Fatal(err)
			}
			if err := c.Open(cs); err != nil {
				t.Fatal(err)
			}
			if err := c.Handshake(); err != nil {
				t.Fatal("handshake:", err)
			}
			if c.ALPN() != "test/1" {
				t.Fatalf("ALPN %q", c.ALPN())
			}
			if c.hbuf != nil || c.certBuf != nil {
				t.Fatal("handshake buffers kept after the handshake")
			}
			msg := make([]byte, 20000) // Spans more than one record each way.
			rand.Read(msg)
			// Write while reading the echo so neither side fills its socket buffer.
			wrote := make(chan error, 1)
			go func() {
				_, err := c.Write(msg)
				wrote <- err
			}()
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(&c, got); err != nil {
				t.Fatal(err)
			}
			if err := <-wrote; err != nil {
				t.Fatal(err)
			}
			if string(got) != string(msg) {
				t.Fatal("echo mismatch")
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal("server:", err)
			}
		})
	}
}

func TestHandshakeRejectsWrongRoot(t *testing.T) {
	p := newPKI(t)
	other := newPKI(t)
	cs, done := serve(t, p.serverConfig())
	cfg := p.clientConfig(t)
	cfg.Verifier = other.clientConfig(t).Verifier
	var c Conn
	if err := c.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	c.Open(cs)
	var verr verifyError
	if err := c.Handshake(); !errors.As(err, &verr) {
		t.Fatalf("want verify error, got %v", err)
	}
	cs.Close()
	if err := <-done; err == nil {
		t.Fatal("server accepted a failed handshake")
	}
}

func TestHandshakeRejectsWrongALPN(t *testing.T) {
	p := newPKI(t)
	scfg := p.serverConfig()
	scfg.NextProtos = []string{"other/1"}
	cs, done := serve(t, scfg)
	var c Conn
	c.Configure(p.clientConfig(t))
	c.Open(cs)
	if err := c.Handshake(); err == nil {
		t.Fatal("handshake succeeded without ALPN")
	}
	cs.Close()
	<-done
}

func TestMaxRecord(t *testing.T) {
	if runtime.Compiler == "tinygo" {
		t.Skip("TinyGo's crypto/tls performs no handshake")
	}
	p := newPKI(t)
	ss, cs := bufPipe()
	go func() {
		scfg := p.serverConfig()
		scfg.DynamicRecordSizingDisabled = true // Send full size records from the start.
		srv := tls.Server(ss, scfg)
		defer srv.Close()
		if srv.Handshake() == nil {
			srv.Write(make([]byte, 8000)) // One record over the client's limit.
			io.Copy(io.Discard, srv)
		}
	}()
	defer cs.Close()
	cfg := p.clientConfig(t)
	cfg.MaxRecord = 4096
	var c Conn
	if err := c.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	c.Open(cs)
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	_, err := io.ReadFull(&c, make([]byte, 8000))
	if err != alertError(tlsraw.AlertRecordOverflow) {
		t.Fatalf("got %v, want record_overflow", err)
	}
}

func TestErrors(t *testing.T) {
	if alertError(40).Error() != "tlsauto: sent alert 40" || peerAlertError(42).Error() != "tlsauto: received alert 42" {
		t.Fatal("alert text")
	}
	v := verifyError{io.EOF}
	if v.Error() != "tlsauto: peer verification failed: EOF" || !errors.Is(v, io.EOF) {
		t.Fatal("verify error")
	}
}

func TestPeerChain(t *testing.T) {
	p := peerChain{n: 1}
	p.certs[0] = []byte{1, 2, 3}
	if n, err := p.Cert(make([]byte, 2), 0); n != 3 || err != io.ErrShortBuffer {
		t.Fatal("short buffer", n, err)
	}
	if n, err := p.Cert(make([]byte, 3), 0); n != 3 || err != nil {
		t.Fatal("cert", n, err)
	}
	if _, err := p.Cert(nil, 1); err == nil {
		t.Fatal("cert out of range")
	}
	if _, err := p.CertView(1); err == nil {
		t.Fatal("cert view out of range")
	}
}

func TestSkipTickets(t *testing.T) {
	ticket := func(body int) []byte {
		m := []byte{byte(tlsraw.HandshakeTypeNewSessionTicket), byte(body >> 16), byte(body >> 8), byte(body)}
		return append(m, make([]byte, body)...)
	}
	stream := append(ticket(200), ticket(5000)...)
	stream = append(stream, ticket(0)...)
	for _, size := range []int{1, 3, 4, 7, 200, 4096, len(stream)} {
		var c Conn
		for rest := stream; len(rest) > 0; {
			n := min(size, len(rest))
			if err := c.skipTickets(rest[:n]); err != nil {
				t.Fatalf("records of %d bytes: %v", size, err)
			}
			rest = rest[n:]
		}
		if c.ticketHdrN != 0 || c.ticketSkip != 0 {
			t.Fatalf("records of %d bytes: stopped inside a message", size)
		}
	}

	var c Conn
	keyUpdate := []byte{byte(tlsraw.HandshakeTypeKeyUpdate), 0, 0, 1, 0}
	if err := c.skipTickets(append(ticket(10), keyUpdate...)); err != alertError(tlsraw.AlertUnexpectedMessage) {
		t.Fatalf("KeyUpdate after a ticket: got %v, want unexpected_message", err)
	}
}
