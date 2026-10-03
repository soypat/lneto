package tlsauto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"
	"unsafe"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/lcrypto"
	"github.com/soypat/lneto/crypto/internal/rfc8448"
	"github.com/soypat/lneto/crypto/tlsraw"
)

// TestConnStdlibClient runs a handshake and ping/pong between a server [Conn]
// and the standard library client with its default key shares.
func TestConnStdlibClient(t *testing.T) {
	testStdlibClient(t, SuiteRFC8448())
}

// TestConnStdlibClientSHA384 runs the same exchange over TLS_AES_256_GCM_SHA384,
// whose 48 byte secrets exercise a key schedule hash other than SHA-256.
func TestConnStdlibClientSHA384(t *testing.T) {
	testStdlibClient(t, SuiteAES256GCMSHA384())
}

func testStdlibClient(t *testing.T, suite Suite) {
	t.Helper()
	const host = "lneto.test"
	certDER, certKey := selfSignedP256(t, host)
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	cconn, sconn := net.Pipe()
	sconn.SetDeadline(time.Now().Add(5 * time.Second))
	var srv Conn
	cfg := Config{
		Rand:         rand.Reader,
		Suites:       []Suite{suite},
		KeyExchanges: []KeyExchange{GroupX25519()},
		Credential:   &ecdsaCredential{cert: certDER, key: certKey},
	}
	err = srv.Configure(cfg)
	if err != nil {
		t.Fatal("configure", err)
	}
	err = srv.Open(sconn, false)
	if err != nil {
		t.Fatal("open", err)
	}

	clientErr := make(chan error, 1)
	go func() {
		c := stdtls.Client(cconn, &stdtls.Config{
			MinVersion: stdtls.VersionTLS13,
			ServerName: host,
			RootCAs:    roots,
		})
		err := c.Handshake()
		if err == nil {
			_, err = c.Write([]byte("ping"))
		}
		if err == nil {
			pong := make([]byte, 4)
			_, err = io.ReadFull(c, pong)
			if err == nil && string(pong) != "pong" {
				err = fmt.Errorf("got %q, want pong", pong)
			}
		}
		if err == nil {
			err = c.CloseWrite() // Sends close_notify.
		}
		if err == nil {
			_, err = io.Copy(io.Discard, c) // Until the server's close_notify.
		} else {
			cconn.Close() // Unblock the server.
		}
		clientErr <- err
	}()
	// fatal closes the pipe first so a blocked client returns its error.
	fatal := func(what string, err error) {
		sconn.Close()
		t.Fatalf("server %s: %v; client: %v", what, err, <-clientErr)
	}

	if err := srv.Handshake(); err != nil {
		fatal("handshake", err)
	}
	ping := make([]byte, 4)
	if _, err := io.ReadFull(&srv, ping); err != nil {
		fatal("read", err)
	} else if string(ping) != "ping" {
		fatal("read", fmt.Errorf("got %q, want ping", ping))
	}
	if _, err := srv.Write([]byte("pong")); err != nil {
		fatal("write", err)
	}
	if n, err := srv.Read(ping); err != io.EOF {
		fatal("read close_notify", fmt.Errorf("n=%d err=%v, want io.EOF", n, err))
	}
	if err := srv.Close(); err != nil {
		t.Error("server close:", err)
	}
	if err := <-clientErr; err != nil {
		t.Fatal("client:", err)
	}
}

// TestConnWriteSizes sends buffers of growing size to the standard library
// client, each one checked byte for byte, and then checks [Conn.Write] does not
// allocate at any of those sizes. A write splits into records out of wbuf, which
// Open sizes once, so the number of records a write takes must not show up as
// allocations: a Conn that allocated per record would allocate more the larger
// the buffer written, which is what this guards.
func TestConnWriteSizes(t *testing.T) {
	const host = "lneto.test"
	sizes := []int{
		1, 64, 1 << 10,
		tlsraw.MaxPlaintext - 1, tlsraw.MaxPlaintext, tlsraw.MaxPlaintext + 1, // Record boundary.
		1 << 16, 1 << 18,
	}
	data := make([]byte, sizes[len(sizes)-1])
	fillPattern(data)

	certDER, certKey := selfSignedP256(t, host)
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	cconn, sconn := net.Pipe()
	deadline := time.Now().Add(20 * time.Second)
	sconn.SetDeadline(deadline)
	cconn.SetDeadline(deadline)
	// sink drops the server's records once the client is gone, so the allocation
	// pass exercises the record path and not a blocked or failing pipe write.
	peer := &sinkConn{Conn: sconn}
	var srv Conn
	err = srv.Configure(Config{
		Rand:         rand.Reader,
		Suites:       []Suite{SuiteRFC8448()},
		KeyExchanges: []KeyExchange{GroupX25519()},
		Credential:   &ecdsaCredential{cert: certDER, key: certKey},
	})
	if err != nil {
		t.Fatal("configure", err)
	}
	if err = srv.Open(peer, false); err != nil {
		t.Fatal("open", err)
	}

	clientErr := make(chan error, 1)
	go func() {
		c := stdtls.Client(cconn, &stdtls.Config{
			MinVersion: stdtls.VersionTLS13,
			ServerName: host,
			RootCAs:    roots,
		})
		err := c.Handshake()
		got := make([]byte, len(data))
		for _, size := range sizes {
			if err != nil {
				break
			}
			if _, err = io.ReadFull(c, got[:size]); err != nil {
				err = fmt.Errorf("read %d bytes: %w", size, err)
			} else if !bytes.Equal(got[:size], data[:size]) {
				err = fmt.Errorf("read %d bytes: content mismatch", size)
			}
		}
		if err == nil {
			_, err = c.Write([]byte("done")) // Tells the server every size arrived.
		}
		if err != nil {
			cconn.Close() // Unblock the server.
		}
		clientErr <- err
	}()
	fatal := func(what string, err error) {
		sconn.Close()
		t.Fatalf("server %s: %v; client: %v", what, err, <-clientErr)
	}

	if err := srv.Handshake(); err != nil {
		fatal("handshake", err)
	}
	for _, size := range sizes {
		n, err := srv.Write(data[:size])
		if err != nil {
			fatal("write", fmt.Errorf("size %d: %w", size, err))
		} else if n != size {
			fatal("write", fmt.Errorf("n=%d, want %d", n, size))
		}
	}
	ack := make([]byte, 4)
	if _, err := io.ReadFull(&srv, ack); err != nil {
		fatal("read ack", err)
	} else if string(ack) != "done" {
		fatal("read ack", fmt.Errorf("got %q, want done", ack))
	}
	if err := <-clientErr; err != nil {
		sconn.Close()
		t.Fatal("client:", err)
	}
	// The client goroutine has returned, so nothing but the server allocates from here on.
	peer.sink = true
	for _, size := range sizes {
		buf := data[:size]
		var werr error
		allocs := testing.AllocsPerRun(4, func() {
			if _, err := srv.Write(buf); err != nil && werr == nil {
				werr = err
			}
		})
		if werr != nil {
			t.Fatalf("write %d bytes: %v", size, werr)
		}
		if allocs != 0 {
			t.Errorf("Write(%d bytes) allocs=%v, want 0", size, allocs)
		}
	}
	if err := srv.Close(); err != nil {
		t.Error("server close:", err)
	}
}

// sinkConn is the server's side of a pipe whose writes stop reaching the peer
// once sink is set. Reads and deadlines stay those of the pipe.
type sinkConn struct {
	net.Conn
	sink bool
}

func (s *sinkConn) Write(p []byte) (int, error) {
	if s.sink {
		return len(p), nil
	}
	return s.Conn.Write(p)
}

// fillPattern writes a position dependent pattern, so a record written out of
// order or short is caught by the peer.
func fillPattern(b []byte) {
	for i := range b {
		b[i] = byte(i*31 + 7)
	}
}

// TestConnRFC8448 feeds the RFC 8448 ClientHello to a server [Conn] with the RFC's
// server random and key share, checks the ServerHello byte for byte and that the
// handshake does not allocate. Capabilities are stubs that do not allocate, so
// only Conn's own allocations count.
func TestConnRFC8448(t *testing.T) {
	serverRandom := rfc8448ServerRandom()
	record := clientHelloRecord()
	rnd := bytes.NewReader(serverRandom)
	cfg := testConfig(rnd)
	var conn fakeConn
	conn.out.Grow(4096)
	var c Conn
	err := c.Configure(cfg)
	if err != nil {
		t.Fatal("configure", err)
	}
	handshake := func() error {
		rnd.Reset(serverRandom)
		conn.in.Reset(record)
		conn.out.Reset()
		if err := c.Open(&conn, false); err != nil {
			t.Fatal("open", err)
		}
		return c.Handshake() // Fails reading the client Finished, which is not sent.
	}

	if err := handshake(); err != io.ErrUnexpectedEOF {
		t.Fatalf("handshake err=%v, want %v", err, io.ErrUnexpectedEOF)
	}
	out := conn.out.Bytes()
	gotSH := out[tlsraw.SizeHeaderRecord:][:len(rfc8448.ServerHello)]
	if !bytes.Equal(gotSH, rfc8448.ServerHello) {
		t.Fatalf("ServerHello=%x, want %x", gotSH, rfc8448.ServerHello)
	}
	if allocs := testing.AllocsPerRun(10, func() { handshake() }); allocs != 0 {
		t.Errorf("handshake allocs=%v, want 0", allocs)
	}
}

// TestConnReadTruncated checks Read does not report a stream the peer ended
// without close_notify as a clean end of data. RFC 8446 6.1 ends a connection
// with close_notify, so answering a bare transport close with io.EOF would let
// anyone able to inject a FIN truncate the plaintext stream undetected.
func TestConnReadTruncated(t *testing.T) {
	const host = "lneto.test"
	certDER, certKey := selfSignedP256(t, host)
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	cconn, sconn := net.Pipe()
	deadline := time.Now().Add(10 * time.Second)
	sconn.SetDeadline(deadline)
	cconn.SetDeadline(deadline)
	var srv Conn
	err = srv.Configure(Config{
		Rand:         rand.Reader,
		Suites:       []Suite{SuiteRFC8448()},
		KeyExchanges: []KeyExchange{GroupX25519()},
		Credential:   &ecdsaCredential{cert: certDER, key: certKey},
	})
	if err != nil {
		t.Fatal("configure", err)
	}
	if err = srv.Open(sconn, false); err != nil {
		t.Fatal("open", err)
	}
	clientErr := make(chan error, 1)
	go func() {
		c := stdtls.Client(cconn, &stdtls.Config{
			MinVersion: stdtls.VersionTLS13,
			ServerName: host,
			RootCAs:    roots,
		})
		err := c.Handshake()
		if err == nil {
			_, err = c.Write([]byte("ping"))
		}
		// A transport close with no close_notify: the stream is truncated. The pipe
		// is unbuffered, so the ping has been read by the time Write returns.
		cconn.Close()
		clientErr <- err
	}()
	fatal := func(what string, err error) {
		sconn.Close()
		t.Fatalf("server %s: %v; client: %v", what, err, <-clientErr)
	}
	if err := srv.Handshake(); err != nil {
		fatal("handshake", err)
	}
	ping := make([]byte, 4)
	if _, err := io.ReadFull(&srv, ping); err != nil {
		fatal("read", err)
	} else if string(ping) != "ping" {
		fatal("read", fmt.Errorf("got %q, want ping", ping))
	}
	if n, err := srv.Read(ping); err != io.ErrUnexpectedEOF {
		t.Errorf("Read after transport close: n=%d err=%v, want %v", n, err, io.ErrUnexpectedEOF)
	}
	if err := <-clientErr; err != nil {
		t.Fatal("client:", err)
	}
	srv.Close()
}

// TestConnDroppedCCSFlood checks a peer cannot hold the handshake open with an
// unbounded run of the ChangeCipherSpec records RFC 8446 5 drops. Each one is
// dropped inside readRecord, so an uncapped run never returns to its caller.
func TestConnDroppedCCSFlood(t *testing.T) {
	const nCCS = 64
	record := clientHelloRecord()
	for range nCCS {
		record = append(record, byte(tlsraw.ContentTypeChangeCipherSpec), 3, 3, 0, 1, 1)
	}
	var conn fakeConn
	conn.in.Reset(record)
	var c Conn
	if err := c.Configure(testConfig(bytes.NewReader(rfc8448ServerRandom()))); err != nil {
		t.Fatal("configure", err)
	}
	if err := c.Open(&conn, false); err != nil {
		t.Fatal("open", err)
	}
	want := alertError(tlsraw.AlertUnexpectedMessage)
	if err := c.Handshake(); err != want {
		t.Errorf("handshake err=%v, want %v", err, want)
	}
}

// TestConnNoAlertAfterEOF checks Conn does not answer a transport level close
// with an alert: the peer is gone, so that write can only block or fail.
func TestConnNoAlertAfterEOF(t *testing.T) {
	var conn eofConn
	conn.in.Reset(clientHelloRecord())
	var c Conn
	if err := c.Configure(testConfig(bytes.NewReader(rfc8448ServerRandom()))); err != nil {
		t.Fatal("configure", err)
	}
	if err := c.Open(&conn, false); err != nil {
		t.Fatal("open", err)
	}
	if err := c.Handshake(); err != io.ErrUnexpectedEOF {
		t.Fatalf("handshake err=%v, want %v", err, io.ErrUnexpectedEOF)
	}
	if conn.wroteAfterEOF {
		t.Error("Conn wrote an alert to a connection whose peer had already closed")
	}
}

// eofConn reads from in and writes to out, and notes a write made after in ran out.
type eofConn struct {
	net.Conn
	in            bytes.Reader
	out           bytes.Buffer
	drained       bool
	wroteAfterEOF bool
}

func (e *eofConn) Read(p []byte) (int, error) {
	n, err := e.in.Read(p)
	if err != nil {
		e.drained = true
	}
	return n, err
}

func (e *eofConn) Write(p []byte) (int, error) {
	if e.drained {
		e.wroteAfterEOF = true
	}
	return e.out.Write(p)
}

func (e *eofConn) Close() error { return nil }

// clientHelloRecord returns the RFC 8448 ClientHello wrapped in a plaintext record.
func clientHelloRecord() []byte {
	hello := rfc8448.ClientHello
	rec := []byte{byte(tlsraw.ContentTypeHandshake), 3, 1, byte(len(hello) >> 8), byte(len(hello))}
	return append(rec, hello...)
}

// rfc8448ServerRandom returns the server random of the RFC 8448 trace, which the
// stub entropy source hands to the server so its ServerHello matches the trace.
func rfc8448ServerRandom() []byte {
	return rfc8448.ServerHello[tlsraw.SizeHeaderHandshake+2:][:tlsraw.SizeHelloRandom]
}

// TestConnSize guards the memory a Conn takes. Conn is meant for targets that
// count bytes, and the handshake state it holds is easy to grow back: a buffer
// added here is one the handshake could have written straight into the record
// it is bound for, or derived inside the type that owns it.
func TestConnSize(t *testing.T) {
	const want = 1500
	if got := unsafe.Sizeof(Conn{}); got > want {
		t.Errorf("unsafe.Sizeof(Conn{})=%d bytes, want <=%d", got, want)
	}
}

// TestOpenWipesKeys checks Open starts from an unkeyed connection. A Conn abandoned
// without Close still has the record keys of that connection installed, and would
// read the next peer's first plaintext record as ciphertext.
func TestOpenWipesKeys(t *testing.T) {
	var c Conn
	if err := c.Configure(testConfig(bytes.NewReader(nil))); err != nil {
		t.Fatal("configure", err)
	}
	if err := c.in.SetAEAD(nullAEAD{}, new([12]byte)); err != nil {
		t.Fatal(err)
	}
	if err := c.Open(&fakeConn{}, false); err != nil {
		t.Fatal("open", err)
	}
	if c.in.HasKeys() {
		t.Error("Open left the previous connection's read keys installed")
	}
}

// TestConfigureInvalid checks Configure rejects suites and groups Conn cannot
// use, which would otherwise fail mid-handshake, a nil constructor by panicking.
func TestConfigureInvalid(t *testing.T) {
	var c Conn
	good := testConfig(bytes.NewReader(nil))
	for _, test := range []struct {
		name   string
		mangle func(cfg *Config)
	}{
		{"nil NewAEAD", func(cfg *Config) { cfg.Suites[0].NewAEAD = nil }},
		{"nil NewHash", func(cfg *Config) { cfg.Suites[0].NewHash = nil }},
		{"zero suite ID", func(cfg *Config) { cfg.Suites[0].ID = 0 }},
		{"zero KeyLen", func(cfg *Config) { cfg.Suites[0].KeyLen = 0 }},
		{"long KeyLen", func(cfg *Config) { cfg.Suites[0].KeyLen = maxKeyLen + 1 }},
		{"nil NewExchanger", func(cfg *Config) { cfg.KeyExchanges[0].NewExchanger = nil }},
		{"zero ClientShareLen", func(cfg *Config) { cfg.KeyExchanges[0].ClientShareLen = 0 }},
		{"zero ServerShareLen", func(cfg *Config) { cfg.KeyExchanges[0].ServerShareLen = 0 }},
		{"zero SharedLen", func(cfg *Config) { cfg.KeyExchanges[0].SharedLen = 0 }},
		{"long ClientShareLen", func(cfg *Config) { cfg.KeyExchanges[0].ClientShareLen = maxKeyShare + 1 }},
		{"long ServerShareLen", func(cfg *Config) { cfg.KeyExchanges[0].ServerShareLen = maxKeyShare + 1 }},
		{"long SharedLen", func(cfg *Config) { cfg.KeyExchanges[0].SharedLen = maxShared + 1 }},
		{"no credential", func(cfg *Config) { cfg.Credential = nil }},
		{"no rand", func(cfg *Config) { cfg.Rand = nil }},
	} {
		cfg := good
		cfg.Suites = []Suite{good.Suites[0]}
		cfg.KeyExchanges = []KeyExchange{good.KeyExchanges[0]}
		test.mangle(&cfg)
		if err := c.Configure(cfg); err != lneto.ErrInvalidConfig {
			t.Errorf("%s: Configure err=%v, want %v", test.name, err, lneto.ErrInvalidConfig)
		}
	}
	// The unmodified config configures, and Open needs it: a Conn never configured has no suite to negotiate.
	if err := c.Configure(good); err != nil {
		t.Fatal("configure", err)
	}
	if err := (&Conn{}).Open(&fakeConn{}, false); err != lneto.ErrBadState {
		t.Errorf("Open before Configure err=%v, want %v", err, lneto.ErrBadState)
	}
}

// TestConfigureLive checks Configure refuses to wipe the keys of a live
// connection, which would leave it reading the peer's ciphertext as plaintext.
func TestConfigureLive(t *testing.T) {
	var c Conn
	cfg := testConfig(bytes.NewReader(nil))
	if err := c.Configure(cfg); err != nil {
		t.Fatal("configure", err)
	}
	if err := c.Open(&fakeConn{}, false); err != nil {
		t.Fatal("open", err)
	}
	if err := c.Configure(cfg); err != lneto.ErrBadState {
		t.Errorf("Configure during handshake err=%v, want %v", err, lneto.ErrBadState)
	}
	if err := c.Close(); err != nil {
		t.Fatal("close", err)
	}
	if err := c.Configure(cfg); err != nil {
		t.Error("Configure after Close:", err)
	}
}

// testConfig returns a server config of stub capabilities that do not allocate.
func testConfig(rand io.Reader) Config {
	return Config{
		Rand:         rand,
		Suites:       []Suite{SuiteNull()},
		KeyExchanges: []KeyExchange{GroupRFC8448()},
		Credential:   rfc8448Credential{},
	}
}

// SuiteRFC8448 returns TLS_AES_128_GCM_SHA256 as implemented on top of the
// standard library, the cipher suite of the RFC 8448 trace.
func SuiteRFC8448() Suite {
	return Suite{
		ID:      rfc8448.AES128GCMSHA256ID,
		KeyLen:  rfc8448.AES128GCMSHA256KeyLen,
		NewAEAD: rfc8448.NewAES128GCM,
		NewHash: rfc8448.NewSHA256,
	}
}

// SuiteAES256GCMSHA384 returns TLS_AES_256_GCM_SHA384 on top of the standard
// library. Its AEAD is the same AES-GCM adapter, which keys AES-256 from the
// 32 byte key.
func SuiteAES256GCMSHA384() Suite {
	return Suite{
		ID:      uint16(tlsraw.SuiteAES256GCMSHA384),
		KeyLen:  32,
		NewAEAD: rfc8448.NewAES128GCM,
		NewHash: sha512.New384,
	}
}

// GroupX25519 returns the X25519 group of RFC 8446 4.2.8 built on crypto/ecdh.
func GroupX25519() KeyExchange {
	return KeyExchange{
		ID:             uint16(tlsraw.GroupX25519),
		ClientShareLen: 32, ServerShareLen: 32, SharedLen: 32,
		NewExchanger: func() lcrypto.Exchanger { return new(x25519Exchanger) },
	}
}

type x25519Exchanger struct{ priv *ecdh.PrivateKey }

func (x *x25519Exchanger) ClientGenerateRekey(dstClientShare []byte, rand io.Reader) (int, error) {
	priv, err := ecdh.X25519().GenerateKey(rand)
	if err != nil {
		return 0, err
	}
	x.priv = priv
	return copy(dstClientShare, priv.PublicKey().Bytes()), nil
}

func (x *x25519Exchanger) ServerSharedRekey(dstServerShare, dstShared, clientShare []byte, rand io.Reader) (int, int, error) {
	if _, err := x.ClientGenerateRekey(dstServerShare, rand); err != nil {
		return 0, 0, err
	}
	n, err := x.ClientShared(dstShared, clientShare)
	return len(dstServerShare), n, err
}

func (x *x25519Exchanger) ClientShared(dstShared, serverShare []byte) (int, error) {
	peer, err := ecdh.X25519().NewPublicKey(serverShare)
	if err != nil {
		return 0, err
	}
	shared, err := x.priv.ECDH(peer)
	if err != nil {
		return 0, err
	}
	return copy(dstShared, shared), nil
}

func (x *x25519Exchanger) Zeroize() { x.priv = nil }

// ecdsaCredential implements [lcrypto.Credential] for a single P-256 certificate.
type ecdsaCredential struct {
	cert []byte
	key  *ecdsa.PrivateKey
}

func (c *ecdsaCredential) NumCerts() int                  { return 1 }
func (c *ecdsaCredential) CertView(i int) ([]byte, error) { return c.cert, nil }
func (c *ecdsaCredential) Cert(dst []byte, i int) (int, error) {
	if len(dst) < len(c.cert) {
		return len(c.cert), io.ErrShortBuffer
	}
	return copy(dst, c.cert), nil
}

func (c *ecdsaCredential) Scheme(offered []uint16) uint16 {
	if slices.Contains(offered, uint16(tlsraw.SigECDSAP256SHA256)) {
		return uint16(tlsraw.SigECDSAP256SHA256)
	}
	return 0
}

func (c *ecdsaCredential) Sign(sig, msg []byte, selectedScheme uint16) (int, error) {
	digest := sha256.Sum256(msg)
	der, err := ecdsa.SignASN1(rand.Reader, c.key, digest[:])
	if err != nil {
		return 0, err
	} else if len(der) > len(sig) {
		return 0, io.ErrShortBuffer
	}
	return copy(sig, der), nil
}

// GroupRFC8448 returns a group that replays the X25519 exchange of the RFC 8448
// trace. Its Exchanger is stateless, so building one does not allocate.
func GroupRFC8448() KeyExchange {
	return KeyExchange{
		ID:             uint16(tlsraw.GroupX25519),
		ClientShareLen: 32, ServerShareLen: 32, SharedLen: 32,
		NewExchanger: func() lcrypto.Exchanger { return rfc8448Exchanger{} },
	}
}

// rfc8448Exchanger returns the RFC 8448 server key share and shared secret.
type rfc8448Exchanger struct{}

func (rfc8448Exchanger) ClientGenerateRekey([]byte, io.Reader) (int, error) { panic("unused") }
func (rfc8448Exchanger) ClientShared([]byte, []byte) (int, error)           { panic("unused") }
func (rfc8448Exchanger) Zeroize()                                           {}
func (rfc8448Exchanger) ServerSharedRekey(dstServerShare, dstShared, _ []byte, _ io.Reader) (int, int, error) {
	return copy(dstServerShare, rfc8448.ServerPub), copy(dstShared, rfc8448.WantShared), nil
}

// rfc8448Credential presents the RFC 8448 certificate and replays its CertificateVerify signature.
type rfc8448Credential struct{}

func (rfc8448Credential) NumCerts() int                  { return 1 }
func (rfc8448Credential) CertView(i int) ([]byte, error) { return rfc8448Cert(), nil }
func (rfc8448Credential) Cert(dst []byte, i int) (int, error) {
	return copy(dst, rfc8448Cert()), nil
}
func (rfc8448Credential) Scheme(offered []uint16) uint16 {
	return uint16(tlsraw.SigRSAPSSRSAESHA256)
}
func (rfc8448Credential) Sign(sig, msg []byte, selectedScheme uint16) (int, error) {
	return copy(sig, rfc8448.CertificateVerify[tlsraw.SizeHeaderHandshake+4:]), nil
}

func rfc8448Cert() []byte { return rfc8448.Certificate[tlsraw.SizeHeaderHandshake+1+3+3:][:0x1b0] }

// SuiteNull returns TLS_AES_128_GCM_SHA256 with a cipher that does not encrypt
// and does not allocate, so allocation tests count only Conn's allocations.
func SuiteNull() Suite {
	return Suite{
		ID:      uint16(tlsraw.SuiteAES128GCMSHA256),
		KeyLen:  16,
		NewAEAD: func() lcrypto.AEADCipher { return nullAEAD{} },
		NewHash: sha256.New,
	}
}

type nullAEAD struct{}

func (nullAEAD) NonceSize() int     { return 12 }
func (nullAEAD) Overhead() int      { return 16 }
func (nullAEAD) Rekey([]byte) error { return nil }
func (nullAEAD) Zeroize()           {}
func (nullAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	var tag [16]byte
	return append(append(dst, plaintext...), tag[:]...)
}
func (nullAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return append(dst, ciphertext[:len(ciphertext)-16]...), nil
}

// fakeConn reads from in and writes to out. Other net.Conn methods panic.
type fakeConn struct {
	net.Conn
	in  bytes.Reader
	out bytes.Buffer
}

func (f *fakeConn) Read(p []byte) (int, error)  { return f.in.Read(p) }
func (f *fakeConn) Write(p []byte) (int, error) { return f.out.Write(p) }
func (f *fakeConn) Close() error                { return nil }

// selfSignedP256 returns a self-signed P-256 certificate for host and its key.
func selfSignedP256(t *testing.T, host string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}
