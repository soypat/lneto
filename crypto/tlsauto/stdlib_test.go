package tlsauto

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/soypat/lneto/crypto/internal/rfc8448"
	"github.com/soypat/lneto/crypto/tlsraw"
)

func aes128GCMSHA256() Suite {
	return Suite{
		ID:      uint16(tlsraw.SuiteAES128GCMSHA256),
		KeyLen:  rfc8448.AES128GCMSHA256KeyLen,
		NewAEAD: rfc8448.NewAES128GCM,
		NewHash: rfc8448.NewSHA256,
	}
}

func x25519() KeyExchange {
	return KeyExchange{
		ID:             uint16(tlsraw.GroupX25519),
		ClientShareLen: 32,
		ServerShareLen: 32,
		SharedLen:      32,
		NewExchanger:   func() Exchanger { return &ecdhExchanger{curve: ecdh.X25519()} },
	}
}

func p256() KeyExchange {
	return KeyExchange{
		ID:             uint16(tlsraw.GroupSECP256R1),
		ClientShareLen: 65,
		ServerShareLen: 65,
		SharedLen:      32,
		NewExchanger:   func() Exchanger { return &ecdhExchanger{curve: ecdh.P256()} },
	}
}

type ecdhExchanger struct {
	curve ecdh.Curve
	key   *ecdh.PrivateKey
}

func (e *ecdhExchanger) ClientGenerateRekey(dst []byte, r io.Reader) (int, error) {
	key, err := e.curve.GenerateKey(r)
	if err != nil {
		return 0, err
	}
	e.key = key
	pub := key.PublicKey().Bytes()
	if len(dst) < len(pub) {
		return 0, io.ErrShortBuffer
	}
	return copy(dst, pub), nil
}

func (e *ecdhExchanger) ServerSharedRekey(dstServerShare, dstShared, clientShare []byte, r io.Reader) (int, int, error) {
	return 0, 0, errors.New("server role not implemented")
}

func (e *ecdhExchanger) ClientShared(dst, serverShare []byte) (int, error) {
	if e.key == nil {
		return 0, errors.New("unkeyed")
	}
	pub, err := e.curve.NewPublicKey(serverShare)
	if err != nil {
		return 0, err
	}
	shared, err := e.key.ECDH(pub)
	if err != nil {
		return 0, err
	}
	if len(dst) < len(shared) {
		return 0, io.ErrShortBuffer
	}
	return copy(dst, shared), nil
}

func (e *ecdhExchanger) Zeroize() { e.key = nil }

type derChain [][]byte

func (c derChain) NumCerts() int { return len(c) }

func (c derChain) Cert(dst []byte, i int) (int, error) {
	if i < 0 || i >= len(c) {
		return 0, errors.New("cert index out of range")
	}
	if len(dst) < len(c[i]) {
		return len(c[i]), io.ErrShortBuffer
	}
	return copy(dst, c[i]), nil
}

func (c derChain) CertView(i int) ([]byte, error) {
	if i < 0 || i >= len(c) {
		return nil, errors.New("cert index out of range")
	}
	return c[i], nil
}

// ecdsaCredential signs with ecdsa_secp256r1_sha256 only.
type ecdsaCredential struct {
	derChain
	key *ecdsa.PrivateKey
}

func (c *ecdsaCredential) Scheme(offered []uint16) uint16 {
	for _, s := range offered {
		if s == uint16(tlsraw.SigECDSAP256SHA256) {
			return s
		}
	}
	return 0
}

func (c *ecdsaCredential) Sign(sig, msg []byte, scheme uint16) (int, error) {
	if scheme != uint16(tlsraw.SigECDSAP256SHA256) {
		return 0, errors.New("unsupported scheme")
	}
	h := sha256.Sum256(msg)
	s, err := c.key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return 0, err
	}
	if len(sig) < len(s) {
		return 0, io.ErrShortBuffer
	}
	return copy(sig, s), nil
}

// x509Verifier checks ECDSA P-256 chains against roots with crypto/x509.
type x509Verifier struct {
	roots *x509.CertPool
}

func (v *x509Verifier) VerifyPeer(chain CertChain, scheme uint16, peerIsServer bool, expectName, msg, sig []byte) error {
	if chain.NumCerts() == 0 {
		return errors.New("empty chain")
	}
	if scheme != uint16(tlsraw.SigECDSAP256SHA256) {
		return errors.New("unsupported scheme")
	}
	certs := make([]*x509.Certificate, chain.NumCerts())
	for i := range certs {
		der, err := chain.CertView(i)
		if err != nil {
			return err
		}
		certs[i], err = x509.ParseCertificate(der)
		if err != nil {
			return err
		}
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	eku := x509.ExtKeyUsageClientAuth
	if peerIsServer {
		eku = x509.ExtKeyUsageServerAuth
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		DNSName:       string(expectName),
		Roots:         v.roots,
		Intermediates: inter,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{eku},
	})
	if err != nil {
		return err
	}
	pub, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("leaf key is not ECDSA")
	}
	h := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(pub, h[:], sig) {
		return errors.New("bad CertificateVerify signature")
	}
	return nil
}

// bufPipe is net.Pipe with unbounded buffering so writes never block, like a TCP socket buffer.
func bufPipe() (net.Conn, net.Conn) {
	a, b := new(halfPipe), new(halfPipe)
	a.cond.L, b.cond.L = &a.mu, &b.mu
	return &pipeConn{r: a, w: b}, &pipeConn{r: b, w: a}
}

type halfPipe struct {
	mu     sync.Mutex
	cond   sync.Cond
	buf    []byte
	closed bool
}

func (h *halfPipe) close() {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	h.cond.Broadcast()
}

type pipeConn struct {
	r, w *halfPipe
}

func (p *pipeConn) Read(b []byte) (int, error) {
	h := p.r
	h.mu.Lock()
	defer h.mu.Unlock()
	for len(h.buf) == 0 && !h.closed {
		h.cond.Wait()
	}
	if len(h.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(b, h.buf)
	h.buf = h.buf[n:]
	return n, nil
}

func (p *pipeConn) Write(b []byte) (int, error) {
	h := p.w
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	h.buf = append(h.buf, b...)
	h.mu.Unlock()
	h.cond.Broadcast()
	return len(b), nil
}

func (p *pipeConn) Close() error {
	p.r.close()
	p.w.close()
	return nil
}

func (p *pipeConn) LocalAddr() net.Addr                { return pipeAddr{} }
func (p *pipeConn) RemoteAddr() net.Addr               { return pipeAddr{} }
func (p *pipeConn) SetDeadline(t time.Time) error      { return nil }
func (p *pipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *pipeConn) SetWriteDeadline(t time.Time) error { return nil }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }
