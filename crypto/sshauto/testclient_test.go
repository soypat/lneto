package sshauto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/lcrypto"
	"github.com/soypat/lneto/crypto/internal/rfc8448"
	"github.com/soypat/lneto/crypto/sshraw"
)

// testClient is a minimal SSH client built from sshraw and the standard
// library, enough to drive a server Transport through key exchanges and
// packets. Its steady state Read/Write paths do not allocate.
type testClient struct {
	conn    net.Conn
	in, out sshraw.HalfConn
	ks      sshraw.KeySchedule
	rbuf    []byte
	wbuf    []byte
	vc, vs  []byte
	ic, is  []byte
	hostKey []byte // Expected K_S.
	hostPub ed25519.PublicKey

	aeadIn, aeadOut lcrypto.AEADCipher
	kexList         string
	cipher          string
	follows         bool                   // first_kex_packet_follows.
	guess           func(*testClient) error // Sends the guessed packet right after KEXINIT.
	strict          bool
}

func newTestClient(conn net.Conn, hk *ed25519HostKey) *testClient {
	blob := make([]byte, 64)
	n, _ := hk.PublicKey(blob)
	return &testClient{
		conn:    conn,
		rbuf:    make([]byte, sshraw.MaxPacket),
		wbuf:    make([]byte, sshraw.MaxPacket),
		hostKey: blob[:n],
		hostPub: hk.priv.Public().(ed25519.PublicKey),
		aeadIn:  rfc8448.NewAES128GCM(),
		aeadOut: rfc8448.NewAES128GCM(),
		kexList: sshraw.KexCurve25519SHA256 + "," + sshraw.KexStrictClient,
		cipher:  sshraw.CipherAES256GCM,
	}
}

func (c *testClient) handshake() error {
	if err := c.ident(); err != nil {
		return err
	}
	return c.kex()
}

// ident exchanges identification strings.
func (c *testClient) ident() error {
	c.vc = []byte("SSH-2.0-lnetotest")
	if _, err := c.conn.Write(append(append([]byte{}, c.vc...), "\r\n"...)); err != nil {
		return err
	}
	var line []byte
	var b [1]byte
	for {
		if _, err := io.ReadFull(c.conn, b[:]); err != nil {
			return err
		} else if b[0] == '\n' {
			break
		}
		line = append(line, b[0])
	}
	c.vs = bytes.TrimSuffix(line, []byte("\r"))
	return nil
}

func (c *testClient) sendKexInit() error {
	var e sshraw.Encoder
	buf := make([]byte, 1024)
	e.Reset(buf, 0)
	e.Uint8(uint8(sshraw.MsgKexInit))
	e.Bytes(make([]byte, sshraw.SizeCookie))
	e.Str(c.kexList)
	e.Str(sshraw.HostKeyEd25519)
	e.Str(c.cipher)
	e.Str(c.cipher)
	e.Str(sshraw.MACHMACSHA256) // Real clients list MACs; the AEAD makes them moot.
	e.Str(sshraw.MACHMACSHA256)
	e.Str(sshraw.CompressionNone)
	e.Str(sshraw.CompressionNone)
	e.Str("")
	e.Str("")
	e.Bool(c.follows)
	e.Uint32(0)
	if e.Err() != nil {
		return e.Err()
	}
	c.ic = buf[:e.Len()]
	return c.writePacket(c.ic)
}

// kex runs a client side key exchange: KEXINIT, ECDH and NEWKEYS.
func (c *testClient) kex() error {
	initial := len(c.ks.SessionID()) == 0
	if err := c.sendKexInit(); err != nil {
		return err
	}
	if c.guess != nil {
		if err := c.guess(c); err != nil {
			return err
		}
	}
	p, err := c.readPacket()
	if err != nil {
		return err
	} else if sshraw.MsgType(p[0]) != sshraw.MsgKexInit {
		return fmt.Errorf("want KEXINIT, got %v", sshraw.MsgType(p[0]))
	}
	c.is = append([]byte{}, p...)
	var msg sshraw.KexInitMsg
	var vld lneto.Validator
	if _, err = msg.Decode(c.is, &vld); err != nil {
		return err
	}
	if initial {
		c.strict = sshraw.HasName([]byte(c.kexList), sshraw.KexStrictClient) &&
			sshraw.HasName(msg.KexAlgorithms(), sshraw.KexStrictServer)
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	qc := priv.PublicKey().Bytes()
	if err = c.writePacket(append([]byte{byte(sshraw.MsgKexECDHInit), 0, 0, 0, 32}, qc...)); err != nil {
		return err
	}
	p, err = c.readPacket()
	if err != nil {
		return err
	} else if sshraw.MsgType(p[0]) != sshraw.MsgKexECDHReply {
		return fmt.Errorf("want KEX_ECDH_REPLY, got %v", sshraw.MsgType(p[0]))
	}
	f, err := strs(p[1:], 3)
	if err != nil {
		return err
	}
	ks, qs, sigBlob := f[0], f[1], f[2]
	if !bytes.Equal(ks, c.hostKey) {
		return fmt.Errorf("host key %x, want %x", ks, c.hostKey)
	}
	serverPub, err := ecdh.X25519().NewPublicKey(qs)
	if err != nil {
		return err
	}
	shared, err := priv.ECDH(serverPub)
	if err != nil {
		return err
	}
	if initial {
		c.ks.Configure(sha256.New())
	}
	if err = c.ks.SetSecret(shared, false); err != nil {
		return err
	}
	c.ks.StartExchange()
	for _, field := range [][]byte{c.vc, c.vs, c.ic, c.is, ks, qc, qs} {
		c.ks.HashString(field)
	}
	c.ks.FinishExchange()
	sig, err := strs(sigBlob, 2)
	if err != nil {
		return err
	} else if string(sig[0]) != sshraw.HostKeyEd25519 || !ed25519.Verify(c.hostPub, c.ks.ExchangeHash(), sig[1]) {
		return errors.New("bad host key signature")
	}

	if err = c.writePacket([]byte{byte(sshraw.MsgNewKeys)}); err != nil {
		return err
	}
	if c.strict {
		c.out.ResetSeq()
	}
	if err = c.ks.InstallKeys(&c.out, c.aeadOut, 32, 'C', 'A'); err != nil {
		return err
	}
	p, err = c.readPacket()
	if err != nil {
		return err
	} else if !bytes.Equal(p, []byte{byte(sshraw.MsgNewKeys)}) {
		return fmt.Errorf("want NEWKEYS, got %x", p)
	}
	if c.strict {
		c.in.ResetSeq()
	}
	err = c.ks.InstallKeys(&c.in, c.aeadIn, 32, 'D', 'B')
	c.ks.WipeExchange()
	return err
}

// readPacket returns the next payload, valid until the next call.
func (c *testClient) readPacket() ([]byte, error) {
	if _, err := io.ReadFull(c.conn, c.rbuf[:4]); err != nil {
		return nil, err
	}
	n, err := c.in.WireLen(c.rbuf[:4])
	if err != nil {
		return nil, err
	} else if _, err = io.ReadFull(c.conn, c.rbuf[4:n]); err != nil {
		return nil, err
	}
	pf, err := c.in.Open(c.rbuf[:n])
	if err != nil {
		return nil, err
	}
	return pf.Payload(), nil
}

func (c *testClient) writePacket(payload []byte) error {
	var e sshraw.Encoder
	e.Reset(c.wbuf, 0)
	start := e.StartPacket(sshraw.MsgType(payload[0]))
	e.Bytes(payload[1:])
	block, aad := sshraw.MinBlockSize, false
	if c.out.HasKeys() {
		block, aad = 16, true
	}
	pkt := e.EndPacket(start, block, aad, rand.Reader)
	if pkt == nil {
		return e.Err()
	}
	sealed, err := c.out.Seal(pkt[:len(pkt):len(c.wbuf)])
	if err != nil {
		return err
	}
	_, err = c.conn.Write(sealed)
	return err
}

// strs parses n consecutive SSH strings of b, which it must consume whole.
func strs(b []byte, n int) ([][]byte, error) {
	out := make([][]byte, n)
	for i := range out {
		if len(b) < 4 || int(binary.BigEndian.Uint32(b)) > len(b)-4 {
			return nil, errors.New("truncated string")
		}
		l := int(binary.BigEndian.Uint32(b))
		out[i], b = b[4:4+l], b[4+l:]
	}
	if len(b) != 0 {
		return nil, errors.New("trailing bytes")
	}
	return out, nil
}

// tcpPair returns both ends of a loopback TCP connection. Unlike net.Pipe it
// buffers, so both sides may write their identification strings first.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	deadline := time.Now().Add(5 * time.Second)
	client.SetDeadline(deadline)
	server.SetDeadline(deadline)
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

// ed25519HostKey is an ssh-ed25519 host key on the standard library.
type ed25519HostKey struct{ priv ed25519.PrivateKey }

func newHostKey() *ed25519HostKey {
	return &ed25519HostKey{priv: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))}
}

func (k *ed25519HostKey) Algorithm() string { return sshraw.HostKeyEd25519 }

func (k *ed25519HostKey) PublicKey(dst []byte) (int, error) {
	const n = 4 + len(sshraw.HostKeyEd25519) + 4 + ed25519.PublicKeySize
	if len(dst) < n {
		return n, io.ErrShortBuffer
	}
	var e sshraw.Encoder
	e.Reset(dst, 0)
	e.Str(sshraw.HostKeyEd25519)
	e.String(k.priv.Public().(ed25519.PublicKey))
	return e.Len(), e.Err()
}

func (k *ed25519HostKey) Sign(sig, msg []byte) (int, error) {
	if len(sig) < ed25519.SignatureSize {
		return 0, io.ErrShortBuffer
	}
	return copy(sig, ed25519.Sign(k.priv, msg)), nil
}

// x25519Exchanger implements curve25519-sha256 on crypto/ecdh.
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
	return 32, n, err
}

func (x *x25519Exchanger) ClientShared(dstShared, serverShare []byte) (int, error) {
	pub, err := ecdh.X25519().NewPublicKey(serverShare)
	if err != nil {
		return 0, err
	}
	shared, err := x.priv.ECDH(pub)
	if err != nil {
		return 0, err
	}
	return copy(dstShared, shared), nil
}

func (x *x25519Exchanger) Zeroize() { x.priv = nil }

func kexCurve25519() KeyExchange {
	return KeyExchange{
		Name:           sshraw.KexCurve25519SHA256,
		ClientShareLen: 32, ServerShareLen: 32, SharedLen: 32,
		NewExchanger: func() LExchanger { return new(x25519Exchanger) },
		NewHash:      func() hash.Hash { return sha256.New() },
	}
}

func cipherAES256GCM() Cipher {
	return Cipher{Name: sshraw.CipherAES256GCM, KeyLen: 32, NewAEAD: rfc8448.NewAES128GCM}
}

func testConfig(hk HostKey) Config {
	return Config{
		Rand:         rand.Reader,
		Software:     "lneto_test",
		KeyExchanges: []KeyExchange{kexCurve25519()},
		Ciphers:      []Cipher{cipherAES256GCM()},
		HostKeys:     []HostKey{hk},
	}
}
