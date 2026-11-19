// Package tlsauto is a TLS 1.3 client with mutual authentication built on tlsraw.
// It supports neither PSK nor HelloRetryRequest.
package tlsauto

import (
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"slices"
	"strconv"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/lcrypto"
	"github.com/soypat/lneto/crypto/tlsraw"
)

// Config configures a client Conn.
type Config struct {
	Rand io.Reader
	// Suites in preference order.
	Suites []Suite
	// KeyExchanges get one key share each in the ClientHello, so the server never needs a HelloRetryRequest.
	KeyExchanges []KeyExchange
	// Schemes offered in signature_algorithms. DefaultSchemes if empty.
	Schemes []uint16
	// Credential answers a CertificateRequest. Without it the client sends an empty Certificate.
	Credential Credential
	// Verifier checks the server chain and CertificateVerify.
	Verifier Verifier
	// ServerName is sent as SNI when set and is passed to Verifier.
	ServerName string
	// ALPN is the one protocol offered. The server must select it.
	ALPN string
	// MaxRecord bounds received record plaintext, tlsraw.MaxPlaintext if zero.
	MaxRecord int
}

const (
	// Sized for P-256 device chains of a few certificates.
	sizeHandshakeBuf = 4096
	sizeCertBuf      = 4096
	sizeWriteBuf     = 2048
	maxWritePlain    = sizeWriteBuf - tlsraw.SizeHeaderRecord - 1 - tlsraw.SizeAEADTag
	maxPeerCerts     = 8
	maxShared        = 32
	maxHashSize      = 48
	maxKeyLen        = 32
	maxOfferedScheme = 32
	maxRequestCtx    = 255
	serverCVContext  = "TLS 1.3, server CertificateVerify"
	clientCVContext  = "TLS 1.3, client CertificateVerify"
	sizeCVPrefix     = 64 + len(serverCVContext) + 1
)

// RFC 8446 4.1.3: ServerHello.random of a HelloRetryRequest.
var helloRetryRandom = [32]byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

var (
	errHelloRetry = errors.New("tlsauto: HelloRetryRequest not supported")
	errNoConfig   = errors.New("tlsauto: invalid config")
)

type connState uint8

const (
	stateIdle connState = iota
	stateHandshake
	stateConnected
	stateFailed
	stateClosed
)

// Conn is a TLS 1.3 client connection. It is not safe for concurrent use.
type Conn struct {
	rw         io.ReadWriter
	cfg        Config
	state      connState
	peerClosed bool

	ks      tlsraw.KeySchedule
	in, out tlsraw.HalfConn
	vld     lneto.Validator

	suite           *Suite
	aeadIn, aeadOut lcrypto.AEADCipher
	transcript, mac hash.Hash
	exch            []lcrypto.Exchanger

	rbuf, hbuf, wbuf []byte
	hsOff, hsEnd     int
	app              []byte
	clientHello      []byte

	certBuf     []byte
	chain       peerChain
	ticketHdr   [tlsraw.SizeHeaderHandshake]byte
	ticketHdrN  int
	ticketSkip  int
	certReq     bool
	reqCtx      [maxRequestCtx]byte
	reqCtxLen   int
	peerSchemes [maxOfferedScheme]uint16
	nPeerScheme int
	alpn        [255]byte
	alpnLen     int
	serverName  []byte // Config.ServerName, converted once for Verifier.VerifyPeer.

	cv       [sizeCVPrefix + maxHashSize]byte
	shared   [maxShared]byte
	clientHS [maxHashSize]byte
	serverHS [maxHashSize]byte
	clientAP [maxHashSize]byte
	serverAP [maxHashSize]byte
	verify   [maxHashSize]byte
}

// Configure checks cfg and keeps a copy of it for the next Open.
func (c *Conn) Configure(cfg Config) error {
	if c.state == stateHandshake || c.state == stateConnected {
		return lneto.ErrBadState
	}
	if cfg.Rand == nil || cfg.Verifier == nil || len(cfg.Suites) == 0 || len(cfg.KeyExchanges) == 0 {
		return errNoConfig
	} else if len(cfg.ALPN) > 255 || len(cfg.ServerName) > 255 {
		return errNoConfig
	} else if cfg.MaxRecord < 0 || cfg.MaxRecord > tlsraw.MaxPlaintext || (cfg.MaxRecord > 0 && cfg.MaxRecord < 512) {
		return errNoConfig
	}
	if cfg.MaxRecord == 0 {
		cfg.MaxRecord = tlsraw.MaxPlaintext
	}
	for _, s := range cfg.Suites {
		if s.ID == 0 || s.NewAEAD == nil || s.NewHash == nil || s.KeyLen <= 0 || s.KeyLen > maxKeyLen {
			return errNoConfig
		}
	}
	for _, g := range cfg.KeyExchanges {
		if g.ID == 0 || g.NewExchanger == nil || g.ClientShareLen <= 0 || g.ServerShareLen <= 0 ||
			g.SharedLen <= 0 || g.SharedLen > maxShared {
			return errNoConfig
		}
	}
	if len(cfg.Schemes) == 0 {
		cfg.Schemes = DefaultSchemes
	}
	c.Zeroize()
	c.cfg = cfg
	c.serverName = []byte(cfg.ServerName)
	c.exch = c.exch[:0]
	for _, g := range cfg.KeyExchanges {
		c.exch = append(c.exch, g.NewExchanger())
	}
	c.suite, c.aeadIn, c.aeadOut, c.transcript, c.mac = nil, nil, nil, nil, nil
	return nil
}

// Open starts a new connection over rw, which must be a fresh reliable stream.
func (c *Conn) Open(rw io.ReadWriter) error {
	if rw == nil {
		return errNoConfig
	} else if c.cfg.Rand == nil {
		return lneto.ErrBadState
	}
	c.Zeroize()
	// The ciphertext adds the inner content type, padding and tag, RFC 8446 5.2.
	c.rbuf = reuse(c.rbuf, tlsraw.SizeHeaderRecord+c.cfg.MaxRecord+256)
	c.hbuf = reuse(c.hbuf, sizeHandshakeBuf)
	c.wbuf = reuse(c.wbuf, sizeWriteBuf)
	c.certBuf = reuse(c.certBuf, sizeCertBuf)
	c.rw = rw
	c.state = stateHandshake
	c.peerClosed = false
	c.hsOff, c.hsEnd = 0, 0
	c.ticketHdrN, c.ticketSkip = 0, 0
	c.certReq, c.reqCtxLen, c.nPeerScheme, c.alpnLen = false, 0, 0, 0
	c.chain = peerChain{}
	c.vld.ResetErr()
	return nil
}

// Handshake runs the handshake if it has not run yet. Read and Write call it.
func (c *Conn) Handshake() error {
	switch c.state {
	case stateConnected:
		return nil
	case stateHandshake:
	default:
		return lneto.ErrBadState
	}
	if err := c.clientHandshake(); err != nil {
		return c.fail(err)
	}
	c.state = stateConnected
	// Only tickets follow, and skipTickets reads them without hbuf, so give both buffers back.
	clear(c.hbuf)
	c.hbuf, c.hsOff, c.hsEnd = nil, 0, 0
	c.certBuf, c.chain = nil, peerChain{}
	return nil
}

// ALPN returns the negotiated protocol.
func (c *Conn) ALPN() string { return string(c.alpn[:c.alpnLen]) }

// Read reads application data. It returns io.EOF after the server's close_notify.
func (c *Conn) Read(p []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	for len(c.app) == 0 {
		if c.peerClosed {
			return 0, io.EOF
		} else if err := c.readApp(); err != nil {
			return 0, c.fail(err)
		}
	}
	n := copy(p, c.app)
	c.app = c.app[n:]
	return n, nil
}

// Write sends p as application data records.
func (c *Conn) Write(p []byte) (n int, err error) {
	if err = c.Handshake(); err != nil {
		return 0, err
	}
	for n < len(p) {
		chunk := min(len(p)-n, maxWritePlain)
		if err = c.writeRecord(tlsraw.ContentTypeApplicationData, p[n:n+chunk]); err != nil {
			return n, c.fail(err)
		}
		n += chunk
	}
	return n, nil
}

// Close sends close_notify, wipes secrets and closes rw if it is an io.Closer.
func (c *Conn) Close() error {
	var err error
	if c.state == stateConnected {
		err = c.writeAlert(tlsraw.AlertCloseNotify)
	}
	c.Zeroize()
	c.state = stateClosed
	if cl, ok := c.rw.(io.Closer); ok {
		if cerr := cl.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// Zeroize wipes secrets and buffered data. Open must be called before reuse.
func (c *Conn) Zeroize() {
	c.ks.Zeroize()
	c.in.Zeroize()
	c.out.Zeroize()
	if c.aeadIn != nil {
		c.aeadIn.Zeroize()
		c.aeadOut.Zeroize()
	}
	for _, x := range c.exch {
		x.Zeroize()
	}
	clear(c.shared[:])
	clear(c.clientHS[:])
	clear(c.serverHS[:])
	clear(c.clientAP[:])
	clear(c.serverAP[:])
	clear(c.verify[:])
	clear(c.rbuf)
	clear(c.hbuf)
	clear(c.wbuf)
	c.app = nil
	c.clientHello = nil
}

func (c *Conn) clientHandshake() error {
	if err := c.writeClientHello(); err != nil {
		return err
	}
	msg, err := c.readHandshake(tlsraw.HandshakeTypeServerHello)
	if err != nil {
		return err
	} else if err = c.handleServerHello(msg); err != nil {
		return err
	}
	msg, err = c.readHandshake(tlsraw.HandshakeTypeEncryptedExtensions)
	if err != nil {
		return err
	} else if err = c.handleEncryptedExtensions(msg); err != nil {
		return err
	}
	msg, err = c.readHandshake(0)
	if err != nil {
		return err
	}
	if tlsraw.HandshakeType(msg[0]) == tlsraw.HandshakeTypeCertificateRequest {
		if err = c.handleCertificateRequest(msg); err != nil {
			return err
		}
		msg, err = c.readHandshake(tlsraw.HandshakeTypeCertificate)
		if err != nil {
			return err
		}
	}
	if err = c.handleCertificate(msg); err != nil {
		return err
	}
	msg, err = c.readHandshake(tlsraw.HandshakeTypeCertificateVerify)
	if err != nil {
		return err
	} else if err = c.handleCertificateVerify(msg); err != nil {
		return err
	}
	msg, err = c.readHandshake(tlsraw.HandshakeTypeFinished)
	if err != nil {
		return err
	} else if err = c.handleServerFinished(msg); err != nil {
		return err
	}
	return c.writeClientFlight()
}

func (c *Conn) writeClientHello() error {
	e := c.encoder()
	rec := e.StartRecord(tlsraw.ContentTypeHandshake)
	msg := e.StartMessage(tlsraw.HandshakeTypeClientHello)
	e.Uint16(tlsraw.VersionTLS12)
	random := e.Reserve(tlsraw.SizeHelloRandom)
	if random == nil {
		return e.Err()
	} else if _, err := io.ReadFull(c.cfg.Rand, random); err != nil {
		return err
	}
	e.Uint8(0) // Empty legacy_session_id, so no middlebox compatibility mode.
	list := e.Open(2)
	for _, s := range c.cfg.Suites {
		e.Uint16(s.ID)
	}
	e.Close(list, 2)
	e.Uint8(1)
	e.Uint8(0)
	exts := e.Open(2)

	ext := startExt(&e, tlsraw.ExtSupportedVersions)
	e.Uint8(2)
	e.Uint16(tlsraw.VersionTLS13)
	e.Close(ext, 2)

	ext = startExt(&e, tlsraw.ExtSupportedGroups)
	list = e.Open(2)
	for _, g := range c.cfg.KeyExchanges {
		e.Uint16(g.ID)
	}
	e.Close(list, 2)
	e.Close(ext, 2)

	ext = startExt(&e, tlsraw.ExtSignatureAlgorithms)
	list = e.Open(2)
	for _, s := range c.cfg.Schemes {
		e.Uint16(s)
	}
	e.Close(list, 2)
	e.Close(ext, 2)

	ext = startExt(&e, tlsraw.ExtKeyShare)
	list = e.Open(2)
	for i, g := range c.cfg.KeyExchanges {
		e.Uint16(g.ID)
		key := e.Open(2)
		share := e.Reserve(g.ClientShareLen)
		if share == nil {
			return e.Err()
		}
		n, err := c.exch[i].ClientGenerateRekey(share, c.cfg.Rand)
		if err != nil {
			return err
		} else if n != g.ClientShareLen {
			return errNoConfig
		}
		e.Close(key, 2)
	}
	e.Close(list, 2)
	e.Close(ext, 2)

	if c.cfg.ALPN != "" {
		ext = startExt(&e, tlsraw.ExtALPN)
		list = e.Open(2)
		name := e.Open(1)
		e.Bytes([]byte(c.cfg.ALPN))
		e.Close(name, 1)
		e.Close(list, 2)
		e.Close(ext, 2)
	}
	if c.cfg.ServerName != "" {
		ext = startExt(&e, tlsraw.ExtServerName)
		list = e.Open(2)
		e.Uint8(0) // host_name
		name := e.Open(2)
		e.Bytes([]byte(c.cfg.ServerName))
		e.Close(name, 2)
		e.Close(list, 2)
		e.Close(ext, 2)
	}
	e.Close(exts, 2)
	// Kept in wbuf until the suite, and so the transcript hash, is known.
	c.clientHello = e.EndMessage(msg)
	e.EndRecord(rec)
	return c.flush(&e)
}

func startExt(e *tlsraw.Encoder, typ tlsraw.ExtensionType) int {
	e.Uint16(uint16(typ))
	return e.Open(2)
}

func (c *Conn) handleServerHello(msg []byte) error {
	if err := c.keyChangeBoundary(); err != nil {
		return err
	}
	var sh tlsraw.HelloServerMsg
	body := msg[tlsraw.SizeHeaderHandshake:]
	n, err := sh.Decode(body)
	if err != nil || n != len(body) {
		return alertError(tlsraw.AlertDecodeError)
	}
	if binary.BigEndian.Uint16(body) != tlsraw.VersionTLS12 {
		return alertError(tlsraw.AlertProtocolVersion)
	} else if *sh.Random() == helloRetryRandom {
		return errHelloRetry
	} else if len(sh.SessionID()) != 0 || sh.Compression() != 0 {
		return alertError(tlsraw.AlertIllegalParameter)
	}
	suite := -1
	for i := range c.cfg.Suites {
		if c.cfg.Suites[i].ID == uint16(sh.CipherSuite()) {
			suite = i
			break
		}
	}
	if suite < 0 {
		return alertError(tlsraw.AlertIllegalParameter)
	}
	var tls13 bool
	var group uint16
	var share []byte
	var seen uint64
	for exts := sh.Extensions(); len(exts) > 0; {
		ef, err := tlsraw.NewExtensionFrame(exts)
		if err != nil {
			return alertError(tlsraw.AlertDecodeError)
		}
		exts = exts[len(ef.RawData()):]
		if err := c.checkExt(ef, &seen); err != nil {
			return err
		}
		switch ef.Type() {
		case tlsraw.ExtSupportedVersions:
			tls13 = binary.BigEndian.Uint16(ef.Data()) == tlsraw.VersionTLS13
		case tlsraw.ExtKeyShare:
			g, key, _, err := tlsraw.NextKeyShare(ef.Data(), true)
			if err != nil || key == nil {
				return alertError(tlsraw.AlertIllegalParameter)
			}
			group, share = uint16(g), key
		default:
			return alertError(tlsraw.AlertUnsupportedExtension)
		}
	}
	if !tls13 {
		return alertError(tlsraw.AlertProtocolVersion)
	} else if share == nil {
		return alertError(tlsraw.AlertMissingExtension)
	}
	gi := -1
	for i := range c.cfg.KeyExchanges {
		if c.cfg.KeyExchanges[i].ID == group {
			gi = i
			break
		}
	}
	if gi < 0 || len(share) != c.cfg.KeyExchanges[gi].ServerShareLen {
		return alertError(tlsraw.AlertIllegalParameter)
	}
	if err := c.useSuite(suite); err != nil {
		return err
	} else if err := c.ks.Configure(c.transcript, c.mac, true); err != nil {
		return err
	}
	c.ks.AddMessage(c.clientHello)
	c.ks.AddMessage(msg)
	c.clientHello = nil

	g := &c.cfg.KeyExchanges[gi]
	n, err = c.exch[gi].ClientShared(c.shared[:g.SharedLen], share)
	if err != nil || n != g.SharedLen {
		return alertError(tlsraw.AlertIllegalParameter)
	}
	for _, x := range c.exch {
		x.Zeroize()
	}
	hs := c.ks.Size()
	c.ks.Handshake(c.clientHS[:hs], c.serverHS[:hs], c.shared[:g.SharedLen])
	clear(c.shared[:])
	if err := c.setKeys(&c.in, c.aeadIn, c.serverHS[:hs]); err != nil {
		return err
	}
	return c.setKeys(&c.out, c.aeadOut, c.clientHS[:hs])
}

// checkExt validates the shape of a server extension and rejects duplicates.
func (c *Conn) checkExt(ef tlsraw.ExtensionFrame, seen *uint64) error {
	ef.ValidateType(&c.vld, true)
	if c.vld.HasError() {
		c.vld.ResetErr()
		return alertError(tlsraw.AlertDecodeError)
	}
	if typ := ef.Type(); typ < 64 {
		if *seen&(1<<typ) != 0 {
			return alertError(tlsraw.AlertIllegalParameter)
		}
		*seen |= 1 << typ
	}
	return nil
}

func (c *Conn) useSuite(i int) error {
	s := &c.cfg.Suites[i]
	c.aeadIn, c.aeadOut = s.NewAEAD(), s.NewAEAD()
	c.transcript, c.mac = s.NewHash(), s.NewHash()
	if c.transcript.Size() > maxHashSize {
		return lneto.ErrUnsupported
	}
	c.suite = s
	return nil
}

func (c *Conn) handleEncryptedExtensions(msg []byte) error {
	body := msg[tlsraw.SizeHeaderHandshake:]
	if len(body) < 2 || int(binary.BigEndian.Uint16(body)) != len(body)-2 {
		return alertError(tlsraw.AlertDecodeError)
	}
	var seen uint64
	for exts := body[2:]; len(exts) > 0; {
		ef, err := tlsraw.NewExtensionFrame(exts)
		if err != nil {
			return alertError(tlsraw.AlertDecodeError)
		}
		exts = exts[len(ef.RawData()):]
		if err := c.checkExt(ef, &seen); err != nil {
			return err
		}
		switch ef.Type() {
		case tlsraw.ExtALPN:
			name := ef.Data()[3:]
			if c.cfg.ALPN == "" || string(name) != c.cfg.ALPN {
				return alertError(tlsraw.AlertIllegalParameter)
			}
			c.alpnLen = copy(c.alpn[:], name)
		case tlsraw.ExtKeyShare, tlsraw.ExtSupportedVersions, tlsraw.ExtSignatureAlgorithms,
			tlsraw.ExtPreSharedKey, tlsraw.ExtCookie, tlsraw.ExtPSKKeyExchangeModes:
			// RFC 8446 4.2: not allowed in EncryptedExtensions.
			return alertError(tlsraw.AlertIllegalParameter)
		}
	}
	if c.cfg.ALPN != "" && c.alpnLen == 0 {
		return alertError(tlsraw.AlertNoApplicationProtocol)
	}
	c.ks.AddMessage(msg)
	return nil
}

func (c *Conn) handleCertificateRequest(msg []byte) error {
	body := msg[tlsraw.SizeHeaderHandshake:]
	if len(body) < 1 {
		return alertError(tlsraw.AlertDecodeError)
	}
	ctxLen := int(body[0])
	body = body[1:]
	if len(body) < ctxLen+2 {
		return alertError(tlsraw.AlertDecodeError)
	}
	c.reqCtxLen = copy(c.reqCtx[:], body[:ctxLen])
	body = body[ctxLen:]
	if int(binary.BigEndian.Uint16(body)) != len(body)-2 {
		return alertError(tlsraw.AlertDecodeError)
	}
	var seen uint64
	var schemes []byte
	for exts := body[2:]; len(exts) > 0; {
		ef, err := tlsraw.NewExtensionFrame(exts)
		if err != nil {
			return alertError(tlsraw.AlertDecodeError)
		}
		exts = exts[len(ef.RawData()):]
		if err := c.checkExt(ef, &seen); err != nil {
			return err
		}
		if ef.Type() == tlsraw.ExtSignatureAlgorithms {
			schemes = ef.Data()[2:]
		}
	}
	if schemes == nil {
		return alertError(tlsraw.AlertMissingExtension)
	}
	c.nPeerScheme = 0
	for i := 0; i+1 < len(schemes) && c.nPeerScheme < len(c.peerSchemes); i += 2 {
		c.peerSchemes[c.nPeerScheme] = binary.BigEndian.Uint16(schemes[i:])
		c.nPeerScheme++
	}
	c.certReq = true
	c.ks.AddMessage(msg)
	return nil
}

func (c *Conn) handleCertificate(msg []byte) error {
	if tlsraw.HandshakeType(msg[0]) != tlsraw.HandshakeTypeCertificate {
		return alertError(tlsraw.AlertUnexpectedMessage)
	}
	body := msg[tlsraw.SizeHeaderHandshake:]
	if len(body) > len(c.certBuf) {
		return alertError(tlsraw.AlertBadCertificate)
	}
	// Copied out because readHandshake moves hbuf before CertificateVerify arrives.
	body = c.certBuf[:copy(c.certBuf, body)]
	if len(body) < 4 || body[0] != 0 {
		return alertError(tlsraw.AlertDecodeError)
	}
	list := body[1:]
	if int(uint24(list)) != len(list)-3 {
		return alertError(tlsraw.AlertDecodeError)
	}
	list = list[3:]
	c.chain = peerChain{}
	for len(list) > 0 {
		if len(list) < 3 {
			return alertError(tlsraw.AlertDecodeError)
		}
		n := int(uint24(list))
		list = list[3:]
		if n == 0 || len(list) < n+2 {
			return alertError(tlsraw.AlertDecodeError)
		}
		if c.chain.n == maxPeerCerts {
			return alertError(tlsraw.AlertBadCertificate)
		}
		c.chain.certs[c.chain.n] = list[:n]
		c.chain.n++
		list = list[n:]
		extLen := int(binary.BigEndian.Uint16(list))
		if len(list) < 2+extLen {
			return alertError(tlsraw.AlertDecodeError)
		}
		list = list[2+extLen:]
	}
	if c.chain.n == 0 {
		return alertError(tlsraw.AlertDecodeError)
	}
	c.ks.AddMessage(msg)
	return nil
}

func (c *Conn) handleCertificateVerify(msg []byte) error {
	body := msg[tlsraw.SizeHeaderHandshake:]
	if len(body) < 4 || int(binary.BigEndian.Uint16(body[2:])) != len(body)-4 {
		return alertError(tlsraw.AlertDecodeError)
	}
	scheme := binary.BigEndian.Uint16(body)
	offered := false
	for _, s := range c.cfg.Schemes {
		offered = offered || s == scheme
	}
	if !offered || legacyScheme(scheme) {
		return alertError(tlsraw.AlertIllegalParameter)
	}
	signed := c.cvContent(serverCVContext)
	err := c.cfg.Verifier.VerifyPeer(&c.chain, scheme, true, c.serverName, signed, body[4:])
	if err != nil {
		return verifyError{err}
	}
	c.ks.AddMessage(msg)
	return nil
}

// cvContent builds the signed content of RFC 8446 4.4.3 for the transcript so far.
func (c *Conn) cvContent(context string) []byte {
	for i := range 64 {
		c.cv[i] = 0x20
	}
	copy(c.cv[64:], context)
	c.cv[sizeCVPrefix-1] = 0
	signed := c.cv[:sizeCVPrefix+c.ks.Size()]
	c.ks.TranscriptHash(signed[sizeCVPrefix:])
	return signed
}

func (c *Conn) handleServerFinished(msg []byte) error {
	if err := c.keyChangeBoundary(); err != nil {
		return err
	}
	hs := c.ks.Size()
	c.ks.Finished(c.verify[:hs], c.serverHS[:hs])
	got := msg[tlsraw.SizeHeaderHandshake:]
	if len(got) != hs {
		return alertError(tlsraw.AlertDecodeError)
	} else if !ctEqual(got, c.verify[:hs]) {
		return alertError(tlsraw.AlertDecryptError)
	}
	c.ks.AddMessage(msg)
	c.ks.Master(c.clientAP[:hs], c.serverAP[:hs])
	clear(c.serverHS[:])
	return c.setKeys(&c.in, c.aeadIn, c.serverAP[:hs])
}

func (c *Conn) writeClientFlight() error {
	hs := c.ks.Size()
	e := c.encoder()
	rec := e.StartRecord(tlsraw.ContentTypeApplicationData)
	if c.certReq {
		var scheme uint16
		cred := c.cfg.Credential
		if cred != nil && cred.NumCerts() > 0 {
			scheme = cred.Scheme(c.peerSchemes[:c.nPeerScheme])
			if legacyScheme(scheme) || !hasScheme(c.peerSchemes[:c.nPeerScheme], scheme) {
				scheme = 0
			}
		}
		msg := e.StartMessage(tlsraw.HandshakeTypeCertificate)
		e.Uint8(uint8(c.reqCtxLen))
		e.Bytes(c.reqCtx[:c.reqCtxLen])
		list := e.Open(3)
		if scheme != 0 {
			for i := range cred.NumCerts() {
				data := e.Open(3)
				n, err := cred.Cert(e.Rest(), i)
				if err != nil {
					return err
				}
				e.Advance(n)
				e.Close(data, 3)
				e.Uint16(0)
			}
		}
		e.Close(list, 3)
		c.ks.AddMessage(e.EndMessage(msg))
		if scheme != 0 {
			signed := c.cvContent(clientCVContext)
			msg = e.StartMessage(tlsraw.HandshakeTypeCertificateVerify)
			e.Uint16(scheme)
			sig := e.Open(2)
			n, err := cred.Sign(e.Rest(), signed, scheme)
			if err != nil {
				return err
			}
			e.Advance(n)
			e.Close(sig, 2)
			c.ks.AddMessage(e.EndMessage(msg))
		}
	}
	msg := e.StartMessage(tlsraw.HandshakeTypeFinished)
	if verify := e.Reserve(hs); verify != nil {
		c.ks.Finished(verify, c.clientHS[:hs])
	}
	e.EndMessage(msg)
	e.SealRecord(&c.out, rec, tlsraw.ContentTypeHandshake)
	if err := c.flush(&e); err != nil {
		return err
	}
	clear(c.clientHS[:])
	err := c.setKeys(&c.out, c.aeadOut, c.clientAP[:hs])
	clear(c.clientAP[:])
	clear(c.serverAP[:])
	c.ks.Zeroize()
	return err
}

// keyChangeBoundary rejects handshake data after a message that changes keys, RFC 8446 5.1.
func (c *Conn) keyChangeBoundary() error {
	if c.hsOff != c.hsEnd {
		return alertError(tlsraw.AlertUnexpectedMessage)
	}
	return nil
}

func (c *Conn) setKeys(hc *tlsraw.HalfConn, aead lcrypto.AEADCipher, secret []byte) error {
	return c.ks.InstallKeys(hc, aead, c.suite.KeyLen, secret)
}

// readHandshake returns the next handshake message, header included, of type want or any type if want is 0.
// It points into hbuf and is valid until the next call.
func (c *Conn) readHandshake(want tlsraw.HandshakeType) ([]byte, error) {
	for {
		msg, err := c.nextHandshake()
		if err != nil {
			return nil, err
		} else if msg != nil {
			if want != 0 && tlsraw.HandshakeType(msg[0]) != want {
				return nil, alertError(tlsraw.AlertUnexpectedMessage)
			}
			return msg, nil
		}
		ct, content, err := c.readRecord()
		if err != nil {
			return nil, err
		}
		switch ct {
		case tlsraw.ContentTypeHandshake:
			if err := c.pushHandshake(content); err != nil {
				return nil, err
			}
		case tlsraw.ContentTypeAlert:
			if err := c.handleAlert(content); err != nil {
				return nil, err
			}
			return nil, io.ErrUnexpectedEOF
		default:
			return nil, alertError(tlsraw.AlertUnexpectedMessage)
		}
	}
}

// nextHandshake pops a complete message from hbuf, or returns nil if none is buffered.
func (c *Conn) nextHandshake() ([]byte, error) {
	pending := c.hbuf[c.hsOff:c.hsEnd]
	if len(pending) < tlsraw.SizeHeaderHandshake {
		return nil, nil
	}
	end := tlsraw.SizeHeaderHandshake + int(uint24(pending[1:]))
	if end > len(c.hbuf) {
		return nil, alertError(tlsraw.AlertRecordOverflow)
	} else if end > len(pending) {
		return nil, nil
	}
	c.hsOff += end
	return pending[:end], nil
}

func (c *Conn) pushHandshake(content []byte) error {
	c.hsEnd = copy(c.hbuf, c.hbuf[c.hsOff:c.hsEnd])
	c.hsOff = 0
	if len(content) == 0 {
		return alertError(tlsraw.AlertUnexpectedMessage)
	} else if len(content) > len(c.hbuf)-c.hsEnd {
		return alertError(tlsraw.AlertRecordOverflow)
	}
	c.hsEnd += copy(c.hbuf[c.hsEnd:], content)
	return nil
}

// readApp reads one record after the handshake. Application data is left in c.app.
func (c *Conn) readApp() error {
	ct, content, err := c.readRecord()
	if err != nil {
		return err
	}
	switch ct {
	case tlsraw.ContentTypeApplicationData:
		c.app = content
		return nil
	case tlsraw.ContentTypeAlert:
		return c.handleAlert(content)
	case tlsraw.ContentTypeHandshake:
		if len(content) == 0 {
			return alertError(tlsraw.AlertUnexpectedMessage)
		}
		return c.skipTickets(content)
	}
	return alertError(tlsraw.AlertUnexpectedMessage)
}

// skipTickets drops NewSessionTicket messages as they arrive, split across records or not.
// PSK is not supported and KeyUpdate is not supported yet, so anything else is an error.
func (c *Conn) skipTickets(content []byte) error {
	for len(content) > 0 {
		if c.ticketSkip > 0 {
			n := min(c.ticketSkip, len(content))
			c.ticketSkip -= n
			content = content[n:]
			continue
		}
		n := copy(c.ticketHdr[c.ticketHdrN:], content)
		c.ticketHdrN += n
		content = content[n:]
		if c.ticketHdrN < len(c.ticketHdr) {
			return nil
		}
		if tlsraw.HandshakeType(c.ticketHdr[0]) != tlsraw.HandshakeTypeNewSessionTicket {
			return alertError(tlsraw.AlertUnexpectedMessage)
		}
		c.ticketHdrN, c.ticketSkip = 0, int(uint24(c.ticketHdr[1:]))
	}
	return nil
}

// readRecord reads one record and returns its content type and content, decrypted
// once keys are installed. content points into rbuf and is valid until the next call.
func (c *Conn) readRecord() (tlsraw.ContentType, []byte, error) {
	for dropped := 0; ; dropped++ {
		hdr := c.rbuf[:tlsraw.SizeHeaderRecord]
		if _, err := io.ReadFull(c.rw, hdr); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF // Only close_notify ends a connection cleanly, RFC 8446 6.1.
			}
			return 0, nil, err
		}
		n := int(binary.BigEndian.Uint16(hdr[3:5]))
		if n > tlsraw.MaxCiphertext || n > len(c.rbuf)-tlsraw.SizeHeaderRecord {
			return 0, nil, alertError(tlsraw.AlertRecordOverflow)
		}
		rec := c.rbuf[:tlsraw.SizeHeaderRecord+n]
		if _, err := io.ReadFull(c.rw, rec[tlsraw.SizeHeaderRecord:]); err != nil {
			return 0, nil, err
		}
		ct := tlsraw.ContentType(rec[0])
		content := rec[tlsraw.SizeHeaderRecord:]
		switch {
		case ct == tlsraw.ContentTypeChangeCipherSpec:
			// RFC 8446 5: dropped during the handshake.
			if c.state != stateHandshake || n != 1 || content[0] != 1 || dropped > 0 {
				return 0, nil, alertError(tlsraw.AlertUnexpectedMessage)
			}
			continue
		case c.in.HasKeys():
			if ct != tlsraw.ContentTypeApplicationData {
				return 0, nil, alertError(tlsraw.AlertUnexpectedMessage)
			}
			var err error
			content, ct, err = c.in.Open(rec)
			if err != nil {
				return 0, nil, alertError(tlsraw.AlertBadRecordMAC)
			}
		case ct != tlsraw.ContentTypeHandshake && ct != tlsraw.ContentTypeAlert:
			return 0, nil, alertError(tlsraw.AlertUnexpectedMessage)
		}
		if len(content) > c.cfg.MaxRecord {
			return 0, nil, alertError(tlsraw.AlertRecordOverflow)
		}
		return ct, content, nil
	}
}

func (c *Conn) handleAlert(content []byte) error {
	if len(content) != 2 {
		return alertError(tlsraw.AlertDecodeError)
	}
	switch desc := tlsraw.AlertDescription(content[1]); desc {
	case tlsraw.AlertCloseNotify:
		c.peerClosed = true
		return nil
	case tlsraw.AlertUserCanceled:
		return nil
	default:
		return peerAlertError(desc)
	}
}

func (c *Conn) writeRecord(ct tlsraw.ContentType, content []byte) error {
	e := c.encoder()
	rec := e.StartRecord(ct)
	e.Bytes(content)
	if c.out.HasKeys() {
		e.SealRecord(&c.out, rec, ct)
	} else {
		e.EndRecord(rec)
	}
	return c.flush(&e)
}

func (c *Conn) writeAlert(desc tlsraw.AlertDescription) error {
	level := tlsraw.AlertLevelFatal
	if desc == tlsraw.AlertCloseNotify {
		level = tlsraw.AlertLevelWarning
	}
	alert := [2]byte{byte(level), byte(desc)}
	return c.writeRecord(tlsraw.ContentTypeAlert, alert[:])
}

func (c *Conn) encoder() tlsraw.Encoder {
	var e tlsraw.Encoder
	e.Reset(c.wbuf, 0)
	return e
}

func (c *Conn) flush(e *tlsraw.Encoder) error {
	if err := e.Err(); err != nil {
		return err
	}
	_, err := c.rw.Write(c.wbuf[:e.Len()])
	return err
}

// fail sends the alert for err, wipes secrets and marks c unusable.
func (c *Conn) fail(err error) error {
	switch a := err.(type) {
	case peerAlertError:
	case alertError:
		c.writeAlert(tlsraw.AlertDescription(a))
	case verifyError:
		c.writeAlert(tlsraw.AlertBadCertificate)
	default:
		if err == errHelloRetry {
			c.writeAlert(tlsraw.AlertHandshakeFailure)
		} else if err != io.EOF && err != io.ErrUnexpectedEOF {
			c.writeAlert(tlsraw.AlertInternalError)
		}
	}
	c.Zeroize()
	c.state = stateFailed
	return err
}

// peerChain is a view of the server's Certificate message in certBuf.
type peerChain struct {
	certs [maxPeerCerts][]byte
	n     int
}

func (p *peerChain) NumCerts() int { return p.n }

func (p *peerChain) Cert(dst []byte, i int) (int, error) {
	if i < 0 || i >= p.n {
		return 0, lneto.ErrInvalidConfig
	} else if len(dst) < len(p.certs[i]) {
		return len(p.certs[i]), io.ErrShortBuffer
	}
	return copy(dst, p.certs[i]), nil
}

func (p *peerChain) CertView(i int) ([]byte, error) {
	if i < 0 || i >= p.n {
		return nil, lneto.ErrInvalidConfig
	}
	return p.certs[i], nil
}

// legacyScheme reports SHA-1 and RSASSA-PKCS1-v1_5 schemes, which RFC 8446 4.2.3 forbids in CertificateVerify.
func legacyScheme(s uint16) bool {
	h, sig := s>>8, s&0xff
	return h == 0x02 || (sig == 0x01 && h <= 0x06)
}

func hasScheme(list []uint16, s uint16) bool {
	return slices.Contains(list, s)
}

func uint24(b []byte) uint32 { return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]) }

func ctEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func reuse(buf []byte, n int) []byte {
	if cap(buf) < n {
		return make([]byte, n)
	}
	return buf[:n]
}

type alertError tlsraw.AlertDescription

func (a alertError) Error() string { return "tlsauto: sent alert " + strconv.Itoa(int(a)) }

type peerAlertError tlsraw.AlertDescription

func (a peerAlertError) Error() string { return "tlsauto: received alert " + strconv.Itoa(int(a)) }

type verifyError struct{ err error }

func (v verifyError) Error() string { return "tlsauto: peer verification failed: " + v.err.Error() }
func (v verifyError) Unwrap() error { return v.err }
