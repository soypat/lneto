package tlsauto

import (
	"encoding/binary"
	"hash"
	"io"
	"slices"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/lcrypto"
	"github.com/soypat/lneto/crypto/tlsraw"
)

const (
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

// recordKeys is the record protection of both directions. The handshake installs
// keys into it, and the handler seals and opens with it.
type recordKeys struct {
	in, out         tlsraw.HalfConn
	aeadIn, aeadOut lcrypto.AEADCipher
}

func (rk *recordKeys) zeroize() {
	rk.in.Zeroize()
	rk.out.Zeroize()
	if rk.aeadIn != nil {
		rk.aeadIn.Zeroize()
		rk.aeadOut.Zeroize()
	}
}

// handshakeCommon is the part of the RFC 8446 handshake both roles share: the
// key schedule and the authentication messages of 4.4 (Certificate,
// CertificateVerify and Finished), which are the same in either direction.
// Secrets are named own and peer instead of client and server, so only the key
// schedule calls depend on the role. The order of messages and the hellos are
// not shared: each role's handshake embeds handshakeCommon and drives it.
type handshakeCommon struct {
	cfg  *Config // The handler's copy, set by configure.
	exch []lcrypto.Exchanger
	vld  lneto.Validator
	// peerIsServer is true on the client. It picks how the key schedule's
	// secrets map to own and peer, the CertificateVerify contexts and the Verifier's role.
	peerIsServer bool
	// peerName is the identity Verifier checks the peer's leaf against: cfg.ServerName on the client.
	peerName []byte

	suite           *Suite
	ks              tlsraw.KeySchedule
	transcript, mac hash.Hash
	// alpnOK reports that cfg.ALPN was negotiated, the only acceptable protocol.
	alpnOK bool

	// peerSchemes is the peer's signature_algorithms: what it accepts in our CertificateVerify.
	peerSchemes [maxOfferedScheme]uint16
	nPeerScheme uint8
	// certBuf keeps the peer's Certificate, since the HandshakeReader moves its
	// bytes before CertificateVerify arrives.
	certBuf []byte
	chain   peerChain

	cv            [sizeCVPrefix + maxHashSize]byte
	shared        [maxShared]byte
	ownHS, peerHS [maxHashSize]byte // Handshake traffic secrets.
	ownAP, peerAP [maxHashSize]byte // Application traffic secrets.
	verify        [maxHashSize]byte
}

// configure binds cfg and the role, and builds one Exchanger per key exchange.
// It clears peerName, which the role sets after.
func (hs *handshakeCommon) configure(cfg *Config, peerIsServer bool) {
	hs.cfg = cfg
	hs.peerIsServer = peerIsServer
	hs.peerName = nil
	hs.exch = hs.exch[:0]
	for _, g := range cfg.KeyExchanges {
		hs.exch = append(hs.exch, g.NewExchanger())
	}
	hs.suite, hs.transcript, hs.mac = nil, nil, nil
}

// reset wipes secrets and negotiated state for a new handshake that keeps the
// peer's Certificate in certBuf. It keeps cfg, exch, the role and peerName.
func (hs *handshakeCommon) reset(certBuf []byte) {
	hs.zeroize()
	hs.vld.ResetErr()
	hs.suite, hs.transcript, hs.mac = nil, nil, nil
	hs.alpnOK = false
	hs.nPeerScheme = 0
	hs.certBuf = certBuf
}

// zeroize wipes key shares, secrets and the peer chain. It keeps negotiated state such as alpnOK.
func (hs *handshakeCommon) zeroize() {
	hs.ks.Zeroize()
	for _, x := range hs.exch {
		x.Zeroize()
	}
	clear(hs.cv[:])
	clear(hs.shared[:])
	clear(hs.ownHS[:])
	clear(hs.peerHS[:])
	clear(hs.ownAP[:])
	clear(hs.peerAP[:])
	clear(hs.verify[:])
	clear(hs.certBuf)
	hs.chain = peerChain{}
}

// expect rejects a message of the wrong type, or one followed by buffered
// handshake bytes when it changes keys.
func expect(got, want tlsraw.HandshakeType, pendingAtKeyChange bool) error {
	if got != want || pendingAtKeyChange {
		return alertError(tlsraw.AlertUnexpectedMessage)
	}
	return nil
}

func startExt(e *tlsraw.Encoder, typ tlsraw.ExtensionType) int {
	e.Uint16(uint16(typ))
	return e.Open(2)
}

// checkExt validates the shape of an extension the peer sent and rejects duplicates.
func (hs *handshakeCommon) checkExt(ef tlsraw.ExtensionFrame, seen *uint64) error {
	ef.ValidateType(&hs.vld, hs.peerIsServer)
	if hs.vld.HasError() {
		hs.vld.ResetErr()
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

// useSuite selects cfg.Suites[i]: it builds the AEADs and hashes and starts the key schedule.
func (hs *handshakeCommon) useSuite(rk *recordKeys, i int) error {
	s := &hs.cfg.Suites[i]
	rk.aeadIn, rk.aeadOut = s.NewAEAD(), s.NewAEAD()
	hs.transcript, hs.mac = s.NewHash(), s.NewHash()
	if hs.transcript.Size() > maxHashSize {
		return lneto.ErrUnsupported
	}
	hs.suite = s
	return hs.ks.Configure(hs.transcript, hs.mac, true)
}

// installHandshakeKeys advances the key schedule with the shared secret in
// hs.shared[:n], which it wipes, and installs the handshake traffic keys of
// both directions. The transcript must end at ServerHello.
func (hs *handshakeCommon) installHandshakeKeys(rk *recordKeys, n int) error {
	size := hs.ks.Size()
	own, peer := hs.ownHS[:size], hs.peerHS[:size]
	if hs.peerIsServer {
		hs.ks.Handshake(own, peer, hs.shared[:n])
	} else {
		hs.ks.Handshake(peer, own, hs.shared[:n])
	}
	clear(hs.shared[:])
	if err := hs.setKeys(&rk.in, rk.aeadIn, peer); err != nil {
		return err
	}
	return hs.setKeys(&rk.out, rk.aeadOut, own)
}

// deriveMaster advances to the master secret and writes the application traffic
// secrets to ownAP and peerAP. The transcript must end at the server Finished.
func (hs *handshakeCommon) deriveMaster() {
	size := hs.ks.Size()
	own, peer := hs.ownAP[:size], hs.peerAP[:size]
	if hs.peerIsServer {
		hs.ks.Master(own, peer)
	} else {
		hs.ks.Master(peer, own)
	}
}

func (hs *handshakeCommon) setKeys(hc *tlsraw.HalfConn, aead lcrypto.AEADCipher, secret []byte) error {
	return hs.ks.InstallKeys(hc, aead, hs.suite.KeyLen, secret)
}

// cvContexts returns the CertificateVerify context strings of RFC 8446 4.4.3
// that this side and its peer sign with.
func (hs *handshakeCommon) cvContexts() (own, peer string) {
	if hs.peerIsServer {
		return clientCVContext, serverCVContext
	}
	return serverCVContext, clientCVContext
}

// cvContent builds the signed content of RFC 8446 4.4.3 for the transcript so far.
func (hs *handshakeCommon) cvContent(context string) []byte {
	for i := range 64 {
		hs.cv[i] = 0x20
	}
	copy(hs.cv[64:], context)
	hs.cv[sizeCVPrefix-1] = 0
	signed := hs.cv[:sizeCVPrefix+hs.ks.Size()]
	hs.ks.TranscriptHash(signed[sizeCVPrefix:])
	return signed
}

// readCertificate copies the peer's Certificate message, RFC 8446 4.4.2, into
// certBuf and views its chain. Its certificate_request_context must be empty,
// as RFC 8446 4.3.2 requires outside post-handshake authentication.
func (hs *handshakeCommon) readCertificate(msg []byte) error {
	body := msg[tlsraw.SizeHeaderHandshake:]
	if len(body) > len(hs.certBuf) {
		return alertError(tlsraw.AlertBadCertificate)
	}
	// Copied out because HandshakeReader.Next moves its buffer before CertificateVerify arrives.
	body = hs.certBuf[:copy(hs.certBuf, body)]
	if len(body) < 4 || body[0] != 0 {
		return alertError(tlsraw.AlertDecodeError)
	}
	list := body[1:]
	if int(uint24(list)) != len(list)-3 {
		return alertError(tlsraw.AlertDecodeError)
	}
	list = list[3:]
	hs.chain = peerChain{}
	for len(list) > 0 {
		if len(list) < 3 {
			return alertError(tlsraw.AlertDecodeError)
		}
		n := int(uint24(list))
		list = list[3:]
		if n == 0 || len(list) < n+2 {
			return alertError(tlsraw.AlertDecodeError)
		}
		if hs.chain.n == maxPeerCerts {
			return alertError(tlsraw.AlertBadCertificate)
		}
		hs.chain.certs[hs.chain.n] = list[:n]
		hs.chain.n++
		list = list[n:]
		extLen := int(binary.BigEndian.Uint16(list))
		if len(list) < 2+extLen {
			return alertError(tlsraw.AlertDecodeError)
		}
		list = list[2+extLen:]
	}
	if hs.chain.n == 0 {
		return alertError(tlsraw.AlertDecodeError)
	}
	hs.ks.AddMessage(msg)
	return nil
}

// readCertificateVerify has Verifier check the peer's chain and its signature
// over the transcript so far, RFC 8446 4.4.3, made with a scheme this side offered.
func (hs *handshakeCommon) readCertificateVerify(msg []byte) error {
	body := msg[tlsraw.SizeHeaderHandshake:]
	if len(body) < 4 || int(binary.BigEndian.Uint16(body[2:])) != len(body)-4 {
		return alertError(tlsraw.AlertDecodeError)
	}
	scheme := binary.BigEndian.Uint16(body)
	if !hasScheme(hs.cfg.Schemes, scheme) || legacyScheme(scheme) {
		return alertError(tlsraw.AlertIllegalParameter)
	}
	_, peerContext := hs.cvContexts()
	signed := hs.cvContent(peerContext)
	err := hs.cfg.Verifier.VerifyPeer(&hs.chain, scheme, hs.peerIsServer, hs.peerName, signed, body[4:])
	if err != nil {
		return verifyError{err}
	}
	hs.ks.AddMessage(msg)
	return nil
}

// readFinished checks the peer's Finished, RFC 8446 4.4.4, against its
// handshake traffic secret, which it then wipes.
func (hs *handshakeCommon) readFinished(msg []byte) error {
	size := hs.ks.Size()
	hs.ks.Finished(hs.verify[:size], hs.peerHS[:size])
	got := msg[tlsraw.SizeHeaderHandshake:]
	if len(got) != size {
		return alertError(tlsraw.AlertDecodeError)
	} else if !ctEqual(got, hs.verify[:size]) {
		return alertError(tlsraw.AlertDecryptError)
	}
	hs.ks.AddMessage(msg)
	clear(hs.peerHS[:])
	return nil
}

// ownScheme returns the scheme cfg.Credential signs CertificateVerify with, chosen
// from those the peer accepts, or 0 when there is no usable credential.
func (hs *handshakeCommon) ownScheme() uint16 {
	cred := hs.cfg.Credential
	if cred == nil || cred.NumCerts() == 0 {
		return 0
	}
	accepted := hs.peerSchemes[:hs.nPeerScheme]
	scheme := cred.Scheme(accepted)
	if legacyScheme(scheme) || !hasScheme(accepted, scheme) {
		return 0
	}
	return scheme
}

// writeCertificate encodes a Certificate message, RFC 8446 4.4.2, carrying
// cfg.Credential's chain, or no certificates when withChain is false, and adds
// it to the transcript.
func (hs *handshakeCommon) writeCertificate(e *tlsraw.Encoder, reqCtx []byte, withChain bool) error {
	msg := e.StartMessage(tlsraw.HandshakeTypeCertificate)
	e.Uint8(uint8(len(reqCtx)))
	e.Bytes(reqCtx)
	list := e.Open(3)
	if withChain {
		cred := hs.cfg.Credential
		for i := range cred.NumCerts() {
			data := e.Open(3)
			n, err := cred.Cert(e.Rest(), i)
			if err != nil {
				return err
			}
			e.Advance(n)
			e.Close(data, 3)
			e.Uint16(0) // No certificate extensions.
		}
	}
	e.Close(list, 3)
	hs.ks.AddMessage(e.EndMessage(msg))
	return nil
}

// writeCertificateVerify signs the transcript so far with cfg.Credential, RFC
// 8446 4.4.3, and adds the message to the transcript.
func (hs *handshakeCommon) writeCertificateVerify(e *tlsraw.Encoder, scheme uint16) error {
	ownContext, _ := hs.cvContexts()
	signed := hs.cvContent(ownContext)
	msg := e.StartMessage(tlsraw.HandshakeTypeCertificateVerify)
	e.Uint16(scheme)
	sig := e.Open(2)
	n, err := hs.cfg.Credential.Sign(e.Rest(), signed, scheme)
	if err != nil {
		return err
	}
	e.Advance(n)
	e.Close(sig, 2)
	hs.ks.AddMessage(e.EndMessage(msg))
	return nil
}

// writeFinished encodes this side's Finished, RFC 8446 4.4.4, adds it to the
// transcript and wipes this side's handshake traffic secret.
func (hs *handshakeCommon) writeFinished(e *tlsraw.Encoder) {
	size := hs.ks.Size()
	msg := e.StartMessage(tlsraw.HandshakeTypeFinished)
	if verify := e.Reserve(size); verify != nil {
		hs.ks.Finished(verify, hs.ownHS[:size])
	}
	hs.ks.AddMessage(e.EndMessage(msg))
	clear(hs.ownHS[:])
}

// peerChain is a view of the peer's Certificate message in certBuf.
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
