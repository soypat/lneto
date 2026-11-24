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

type hsState uint8

const (
	hsIdle hsState = iota // Nothing sent.
	hsWaitServerHello
	hsWaitEncryptedExtensions
	hsWaitCertOrRequest
	hsWaitCertificate // After CertificateRequest.
	hsWaitCertVerify
	hsWaitFinished
	hsWantFlight // Server Finished verified, client flight not yet written.
	hsDone
)

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

// clientHandshake is the client side of the RFC 8446 handshake with no I/O and
// no record layer, the role tcp.ControlBlock plays. It consumes whole handshake
// messages and writes the client's messages to an Encoder.
type clientHandshake struct {
	cfg        *Config // The handler's copy, set by configure.
	serverName []byte  // cfg.ServerName converted once for Verifier.VerifyPeer.
	exch       []lcrypto.Exchanger
	state      hsState
	vld        lneto.Validator

	suite           *Suite
	ks              tlsraw.KeySchedule
	transcript, mac hash.Hash
	// clientHello points into the handler's WriteBuf until ServerHello picks
	// the transcript hash. Nothing else is encoded in that window.
	clientHello []byte
	// alpnOK reports that the server selected cfg.ALPN, the only acceptable answer.
	alpnOK bool

	certReq     bool
	reqCtx      [maxRequestCtx]byte
	reqCtxLen   uint8
	peerSchemes [maxOfferedScheme]uint16
	nPeerScheme uint8
	// certBuf keeps the server Certificate, since the HandshakeReader moves its
	// bytes before CertificateVerify arrives.
	certBuf []byte
	chain   peerChain

	cv                 [sizeCVPrefix + maxHashSize]byte
	shared             [maxShared]byte
	clientHS, serverHS [maxHashSize]byte
	clientAP, serverAP [maxHashSize]byte
	verify             [maxHashSize]byte
}

// configure binds cfg and builds one Exchanger per key exchange.
func (hs *clientHandshake) configure(cfg *Config) {
	hs.cfg = cfg
	hs.serverName = []byte(cfg.ServerName)
	hs.exch = hs.exch[:0]
	for _, g := range cfg.KeyExchanges {
		hs.exch = append(hs.exch, g.NewExchanger())
	}
	hs.suite, hs.transcript, hs.mac = nil, nil, nil
}

// reset wipes secrets and scratch and returns to hsIdle. It keeps cfg, exch and serverName.
func (hs *clientHandshake) reset(certBuf []byte) {
	hs.zeroize()
	hs.state = hsIdle
	hs.vld.ResetErr()
	hs.suite, hs.transcript, hs.mac = nil, nil, nil
	hs.alpnOK, hs.certReq = false, false
	hs.reqCtxLen, hs.nPeerScheme = 0, 0
	hs.certBuf = certBuf
}

// zeroize wipes key shares, secrets and the peer chain. It keeps state and alpnOK.
func (hs *clientHandshake) zeroize() {
	hs.ks.Zeroize()
	for _, x := range hs.exch {
		x.Zeroize()
	}
	clear(hs.cv[:])
	clear(hs.shared[:])
	clear(hs.clientHS[:])
	clear(hs.serverHS[:])
	clear(hs.clientAP[:])
	clear(hs.serverAP[:])
	clear(hs.verify[:])
	clear(hs.certBuf)
	hs.chain = peerChain{}
	hs.clientHello = nil
}

func (hs *clientHandshake) done() bool       { return hs.state == hsDone }
func (hs *clientHandshake) wantFlight() bool { return hs.state == hsWantFlight }

// handle consumes one handshake message with its header. It installs keys into rk
// on ServerHello and server Finished. pending reports more buffered handshake
// bytes, which RFC 8446 5.1 forbids at both key changes.
func (hs *clientHandshake) handle(rk *recordKeys, msg []byte, pending bool) error {
	typ := tlsraw.HandshakeType(msg[0])
	var err error
	switch hs.state {
	case hsWaitServerHello:
		if err = expect(typ, tlsraw.HandshakeTypeServerHello, pending); err == nil {
			err = hs.handleServerHello(rk, msg)
		}
		hs.state = hsWaitEncryptedExtensions
	case hsWaitEncryptedExtensions:
		if err = expect(typ, tlsraw.HandshakeTypeEncryptedExtensions, false); err == nil {
			err = hs.handleEncryptedExtensions(msg)
		}
		hs.state = hsWaitCertOrRequest
	case hsWaitCertOrRequest:
		if typ == tlsraw.HandshakeTypeCertificateRequest {
			err = hs.handleCertificateRequest(msg)
			hs.state = hsWaitCertificate
			break
		}
		err = hs.handleCertificate(msg)
		hs.state = hsWaitCertVerify
	case hsWaitCertificate:
		if err = expect(typ, tlsraw.HandshakeTypeCertificate, false); err == nil {
			err = hs.handleCertificate(msg)
		}
		hs.state = hsWaitCertVerify
	case hsWaitCertVerify:
		if err = expect(typ, tlsraw.HandshakeTypeCertificateVerify, false); err == nil {
			err = hs.handleCertificateVerify(msg)
		}
		hs.state = hsWaitFinished
	case hsWaitFinished:
		if err = expect(typ, tlsraw.HandshakeTypeFinished, pending); err == nil {
			err = hs.handleServerFinished(rk, msg)
		}
		hs.state = hsWantFlight
	default:
		err = alertError(tlsraw.AlertUnexpectedMessage)
	}
	return err
}

// expect rejects a message of the wrong type, or one followed by buffered
// handshake bytes when it changes keys.
func expect(got, want tlsraw.HandshakeType, pendingAtKeyChange bool) error {
	if got != want || pendingAtKeyChange {
		return alertError(tlsraw.AlertUnexpectedMessage)
	}
	return nil
}

// writeHello encodes the ClientHello record into e and keeps a view of it.
func (hs *clientHandshake) writeHello(e *tlsraw.Encoder) error {
	cfg := hs.cfg
	rec := e.StartRecord(tlsraw.ContentTypeHandshake)
	msg := e.StartMessage(tlsraw.HandshakeTypeClientHello)
	e.Uint16(tlsraw.VersionTLS12)
	random := e.Reserve(tlsraw.SizeHelloRandom)
	if random == nil {
		return e.Err()
	} else if _, err := io.ReadFull(cfg.Rand, random); err != nil {
		return err
	}
	e.Uint8(0) // Empty legacy_session_id, so no middlebox compatibility mode.
	list := e.Open(2)
	for _, s := range cfg.Suites {
		e.Uint16(s.ID)
	}
	e.Close(list, 2)
	e.Uint8(1)
	e.Uint8(0)
	exts := e.Open(2)

	ext := startExt(e, tlsraw.ExtSupportedVersions)
	e.Uint8(2)
	e.Uint16(tlsraw.VersionTLS13)
	e.Close(ext, 2)

	ext = startExt(e, tlsraw.ExtSupportedGroups)
	list = e.Open(2)
	for _, g := range cfg.KeyExchanges {
		e.Uint16(g.ID)
	}
	e.Close(list, 2)
	e.Close(ext, 2)

	ext = startExt(e, tlsraw.ExtSignatureAlgorithms)
	list = e.Open(2)
	for _, s := range cfg.Schemes {
		e.Uint16(s)
	}
	e.Close(list, 2)
	e.Close(ext, 2)

	ext = startExt(e, tlsraw.ExtKeyShare)
	list = e.Open(2)
	for i, g := range cfg.KeyExchanges {
		e.Uint16(g.ID)
		key := e.Open(2)
		share := e.Reserve(g.ClientShareLen)
		if share == nil {
			return e.Err()
		}
		n, err := hs.exch[i].ClientGenerateRekey(share, cfg.Rand)
		if err != nil {
			return err
		} else if n != g.ClientShareLen {
			return errNoConfig
		}
		e.Close(key, 2)
	}
	e.Close(list, 2)
	e.Close(ext, 2)

	if cfg.ALPN != "" {
		ext = startExt(e, tlsraw.ExtALPN)
		list = e.Open(2)
		name := e.Open(1)
		e.Bytes([]byte(cfg.ALPN))
		e.Close(name, 1)
		e.Close(list, 2)
		e.Close(ext, 2)
	}
	if cfg.ServerName != "" {
		ext = startExt(e, tlsraw.ExtServerName)
		list = e.Open(2)
		e.Uint8(0) // host_name
		name := e.Open(2)
		e.Bytes(hs.serverName)
		e.Close(name, 2)
		e.Close(list, 2)
		e.Close(ext, 2)
	}
	e.Close(exts, 2)
	// Kept in WriteBuf until the suite, and so the transcript hash, is known.
	hs.clientHello = e.EndMessage(msg)
	e.EndRecord(rec)
	if err := e.Err(); err != nil {
		return err
	}
	hs.state = hsWaitServerHello
	return nil
}

func startExt(e *tlsraw.Encoder, typ tlsraw.ExtensionType) int {
	e.Uint16(uint16(typ))
	return e.Open(2)
}

func (hs *clientHandshake) handleServerHello(rk *recordKeys, msg []byte) error {
	cfg := hs.cfg
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
	for i := range cfg.Suites {
		if cfg.Suites[i].ID == uint16(sh.CipherSuite()) {
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
		if err := hs.checkExt(ef, &seen); err != nil {
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
	for i := range cfg.KeyExchanges {
		if cfg.KeyExchanges[i].ID == group {
			gi = i
			break
		}
	}
	if gi < 0 || len(share) != cfg.KeyExchanges[gi].ServerShareLen {
		return alertError(tlsraw.AlertIllegalParameter)
	}
	if err := hs.useSuite(rk, suite); err != nil {
		return err
	} else if err := hs.ks.Configure(hs.transcript, hs.mac, true); err != nil {
		return err
	}
	hs.ks.AddMessage(hs.clientHello)
	hs.ks.AddMessage(msg)
	hs.clientHello = nil

	g := &cfg.KeyExchanges[gi]
	n, err = hs.exch[gi].ClientShared(hs.shared[:g.SharedLen], share)
	if err != nil || n != g.SharedLen {
		return alertError(tlsraw.AlertIllegalParameter)
	}
	for _, x := range hs.exch {
		x.Zeroize()
	}
	size := hs.ks.Size()
	hs.ks.Handshake(hs.clientHS[:size], hs.serverHS[:size], hs.shared[:g.SharedLen])
	clear(hs.shared[:])
	if err := hs.setKeys(&rk.in, rk.aeadIn, hs.serverHS[:size]); err != nil {
		return err
	}
	return hs.setKeys(&rk.out, rk.aeadOut, hs.clientHS[:size])
}

// checkExt validates the shape of a server extension and rejects duplicates.
func (hs *clientHandshake) checkExt(ef tlsraw.ExtensionFrame, seen *uint64) error {
	ef.ValidateType(&hs.vld, true)
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

func (hs *clientHandshake) useSuite(rk *recordKeys, i int) error {
	s := &hs.cfg.Suites[i]
	rk.aeadIn, rk.aeadOut = s.NewAEAD(), s.NewAEAD()
	hs.transcript, hs.mac = s.NewHash(), s.NewHash()
	if hs.transcript.Size() > maxHashSize {
		return lneto.ErrUnsupported
	}
	hs.suite = s
	return nil
}

func (hs *clientHandshake) handleEncryptedExtensions(msg []byte) error {
	body := msg[tlsraw.SizeHeaderHandshake:]
	if len(body) < 2 || int(binary.BigEndian.Uint16(body)) != len(body)-2 {
		return alertError(tlsraw.AlertDecodeError)
	}
	alpn := hs.cfg.ALPN
	var seen uint64
	for exts := body[2:]; len(exts) > 0; {
		ef, err := tlsraw.NewExtensionFrame(exts)
		if err != nil {
			return alertError(tlsraw.AlertDecodeError)
		}
		exts = exts[len(ef.RawData()):]
		if err := hs.checkExt(ef, &seen); err != nil {
			return err
		}
		switch ef.Type() {
		case tlsraw.ExtALPN:
			name := ef.Data()[3:]
			if alpn == "" || string(name) != alpn {
				return alertError(tlsraw.AlertIllegalParameter)
			}
			hs.alpnOK = true
		case tlsraw.ExtKeyShare, tlsraw.ExtSupportedVersions, tlsraw.ExtSignatureAlgorithms,
			tlsraw.ExtPreSharedKey, tlsraw.ExtCookie, tlsraw.ExtPSKKeyExchangeModes:
			// RFC 8446 4.2: not allowed in EncryptedExtensions.
			return alertError(tlsraw.AlertIllegalParameter)
		}
	}
	if alpn != "" && !hs.alpnOK {
		return alertError(tlsraw.AlertNoApplicationProtocol)
	}
	hs.ks.AddMessage(msg)
	return nil
}

func (hs *clientHandshake) handleCertificateRequest(msg []byte) error {
	body := msg[tlsraw.SizeHeaderHandshake:]
	if len(body) < 1 {
		return alertError(tlsraw.AlertDecodeError)
	}
	ctxLen := int(body[0])
	body = body[1:]
	if len(body) < ctxLen+2 {
		return alertError(tlsraw.AlertDecodeError)
	}
	hs.reqCtxLen = uint8(copy(hs.reqCtx[:], body[:ctxLen]))
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
		if err := hs.checkExt(ef, &seen); err != nil {
			return err
		}
		if ef.Type() == tlsraw.ExtSignatureAlgorithms {
			schemes = ef.Data()[2:]
		}
	}
	if schemes == nil {
		return alertError(tlsraw.AlertMissingExtension)
	}
	hs.nPeerScheme = 0
	for i := 0; i+1 < len(schemes) && int(hs.nPeerScheme) < len(hs.peerSchemes); i += 2 {
		hs.peerSchemes[hs.nPeerScheme] = binary.BigEndian.Uint16(schemes[i:])
		hs.nPeerScheme++
	}
	hs.certReq = true
	hs.ks.AddMessage(msg)
	return nil
}

func (hs *clientHandshake) handleCertificate(msg []byte) error {
	if tlsraw.HandshakeType(msg[0]) != tlsraw.HandshakeTypeCertificate {
		return alertError(tlsraw.AlertUnexpectedMessage)
	}
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

func (hs *clientHandshake) handleCertificateVerify(msg []byte) error {
	body := msg[tlsraw.SizeHeaderHandshake:]
	if len(body) < 4 || int(binary.BigEndian.Uint16(body[2:])) != len(body)-4 {
		return alertError(tlsraw.AlertDecodeError)
	}
	scheme := binary.BigEndian.Uint16(body)
	if !hasScheme(hs.cfg.Schemes, scheme) || legacyScheme(scheme) {
		return alertError(tlsraw.AlertIllegalParameter)
	}
	signed := hs.cvContent(serverCVContext)
	err := hs.cfg.Verifier.VerifyPeer(&hs.chain, scheme, true, hs.serverName, signed, body[4:])
	if err != nil {
		return verifyError{err}
	}
	hs.ks.AddMessage(msg)
	return nil
}

// cvContent builds the signed content of RFC 8446 4.4.3 for the transcript so far.
func (hs *clientHandshake) cvContent(context string) []byte {
	for i := range 64 {
		hs.cv[i] = 0x20
	}
	copy(hs.cv[64:], context)
	hs.cv[sizeCVPrefix-1] = 0
	signed := hs.cv[:sizeCVPrefix+hs.ks.Size()]
	hs.ks.TranscriptHash(signed[sizeCVPrefix:])
	return signed
}

func (hs *clientHandshake) handleServerFinished(rk *recordKeys, msg []byte) error {
	size := hs.ks.Size()
	hs.ks.Finished(hs.verify[:size], hs.serverHS[:size])
	got := msg[tlsraw.SizeHeaderHandshake:]
	if len(got) != size {
		return alertError(tlsraw.AlertDecodeError)
	} else if !ctEqual(got, hs.verify[:size]) {
		return alertError(tlsraw.AlertDecryptError)
	}
	hs.ks.AddMessage(msg)
	hs.ks.Master(hs.clientAP[:size], hs.serverAP[:size])
	clear(hs.serverHS[:])
	return hs.setKeys(&rk.in, rk.aeadIn, hs.serverAP[:size])
}

// writeFlight encodes Certificate, CertificateVerify and Finished in one record
// sealed with rk.out, then installs the client application keys.
func (hs *clientHandshake) writeFlight(rk *recordKeys, e *tlsraw.Encoder) error {
	size := hs.ks.Size()
	rec := e.StartRecord(tlsraw.ContentTypeApplicationData)
	if hs.certReq {
		peerSchemes := hs.peerSchemes[:hs.nPeerScheme]
		var scheme uint16
		cred := hs.cfg.Credential
		if cred != nil && cred.NumCerts() > 0 {
			scheme = cred.Scheme(peerSchemes)
			if legacyScheme(scheme) || !hasScheme(peerSchemes, scheme) {
				scheme = 0
			}
		}
		msg := e.StartMessage(tlsraw.HandshakeTypeCertificate)
		e.Uint8(hs.reqCtxLen)
		e.Bytes(hs.reqCtx[:hs.reqCtxLen])
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
		hs.ks.AddMessage(e.EndMessage(msg))
		if scheme != 0 {
			signed := hs.cvContent(clientCVContext)
			msg = e.StartMessage(tlsraw.HandshakeTypeCertificateVerify)
			e.Uint16(scheme)
			sig := e.Open(2)
			n, err := cred.Sign(e.Rest(), signed, scheme)
			if err != nil {
				return err
			}
			e.Advance(n)
			e.Close(sig, 2)
			hs.ks.AddMessage(e.EndMessage(msg))
		}
	}
	msg := e.StartMessage(tlsraw.HandshakeTypeFinished)
	if verify := e.Reserve(size); verify != nil {
		hs.ks.Finished(verify, hs.clientHS[:size])
	}
	e.EndMessage(msg)
	e.SealRecord(&rk.out, rec, tlsraw.ContentTypeHandshake)
	if err := e.Err(); err != nil {
		return err
	}
	clear(hs.clientHS[:])
	err := hs.setKeys(&rk.out, rk.aeadOut, hs.clientAP[:size])
	clear(hs.clientAP[:])
	clear(hs.serverAP[:])
	hs.ks.Zeroize()
	if err != nil {
		return err
	}
	hs.state = hsDone
	return nil
}

func (hs *clientHandshake) setKeys(hc *tlsraw.HalfConn, aead lcrypto.AEADCipher, secret []byte) error {
	return hs.ks.InstallKeys(hc, aead, hs.suite.KeyLen, secret)
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
