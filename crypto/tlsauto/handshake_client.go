package tlsauto

import (
	"encoding/binary"
	"io"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/tlsraw"
)

type hsState uint8

const (
	hsIdle hsState = iota // Nothing sent. The ClientHello is the next flight.
	hsWaitServerHello
	hsWaitEncryptedExtensions
	hsWaitCertOrRequest
	hsWaitCertificate // After CertificateRequest.
	hsWaitCertVerify
	hsWaitFinished
	hsWantFlight // Server Finished verified, client flight not yet written.
	hsDone
)

// clientHandshake is the client side of the RFC 8446 handshake with no I/O and
// no record layer, the role tcp.ControlBlock plays. handle consumes whole
// handshake messages and writeFlight writes the client's flights to an Encoder
// when wantFlight reports one.
type clientHandshake struct {
	handshakeCommon
	state hsState
	// clientHello points into the handler's WriteBuf until ServerHello picks
	// the transcript hash. Nothing else is encoded in that window.
	clientHello []byte
	certReq     bool // The server sent a CertificateRequest.
	reqCtx      [maxRequestCtx]byte
	reqCtxLen   uint8
}

// configure binds cfg and builds one Exchanger per key exchange.
func (hs *clientHandshake) configure(cfg *Config) {
	hs.handshakeCommon.configure(cfg, true)
	hs.peerName = []byte(cfg.ServerName)
}

// reset wipes secrets and scratch and returns to hsIdle. It keeps cfg, exch and peerName.
func (hs *clientHandshake) reset(certBuf []byte) {
	hs.handshakeCommon.reset(certBuf)
	hs.state = hsIdle
	hs.clientHello = nil
	hs.certReq, hs.reqCtxLen = false, 0
}

// zeroize wipes key shares, secrets and the peer chain. It keeps state and alpnOK.
func (hs *clientHandshake) zeroize() {
	hs.handshakeCommon.zeroize()
	hs.clientHello = nil
}

func (hs *clientHandshake) done() bool { return hs.state == hsDone }

// wantFlight reports a flight for writeFlight: the ClientHello, or the client's Finished flight.
func (hs *clientHandshake) wantFlight() bool { return hs.state == hsIdle || hs.state == hsWantFlight }

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
		fallthrough
	case hsWaitCertificate:
		if err = expect(typ, tlsraw.HandshakeTypeCertificate, false); err == nil {
			err = hs.readCertificate(msg)
		}
		hs.state = hsWaitCertVerify
	case hsWaitCertVerify:
		if err = expect(typ, tlsraw.HandshakeTypeCertificateVerify, false); err == nil {
			err = hs.readCertificateVerify(msg)
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

// writeFlight encodes the flight wantFlight reports. In hsIdle it is the
// ClientHello. After the server Finished it is Certificate, CertificateVerify
// and Finished in one record sealed with rk.out, after which the client
// application keys are installed.
func (hs *clientHandshake) writeFlight(rk *recordKeys, e *tlsraw.Encoder) error {
	switch hs.state {
	case hsIdle:
		return hs.writeHello(e)
	case hsWantFlight:
	default:
		return lneto.ErrBadState
	}
	rec := e.StartRecord(tlsraw.ContentTypeApplicationData)
	if hs.certReq {
		// Without a usable credential RFC 8446 4.4.2 has the client send an empty Certificate.
		scheme := hs.ownScheme()
		if err := hs.writeCertificate(e, hs.reqCtx[:hs.reqCtxLen], scheme != 0); err != nil {
			return err
		} else if scheme != 0 {
			if err := hs.writeCertificateVerify(e, scheme); err != nil {
				return err
			}
		}
	}
	hs.writeFinished(e)
	e.SealRecord(&rk.out, rec, tlsraw.ContentTypeHandshake)
	if err := e.Err(); err != nil {
		return err
	}
	err := hs.setKeys(&rk.out, rk.aeadOut, hs.ownAP[:hs.ks.Size()])
	clear(hs.ownAP[:])
	clear(hs.peerAP[:])
	hs.ks.Zeroize()
	if err != nil {
		return err
	}
	hs.state = hsDone
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
		e.Bytes(hs.peerName)
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
	return hs.installHandshakeKeys(rk, n)
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

// handleServerFinished verifies the server Finished and installs the server application keys.
func (hs *clientHandshake) handleServerFinished(rk *recordKeys, msg []byte) error {
	if err := hs.readFinished(msg); err != nil {
		return err
	}
	hs.deriveMaster()
	return hs.setKeys(&rk.in, rk.aeadIn, hs.peerAP[:hs.ks.Size()])
}
