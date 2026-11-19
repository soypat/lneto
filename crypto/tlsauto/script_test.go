package tlsauto

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/rfc8448"
	"github.com/soypat/lneto/crypto/tlsraw"
)

// script drives scriptServer. The zero value runs a valid handshake that selects ALPN "test/1".
type script struct {
	noALPN  bool
	certReq bool
	// reqSchemes are offered in CertificateRequest, ECDSA P-256 SHA-256 if nil.
	reqSchemes []uint16
	// mut changes a handshake message, header included, before it is sent. Returning nil skips it.
	mut map[tlsraw.HandshakeType]func(msg []byte) []byte
	// before runs before the message of that type is sent.
	before map[tlsraw.HandshakeType]func(s *scriptServer)
	// cfg changes the client config.
	cfg func(*Config)
	// after runs once the client flight is read and application keys are in place.
	after func(s *scriptServer)
}

// scriptServer is a minimal TLS 1.3 server that can send malformed messages.
type scriptServer struct {
	p           *pki
	sc          script
	conn        net.Conn
	ks          tlsraw.KeySchedule
	in, out     tlsraw.HalfConn
	buf         [1 << 15]byte
	clientHello []byte
	// clientFlight holds the decrypted handshake messages of the client's last flight.
	clientFlight []byte
}

func hsMsg(typ tlsraw.HandshakeType, body []byte) []byte {
	m := []byte{byte(typ), byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(m, body...)
}

func ext(typ tlsraw.ExtensionType, data []byte) []byte {
	return append(binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, uint16(typ)), uint16(len(data))), data...)
}

func vec16(data []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(data))), data...)
}

func (s *scriptServer) writeRecord(ct tlsraw.ContentType, content []byte) error {
	var e tlsraw.Encoder
	e.Reset(s.buf[:], 0)
	rec := e.StartRecord(ct)
	e.Bytes(content)
	if s.out.HasKeys() {
		e.SealRecord(&s.out, rec, ct)
	} else {
		e.EndRecord(rec)
	}
	if err := e.Err(); err != nil {
		return err
	}
	_, err := s.conn.Write(s.buf[:e.Len()])
	return err
}

func (s *scriptServer) writeRaw(b []byte) { s.conn.Write(b) }

func (s *scriptServer) readRecord() (tlsraw.ContentType, []byte, error) {
	hdr := s.buf[:tlsraw.SizeHeaderRecord]
	if _, err := io.ReadFull(s.conn, hdr); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[3:]))
	rec := s.buf[:tlsraw.SizeHeaderRecord+n]
	if _, err := io.ReadFull(s.conn, rec[tlsraw.SizeHeaderRecord:]); err != nil {
		return 0, nil, err
	}
	if s.in.HasKeys() {
		content, ct, err := s.in.Open(rec)
		return ct, content, err
	}
	return tlsraw.ContentType(rec[0]), rec[tlsraw.SizeHeaderRecord:], nil
}

// sendHS applies the script to msg, sends it and adds it to the transcript.
func (s *scriptServer) sendHS(msg []byte) error {
	typ := tlsraw.HandshakeType(msg[0])
	if f := s.sc.before[typ]; f != nil {
		f(s)
	}
	if f := s.sc.mut[typ]; f != nil {
		msg = f(msg)
		if msg == nil {
			return nil
		}
	}
	s.ks.AddMessage(msg)
	return s.writeRecord(tlsraw.ContentTypeHandshake, msg)
}

func (s *scriptServer) run() error {
	ct, content, err := s.readRecord()
	if err != nil {
		return err
	} else if ct != tlsraw.ContentTypeHandshake {
		return errors.New("want ClientHello")
	}
	s.clientHello = append([]byte(nil), content...)
	var ch tlsraw.HelloClientMsg
	if _, err := ch.Decode(s.clientHello[tlsraw.SizeHeaderHandshake:]); err != nil {
		return err
	}
	var clientShare []byte
	for exts := ch.Extensions(); len(exts) > 0; {
		ef, err := tlsraw.NewExtensionFrame(exts)
		if err != nil {
			return err
		}
		exts = exts[len(ef.RawData()):]
		if ef.Type() != tlsraw.ExtKeyShare {
			continue
		}
		for shares := ef.Data()[2:]; len(shares) > 0; {
			g, key, n, err := tlsraw.NextKeyShare(shares, false)
			if err != nil {
				return err
			}
			if g == tlsraw.GroupX25519 {
				clientShare = key
			}
			shares = shares[n:]
		}
	}
	peer, err := ecdh.X25519().NewPublicKey(clientShare)
	if err != nil {
		return err
	}
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	shared, _ := key.ECDH(peer)

	sh := binary.BigEndian.AppendUint16(nil, tlsraw.VersionTLS12)
	sh = append(sh, make([]byte, tlsraw.SizeHelloRandom)...)
	rand.Read(sh[2:])
	sh = append(sh, 0)
	sh = binary.BigEndian.AppendUint16(sh, uint16(tlsraw.SuiteAES128GCMSHA256))
	sh = append(sh, 0)
	shExts := ext(tlsraw.ExtSupportedVersions, binary.BigEndian.AppendUint16(nil, tlsraw.VersionTLS13))
	share := binary.BigEndian.AppendUint16(nil, uint16(tlsraw.GroupX25519))
	share = append(share, vec16(key.PublicKey().Bytes())...)
	shExts = append(shExts, ext(tlsraw.ExtKeyShare, share)...)
	sh = append(sh, vec16(shExts)...)

	if err := s.ks.Configure(rfc8448.NewSHA256(), rfc8448.NewSHA256(), true); err != nil {
		return err
	}
	s.ks.AddMessage(s.clientHello)
	if err := s.sendHS(hsMsg(tlsraw.HandshakeTypeServerHello, sh)); err != nil {
		return err
	}
	var clientHS, serverHS, clientAP, serverAP, verify [32]byte
	s.ks.Handshake(clientHS[:], serverHS[:], shared)
	if err := s.ks.InstallKeys(&s.in, rfc8448.NewAES128GCM(), 16, clientHS[:]); err != nil {
		return err
	} else if err := s.ks.InstallKeys(&s.out, rfc8448.NewAES128GCM(), 16, serverHS[:]); err != nil {
		return err
	}

	var ee []byte
	if !s.sc.noALPN {
		ee = ext(tlsraw.ExtALPN, vec16(append([]byte{6}, "test/1"...)))
	}
	if err := s.sendHS(hsMsg(tlsraw.HandshakeTypeEncryptedExtensions, vec16(ee))); err != nil {
		return err
	}
	if s.sc.certReq {
		schemes := s.sc.reqSchemes
		if schemes == nil {
			schemes = []uint16{uint16(tlsraw.SigECDSAP256SHA256)}
		}
		var list []byte
		for _, sch := range schemes {
			list = binary.BigEndian.AppendUint16(list, sch)
		}
		cr := append([]byte{0}, vec16(ext(tlsraw.ExtSignatureAlgorithms, vec16(list)))...)
		if err := s.sendHS(hsMsg(tlsraw.HandshakeTypeCertificateRequest, cr)); err != nil {
			return err
		}
	}
	entry := append([]byte{byte(len(s.p.serverDER) >> 16), byte(len(s.p.serverDER) >> 8), byte(len(s.p.serverDER))}, s.p.serverDER...)
	entry = append(entry, 0, 0)
	cert := append([]byte{0, byte(len(entry) >> 16), byte(len(entry) >> 8), byte(len(entry))}, entry...)
	if err := s.sendHS(hsMsg(tlsraw.HandshakeTypeCertificate, cert)); err != nil {
		return err
	}
	signed := make([]byte, sizeCVPrefix+32)
	for i := range 64 {
		signed[i] = 0x20
	}
	copy(signed[64:], serverCVContext)
	s.ks.TranscriptHash(signed[sizeCVPrefix:])
	h := sha256.Sum256(signed)
	sig, err := s.p.serverKey.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return err
	}
	cv := append(binary.BigEndian.AppendUint16(nil, uint16(tlsraw.SigECDSAP256SHA256)), vec16(sig)...)
	if err := s.sendHS(hsMsg(tlsraw.HandshakeTypeCertificateVerify, cv)); err != nil {
		return err
	}
	s.ks.Finished(verify[:], serverHS[:])
	if err := s.sendHS(hsMsg(tlsraw.HandshakeTypeFinished, verify[:])); err != nil {
		return err
	}
	s.ks.Master(clientAP[:], serverAP[:])

	ct, content, err = s.readRecord()
	if err != nil {
		return err
	} else if ct != tlsraw.ContentTypeHandshake {
		return errors.New("want client flight")
	}
	s.clientFlight = append([]byte(nil), content...)
	if err := s.ks.InstallKeys(&s.in, rfc8448.NewAES128GCM(), 16, clientAP[:]); err != nil {
		return err
	} else if err := s.ks.InstallKeys(&s.out, rfc8448.NewAES128GCM(), 16, serverAP[:]); err != nil {
		return err
	}
	if s.sc.after != nil {
		s.sc.after(s)
	}
	return nil
}

// runScript starts a scriptServer and a configured client connected to it.
func runScript(t *testing.T, sc script) (*Conn, *scriptServer, chan error) {
	t.Helper()
	p := newPKI(t)
	ss, cs := bufPipe()
	s := &scriptServer{p: p, sc: sc, conn: ss}
	done := make(chan error, 1)
	go func() {
		err := s.run()
		ss.Close()
		done <- err
	}()
	cfg := p.clientConfig(t)
	if sc.cfg != nil {
		sc.cfg(&cfg)
	}
	c := new(Conn)
	if err := c.Configure(cfg); err != nil {
		t.Fatal(err)
	} else if err := c.Open(cs); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return c, s, done
}

func TestScriptHandshake(t *testing.T) {
	c, _, done := runScript(t, script{after: func(s *scriptServer) {
		s.writeRecord(tlsraw.ContentTypeApplicationData, []byte("hello"))
		s.writeRecord(tlsraw.ContentTypeAlert, []byte{1, byte(tlsraw.AlertCloseNotify)})
	}})
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "hello" {
		t.Fatalf("got %q, %v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal("server:", err)
	}
}

func mutBody(f func(body []byte) []byte) func([]byte) []byte {
	return func(msg []byte) []byte {
		return hsMsg(tlsraw.HandshakeType(msg[0]), f(append([]byte(nil), msg[tlsraw.SizeHeaderHandshake:]...)))
	}
}

func replaceMsg(typ tlsraw.HandshakeType, body []byte) func([]byte) []byte {
	return func([]byte) []byte { return hsMsg(typ, body) }
}

// shWithExts rebuilds a ServerHello body with exts in place of its extensions.
func shWithExts(exts []byte) func([]byte) []byte {
	return mutBody(func(b []byte) []byte {
		head := b[:2+tlsraw.SizeHelloRandom+1+2+1]
		return append(append([]byte(nil), head...), vec16(exts)...)
	})
}

var (
	extTLS13   = ext(tlsraw.ExtSupportedVersions, []byte{3, 4})
	extShare25 = ext(tlsraw.ExtKeyShare, append([]byte{0, 0x1d}, vec16(make([]byte, 32))...))
)

func TestScriptServerHelloErrors(t *testing.T) {
	const sh = tlsraw.HandshakeTypeServerHello
	for _, tc := range []struct {
		name string
		mut  func([]byte) []byte
		want error
	}{
		{"truncated", mutBody(func(b []byte) []byte { return b[:10] }), alertError(tlsraw.AlertDecodeError)},
		{"trailing data", mutBody(func(b []byte) []byte { return append(b, 0) }), alertError(tlsraw.AlertDecodeError)},
		{"legacy version", mutBody(func(b []byte) []byte { b[1] = 1; return b }), alertError(tlsraw.AlertProtocolVersion)},
		{"hello retry", mutBody(func(b []byte) []byte { copy(b[2:], helloRetryRandom[:]); return b }), errHelloRetry},
		{"compression", mutBody(func(b []byte) []byte { b[2+tlsraw.SizeHelloRandom+3] = 1; return b }), alertError(tlsraw.AlertIllegalParameter)},
		{"unknown suite", mutBody(func(b []byte) []byte { b[2+tlsraw.SizeHelloRandom+2] = 0x99; return b }), alertError(tlsraw.AlertIllegalParameter)},
		{"bad extension frame", shWithExts([]byte{0, 0x2b, 0, 9}), alertError(tlsraw.AlertDecodeError)},
		{"bad supported_versions", shWithExts(ext(tlsraw.ExtSupportedVersions, []byte{3})), alertError(tlsraw.AlertDecodeError)},
		{"duplicate extension", shWithExts(append(append([]byte(nil), extTLS13...), extTLS13...)), alertError(tlsraw.AlertIllegalParameter)},
		{"unsupported extension", shWithExts(append(append([]byte(nil), extTLS13...), ext(tlsraw.ExtALPN, vec16([]byte{1, 'a'}))...)), alertError(tlsraw.AlertUnsupportedExtension)},
		{"key_share without key", shWithExts(append(append([]byte(nil), extTLS13...), ext(tlsraw.ExtKeyShare, []byte{0, 0x1d})...)), alertError(tlsraw.AlertIllegalParameter)},
		{"TLS 1.2", shWithExts(append(ext(tlsraw.ExtSupportedVersions, []byte{3, 3}), extShare25...)), alertError(tlsraw.AlertProtocolVersion)},
		{"missing key_share", shWithExts(extTLS13), alertError(tlsraw.AlertMissingExtension)},
		{"unknown group", shWithExts(append(append([]byte(nil), extTLS13...), ext(tlsraw.ExtKeyShare, append([]byte{0, 0x1e}, vec16(make([]byte, 32))...))...)), alertError(tlsraw.AlertIllegalParameter)},
		{"low order share", shWithExts(append(append([]byte(nil), extTLS13...), extShare25...)), alertError(tlsraw.AlertIllegalParameter)},
		{"data after ServerHello", func(m []byte) []byte { return append(m, byte(tlsraw.HandshakeTypeEncryptedExtensions), 0, 0, 2, 0, 0) }, alertError(tlsraw.AlertUnexpectedMessage)},
		{"wrong message", replaceMsg(tlsraw.HandshakeTypeCertificate, []byte{0}), alertError(tlsraw.AlertUnexpectedMessage)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _ := runScript(t, script{mut: map[tlsraw.HandshakeType]func([]byte) []byte{sh: tc.mut}})
			if err := c.Handshake(); err != tc.want {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if err := c.Handshake(); err != lneto.ErrBadState {
				t.Fatalf("handshake after failure: %v", err)
			}
		})
	}
}

func TestScriptEncryptedErrors(t *testing.T) {
	type mutMap = map[tlsraw.HandshakeType]func([]byte) []byte
	const (
		ee   = tlsraw.HandshakeTypeEncryptedExtensions
		cr   = tlsraw.HandshakeTypeCertificateRequest
		cert = tlsraw.HandshakeTypeCertificate
		cv   = tlsraw.HandshakeTypeCertificateVerify
		fin  = tlsraw.HandshakeTypeFinished
	)
	certEntry := func(n int) []byte { return append([]byte{byte(n >> 16), byte(n >> 8), byte(n)}, make([]byte, n)...) }
	certList := func(entries ...[]byte) []byte {
		var l []byte
		for _, e := range entries {
			l = append(l, e...)
		}
		return append([]byte{0, byte(len(l) >> 16), byte(len(l) >> 8), byte(len(l))}, l...)
	}
	var nine [][]byte
	for range 9 {
		nine = append(nine, append(certEntry(1), 0, 0))
	}
	for _, tc := range []struct {
		name string
		sc   script
		want error
	}{
		{"EE short", script{mut: mutMap{ee: replaceMsg(ee, []byte{0})}}, alertError(tlsraw.AlertDecodeError)},
		{"EE bad frame", script{mut: mutMap{ee: replaceMsg(ee, vec16([]byte{0, 16, 0, 9}))}}, alertError(tlsraw.AlertDecodeError)},
		{"EE bad ALPN", script{mut: mutMap{ee: replaceMsg(ee, vec16(ext(tlsraw.ExtALPN, []byte{0, 9})))}}, alertError(tlsraw.AlertDecodeError)},
		{"EE other ALPN", script{mut: mutMap{ee: replaceMsg(ee, vec16(ext(tlsraw.ExtALPN, vec16([]byte{1, 'x'}))))}}, alertError(tlsraw.AlertIllegalParameter)},
		{"EE key_share", script{noALPN: true, mut: mutMap{ee: replaceMsg(ee, vec16(extShare25))}}, alertError(tlsraw.AlertIllegalParameter)},
		{"EE no ALPN", script{noALPN: true}, alertError(tlsraw.AlertNoApplicationProtocol)},
		{"CR empty", script{certReq: true, mut: mutMap{cr: replaceMsg(cr, nil)}}, alertError(tlsraw.AlertDecodeError)},
		{"CR short context", script{certReq: true, mut: mutMap{cr: replaceMsg(cr, []byte{5, 1})}}, alertError(tlsraw.AlertDecodeError)},
		{"CR bad length", script{certReq: true, mut: mutMap{cr: replaceMsg(cr, []byte{0, 0, 9})}}, alertError(tlsraw.AlertDecodeError)},
		{"CR bad frame", script{certReq: true, mut: mutMap{cr: replaceMsg(cr, append([]byte{0}, vec16([]byte{0, 13, 0, 9})...))}}, alertError(tlsraw.AlertDecodeError)},
		{"CR duplicate", script{certReq: true, mut: mutMap{cr: replaceMsg(cr, append([]byte{0}, vec16(append(ext(16, nil), ext(16, nil)...))...))}}, alertError(tlsraw.AlertDecodeError)},
		{"CR no schemes", script{certReq: true, mut: mutMap{cr: replaceMsg(cr, append([]byte{0}, vec16(nil)...))}}, alertError(tlsraw.AlertMissingExtension)},
		{"cert wrong type", script{mut: mutMap{cert: replaceMsg(cv, []byte{0})}}, alertError(tlsraw.AlertUnexpectedMessage)},
		{"cert short", script{mut: mutMap{cert: replaceMsg(cert, []byte{0})}}, alertError(tlsraw.AlertDecodeError)},
		{"cert context", script{mut: mutMap{cert: replaceMsg(cert, []byte{1, 0, 0, 0, 0})}}, alertError(tlsraw.AlertDecodeError)},
		{"cert list length", script{mut: mutMap{cert: replaceMsg(cert, []byte{0, 0, 0, 9})}}, alertError(tlsraw.AlertDecodeError)},
		{"cert entry short", script{mut: mutMap{cert: replaceMsg(cert, certList([]byte{0, 0}))}}, alertError(tlsraw.AlertDecodeError)},
		{"cert empty entry", script{mut: mutMap{cert: replaceMsg(cert, certList([]byte{0, 0, 0, 0, 0}))}}, alertError(tlsraw.AlertDecodeError)},
		{"cert extensions overflow", script{mut: mutMap{cert: replaceMsg(cert, certList(append(certEntry(1), 0, 9)))}}, alertError(tlsraw.AlertDecodeError)},
		{"cert too many", script{mut: mutMap{cert: replaceMsg(cert, certList(nine...))}}, alertError(tlsraw.AlertBadCertificate)},
		{"cert none", script{mut: mutMap{cert: replaceMsg(cert, certList())}}, alertError(tlsraw.AlertDecodeError)},
		{"cert too big", script{mut: mutMap{cert: replaceMsg(cert, make([]byte, sizeHandshakeBuf))}}, alertError(tlsraw.AlertRecordOverflow)},
		{"CV short", script{mut: mutMap{cv: replaceMsg(cv, []byte{4, 3})}}, alertError(tlsraw.AlertDecodeError)},
		{"CV not offered", script{mut: mutMap{cv: replaceMsg(cv, []byte{8, 8, 0, 0})}}, alertError(tlsraw.AlertIllegalParameter)},
		{"CV legacy", script{cfg: func(c *Config) { c.Schemes = []uint16{0x0403, 0x0401} }, mut: mutMap{cv: replaceMsg(cv, []byte{4, 1, 0, 0})}}, alertError(tlsraw.AlertIllegalParameter)},
		{"fin length", script{mut: mutMap{fin: replaceMsg(fin, []byte{1})}}, alertError(tlsraw.AlertDecodeError)},
		{"fin value", script{mut: mutMap{fin: mutBody(func(b []byte) []byte { b[0] ^= 1; return b })}}, alertError(tlsraw.AlertDecryptError)},
		{"data after fin", script{mut: mutMap{fin: func(m []byte) []byte { return append(m, 4, 0, 0, 0) }}}, alertError(tlsraw.AlertUnexpectedMessage)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _ := runScript(t, tc.sc)
			if err := c.Handshake(); err != tc.want {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestScriptRecordErrors(t *testing.T) {
	type beforeMap = map[tlsraw.HandshakeType]func(s *scriptServer)
	const (
		sh = tlsraw.HandshakeTypeServerHello
		ee = tlsraw.HandshakeTypeEncryptedExtensions
	)
	raw := func(b ...byte) func(s *scriptServer) { return func(s *scriptServer) { s.writeRaw(b) } }
	record := func(ct tlsraw.ContentType, content ...byte) func(s *scriptServer) {
		return func(s *scriptServer) { s.writeRecord(ct, content) }
	}
	for _, tc := range []struct {
		name string
		sc   script
		want error
	}{
		{"EOF in header", script{before: beforeMap{sh: func(s *scriptServer) { s.conn.Close() }}}, io.ErrUnexpectedEOF},
		{"EOF in body", script{before: beforeMap{sh: func(s *scriptServer) { s.writeRaw([]byte{22, 3, 3, 0, 9, 1}); s.conn.Close() }}}, io.ErrUnexpectedEOF},
		{"record overflow", script{before: beforeMap{sh: raw(22, 3, 3, 0xff, 0xff)}}, alertError(tlsraw.AlertRecordOverflow)},
		{"plaintext over MaxRecord", script{cfg: func(c *Config) { c.MaxRecord = 512 }, before: beforeMap{sh: record(tlsraw.ContentTypeHandshake, make([]byte, 600)...)}}, alertError(tlsraw.AlertRecordOverflow)},
		{"unknown type", script{before: beforeMap{sh: record(99, 1)}}, alertError(tlsraw.AlertUnexpectedMessage)},
		{"empty handshake record", script{before: beforeMap{sh: record(tlsraw.ContentTypeHandshake)}}, alertError(tlsraw.AlertUnexpectedMessage)},
		{"message over hbuf", script{before: beforeMap{sh: record(tlsraw.ContentTypeHandshake, 2, 0xff, 0xff, 0xff)}}, alertError(tlsraw.AlertRecordOverflow)},
		{"two CCS", script{before: beforeMap{sh: func(s *scriptServer) { s.writeRaw([]byte{20, 3, 3, 0, 1, 1, 20, 3, 3, 0, 1, 1}) }}}, alertError(tlsraw.AlertUnexpectedMessage)},
		{"bad CCS", script{before: beforeMap{sh: raw(20, 3, 3, 0, 1, 2)}}, alertError(tlsraw.AlertUnexpectedMessage)},
		{"peer alert", script{before: beforeMap{sh: record(tlsraw.ContentTypeAlert, 2, byte(tlsraw.AlertHandshakeFailure))}}, peerAlertError(tlsraw.AlertHandshakeFailure)},
		{"bad alert", script{before: beforeMap{sh: record(tlsraw.ContentTypeAlert, 2)}}, alertError(tlsraw.AlertDecodeError)},
		{"close_notify in handshake", script{before: beforeMap{sh: record(tlsraw.ContentTypeAlert, 1, byte(tlsraw.AlertCloseNotify))}}, io.ErrUnexpectedEOF},
		{"plaintext after keys", script{before: beforeMap{ee: func(s *scriptServer) { s.writeRaw([]byte{22, 3, 3, 0, 1, 0}) }}}, alertError(tlsraw.AlertUnexpectedMessage)},
		{"bad MAC", script{before: beforeMap{ee: raw(23, 3, 3, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)}}, alertError(tlsraw.AlertBadRecordMAC)},
		{"EOF before cert", script{certReq: true, before: beforeMap{tlsraw.HandshakeTypeCertificate: closeConn}}, io.ErrUnexpectedEOF},
		{"EOF before CV", script{before: beforeMap{tlsraw.HandshakeTypeCertificateVerify: closeConn}}, io.ErrUnexpectedEOF},
		{"EOF before fin", script{before: beforeMap{tlsraw.HandshakeTypeFinished: closeConn}}, io.ErrUnexpectedEOF},
		{"app data in handshake", script{before: beforeMap{ee: record(tlsraw.ContentTypeApplicationData, 1)}}, alertError(tlsraw.AlertUnexpectedMessage)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _ := runScript(t, tc.sc)
			if err := c.Handshake(); err != tc.want {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestScriptCCSDropped(t *testing.T) {
	c, _, done := runScript(t, script{before: map[tlsraw.HandshakeType]func(*scriptServer){
		tlsraw.HandshakeTypeServerHello: func(s *scriptServer) { s.writeRaw([]byte{20, 3, 3, 0, 1, 1}) },
	}})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if err := <-done; err != nil {
		t.Fatal("server:", err)
	}
}

func TestScriptAfterHandshake(t *testing.T) {
	ticket := hsMsg(tlsraw.HandshakeTypeNewSessionTicket, make([]byte, 40))
	for _, tc := range []struct {
		name  string
		after func(s *scriptServer)
		data  string
		want  error
	}{
		{"tickets and close", func(s *scriptServer) {
			s.writeRecord(tlsraw.ContentTypeHandshake, ticket)
			s.writeRecord(tlsraw.ContentTypeApplicationData, []byte("hi"))
			s.writeRecord(tlsraw.ContentTypeAlert, []byte{1, byte(tlsraw.AlertUserCanceled)})
			s.writeRecord(tlsraw.ContentTypeAlert, []byte{1, byte(tlsraw.AlertCloseNotify)})
		}, "hi", nil},
		{"empty handshake", func(s *scriptServer) { s.writeRecord(tlsraw.ContentTypeHandshake, nil) }, "", alertError(tlsraw.AlertUnexpectedMessage)},
		{"key update", func(s *scriptServer) {
			s.writeRecord(tlsraw.ContentTypeHandshake, hsMsg(tlsraw.HandshakeTypeKeyUpdate, []byte{0}))
		}, "", alertError(tlsraw.AlertUnexpectedMessage)},
		{"inner CCS", func(s *scriptServer) { s.writeRecord(tlsraw.ContentTypeChangeCipherSpec, []byte{1}) }, "", alertError(tlsraw.AlertUnexpectedMessage)},
		{"plaintext CCS", func(s *scriptServer) { s.writeRaw([]byte{20, 3, 3, 0, 1, 1}) }, "", alertError(tlsraw.AlertUnexpectedMessage)},
		{"fatal alert", func(s *scriptServer) {
			s.writeRecord(tlsraw.ContentTypeAlert, []byte{2, byte(tlsraw.AlertInternalError)})
		}, "", peerAlertError(tlsraw.AlertInternalError)},
		{"EOF", func(s *scriptServer) {}, "", io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _ := runScript(t, script{after: tc.after})
			got, err := io.ReadAll(c)
			if string(got) != tc.data || err != tc.want {
				t.Fatalf("got %q, %v, want %q, %v", got, err, tc.data, tc.want)
			}
			if tc.want != nil {
				if _, err := c.Read(make([]byte, 1)); err != lneto.ErrBadState {
					t.Fatalf("read after failure: %v", err)
				} else if _, err := c.Write([]byte{1}); err != lneto.ErrBadState {
					t.Fatalf("write after failure: %v", err)
				}
			}
		})
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// shortExchanger returns one byte less than the configured share length.
type shortExchanger struct{ ecdhExchanger }

func (e *shortExchanger) ClientGenerateRekey(dst []byte, r io.Reader) (int, error) {
	n, err := e.ecdhExchanger.ClientGenerateRekey(dst, r)
	return n - 1, err
}

type failingCredential struct {
	*ecdsaCredential
	certErr, signErr error
}

func (f *failingCredential) Cert(dst []byte, i int) (int, error) {
	if f.certErr != nil {
		return 0, f.certErr
	}
	return f.ecdsaCredential.Cert(dst, i)
}

func (f *failingCredential) Sign(sig, msg []byte, scheme uint16) (int, error) {
	if f.signErr != nil {
		return 0, f.signErr
	}
	return f.ecdsaCredential.Sign(sig, msg, scheme)
}

// failWriter fails writes after n successful ones.
type failWriter struct {
	io.ReadWriter
	n int
}

func (f *failWriter) Write(b []byte) (int, error) {
	if f.n == 0 {
		return 0, io.ErrClosedPipe
	}
	f.n--
	return f.ReadWriter.Write(b)
}

func TestConfigure(t *testing.T) {
	p := newPKI(t)
	valid := p.clientConfig(t)
	for _, tc := range []struct {
		name string
		mod  func(*Config)
	}{
		{"no rand", func(c *Config) { c.Rand = nil }},
		{"no verifier", func(c *Config) { c.Verifier = nil }},
		{"no suites", func(c *Config) { c.Suites = nil }},
		{"no groups", func(c *Config) { c.KeyExchanges = nil }},
		{"long ALPN", func(c *Config) { c.ALPN = string(make([]byte, 256)) }},
		{"long server name", func(c *Config) { c.ServerName = string(make([]byte, 256)) }},
		{"negative MaxRecord", func(c *Config) { c.MaxRecord = -1 }},
		{"small MaxRecord", func(c *Config) { c.MaxRecord = 100 }},
		{"large MaxRecord", func(c *Config) { c.MaxRecord = tlsraw.MaxPlaintext + 1 }},
		{"bad suite", func(c *Config) { c.Suites = []Suite{{ID: 1}} }},
		{"bad group", func(c *Config) { c.KeyExchanges = []KeyExchange{{ID: 1}} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mod(&cfg)
			var c Conn
			if err := c.Configure(cfg); err != errNoConfig {
				t.Fatalf("got %v", err)
			}
		})
	}
	var c Conn
	if err := c.Open(new(bytes.Buffer)); err != lneto.ErrBadState {
		t.Fatalf("open before configure: %v", err)
	} else if err := c.Handshake(); err != lneto.ErrBadState {
		t.Fatalf("handshake before open: %v", err)
	} else if err := c.Configure(valid); err != nil {
		t.Fatal(err)
	} else if err := c.Open(nil); err != errNoConfig {
		t.Fatalf("open nil: %v", err)
	}
	// A second Open reuses the buffers of the first.
	for range 2 {
		if err := c.Open(new(bytes.Buffer)); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Configure(valid); err != lneto.ErrBadState {
		t.Fatalf("configure during handshake: %v", err)
	}
}

func TestClientHelloErrors(t *testing.T) {
	p := newPKI(t)
	x := x25519()
	for _, tc := range []struct {
		name string
		mod  func(*Config)
		want error
	}{
		{"rand", func(c *Config) { c.Rand = errReader{} }, nil},
		{"exchanger", func(c *Config) {
			c.KeyExchanges[0].NewExchanger = func() Exchanger { return new(failExchanger) }
		}, nil},
		{"share length", func(c *Config) {
			c.KeyExchanges[0].NewExchanger = func() Exchanger { return &shortExchanger{ecdhExchanger{curve: ecdh.X25519()}} }
		}, errNoConfig},
		{"share too big", func(c *Config) { c.KeyExchanges[0].ClientShareLen = sizeWriteBuf }, nil},
		{"hello too big", func(c *Config) { c.Schemes = make([]uint16, sizeWriteBuf/2) }, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := p.clientConfig(t)
			cfg.KeyExchanges = []KeyExchange{x}
			tc.mod(&cfg)
			var c Conn
			if err := c.Configure(cfg); err != nil {
				t.Fatal(err)
			}
			var w bytes.Buffer
			c.Open(&w)
			err := c.Handshake()
			if err == nil || (tc.want != nil && err != tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

type failExchanger struct{ ecdhExchanger }

func (*failExchanger) ClientGenerateRekey([]byte, io.Reader) (int, error) {
	return 0, errors.New("exchanger failed")
}

func TestScriptSuiteErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(*Suite)
		want error
	}{
		{"hash too big", func(s *Suite) { s.NewHash = sha512.New }, lneto.ErrUnsupported},
		{"hash not accepted", func(s *Suite) { s.NewHash = sha256.New224 }, nil},
		{"key length", func(s *Suite) { s.KeyLen = 5 }, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _ := runScript(t, script{cfg: func(c *Config) { tc.mod(&c.Suites[0]) }})
			err := c.Handshake()
			if err == nil || (tc.want != nil && err != tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestScriptClientCert(t *testing.T) {
	failCred := func(certErr, signErr error) func(c *Config) {
		return func(c *Config) {
			c.Credential = &failingCredential{c.Credential.(*ecdsaCredential), certErr, signErr}
		}
	}
	for _, tc := range []struct {
		name      string
		sc        script
		wantErr   bool
		wantCerts bool
	}{
		{"signed", script{certReq: true}, false, true},
		{"scheme not offered", script{certReq: true, reqSchemes: []uint16{uint16(tlsraw.SigEd25519)}}, false, false},
		{"no credential", script{certReq: true, cfg: func(c *Config) { c.Credential = nil }}, false, false},
		{"cert error", script{certReq: true, cfg: failCred(errors.New("cert"), nil)}, true, false},
		{"sign error", script{certReq: true, cfg: failCred(nil, errors.New("sign"))}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s, done := runScript(t, tc.sc)
			err := c.Handshake()
			if (err != nil) != tc.wantErr {
				t.Fatalf("got %v", err)
			}
			if tc.wantErr {
				return
			}
			c.Close()
			if err := <-done; err != nil {
				t.Fatal("server:", err)
			}
			// The client Certificate leads its flight. Bytes 5 to 8 hold the length of its certificate list.
			if hasCerts := uint24(s.clientFlight[5:]) > 0; hasCerts != tc.wantCerts {
				t.Fatalf("client sent certificates: %v", hasCerts)
			}
		})
	}
}

func TestWriteErrors(t *testing.T) {
	c, _, _ := runScript(t, script{})
	c.rw = &failWriter{ReadWriter: c.rw, n: 1}
	if err := c.Handshake(); err != io.ErrClosedPipe {
		t.Fatalf("client flight: got %v", err)
	}

	c, _, _ = runScript(t, script{})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	c.rw = &failWriter{ReadWriter: c.rw}
	if n, err := c.Write([]byte("x")); n != 0 || err != io.ErrClosedPipe {
		t.Fatalf("write: %d, %v", n, err)
	}
}

func closeConn(s *scriptServer) { s.conn.Close() }

func TestScriptSplitMessage(t *testing.T) {
	ee := hsMsg(tlsraw.HandshakeTypeEncryptedExtensions, vec16(ext(tlsraw.ExtALPN, vec16(append([]byte{6}, "test/1"...)))))
	c, _, done := runScript(t, script{
		mut: map[tlsraw.HandshakeType]func([]byte) []byte{
			tlsraw.HandshakeTypeEncryptedExtensions: func([]byte) []byte { return nil },
		},
		before: map[tlsraw.HandshakeType]func(*scriptServer){
			tlsraw.HandshakeTypeEncryptedExtensions: func(s *scriptServer) {
				s.ks.AddMessage(ee)
				s.writeRecord(tlsraw.ContentTypeHandshake, ee[:2])
				s.writeRecord(tlsraw.ContentTypeHandshake, ee[2:7])
				s.writeRecord(tlsraw.ContentTypeHandshake, ee[7:])
			},
		},
	})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if err := <-done; err != nil {
		t.Fatal("server:", err)
	}
}
