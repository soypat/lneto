package nts

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ntp"
	"github.com/soypat/lneto/x/siv"
)

func TestKERecord_RoundTrip(t *testing.T) {
	body := []byte("hello NTS-KE")
	buf := AppendKERecord(nil, true, RecordNewCookie, body)

	rec, err := NewKERecord(buf)
	if err != nil {
		t.Fatal(err)
	}
	if rec.RecordType() != RecordNewCookie {
		t.Errorf("RecordType = %v; want %v", rec.RecordType(), RecordNewCookie)
	}
	if !rec.IsCritical() {
		t.Error("IsCritical = false; want true")
	}
	if !bytes.Equal(rec.Body(), body) {
		t.Errorf("Body mismatch: got %x want %x", rec.Body(), body)
	}
}

func TestKERecord_NonCritical(t *testing.T) {
	buf := AppendKERecord(nil, false, RecordWarning, []byte{0, 1})
	rec, err := NewKERecord(buf)
	if err != nil {
		t.Fatal(err)
	}
	if rec.IsCritical() {
		t.Error("IsCritical = true; want false")
	}
	if rec.RecordType() != RecordWarning {
		t.Errorf("RecordType = %v; want %v", rec.RecordType(), RecordWarning)
	}
}

func TestKERecord_TruncatedBuffer(t *testing.T) {
	buf := AppendKERecord(nil, true, RecordEndOfMessage, nil)
	for i := range buf {
		if _, err := NewKERecord(buf[:i]); err == nil {
			t.Errorf("NewKERecord(buf[:%d]): expected error", i)
		}
	}
}

func TestKERecord_ValidateSize(t *testing.T) {
	buf := AppendKERecord(nil, false, RecordAEADAlgNeg, []byte{0, 15})
	rec, _ := NewKERecord(buf)
	var v lneto.Validator
	rec.ValidateSize(&v)
	if v.HasError() {
		t.Errorf("ValidateSize: unexpected error: %v", v.ErrPop())
	}
}

// generateSelfSignedCert returns a TLS certificate for localhost, suitable
// for in-process testing.
func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key, Leaf: cert}
}

// runMockKEServer runs a minimal NTS-KE server over conn that responds with
// one cookie and the chosen algorithm.
func runMockKEServer(t *testing.T, conn net.Conn, tlsCfg *tls.Config, cookie []byte) {
	t.Helper()
	tc := tls.Server(conn, tlsCfg)
	if err := tc.Handshake(); err != nil {
		t.Errorf("server TLS handshake: %v", err)
		return
	}
	defer tc.Close()

	// Read client records until EndOfMessage.
	hdr := make([]byte, 4)
	for {
		if _, err := tc.Read(hdr); err != nil {
			return
		}
		bodyLen := int(binary.BigEndian.Uint16(hdr[2:4]))
		recType := KERecordType(binary.BigEndian.Uint16(hdr[0:2]) & 0x7FFF)
		if bodyLen > 0 {
			body := make([]byte, bodyLen)
			tc.Read(body)
		}
		if recType == RecordEndOfMessage {
			break
		}
	}

	// Send response per RFC 8915 §4.1: NextProtoNeg + AEAD + Cookie + EndOfMessage.
	var resp []byte
	var protoBody [2]byte
	binary.BigEndian.PutUint16(protoBody[:], ntpv4ProtocolID)
	resp = AppendKERecord(resp, true, RecordNextProtoNeg, protoBody[:])
	var algBody [2]byte
	binary.BigEndian.PutUint16(algBody[:], uint16(AlgAESSIVCMAC256))
	resp = AppendKERecord(resp, true, RecordAEADAlgNeg, algBody[:])
	resp = AppendKERecord(resp, false, RecordNewCookie, cookie)
	resp = AppendKERecord(resp, true, RecordEndOfMessage, nil)
	tc.Write(resp)
}

func TestPerformKE_E2E(t *testing.T) {
	cert := generateSelfSignedCert(t)
	pool := x509.NewCertPool()
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	pool.AddCert(leaf)

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"ntske/1"},
	}
	clientCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"ntske/1"},
	}

	wantCookie := []byte("test-cookie-data-1234")

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runMockKEServer(t, serverConn, serverCfg, wantCookie)
	}()

	tc := tls.Client(clientConn, clientCfg)
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	secrets, err := PerformKE(tc, KEConfig{})
	tc.Close()
	<-done

	if err != nil {
		t.Fatalf("PerformKE: %v", err)
	}
	if secrets.NumCookies != 1 {
		t.Errorf("NumCookies = %d; want 1", secrets.NumCookies)
	}
	if !bytes.Equal(secrets.Cookies[0][:secrets.CookieLens[0]], wantCookie) {
		t.Errorf("cookie mismatch: got %q want %q",
			secrets.Cookies[0][:secrets.CookieLens[0]], wantCookie)
	}
	if secrets.ChosenAlg != AlgAESSIVCMAC256 {
		t.Errorf("ChosenAlg = %v; want %v", secrets.ChosenAlg, AlgAESSIVCMAC256)
	}
	// Keys must be non-zero.
	var zeroKey [32]byte
	if secrets.C2SKey == zeroKey || secrets.S2CKey == zeroKey {
		t.Error("derived keys are all-zero")
	}
}

// TestClient_E2E runs a full NTS Encapsulate→Demux cycle using
// AES-SIV-CMAC-256 as the AEAD.
func TestClient_E2E(t *testing.T) {
	c2sKey := make([]byte, 32)
	s2cKey := make([]byte, 32)
	rand.Read(c2sKey)
	rand.Read(s2cKey)
	c2s, _ := siv.NewAESSIVCMAC256(c2sKey)
	s2c, _ := siv.NewAESSIVCMAC256(s2cKey)

	cookie := []byte("nts-cookie-12345678901234")
	var cfg ClientConfig
	cfg.C2S = c2s
	cfg.S2C = s2c
	cfg.ChosenAlg = AlgAESSIVCMAC256
	for i := range 2 {
		copy(cfg.Cookies[i][:], cookie)
		cfg.CookieLens[i] = len(cookie)
	}
	cfg.NumCookies = 2

	baseTime := ntp.BaseTime()
	clockTime := baseTime.Add(10 * time.Second)
	serverOffset := 200 * time.Millisecond
	cfg.Now = func() time.Time { return clockTime }
	cfg.Sysprec = -20

	var client Client
	if err := client.Reset(cfg); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if client.IsDone() {
		t.Fatal("should not be done before exchange")
	}

	carrier := make([]byte, 1500)

	// --- First exchange ---
	n, err := client.Encapsulate(carrier, 0, 0)
	if err != nil {
		t.Fatalf("Encapsulate 1: %v", err)
	}
	if n < ntp.SizeHeader {
		t.Fatalf("Encapsulate 1: n=%d too small", n)
	}

	// Simulate server response: build an NTP response and re-encrypt.
	resp1 := buildTestResponse(t, carrier[:n], clockTime.Add(serverOffset), clockTime.Add(serverOffset+5*time.Millisecond), s2cKey)
	clockTime = baseTime.Add(10*time.Second + 110*time.Millisecond)
	if err = client.Demux(resp1, 0); err != nil {
		t.Fatalf("Demux 1: %v", err)
	}
	if client.IsDone() {
		t.Fatal("should not be done after first exchange only")
	}

	// --- Second exchange ---
	carrier2 := make([]byte, 1500)
	clockTime = baseTime.Add(10*time.Second + 200*time.Millisecond)
	n2, err := client.Encapsulate(carrier2, 0, 0)
	if err != nil {
		t.Fatalf("Encapsulate 2: %v", err)
	}
	if n2 == 0 {
		t.Fatal("Encapsulate 2 returned 0 bytes")
	}

	resp2 := buildTestResponse(t, carrier2[:n2], clockTime.Add(serverOffset), clockTime.Add(serverOffset+5*time.Millisecond), s2cKey)
	clockTime = baseTime.Add(10*time.Second + 310*time.Millisecond)
	if err = client.Demux(resp2, 0); err != nil {
		t.Fatalf("Demux 2: %v", err)
	}
	if !client.IsDone() {
		t.Fatal("should be done after second exchange")
	}
	if client.RoundTripDelay() < 0 {
		t.Errorf("RoundTripDelay = %v; want >= 0", client.RoundTripDelay())
	}
}

func TestClient_Reset_Validation(t *testing.T) {
	key := make([]byte, 32)
	aead, _ := siv.NewAESSIVCMAC256(key)
	cookie := [MaxCookieLen]byte{}
	cfg := ClientConfig{
		C2S: aead, S2C: aead, NumCookies: 1,
		Cookies:    [MaxCookies][MaxCookieLen]byte{cookie},
		CookieLens: [MaxCookies]int{8},
	}
	var c Client
	if err := c.Reset(cfg); err != nil {
		t.Fatalf("valid Reset: %v", err)
	}
	prevID := *c.ConnectionID()

	cfg2 := cfg
	cfg2.C2S = nil
	if err := c.Reset(cfg2); err == nil {
		t.Error("nil C2S: expected error")
	}
	if *c.ConnectionID() != prevID {
		t.Error("connID should not increment on failed Reset")
	}

	cfg3 := cfg
	cfg3.NumCookies = 0
	if err := c.Reset(cfg3); err == nil {
		t.Error("zero cookies: expected error")
	}
}

func TestClient_ExhaustedCookies(t *testing.T) {
	key := make([]byte, 32)
	aead, _ := siv.NewAESSIVCMAC256(key)
	cfg := ClientConfig{
		C2S: aead, S2C: aead, NumCookies: 1,
		Cookies:    [MaxCookies][MaxCookieLen]byte{[MaxCookieLen]byte{}},
		CookieLens: [MaxCookies]int{8},
	}
	var c Client
	c.Reset(cfg)

	carrier := make([]byte, 1500)
	if _, err := c.Encapsulate(carrier, 0, 0); err != nil {
		t.Fatalf("first Encapsulate: %v", err)
	}
	if c.numCookies != 0 {
		t.Fatalf("numCookies = %d; want 0", c.numCookies)
	}
	if _, err := c.Encapsulate(carrier, 0, 0); err != lneto.ErrExhausted {
		t.Errorf("second Encapsulate: got %v; want ErrExhausted", err)
	}
}

func TestClient_DemuxBadTag(t *testing.T) {
	key := make([]byte, 32)
	aead, _ := siv.NewAESSIVCMAC256(key)
	cookie := make([]byte, 16)
	var cookies [MaxCookies][MaxCookieLen]byte
	copy(cookies[0][:], cookie)
	cfg := ClientConfig{
		C2S: aead, S2C: aead, NumCookies: 1,
		Cookies:    cookies,
		CookieLens: [MaxCookies]int{16},
	}
	var c Client
	c.Reset(cfg)

	carrier := make([]byte, 1500)
	n, _ := c.Encapsulate(carrier, 0, 0)

	resp := buildTestResponse(t, carrier[:n],
		time.Now(), time.Now().Add(time.Millisecond), key)
	// Tamper a byte in the NTP header (part of the AAD); this must cause
	// the authentication tag to be rejected.
	resp[ntp.SizeHeader-1] ^= 0xff
	if err := c.Demux(resp, 0); err != lneto.ErrBadCRC {
		t.Errorf("tampered Demux: got %v; want ErrBadCRC", err)
	}
}

// buildTestResponse constructs a minimal NTS-authenticated NTP server response
// by echoing the client's UniqueID and re-sealing with s2cKey.
// The returned slice contains exactly the response bytes (no trailing zeros).
func buildTestResponse(t *testing.T, request []byte, serverRecv, serverXmt time.Time, s2cKey []byte) []byte {
	t.Helper()
	reqFrm, err := ntp.NewFrame(request)
	if err != nil {
		t.Fatal(err)
	}

	// Extract the Unique-ID from the request so the response can echo it.
	var uniqueID []byte
	extBuf := reqFrm.ExtensionFields()
	for off := 0; off < len(extBuf); {
		field, n, e := ntp.NextExtField(extBuf[off:])
		if e != nil || len(field.RawData()) == 0 {
			break
		}
		if field.Type() == ntp.ExtNTSUniqueID {
			uniqueID = field.Value()
			break
		}
		off += n
	}

	// Build response in a new buffer.
	resp := make([]byte, 1500)
	respFrm, _ := ntp.NewFrame(resp)
	respFrm.SetFlags(ntp.ModeServer, ntp.Version4, ntp.LeapNoWarning)
	respFrm.SetStratum(ntp.StratumPrimary)
	respFrm.SetPrecision(-20)
	respFrm.SetOriginTime(reqFrm.TransmitTime())
	recvTS, _ := ntp.TimestampFromTime(serverRecv)
	xmtTS, _ := ntp.TimestampFromTime(serverXmt)
	respFrm.SetReceiveTime(recvTS)
	respFrm.SetTransmitTime(xmtTS)

	// Append UniqueID extension field (echo).
	respBuf := resp[:ntp.SizeHeader]
	if len(uniqueID) > 0 {
		respBuf = ntp.AppendExtField(respBuf, ntp.ExtNTSUniqueID, uniqueID)
	}

	// Build NTS-Auth field sealed with S2C key.
	s2c, err := siv.NewAESSIVCMAC256(s2cKey)
	if err != nil {
		t.Fatal(err)
	}
	nonceLen := s2c.NonceSize()
	overhead := s2c.Overhead()

	var nonce [maxNonceLen]byte
	rand.Read(nonce[:nonceLen])

	aad := respBuf

	var authBody [maxAuthBody]byte
	binary.BigEndian.PutUint16(authBody[0:2], uint16(nonceLen))
	binary.BigEndian.PutUint16(authBody[2:4], uint16(overhead))
	copy(authBody[4:4+nonceLen], nonce[:nonceLen])
	s2c.Seal(authBody[4+nonceLen:4+nonceLen], nonce[:nonceLen], nil, aad)

	respBuf = ntp.AppendExtField(respBuf, ntp.ExtNTSAuthAndEEF, authBody[:4+nonceLen+overhead])
	result := make([]byte, len(respBuf))
	copy(result, respBuf)
	return result
}

func FuzzKERecord(f *testing.F) {
	// Seed with valid records.
	f.Add(AppendKERecord(nil, true, RecordEndOfMessage, nil))
	f.Add(AppendKERecord(nil, false, RecordNewCookie, []byte("cookie")))
	f.Add(AppendKERecord(nil, true, RecordAEADAlgNeg, []byte{0, 15}))
	// Seed with short inputs.
	f.Add([]byte{})
	f.Add([]byte{0x80, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		rec, err := NewKERecord(data)
		if err != nil {
			return
		}
		var v lneto.Validator
		rec.ValidateSize(&v)
		_ = rec.RecordType()
		_ = rec.IsCritical()
		_ = rec.Body()
	})
}

func FuzzNextExtField(f *testing.F) {
	f.Add(ntp.AppendExtField(nil, ntp.ExtNTSUniqueID, make([]byte, 32)))
	f.Add(ntp.AppendExtField(nil, ntp.ExtNTSCookie, make([]byte, 64)))
	f.Add([]byte{})
	f.Add([]byte{0, 1, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		field, n, _ := ntp.NextExtField(data)
		_ = field.RawData()
		_ = n
	})
}

func TestServer_Reset_Validation(t *testing.T) {
	key := make([]byte, 32)
	aead, _ := siv.NewAESSIVCMAC256(key)
	var s Server
	if err := s.Reset(ServerConfig{C2S: aead, S2C: aead, Stratum: ntp.StratumPrimary}); err != nil {
		t.Fatalf("valid Reset: %v", err)
	}
	prevID := *s.ConnectionID()
	if err := s.Reset(ServerConfig{C2S: nil, S2C: aead}); err == nil {
		t.Error("nil C2S: expected error")
	}
	if *s.ConnectionID() != prevID {
		t.Error("connID should not increment on failed Reset")
	}
}

func TestServer_NoPendingReturnsZero(t *testing.T) {
	key := make([]byte, 32)
	aead, _ := siv.NewAESSIVCMAC256(key)
	var s Server
	s.Reset(ServerConfig{C2S: aead, S2C: aead, Stratum: ntp.StratumPrimary})
	carrier := make([]byte, 1500)
	n, err := s.Encapsulate(carrier, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected 0, got %d", n)
	}
}

func TestClientServer_E2E(t *testing.T) {
	c2sKey := make([]byte, 32)
	s2cKey := make([]byte, 32)
	rand.Read(c2sKey)
	rand.Read(s2cKey)
	c2s, _ := siv.NewAESSIVCMAC256(c2sKey)
	s2c, _ := siv.NewAESSIVCMAC256(s2cKey)

	cookie := []byte("nts-cookie-round-trip-test")

	baseTime := ntp.BaseTime()
	clientTime := baseTime.Add(10 * time.Second)
	serverTime := clientTime.Add(200 * time.Millisecond)

	var clientCfg ClientConfig
	clientCfg.C2S = c2s
	clientCfg.S2C = s2c
	clientCfg.ChosenAlg = AlgAESSIVCMAC256
	clientCfg.Now = func() time.Time { return clientTime }
	clientCfg.Sysprec = -20
	for i := range 2 {
		copy(clientCfg.Cookies[i][:], cookie)
		clientCfg.CookieLens[i] = len(cookie)
	}
	clientCfg.NumCookies = 2

	var client Client
	if err := client.Reset(clientCfg); err != nil {
		t.Fatal(err)
	}

	// Server uses same keys (C2S to verify client, S2C to seal responses).
	var server Server
	if err := server.Reset(ServerConfig{
		C2S:     c2s,
		S2C:     s2c,
		Now:     func() time.Time { return serverTime },
		Stratum: ntp.StratumPrimary,
		Prec:    -20,
		RefID:   [4]byte{'G', 'P', 'S', 0},
	}); err != nil {
		t.Fatal(err)
	}

	for exchange := range 2 {
		carrier := make([]byte, 1500)
		n, err := client.Encapsulate(carrier, 0, 0)
		if err != nil || n == 0 {
			t.Fatalf("exchange %d: client Encapsulate: n=%d err=%v", exchange, n, err)
		}

		if err = server.Demux(carrier[:n], 0); err != nil {
			t.Fatalf("exchange %d: server Demux: %v", exchange, err)
		}

		resp := make([]byte, 1500)
		rn, err := server.Encapsulate(resp, 0, 0)
		if err != nil || rn == 0 {
			t.Fatalf("exchange %d: server Encapsulate: rn=%d err=%v", exchange, rn, err)
		}

		clientTime = clientTime.Add(100 * time.Millisecond)
		serverTime = serverTime.Add(100 * time.Millisecond)

		if err = client.Demux(resp[:rn], 0); err != nil {
			t.Fatalf("exchange %d: client Demux: %v", exchange, err)
		}
	}

	if !client.IsDone() {
		t.Fatal("client should be done after two exchanges")
	}
	if client.RoundTripDelay() < 0 {
		t.Errorf("RTD = %v; want >= 0", client.RoundTripDelay())
	}
}

func TestClientServer_TamperedAADRejected(t *testing.T) {
	c2sKey := make([]byte, 32)
	s2cKey := make([]byte, 32)
	rand.Read(c2sKey)
	rand.Read(s2cKey)
	c2s, _ := siv.NewAESSIVCMAC256(c2sKey)
	s2c, _ := siv.NewAESSIVCMAC256(s2cKey)

	cookie := []byte("cookie-tamper-test")
	var cfg ClientConfig
	cfg.C2S = c2s
	cfg.S2C = s2c
	cfg.NumCookies = 1
	copy(cfg.Cookies[0][:], cookie)
	cfg.CookieLens[0] = len(cookie)

	var client Client
	client.Reset(cfg)

	carrier := make([]byte, 1500)
	n, _ := client.Encapsulate(carrier, 0, 0)

	// Tamper with NTP header (part of AAD).
	carrier[ntp.SizeHeader-1] ^= 0xff

	var server Server
	server.Reset(ServerConfig{C2S: c2s, S2C: s2c, Stratum: ntp.StratumPrimary})

	if err := server.Demux(carrier[:n], 0); err != lneto.ErrBadCRC {
		t.Errorf("tampered Demux: got %v; want ErrBadCRC", err)
	}
}

func TestHandleKE_E2E(t *testing.T) {
	cert := generateSelfSignedCert(t)
	pool := x509.NewCertPool()
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	pool.AddCert(leaf)

	serverTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"ntske/1"},
	}
	clientTLSCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"ntske/1"},
	}

	wantCookie := []byte("ke-server-cookie-data")

	serverConn, clientConn := net.Pipe()
	done := make(chan KESecrets, 1)
	errc := make(chan error, 1)
	go func() {
		tc := tls.Server(serverConn, serverTLSCfg)
		if err := tc.Handshake(); err != nil {
			errc <- err
			return
		}
		defer tc.Close()
		secrets, err := HandleKE(tc, KEServerConfig{
			Cookies: [][]byte{wantCookie},
		})
		if err != nil {
			errc <- err
			return
		}
		done <- secrets
	}()

	tc := tls.Client(clientConn, clientTLSCfg)
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	clientSecrets, err := PerformKE(tc, KEConfig{})
	tc.Close()

	select {
	case err := <-errc:
		t.Fatalf("server KE: %v", err)
	case serverSecrets := <-done:
		if err != nil {
			t.Fatalf("client KE: %v", err)
		}
		if clientSecrets.ChosenAlg != serverSecrets.ChosenAlg {
			t.Errorf("ChosenAlg: client=%v server=%v; want equal", clientSecrets.ChosenAlg, serverSecrets.ChosenAlg)
		}
		if clientSecrets.C2SKey != serverSecrets.C2SKey {
			t.Errorf("C2SKey mismatch: client and server derived different keys")
		}
		if clientSecrets.S2CKey != serverSecrets.S2CKey {
			t.Errorf("S2CKey mismatch: client and server derived different keys")
		}
		if clientSecrets.NumCookies != 1 {
			t.Errorf("NumCookies = %d; want 1", clientSecrets.NumCookies)
		}
		gotCookie := clientSecrets.Cookies[0][:clientSecrets.CookieLens[0]]
		if !bytes.Equal(gotCookie, wantCookie) {
			t.Errorf("cookie = %q; want %q", gotCookie, wantCookie)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("HandleKE server goroutine timed out")
	}
}

func FuzzServerDemux(f *testing.F) {
	key := make([]byte, 32)
	aead, _ := siv.NewAESSIVCMAC256(key)

	// Seed with a valid NTS request built by the client.
	var c Client
	c.Reset(ClientConfig{
		C2S: aead, S2C: aead, NumCookies: 1,
		Cookies:    [MaxCookies][MaxCookieLen]byte{},
		CookieLens: [MaxCookies]int{16},
	})
	carrier := make([]byte, 1500)
	n, _ := c.Encapsulate(carrier, 0, 0)
	if n > 0 {
		f.Add(carrier[:n])
	}
	f.Add(make([]byte, ntp.SizeHeader))
	f.Add([]byte{})
	f.Add(make([]byte, 10))
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzKey := make([]byte, 32)
		fuzzAEAD, _ := siv.NewAESSIVCMAC256(fuzzKey)
		var s Server
		s.Reset(ServerConfig{C2S: fuzzAEAD, S2C: fuzzAEAD, Stratum: ntp.StratumPrimary})
		_ = s.Demux(data, 0)
	})
}

func BenchmarkClient_Encapsulate(b *testing.B) {
	key := make([]byte, 32)
	aead, _ := siv.NewAESSIVCMAC256(key)
	carrier := make([]byte, 1500)

	var c Client
	newCfg := func() ClientConfig {
		var cookies [MaxCookies][MaxCookieLen]byte
		var lens [MaxCookies]int
		for i := range cookies {
			copy(cookies[i][:], make([]byte, 32))
			lens[i] = 32
		}
		return ClientConfig{
			C2S: aead, S2C: aead, ChosenAlg: AlgAESSIVCMAC256,
			NumCookies: MaxCookies, Cookies: cookies, CookieLens: lens,
			Now: time.Now,
		}
	}
	c.Reset(newCfg())
	b.ResetTimer()
	for b.Loop() {
		if c.numCookies == 0 {
			c.Reset(newCfg())
		}
		c.Encapsulate(carrier, 0, 0)
	}
}
