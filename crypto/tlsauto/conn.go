package tlsauto

import (
	"encoding/binary"
	"hash"
	"io"
	"net"
	"slices"
	"strconv"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/lcrypto"
	"github.com/soypat/lneto/crypto/tlsraw"
	"github.com/soypat/lneto/internal"
)

// Aliases so that users outside lneto can name the capability interfaces,
// which live in an internal package.
type (
	LCredential = lcrypto.Credential
	LVerifier   = lcrypto.Verifier
)

// Suite describes a TLS 1.3 cipher suite, RFC 8446 B.4.
type Suite struct {
	ID      uint16                    // RFC 8446 B.4 wire value.
	KeyLen  int                       // Length of the key passed to AEADCipher.Rekey.
	NewAEAD func() lcrypto.AEADCipher // Returns an unkeyed record cipher. Called once per Conn per direction.
	// NewHash returns the key schedule hash, one of those accepted by
	// [tlsraw.KeySchedule.Configure]. Each call must return a fresh instance: the
	// transcript and the HMAC scratch of the key schedule are two of these, and the
	// scratch is reset on every use, so one instance shared between them would
	// silently destroy the transcript.
	NewHash func() hash.Hash
}

// KeyExchange describes an ephemeral key agreement group, RFC 8446 4.2.8.
type KeyExchange struct {
	ID             uint16 // RFC 8446 B.3.1.4 NamedGroup.
	ClientShareLen int    // client key_share length.
	ServerShareLen int    // server key_share length (KEM ciphertext for ML-KEM).
	SharedLen      int    // Shared secret length.
	NewExchanger   func() lcrypto.Exchanger
}

// Config stores TLS connection configuration and may be reused across connections.
// Configure copies Config, so modifying it afterwards does not affect configured
// connections. The copy is shallow: the credential, the entropy source and the
// constructors of [Suite] and [KeyExchange] are shared between connections, so
// they must be safe for concurrent use.
type Config struct {
	// Rand is the entropy source for hello randoms and key shares. It must be
	// safe for concurrent use, as crypto/rand.Reader is.
	Rand io.Reader
	// Suites lists the supported cipher suites in preference order. Their hash
	// must be one the key schedule accepts, see [tlsraw.KeySchedule.Configure].
	Suites []Suite
	// KeyExchanges lists the supported key exchange groups in preference order.
	KeyExchanges []KeyExchange
	// Credential authenticates the server. Required when serving.
	Credential LCredential
}

const (
	sizeHandshakeBuf  = 4096 // Largest handshake message accepted. Fits any real ClientHello, post-quantum included.
	maxKeyShare       = 1216 // Largest key_share of a supported group, either direction: the X25519MLKEM768 client share.
	maxDroppedRecords = 2    // Records dropped in one [Conn.readRecord] call before the peer is doing nothing but stalling.
	maxShared         = 64   // X25519MLKEM768 shared secret.
	maxOfferedSchemes = 32   // Peer signature_algorithms entries passed to Credential.Scheme. Real clients send about 20; entries past the 32nd are ignored, so a Credential that would have chosen one fails the handshake.
	maxHashSize       = 48   // Largest key schedule digest, SHA-384. RFC 8446 B.4 names no suite above it. Sizes every secret held by Conn.
	maxKeyLen         = 32   // Largest AEAD key of the TLS 1.3 suites: AES-256 and ChaCha20.
	serverCVContext   = "TLS 1.3, server CertificateVerify"
)

type connState uint8

const (
	stateIdle      connState = iota // Open not called.
	stateHandshake                  // Open called, handshake not complete.
	stateConnected                  // Handshake complete.
	stateFailed                     // Fatal error, secrets wiped.
	stateClosed                     // Closed by Close.
)

// Conn is a TLS 1.3 connection over a reliable byte stream. It supports the server
// role without PSK or HelloRetryRequest.
//
// Conn is not safe for concurrent use.
type Conn struct {
	rw net.Conn

	isClient   bool
	state      connState
	peerClosed bool // Peer sent close_notify.

	ks      tlsraw.KeySchedule
	in, out tlsraw.HalfConn
	vld     lneto.Validator

	// Instances built by the constructors of [Suite] and [KeyExchange]. They are kept
	// across Open so a reused Conn does not allocate when it negotiates a suite and
	// group it has negotiated before.
	//
	// Each time a new suite/key exchange is instantiated it is stored in case tls.Conn
	// alternates between cipher suites and/or exchangers between connections. Values may be nil.
	// Order of cipher/key exchangers map to Config.Suites and Config.KeyExchanges, respectively.
	instanceCiphersIn, instanceCiphersOut []lcrypto.AEADCipher
	instanceTranscript, instanceMac       []hash.Hash
	instanceExchanger                     []lcrypto.Exchanger
	cfg                                   Config // Snapshot taken by Open. Its slices are owned by Conn.

	suite           *Suite
	aeadIn, aeadOut lcrypto.AEADCipher
	transcript, mac hash.Hash
	group           *KeyExchange
	exch            lcrypto.Exchanger

	rbuf         []byte // One incoming record.
	hbuf         []byte // Incoming handshake messages being reassembled.
	hsOff, hsEnd int    // hbuf[hsOff:hsEnd] is received handshake data not yet handled.
	wbuf         []byte // Outgoing records.
	app          []byte // Received application data not yet returned by Read. Points into rbuf.

	// Handshake state. Buffers passed to interface methods escape to the heap, so they live here.
	scheme    uint16
	sidLen    uint8
	sessionID [tlsraw.MaxSessionIDLen]byte
	offered   [maxOfferedSchemes]uint16
	shared    [maxShared]byte // Key exchange output, of c.group.SharedLen bytes.

	// Secrets. All but the record key and IV are traffic secrets of c.hashSize() bytes.
	secret    [maxHashSize]byte // Server traffic secret being installed.
	clientHS  [maxHashSize]byte
	clientAP  [maxHashSize]byte
	expectFin [maxHashSize]byte // Client Finished verify_data.
	// The record key and IV are not here: [tlsraw.KeySchedule.InstallKeys] derives
	// them into the AEAD and the HalfConn, so Conn never holds a copy of either.
}

const (
	// sizeCVPrefix is the length of the CertificateVerify content preceding the
	// transcript hash: the 64 byte padding, the context string and its separator.
	sizeCVPrefix = 64 + len(serverCVContext) + 1
	// sizeSigned is the room the CertificateVerify content of RFC 8446 4.4.3
	// takes at the end of wbuf, past every record wbuf can hold.
	sizeSigned = sizeCVPrefix + maxHashSize
)

// cvScratch returns the tail of wbuf, where the CertificateVerify content is
// built. It is not part of any record: wbuf is a full record longer than a
// record needs, Sign's destination stops short of it, and SealRecord's tag
// lands at MaxRecord at the furthest, so nothing the encoder writes reaches it.
// The content is a constant prefix and a transcript hash, neither secret, and
// Zeroize clears wbuf with the rest.
func (c *Conn) cvScratch() []byte { return c.wbuf[len(c.wbuf)-sizeSigned:] }

// hashSize is the digest size of the negotiated suite, and the length of every
// traffic secret held by c. It is 0 until the key schedule is first configured,
// and on a reused Conn it is the previous connection's size until this one
// negotiates a suite: [tlsraw.KeySchedule.Zeroize] keeps the size so the schedule
// stays reusable. Callers are past [Conn.useSuite], so they read this connection's.
func (c *Conn) hashSize() int { return c.ks.Size() }

// Configure validates cfg and takes it as the configuration of the connections
// opened from here on. It wipes the secrets and the instances of the previous
// configuration, so it is refused while a connection is live: Close that
// connection first.
func (c *Conn) Configure(cfg Config) error {
	if c.state == stateHandshake || c.state == stateConnected {
		return lneto.ErrBadState // Wiping the keys under a live connection would read the peer's ciphertext as plaintext.
	}
	if cfg.Rand == nil || len(cfg.Suites) == 0 || len(cfg.KeyExchanges) == 0 {
		return lneto.ErrInvalidConfig
	} else if cfg.Credential == nil || cfg.Credential.NumCerts() == 0 {
		return lneto.ErrInvalidConfig
	}
	for _, s := range cfg.Suites {
		if s.ID == 0 || s.NewAEAD == nil || s.NewHash == nil {
			return lneto.ErrInvalidConfig
		} else if s.KeyLen <= 0 || s.KeyLen > maxKeyLen {
			return lneto.ErrInvalidConfig
		}
	}
	for _, g := range cfg.KeyExchanges {
		if g.ID == 0 || g.NewExchanger == nil {
			return lneto.ErrInvalidConfig
		}
		client, server, shared := g.ClientShareLen, g.ServerShareLen, g.SharedLen
		if client <= 0 || server <= 0 || shared <= 0 {
			return lneto.ErrInvalidConfig
		} else if client > maxKeyShare || server > maxKeyShare || shared > maxShared {
			return lneto.ErrInvalidConfig
		}
	}
	c.Zeroize()
	c.zeroizeInstances() // Instances of the previous config are dropped below; they do not outlive it keyed.

	suites, groups := c.cfg.Suites, c.cfg.KeyExchanges // Backing arrays owned by c.
	c.cfg = cfg
	internal.SliceReuse(&suites, len(cfg.Suites))
	internal.SliceReuse(&groups, len(cfg.KeyExchanges))
	c.cfg.Suites = append(suites, cfg.Suites...)
	c.cfg.KeyExchanges = append(groups, cfg.KeyExchanges...)

	sliceReuseZero(&c.instanceCiphersIn, len(c.cfg.Suites))
	sliceReuseZero(&c.instanceCiphersOut, len(c.cfg.Suites))
	sliceReuseZero(&c.instanceTranscript, len(c.cfg.Suites))
	sliceReuseZero(&c.instanceMac, len(c.cfg.Suites))
	sliceReuseZero(&c.instanceExchanger, len(c.cfg.KeyExchanges))

	// The instances the previous config negotiated are gone, so are the pointers into its slices.
	c.suite, c.group = nil, nil
	c.aeadIn, c.aeadOut, c.exch = nil, nil, nil
	c.transcript, c.mac = nil, nil
	return nil
}

// zeroizeInstances wipes every cipher, hash and exchanger kept for the current
// config. [Conn.Zeroize] only reaches the negotiated ones, so instances of
// suites and groups used by an earlier connection are wiped here.
func (c *Conn) zeroizeInstances() {
	for i := range c.instanceCiphersIn {
		if c.instanceCiphersIn[i] == nil {
			continue // useSuite creates the four instances of a suite together.
		}
		c.instanceCiphersIn[i].Zeroize()
		c.instanceCiphersOut[i].Zeroize()
		c.instanceTranscript[i].Reset()
		c.instanceMac[i].Reset()
	}
	for i := range c.instanceExchanger {
		if c.instanceExchanger[i] != nil {
			c.instanceExchanger[i].Zeroize()
		}
	}
}

func sliceReuseZero[T any](buf *[]T, n int) {
	clear((*buf)[:len(*buf)])
	internal.SliceReuse(buf, n)
	*buf = (*buf)[:n]
}

// Open receives a newly established connection (no data sent/received) and
// prepares to begin establishing networking over connection. It wipes the
// previous connection's secrets and reuses its buffers.
func (c *Conn) Open(conn net.Conn, isClient bool) error {
	if conn == nil {
		return lneto.ErrInvalidConfig
	} else if isClient {
		return lneto.ErrUnsupported // TODO: client handshake.
	} else if len(c.cfg.Suites) == 0 {
		return lneto.ErrBadState // Configure not called.
	}
	// Wipe what the previous connection left: its record keys would otherwise
	// still be installed and the peer's first plaintext record read as ciphertext.
	c.Zeroize()
	c.rbuf = reuse(c.rbuf, tlsraw.MaxRecord)
	c.hbuf = reuse(c.hbuf, sizeHandshakeBuf)
	c.wbuf = reuse(c.wbuf, tlsraw.MaxRecord+sizeSigned) // The tail past MaxRecord is cvScratch, never part of a record.
	c.rw = conn
	c.isClient = isClient
	c.state = stateHandshake
	c.peerClosed = false
	c.hsOff, c.hsEnd = 0, 0
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
	if err := c.serverHandshake(); err != nil {
		return c.fail(err)
	}
	c.state = stateConnected
	return nil
}

// Read reads application data. It returns io.EOF after the peer's close_notify.
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
		chunk := min(len(p)-n, tlsraw.MaxPlaintext)
		if err = c.writeRecord(tlsraw.ContentTypeApplicationData, p[n:n+chunk]); err != nil {
			return n, c.fail(err)
		}
		n += chunk
	}
	return n, nil
}

// Close sends close_notify, wipes secrets and closes the underlying connection.
func (c *Conn) Close() error {
	var err error
	if c.state == stateConnected {
		err = c.writeAlert(tlsraw.AlertCloseNotify)
	}
	c.Zeroize()
	c.state = stateClosed
	if c.rw != nil {
		if cerr := c.rw.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// Zeroize wipes all secrets and buffered data. Open must be called before reuse.
func (c *Conn) Zeroize() {
	c.ks.Zeroize()
	c.in.Zeroize()
	c.out.Zeroize()
	if c.aeadIn != nil {
		c.aeadIn.Zeroize()
		c.aeadOut.Zeroize()
	}
	if c.exch != nil {
		c.exch.Zeroize()
	}
	clear(c.shared[:])
	clear(c.secret[:])
	clear(c.clientHS[:])
	clear(c.clientAP[:])
	clear(c.expectFin[:])
	clear(c.rbuf)
	clear(c.hbuf)
	clear(c.wbuf)
	c.app = nil
}

func (c *Conn) serverHandshake() error {
	msg, err := c.readHandshake(tlsraw.HandshakeTypeClientHello)
	if err != nil {
		return err
	}
	clientShare, err := c.handleClientHello(msg)
	if err != nil {
		return err
	} else if err = c.writeServerFlight(clientShare); err != nil {
		return err
	}
	msg, err = c.readHandshake(tlsraw.HandshakeTypeFinished)
	if err != nil {
		return err
	}
	return c.handleClientFinished(msg)
}

// handleClientHello negotiates the suite, group and signature scheme of the
// ClientHello and returns the client's key share. The share points into hbuf and
// is consumed by [Conn.writeServerHello], which runs before the next record is
// read, so it is passed along rather than copied into Conn.
func (c *Conn) handleClientHello(msg []byte) ([]byte, error) {
	if err := c.keyChangeBoundary(); err != nil {
		return nil, err
	}
	var ch tlsraw.HelloClientMsg
	body := msg[tlsraw.SizeHeaderHandshake:]
	n, err := ch.Decode(body, &c.vld)
	if err != nil || n != len(body) {
		c.vld.ResetErr()
		return nil, alertError(tlsraw.AlertDecodeError)
	}
	if comp := ch.Compressions(); len(comp) != 1 || comp[0] != 0 {
		return nil, alertError(tlsraw.AlertIllegalParameter)
	}
	c.sidLen = uint8(copy(c.sessionID[:], ch.SessionID()))

	var tls13 bool
	var shares, schemes []byte
	var seen uint64 // Extension types below 64 already seen, to reject duplicates.
	for exts := ch.Extensions(); len(exts) > 0; {
		ef, err := tlsraw.NewExtensionFrame(exts)
		if err != nil {
			return nil, alertError(tlsraw.AlertDecodeError)
		}
		exts = exts[len(ef.RawData()):]
		ef.ValidateType(&c.vld, false)
		if c.vld.HasError() {
			c.vld.ResetErr()
			return nil, alertError(tlsraw.AlertDecodeError)
		}
		typ := ef.Type()
		if typ < 64 {
			if seen&(1<<typ) != 0 {
				return nil, alertError(tlsraw.AlertIllegalParameter)
			}
			seen |= 1 << typ
		}
		data := ef.Data()
		switch typ {
		case tlsraw.ExtSupportedVersions:
			tls13 = hasUint16(data[1:], tlsraw.VersionTLS13)
		case tlsraw.ExtSignatureAlgorithms:
			schemes = data[2:]
		case tlsraw.ExtKeyShare:
			shares = data[2:]
		}
	}
	if !tls13 {
		return nil, alertError(tlsraw.AlertProtocolVersion)
	} else if schemes == nil || shares == nil {
		return nil, alertError(tlsraw.AlertMissingExtension)
	}
	suiteIdx := c.selectSuite(ch.Suites())
	groupIdx, clientShare, err := c.selectGroup(shares)
	if err != nil {
		return nil, err
	}
	c.scheme = c.selectScheme(schemes)
	if suiteIdx < 0 || groupIdx < 0 || c.scheme == 0 {
		return nil, alertError(tlsraw.AlertHandshakeFailure) // TODO: HelloRetryRequest when only the key share is missing.
	}

	if err = c.useSuite(suiteIdx); err != nil {
		return nil, err
	}
	if err = c.ks.Configure(c.transcript, c.mac, true); err != nil {
		return nil, err // Suite hash the key schedule cannot use.
	}
	c.ks.AddMessage(msg)
	c.useGroup(groupIdx)
	return clientShare, nil
}

// selectSuite returns the index in [Config.Suites] of the first configured
// suite the client offered, or -1 if it offered none.
func (c *Conn) selectSuite(offered []byte) int {
	for i := range c.cfg.Suites {
		if hasUint16(offered, c.cfg.Suites[i].ID) {
			return i
		}
	}
	return -1
}

// selectGroup returns the index in [Config.KeyExchanges] of the first configured
// group the client sent a key share for, and that share. It returns -1 if the
// client sent a share for no configured group.
func (c *Conn) selectGroup(shares []byte) (int, []byte, error) {
	for i := range c.cfg.KeyExchanges {
		g := &c.cfg.KeyExchanges[i]
		var share []byte
		for rest := shares; len(rest) > 0; {
			group, key, n, err := tlsraw.NextKeyShare(rest, false)
			if err != nil || n == 0 {
				// ValidateType walked these same entries, so this is unreachable. It is
				// checked because every error of NextKeyShare comes with n==0, which
				// would leave the walk below unable to advance.
				return -1, nil, alertError(tlsraw.AlertDecodeError)
			}
			rest = rest[n:]
			if uint16(group) != g.ID {
				continue
			} else if share != nil {
				return -1, nil, alertError(tlsraw.AlertIllegalParameter) // One share per group, RFC 8446 4.2.8.
			}
			share = key
		}
		if share == nil {
			continue
		}
		if len(share) != g.ClientShareLen {
			return -1, nil, alertError(tlsraw.AlertIllegalParameter)
		}
		return i, share, nil
	}
	return -1, nil, nil
}

// selectScheme returns the scheme Credential signs with, or 0 if it supports none the client offered.
// The Credential's choice is checked, since a scheme the client did not offer fails the handshake on its side.
func (c *Conn) selectScheme(list []byte) uint16 {
	n := 0
	for i := 0; i+1 < len(list) && n < len(c.offered); i += 2 {
		c.offered[n] = binary.BigEndian.Uint16(list[i:])
		n++
	}
	offered := c.offered[:n]
	s := c.cfg.Credential.Scheme(offered)
	if s == 0 || legacyScheme(s) || !slices.Contains(offered, s) {
		return 0
	}
	return s
}

// useSuite makes [Config.Suites][i] the connection's suite, creating its cipher
// and hash instances unless an earlier connection already did.
func (c *Conn) useSuite(i int) error {
	s := &c.cfg.Suites[i]
	if c.instanceCiphersIn[i] == nil {
		c.instanceCiphersIn[i] = s.NewAEAD()
		c.instanceCiphersOut[i] = s.NewAEAD()
		c.instanceMac[i] = s.NewHash()
		c.instanceTranscript[i] = s.NewHash()
	}
	c.aeadIn = c.instanceCiphersIn[i]
	c.aeadOut = c.instanceCiphersOut[i]
	c.transcript = c.instanceTranscript[i]
	c.mac = c.instanceMac[i]
	if c.transcript.Size() > maxHashSize {
		return lneto.ErrUnsupported // Secrets of Conn would not fit. KeySchedule rejects it too.
	}
	c.suite = s
	return nil
}

// useGroup makes [Config.KeyExchanges][i] the connection's group, creating its
// Exchanger unless an earlier connection already did.
func (c *Conn) useGroup(i int) {
	ke := &c.cfg.KeyExchanges[i]
	if c.instanceExchanger[i] == nil {
		c.instanceExchanger[i] = ke.NewExchanger()
	}
	c.exch = c.instanceExchanger[i]
	c.group = ke
}

// writeServerFlight writes the server's first flight, RFC 8446 2, and installs the handshake keys.
func (c *Conn) writeServerFlight(clientShare []byte) error {
	e := c.encoder()
	rec := e.StartRecord(tlsraw.ContentTypeHandshake)
	sh, err := c.writeServerHello(&e, clientShare)
	if err != nil {
		return err
	}
	c.ks.AddMessage(sh)
	e.EndRecord(rec)
	if c.sidLen > 0 {
		// Client asked for middlebox compatibility mode, RFC 8446 D.4.
		ccs := e.StartRecord(tlsraw.ContentTypeChangeCipherSpec)
		e.Uint8(1)
		e.EndRecord(ccs)
	}
	if err := c.flush(&e); err != nil {
		return err
	}

	hs := c.hashSize()
	c.ks.Handshake(c.clientHS[:hs], c.secret[:hs], c.shared[:c.group.SharedLen])
	clear(c.shared[:])
	if err := c.setKeys(&c.out, c.aeadOut, c.secret[:hs]); err != nil {
		return err
	} else if err = c.setKeys(&c.in, c.aeadIn, c.clientHS[:hs]); err != nil {
		return err
	}

	e = c.encoder()
	rec = e.StartRecord(tlsraw.ContentTypeApplicationData)
	msg := e.StartMessage(tlsraw.HandshakeTypeEncryptedExtensions)
	e.Close(e.Open(2), 2) // No extensions.
	c.ks.AddMessage(e.EndMessage(msg))
	if err := c.writeCertificate(&e); err != nil {
		return err
	} else if err = c.writeCertificateVerify(&e); err != nil {
		return err
	}
	msg = e.StartMessage(tlsraw.HandshakeTypeFinished)
	// verify_data is derived into the record. StartMessage writes to the encoder,
	// not to the transcript, so the digest is the same one a scratch buffer saw.
	if verify := e.Reserve(hs); verify != nil {
		c.ks.Finished(verify, c.secret[:hs])
	}
	c.ks.AddMessage(e.EndMessage(msg))
	e.SealRecord(&c.out, rec, tlsraw.ContentTypeHandshake)
	if err := c.flush(&e); err != nil {
		return err
	}

	// Client Finished and application secrets cover the transcript up to server Finished.
	c.ks.Finished(c.expectFin[:hs], c.clientHS[:hs])
	c.ks.Master(c.clientAP[:hs], c.secret[:hs])
	clear(c.clientHS[:])
	err = c.setKeys(&c.out, c.aeadOut, c.secret[:hs])
	clear(c.secret[:])
	return err
}

func (c *Conn) writeServerHello(e *tlsraw.Encoder, clientShare []byte) ([]byte, error) {
	msg := e.StartMessage(tlsraw.HandshakeTypeServerHello)
	e.Uint16(tlsraw.VersionTLS12)
	// The hello random is drawn straight into the record. It is public and is not
	// needed again, so Conn does not keep a copy of it.
	random := e.Reserve(tlsraw.SizeHelloRandom)
	if random == nil {
		return nil, e.Err()
	} else if _, err := io.ReadFull(c.cfg.Rand, random); err != nil {
		return nil, err
	}
	e.Uint8(c.sidLen)
	e.Bytes(c.sessionID[:c.sidLen])
	e.Uint16(c.suite.ID)
	e.Uint8(0) // legacy_compression_method.
	exts := e.Open(2)

	e.Uint16(uint16(tlsraw.ExtKeyShare))
	ext := e.Open(2)
	e.Uint16(c.group.ID)
	key := e.Open(2)
	// The key exchange runs here so its public share lands in the extension
	// directly. The share is public and is not needed again, so Conn keeps no
	// copy; only the shared secret it produces is kept, to key the schedule.
	serverLen, sharedLen := c.group.ServerShareLen, c.group.SharedLen
	share := e.Reserve(serverLen)
	if share == nil {
		return nil, e.Err()
	}
	nShare, nShared, err := c.exch.ServerSharedRekey(share, c.shared[:sharedLen], clientShare, c.cfg.Rand)
	if err != nil {
		return nil, alertError(tlsraw.AlertIllegalParameter)
	} else if nShare != serverLen || nShared != sharedLen {
		// The Exchanger disagrees with its KeyExchange. The extension length is
		// already committed to ServerShareLen, and keying the connection off the
		// short prefix of a secret it did not finish writing is not an option.
		return nil, lneto.ErrInvalidConfig
	}
	e.Close(key, 2)
	e.Close(ext, 2)

	e.Uint16(uint16(tlsraw.ExtSupportedVersions))
	ext = e.Open(2)
	e.Uint16(tlsraw.VersionTLS13)
	e.Close(ext, 2)

	e.Close(exts, 2)
	return e.EndMessage(msg), nil
}

func (c *Conn) writeCertificate(e *tlsraw.Encoder) error {
	cred := c.cfg.Credential
	msg := e.StartMessage(tlsraw.HandshakeTypeCertificate)
	e.Uint8(0) // Empty certificate_request_context.
	list := e.Open(3)
	for i := range cred.NumCerts() {
		data := e.Open(3)
		n, err := cred.Cert(e.Rest(), i)
		if err != nil {
			return err
		}
		e.Advance(n)
		e.Close(data, 3)
		e.Uint16(0) // No extensions.
	}
	e.Close(list, 3)
	c.ks.AddMessage(e.EndMessage(msg))
	return e.Err()
}

func (c *Conn) writeCertificateVerify(e *tlsraw.Encoder) error {
	scratch := c.cvScratch()
	for i := range 64 {
		scratch[i] = 0x20
	}
	copy(scratch[64:], serverCVContext)
	scratch[sizeCVPrefix-1] = 0 // Separates context and transcript hash.
	signed := scratch[:sizeCVPrefix+c.hashSize()]
	c.ks.TranscriptHash(signed[sizeCVPrefix:])
	msg := e.StartMessage(tlsraw.HandshakeTypeCertificateVerify)
	e.Uint16(c.scheme)
	sig := e.Open(2)
	// The signature is written short of the scratch it is signing over, so no
	// signature can reach it. A credential needing that much room gets a short
	// buffer instead of silently overwriting what it is about to sign.
	dst := e.Rest()
	dst = dst[:max(0, len(dst)-sizeSigned)]
	n, err := c.cfg.Credential.Sign(dst, signed, c.scheme)
	if err != nil {
		return err
	}
	e.Advance(n)
	e.Close(sig, 2)
	c.ks.AddMessage(e.EndMessage(msg))
	return e.Err()
}

func (c *Conn) handleClientFinished(msg []byte) error {
	if err := c.keyChangeBoundary(); err != nil {
		return err
	}
	hs := c.hashSize()
	verify := msg[tlsraw.SizeHeaderHandshake:]
	if len(verify) != hs {
		return alertError(tlsraw.AlertDecodeError)
	} else if !ctEqual(verify, c.expectFin[:hs]) {
		return alertError(tlsraw.AlertDecryptError)
	}
	clear(c.expectFin[:])
	err := c.setKeys(&c.in, c.aeadIn, c.clientAP[:hs])
	clear(c.clientAP[:])
	c.ks.Zeroize()
	return err
}

// keyChangeBoundary returns an error if handshake data follows the message just
// read, which changes keys. RFC 8446 5.1 requires a key change to end its record.
func (c *Conn) keyChangeBoundary() error {
	if c.hsOff != c.hsEnd {
		return alertError(tlsraw.AlertUnexpectedMessage)
	}
	return nil
}

// setKeys derives the record keys of a traffic secret and installs them on hc.
// The key and IV stay inside the key schedule and the record layer, so a failed
// handshake leaves no copy of either in Conn for Zeroize to miss.
func (c *Conn) setKeys(hc *tlsraw.HalfConn, aead lcrypto.AEADCipher, secret []byte) error {
	return c.ks.InstallKeys(hc, aead, c.suite.KeyLen, secret)
}

// readHandshake returns the next handshake message, header included, which must be of type want.
// The message points into hbuf and is valid until the next call.
func (c *Conn) readHandshake(want tlsraw.HandshakeType) ([]byte, error) {
	for {
		if pending := c.hbuf[c.hsOff:c.hsEnd]; len(pending) >= tlsraw.SizeHeaderHandshake {
			end := tlsraw.SizeHeaderHandshake + (int(pending[1])<<16 | int(pending[2])<<8 | int(pending[3]))
			if end > len(c.hbuf) {
				return nil, lneto.ErrShortBuffer
			} else if end <= len(pending) {
				c.hsOff += end
				if tlsraw.HandshakeType(pending[0]) != want {
					return nil, alertError(tlsraw.AlertUnexpectedMessage)
				}
				return pending[:end], nil
			}
		}
		ct, content, err := c.readRecord()
		if err != nil {
			return nil, err
		}
		switch ct {
		case tlsraw.ContentTypeHandshake:
			c.hsEnd = copy(c.hbuf, c.hbuf[c.hsOff:c.hsEnd])
			c.hsOff = 0
			if len(content) == 0 {
				return nil, alertError(tlsraw.AlertUnexpectedMessage)
			} else if len(content) > len(c.hbuf)-c.hsEnd {
				return nil, lneto.ErrShortBuffer
			}
			c.hsEnd += copy(c.hbuf[c.hsEnd:], content)
		case tlsraw.ContentTypeAlert:
			if err = c.handleAlert(content); err != nil {
				return nil, err
			}
			return nil, io.ErrUnexpectedEOF // Peer closed during the handshake.
		default:
			return nil, alertError(tlsraw.AlertUnexpectedMessage)
		}
	}
}

// readApp reads a record after the handshake. Application data is left in c.app.
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
	}
	// TODO: KeyUpdate, which RFC 8446 4.6.3 requires.
	return alertError(tlsraw.AlertUnexpectedMessage)
}

// readRecord reads one record and returns its real content type and content,
// decrypted once the peer's keys are installed. content points into rbuf and
// is valid until the next call.
func (c *Conn) readRecord() (tlsraw.ContentType, []byte, error) {
	dropped := 0 // ChangeCipherSpec records dropped in this call.
	for {
		hdr := c.rbuf[:tlsraw.SizeHeaderRecord]
		if _, err := io.ReadFull(c.rw, hdr); err != nil {
			if err == io.EOF {
				// The peer ended the stream where a record was due. Reporting io.EOF
				// would make a truncated stream indistinguishable from the close_notify
				// of RFC 8446 6.1, which is the only clean end of a connection.
				err = io.ErrUnexpectedEOF
			}
			return 0, nil, err
		}
		n := int(binary.BigEndian.Uint16(hdr[3:5]))
		if n > tlsraw.MaxCiphertext {
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
			// Middlebox compatibility record, RFC 8446 5. Dropped between our flight and the peer's Finished.
			if c.state != stateHandshake || !c.in.HasKeys() || n != 1 || content[0] != 1 {
				return 0, nil, alertError(tlsraw.AlertUnexpectedMessage)
			}
			// A dropped record hands nothing back to the caller, so an uncapped run of
			// them keeps this call from ever returning. RFC 8446 D.4 has the peer send one.
			dropped++
			if dropped > maxDroppedRecords {
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
		if len(content) > tlsraw.MaxPlaintext {
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
		return nil // Followed by close_notify, RFC 8446 6.1.
	default:
		return peerAlertError(desc)
	}
}

// writeRecord sends content as one record, encrypted once keys are installed.
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

// encoder returns an encoder that writes records to wbuf.
func (c *Conn) encoder() tlsraw.Encoder {
	var e tlsraw.Encoder
	e.Reset(c.wbuf, 0)
	return e
}

// flush sends the records written by e.
func (c *Conn) flush(e *tlsraw.Encoder) error {
	if e.Err() != nil {
		return e.Err()
	}
	_, err := c.rw.Write(c.wbuf[:e.Len()])
	return err
}

// fail sends the alert for err, marks the connection unusable and wipes its secrets.
func (c *Conn) fail(err error) error {
	switch a := err.(type) {
	case peerAlertError:
		// Never answer an alert.
	case alertError:
		c.writeAlert(tlsraw.AlertDescription(a)) // Best effort.
	default:
		// A stream that ended where a record was due leaves nobody to read an alert,
		// and the write has no deadline of its own to fall back on.
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			c.writeAlert(tlsraw.AlertInternalError)
		}
	}
	c.Zeroize()
	c.state = stateFailed
	return err
}

// legacyScheme reports whether s is SHA-1 or RSASSA-PKCS1-v1_5 based, which
// TLS 1.3 forbids in CertificateVerify, RFC 8446 4.2.3.
func legacyScheme(s uint16) bool {
	hash, sig := s>>8, s&0xff
	return hash == 0x02 || (sig == 0x01 && hash <= 0x06)
}

// hasUint16 reports whether the list of big-endian uint16 values contains v.
func hasUint16(list []byte, v uint16) bool {
	for i := 0; i+1 < len(list); i += 2 {
		if binary.BigEndian.Uint16(list[i:]) == v {
			return true
		}
	}
	return false
}

// ctEqual compares a and b in time independent of their contents.
// crypto/subtle is not imported to avoid linking Go's crypto packages.
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
	internal.SliceReuse(&buf, n)
	return buf[:n]
}

// alertError is a fatal error reported to the peer with an alert.
type alertError tlsraw.AlertDescription

func (a alertError) Error() string { return "tls: sent alert " + strconv.Itoa(int(a)) }

// peerAlertError is a fatal alert received from the peer.
type peerAlertError tlsraw.AlertDescription

func (a peerAlertError) Error() string { return "tls: received alert " + strconv.Itoa(int(a)) }
