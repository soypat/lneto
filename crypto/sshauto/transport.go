// Package sshauto implements the server side of the SSH transport layer,
// RFC 4253, on top of [sshraw]: version exchange, key exchange, rekeying and
// packet protection. User authentication and the connection protocol are left
// to the layers above, which exchange payloads through [Transport.ReadPacket]
// and [Transport.WritePacket].
//
// This package is not externally audited. Use only if you understand the risks.
package sshauto

import (
	"hash"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/lcrypto"
	"github.com/soypat/lneto/crypto/sshraw"
	"github.com/soypat/lneto/internal"
)

// Aliases so that users outside lneto can name the capability interfaces,
// which live in an internal package.
type (
	LAEADCipher = lcrypto.AEADCipher
	LExchanger  = lcrypto.Exchanger
)

// HostKey is the server's host key, the SSH counterpart of the TLS credential.
// It must be safe for concurrent use: [Config] shares it between connections.
type HostKey interface {
	// Algorithm returns the public key algorithm name, i.e. "ssh-ed25519".
	Algorithm() string
	// PublicKey writes the public key blob K_S in SSH wire format into dst,
	// RFC 4253 6.6. If dst is too short it returns the required length with
	// [io.ErrShortBuffer].
	PublicKey(dst []byte) (n int, err error)
	// Sign writes the signature of msg into sig, without the algorithm name
	// that wraps it on the wire: 64 bytes for ssh-ed25519 (RFC 8709 6), the
	// mpints r and s for ecdsa-sha2-* (RFC 5656 3.1.2). msg is the exchange
	// hash H; implementations hash it as their algorithm requires, ssh-ed25519
	// signs it whole.
	Sign(sig, msg []byte) (n int, err error)
}

// KeyExchange describes an ephemeral key exchange method, RFC 5656 4.
type KeyExchange struct {
	Name           string // Method name, i.e. [sshraw.KexCurve25519SHA256].
	ClientShareLen int    // Length of the client's Q_C.
	ServerShareLen int    // Length of the server's Q_S (KEM ciphertext for ML-KEM).
	SharedLen      int    // Shared secret length.
	NewExchanger   func() LExchanger
	// NewHash returns the method's hash. Each call must return a fresh instance.
	NewHash func() hash.Hash
	// HashedSecret is true for methods whose K is the string HASH(shared
	// secret), such as mlkem768x25519-sha256, and false for those whose K is
	// the shared secret as an mpint, such as curve25519-sha256.
	HashedSecret bool
}

// Cipher describes a packet cipher. Only the AEAD ciphers
// aes128-gcm@openssh.com and aes256-gcm@openssh.com fit: 12 byte nonce, 16 byte tag.
type Cipher struct {
	Name    string // Cipher name, i.e. [sshraw.CipherAES256GCM].
	KeyLen  int    // Length of the key passed to AEADCipher.Rekey.
	NewAEAD func() LAEADCipher
}

// Config stores the server configuration and may be reused across
// connections. Configure copies it, so modifying it afterwards does not affect
// configured transports. The copy is shallow: the host keys, the entropy
// source and the constructors are shared between connections, so they must be
// safe for concurrent use.
type Config struct {
	// Rand is the entropy source for cookies, padding and key shares. It must
	// be safe for concurrent use, as crypto/rand.Reader is.
	Rand io.Reader
	// Software is the softwareversion of the identification string, RFC 4253 4.2.
	Software string
	// KeyExchanges, Ciphers and HostKeys list the supported algorithms in
	// preference order. The client's preference wins, RFC 4253 7.1.
	KeyExchanges []KeyExchange
	Ciphers      []Cipher
	HostKeys     []HostKey
}

const (
	sizeKexInit       = 4096 // Largest client KEXINIT payload accepted. OpenSSH sends about 1.5KiB.
	sizeServerKexInit = 1024 // Room for our own KEXINIT payload.
	maxKeyShare       = 1216 // Largest share of a supported method: the mlkem768x25519 client share.
	maxShared         = 64   // Largest shared secret, the ML-KEM and X25519 secrets together.
	maxKeyLen         = 32   // Largest AEAD key: AES-256.
	sigSlack          = 128  // Room kept past the host key signature for padding, tag and SSH_MSG_NEWKEYS.
)

type connState uint8

const (
	stateIdle      connState = iota // Open not called.
	stateHandshake                  // Open called, first key exchange not complete.
	stateConnected                  // First key exchange complete.
	stateFailed                     // Fatal error, secrets wiped.
	stateClosed                     // Closed by Close or Disconnect.
)

// Transport is the server side of an SSH transport over a reliable byte stream.
// It never initiates a key exchange; it takes part in those the client starts.
//
// Transport is not safe for concurrent use: a key exchange started by the peer
// runs within ReadPacket, so writes must not interleave with it.
type Transport struct {
	rw     net.Conn
	state  connState
	strict bool // Strict key exchange agreed, the Terrapin countermeasure.
	sentKI bool // Our KEXINIT of the ongoing key exchange is sent.

	ks      sshraw.KeySchedule
	in, out sshraw.HalfConn
	vld     lneto.Validator
	lastSeq uint32 // Sequence number of the last packet read.

	// Instances built by the constructors of Config, kept across Open so a
	// reused Transport does not allocate. Order maps to Config's slices.
	instanceExch            []LExchanger
	instanceHash            []hash.Hash
	instanceIn, instanceOut []LAEADCipher
	cfg                     Config // Snapshot taken by Configure. Its slices are owned by Transport.

	kex                 *KeyExchange
	cipherIn, cipherOut *Cipher
	hostKey             HostKey
	exch                LExchanger
	aeadIn, aeadOut     LAEADCipher

	// Name-lists of our KEXINIT, built by Configure. kexList ends in
	// [sshraw.KexStrictServer], offered on the first key exchange only.
	kexList, hostKeyList, cipherList []byte
	kexListLen                       int // Length of kexList without the strict marker.

	rbuf       []byte // Received bytes; rbuf[rOff:rEnd] is not yet consumed.
	rOff, rEnd int
	wbuf       []byte // Outgoing packets.
	ic         []byte // Client KEXINIT payload I_C of the ongoing key exchange.
	is         []byte // Our KEXINIT payload I_S of the ongoing key exchange.
	vc         [sshraw.MaxIdentLen]byte
	vs         [sshraw.MaxIdentLen]byte // Our identification string, CR LF included.
	vcLen      uint8
	vsLen      uint8
	shared     [maxShared]byte // Key exchange output, of kex.SharedLen bytes.
}

// Configure validates cfg and takes it as the configuration of the connections
// opened from here on. It wipes the secrets and the instances of the previous
// configuration, so it is refused while a connection is live.
func (t *Transport) Configure(cfg Config) error {
	if t.state == stateHandshake || t.state == stateConnected {
		return lneto.ErrBadState
	} else if cfg.Rand == nil || len(cfg.KeyExchanges) == 0 || len(cfg.Ciphers) == 0 || len(cfg.HostKeys) == 0 {
		return lneto.ErrInvalidConfig
	}
	var e sshraw.Encoder
	e.Reset(t.vs[:], 0)
	if e.Ident(cfg.Software, ""); e.Err() != nil {
		return lneto.ErrInvalidConfig
	}
	vsLen := e.Len()
	for _, k := range cfg.KeyExchanges {
		if !validName(k.Name) || k.NewExchanger == nil || k.NewHash == nil {
			return lneto.ErrInvalidConfig
		} else if k.ClientShareLen <= 0 || k.ServerShareLen <= 0 || k.SharedLen <= 0 {
			return lneto.ErrInvalidConfig
		} else if k.ClientShareLen > maxKeyShare || k.ServerShareLen > maxKeyShare || k.SharedLen > maxShared {
			return lneto.ErrInvalidConfig
		}
	}
	for _, c := range cfg.Ciphers {
		if !validName(c.Name) || c.NewAEAD == nil || c.KeyLen <= 0 || c.KeyLen > maxKeyLen {
			return lneto.ErrInvalidConfig
		}
	}
	for _, h := range cfg.HostKeys {
		if h == nil || !validName(h.Algorithm()) {
			return lneto.ErrInvalidConfig
		}
	}
	kexList := joinNames(t.kexList, len(cfg.KeyExchanges), func(i int) string { return cfg.KeyExchanges[i].Name })
	kexListLen := len(kexList)
	kexList = append(append(kexList, ','), sshraw.KexStrictServer...)
	hostKeyList := joinNames(t.hostKeyList, len(cfg.HostKeys), func(i int) string { return cfg.HostKeys[i].Algorithm() })
	cipherList := joinNames(t.cipherList, len(cfg.Ciphers), func(i int) string { return cfg.Ciphers[i].Name })
	// KEXINIT: type, cookie, 10 name-lists with their lengths, bool and reserved uint32.
	if 1+sshraw.SizeCookie+10*4+len(kexList)+len(hostKeyList)+2*len(cipherList)+2*len(sshraw.CompressionNone)+1+4 > sizeServerKexInit {
		return lneto.ErrInvalidConfig
	}

	t.Zeroize()
	t.zeroizeInstances()
	t.vsLen = uint8(vsLen)
	t.kexList, t.kexListLen, t.hostKeyList, t.cipherList = kexList, kexListLen, hostKeyList, cipherList
	kexs, ciphers, hostKeys := t.cfg.KeyExchanges, t.cfg.Ciphers, t.cfg.HostKeys // Backing arrays owned by t.
	t.cfg = cfg
	internal.SliceReuse(&kexs, len(cfg.KeyExchanges))
	internal.SliceReuse(&ciphers, len(cfg.Ciphers))
	internal.SliceReuse(&hostKeys, len(cfg.HostKeys))
	t.cfg.KeyExchanges = append(kexs, cfg.KeyExchanges...)
	t.cfg.Ciphers = append(ciphers, cfg.Ciphers...)
	t.cfg.HostKeys = append(hostKeys, cfg.HostKeys...)
	sliceReuseZero(&t.instanceExch, len(cfg.KeyExchanges))
	sliceReuseZero(&t.instanceHash, len(cfg.KeyExchanges))
	sliceReuseZero(&t.instanceIn, len(cfg.Ciphers))
	sliceReuseZero(&t.instanceOut, len(cfg.Ciphers))
	t.kex, t.cipherIn, t.cipherOut, t.hostKey = nil, nil, nil, nil
	t.exch, t.aeadIn, t.aeadOut = nil, nil, nil
	return nil
}

// validName reports whether name is a single algorithm name and not one of
// the pseudo algorithms, which are never negotiated.
func validName(name string) bool {
	if strings.IndexByte(name, ',') >= 0 || sshraw.ValidateNameList([]byte(name)) != nil || name == "" {
		return false
	}
	switch name {
	case sshraw.KexStrictClient, sshraw.KexStrictServer, sshraw.ExtInfoClient, sshraw.ExtInfoServer:
		return false
	}
	return true
}

// joinNames writes n names as a name-list into dst's backing array.
func joinNames(dst []byte, n int, name func(int) string) []byte {
	dst = dst[:0]
	for i := range n {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, name(i)...)
	}
	return dst
}

// zeroizeInstances wipes every cipher and exchanger kept for the current config.
func (t *Transport) zeroizeInstances() {
	for i := range t.instanceIn {
		if t.instanceIn[i] != nil {
			t.instanceIn[i].Zeroize()
			t.instanceOut[i].Zeroize()
		}
	}
	for i := range t.instanceExch {
		if t.instanceExch[i] != nil {
			t.instanceExch[i].Zeroize()
			t.instanceHash[i].Reset()
		}
	}
}

func sliceReuseZero[T any](buf *[]T, n int) {
	clear((*buf)[:len(*buf)])
	internal.SliceReuse(buf, n)
	*buf = (*buf)[:n]
}

// Open receives a newly established connection (no data sent or received) and
// prepares to run the server side of the transport over it. It wipes the
// previous connection's secrets and reuses its buffers.
func (t *Transport) Open(conn net.Conn, isClient bool) error {
	if conn == nil {
		return lneto.ErrInvalidConfig
	} else if isClient {
		return lneto.ErrUnsupported // TODO: client side.
	} else if len(t.cfg.KeyExchanges) == 0 {
		return lneto.ErrBadState // Configure not called.
	}
	t.Zeroize()
	t.rbuf = reuse(t.rbuf, sshraw.MaxPacket)
	t.wbuf = reuse(t.wbuf, sshraw.MaxPacket)
	t.ic = reuse(t.ic, sizeKexInit)[:0]
	t.is = reuse(t.is, sizeServerKexInit)[:0]
	t.rw = conn
	t.state = stateHandshake
	t.strict, t.sentKI = false, false
	t.lastSeq = 0
	t.vld.ResetErr()
	return nil
}

// Handshake exchanges identification strings and runs the first key exchange
// if they have not run yet. ReadPacket and WritePacket call it.
func (t *Transport) Handshake() error {
	switch t.state {
	case stateConnected:
		return nil
	case stateHandshake:
	default:
		return lneto.ErrBadState
	}
	if err := t.serverHandshake(); err != nil {
		return t.fail(err)
	}
	t.state = stateConnected
	return nil
}

// ReadPacket returns the payload of the next packet for the layers above,
// message type byte first. It handles the transport messages: IGNORE, DEBUG
// and UNIMPLEMENTED are dropped and a key exchange started by the client runs
// to completion. The payload points into an internal buffer and is valid
// until the next call.
//
// ReadPacket returns [io.EOF] when the stream ends at a packet boundary and
// [PeerDisconnectError] after SSH_MSG_DISCONNECT. SSH ends connections cleanly
// in the connection protocol, so the transport cannot tell a truncated stream
// from a finished one at a packet boundary; the layers above must.
func (t *Transport) ReadPacket() ([]byte, error) {
	if err := t.Handshake(); err != nil {
		return nil, err
	}
	for {
		payload, err := t.readPacket()
		if err != nil {
			return nil, t.fail(err)
		}
		switch typ := sshraw.MsgType(payload[0]); {
		case typ == sshraw.MsgDisconnect:
			return nil, t.fail(peerDisconnect(payload))
		case typ == sshraw.MsgIgnore || typ == sshraw.MsgDebug || typ == sshraw.MsgUnimplemented:
			continue
		case typ == sshraw.MsgKexInit:
			if err = t.keyExchange(payload); err != nil {
				return nil, t.fail(err)
			}
			continue
		case typ >= sshraw.MsgKexInit && typ < sshraw.MsgUserauthRequest:
			// Key exchange messages outside a key exchange.
			return nil, t.fail(DisconnectError(sshraw.DisconnectProtocolError))
		}
		return payload, nil
	}
}

// WritePacket sends payload, message type byte first, as one packet. It
// refuses the messages the transport sends itself: DISCONNECT, use
// [Transport.Disconnect], and those of key exchange.
func (t *Transport) WritePacket(payload []byte) error {
	if err := t.Handshake(); err != nil {
		return err
	} else if len(payload) == 0 || len(payload) > sshraw.MaxPayload {
		return lneto.ErrInvalidLengthField
	}
	typ := sshraw.MsgType(payload[0])
	if typ == 0 || typ == sshraw.MsgDisconnect || (typ >= sshraw.MsgKexInit && typ < sshraw.MsgUserauthRequest) {
		return lneto.ErrInvalidField
	}
	e := t.encoder()
	start := e.StartPacket(typ)
	e.Bytes(payload[1:])
	if err := t.flush(&e, start); err != nil {
		return t.fail(err)
	}
	return nil
}

// WriteUnimplemented answers the packet last returned by ReadPacket with
// SSH_MSG_UNIMPLEMENTED, which RFC 4253 11.4 requires for unrecognized messages.
func (t *Transport) WriteUnimplemented() error {
	if t.state != stateConnected {
		return lneto.ErrBadState
	}
	e := t.encoder()
	start := e.StartPacket(sshraw.MsgUnimplemented)
	e.Uint32(t.lastSeq)
	if err := t.flush(&e, start); err != nil {
		return t.fail(err)
	}
	return nil
}

// SessionID returns the session identifier, the exchange hash of the first key
// exchange, which user authentication signatures cover. It is empty before the
// handshake completes.
func (t *Transport) SessionID() []byte { return t.ks.SessionID() }

// Algorithms returns the names of the algorithms negotiated by the last key
// exchange, empty before the first.
func (t *Transport) Algorithms() (kex, hostKey, cipherIn, cipherOut string) {
	if t.kex == nil || t.hostKey == nil || t.cipherIn == nil || t.cipherOut == nil {
		return "", "", "", ""
	}
	return t.kex.Name, t.hostKey.Algorithm(), t.cipherIn.Name, t.cipherOut.Name
}

// Disconnect sends SSH_MSG_DISCONNECT with reason and desc and wipes the
// secrets. The underlying connection is left open; Close closes it.
func (t *Transport) Disconnect(reason sshraw.DisconnectReason, desc string) error {
	if t.state != stateHandshake && t.state != stateConnected {
		return lneto.ErrBadState
	}
	err := t.writeDisconnect(reason, desc)
	t.Zeroize()
	t.state = stateClosed
	return err
}

// Close sends SSH_MSG_DISCONNECT if connected, wipes secrets and closes the
// underlying connection.
func (t *Transport) Close() error {
	var err error
	if t.state == stateConnected {
		err = t.writeDisconnect(sshraw.DisconnectByApplication, "")
	}
	t.Zeroize()
	t.state = stateClosed
	if t.rw != nil {
		if cerr := t.rw.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// Zeroize wipes all secrets and buffered data. Open must be called before reuse.
func (t *Transport) Zeroize() {
	t.ks.Zeroize()
	t.in.Zeroize()
	t.out.Zeroize()
	if t.aeadIn != nil {
		t.aeadIn.Zeroize()
	}
	if t.aeadOut != nil {
		t.aeadOut.Zeroize()
	}
	if t.exch != nil {
		t.exch.Zeroize()
	}
	clear(t.shared[:])
	clear(t.rbuf)
	clear(t.wbuf)
	clear(t.ic[:cap(t.ic)])
	clear(t.is[:cap(t.is)])
	clear(t.vc[:])
	t.vcLen = 0
	t.rOff, t.rEnd = 0, 0
}

func (t *Transport) serverHandshake() error {
	// Our identification string and KEXINIT go out together, as OpenSSH does.
	e := t.encoder()
	e.Bytes(t.vs[:t.vsLen])
	if err := t.writeKexInit(&e); err != nil {
		return err
	} else if err = t.write(&e); err != nil {
		return err
	}
	if err := t.readIdent(); err != nil {
		return err
	}
	payload, err := t.readKexPacket()
	if err != nil {
		return err
	} else if sshraw.MsgType(payload[0]) != sshraw.MsgKexInit {
		return DisconnectError(sshraw.DisconnectProtocolError)
	}
	return t.keyExchange(payload)
}

// readIdent reads the client's identification string. Unlike a server's, it
// comes with no lines preceding it, RFC 4253 4.2.
func (t *Transport) readIdent() error {
	for {
		line, n, err := sshraw.NextIdentLine(t.rbuf[t.rOff:t.rEnd])
		if err == lneto.ErrTruncatedFrame {
			if err = t.fill(t.rEnd - t.rOff + 1); err != nil {
				return err
			}
			continue
		} else if err != nil {
			return DisconnectError(sshraw.DisconnectProtocolError)
		}
		t.rOff += n
		if _, _, err = sshraw.ParseIdent(line); err == lneto.ErrUnsupported {
			return DisconnectError(sshraw.DisconnectProtocolVersionNotSupported)
		} else if err != nil {
			return DisconnectError(sshraw.DisconnectProtocolError)
		}
		t.vcLen = uint8(copy(t.vc[:], line))
		return nil
	}
}

// writeKexInit writes our KEXINIT packet to e and keeps its payload as I_S.
func (t *Transport) writeKexInit(e *sshraw.Encoder) error {
	var k sshraw.Encoder
	k.Reset(t.is[:cap(t.is)], 0)
	k.Uint8(uint8(sshraw.MsgKexInit))
	cookie := k.Reserve(sshraw.SizeCookie)
	if cookie == nil {
		return k.Err()
	} else if _, err := io.ReadFull(t.cfg.Rand, cookie); err != nil {
		return err
	}
	kexList := t.kexList
	if len(t.ks.SessionID()) != 0 {
		kexList = kexList[:t.kexListLen] // Strict key exchange is agreed on the first key exchange only.
	}
	k.String(kexList)
	k.String(t.hostKeyList)
	k.String(t.cipherList)
	k.String(t.cipherList)
	k.String(nil) // MACs: the AEAD tag is the MAC, so none is negotiated.
	k.String(nil)
	k.Str(sshraw.CompressionNone)
	k.Str(sshraw.CompressionNone)
	k.String(nil) // Languages.
	k.String(nil)
	k.Bool(false) // first_kex_packet_follows.
	k.Uint32(0)
	if k.Err() != nil {
		return k.Err()
	}
	t.is = t.is[:k.Len()]
	start := e.StartPacket(sshraw.MsgKexInit)
	e.Bytes(t.is[1:])
	t.sentKI = true
	return t.seal(e, start)
}

// keyExchange runs a key exchange started by the client's KEXINIT payload,
// RFC 4253 7, and installs the keys it derives.
func (t *Transport) keyExchange(clientKexInit []byte) error {
	if len(clientKexInit) > cap(t.ic) {
		return DisconnectError(sshraw.DisconnectKeyExchangeFailed)
	}
	t.ic = append(t.ic[:0], clientKexInit...) // I_C outlives the packets read below.
	var msg sshraw.KexInitMsg
	if _, err := msg.Decode(t.ic, &t.vld); err != nil {
		t.vld.ResetErr()
		return DisconnectError(sshraw.DisconnectProtocolError)
	}
	initial := len(t.ks.SessionID()) == 0
	if initial && sshraw.HasName(msg.KexAlgorithms(), sshraw.KexStrictClient) {
		t.strict = true
		if t.in.Seq() != 1 {
			return DisconnectError(sshraw.DisconnectProtocolError) // KEXINIT must be the client's first packet.
		}
	}
	if !t.sentKI {
		e := t.encoder()
		if err := t.writeKexInit(&e); err != nil {
			return err
		} else if err = t.write(&e); err != nil {
			return err
		}
	}
	if err := t.negotiate(&msg); err != nil {
		return err
	}
	// A client guessing the method sends its first key exchange packet right
	// away. A wrong guess is ignored, RFC 4253 7.
	kexGuess, _ := sshraw.NextName(msg.KexAlgorithms())
	hostKeyGuess, _ := sshraw.NextName(msg.HostKeyAlgorithms())
	wrongGuess := msg.FirstKexPacketFollows() &&
		(string(kexGuess) != t.cfg.KeyExchanges[0].Name || string(hostKeyGuess) != t.cfg.HostKeys[0].Algorithm())

	payload, err := t.readKexPacket()
	if err == nil && wrongGuess {
		payload, err = t.readKexPacket()
	}
	if err != nil {
		return err
	}
	qc, err := sshraw.ParseKexECDHInit(payload)
	if err != nil {
		return DisconnectError(sshraw.DisconnectProtocolError)
	} else if len(qc) != t.kex.ClientShareLen {
		return DisconnectError(sshraw.DisconnectKeyExchangeFailed)
	}
	if err = t.writeKexReply(qc); err != nil {
		return err
	}

	payload, err = t.readKexPacket()
	if err != nil {
		return err
	} else if len(payload) != 1 || sshraw.MsgType(payload[0]) != sshraw.MsgNewKeys {
		return DisconnectError(sshraw.DisconnectProtocolError)
	}
	if t.strict {
		t.in.ResetSeq()
	}
	err = t.ks.InstallKeys(&t.in, t.aeadIn, t.cipherIn.KeyLen, 'C', 'A')
	t.ks.WipeExchange()
	t.sentKI = false
	return err
}

// negotiate picks the algorithms of the key exchange, client preference first,
// and readies their instances.
func (t *Transport) negotiate(msg *sshraw.KexInitMsg) error {
	kexIdx := pick(msg.KexAlgorithms(), len(t.cfg.KeyExchanges), func(i int) string { return t.cfg.KeyExchanges[i].Name })
	hkIdx := pick(msg.HostKeyAlgorithms(), len(t.cfg.HostKeys), func(i int) string { return t.cfg.HostKeys[i].Algorithm() })
	cfg := t.cfg.Ciphers
	inIdx := pick(msg.CiphersClientToServer(), len(cfg), func(i int) string { return cfg[i].Name })
	outIdx := pick(msg.CiphersServerToClient(), len(cfg), func(i int) string { return cfg[i].Name })
	if kexIdx < 0 || hkIdx < 0 || inIdx < 0 || outIdx < 0 ||
		!sshraw.HasName(msg.CompressionClientToServer(), sshraw.CompressionNone) ||
		!sshraw.HasName(msg.CompressionServerToClient(), sshraw.CompressionNone) {
		return DisconnectError(sshraw.DisconnectKeyExchangeFailed)
	}
	kex := &t.cfg.KeyExchanges[kexIdx]
	if t.instanceExch[kexIdx] == nil {
		t.instanceExch[kexIdx] = kex.NewExchanger()
		t.instanceHash[kexIdx] = kex.NewHash()
	}
	if err := t.ks.UseHash(t.instanceHash[kexIdx]); err != nil {
		return err
	}
	for _, i := range [2]int{inIdx, outIdx} {
		if t.instanceIn[i] == nil {
			t.instanceIn[i] = cfg[i].NewAEAD()
			t.instanceOut[i] = cfg[i].NewAEAD()
		}
	}
	t.kex, t.exch = kex, t.instanceExch[kexIdx]
	t.hostKey = t.cfg.HostKeys[hkIdx]
	t.cipherIn, t.aeadIn = &cfg[inIdx], t.instanceIn[inIdx]
	t.cipherOut, t.aeadOut = &cfg[outIdx], t.instanceOut[outIdx]
	return nil
}

// pick returns the index of our n names of the first name of list, the
// client's, that we support, or -1 if none.
func pick(list []byte, n int, name func(int) string) int {
	for len(list) > 0 {
		var got []byte
		got, list = sshraw.NextName(list)
		for i := range n {
			if string(got) == name(i) {
				return i
			}
		}
	}
	return -1
}

// writeKexReply runs the server side of the ECDH exchange of RFC 5656 4:
// SSH_MSG_KEX_ECDH_REPLY and then SSH_MSG_NEWKEYS, after which our keys change.
// qc points into rbuf, so nothing is read until it is hashed.
func (t *Transport) writeKexReply(qc []byte) error {
	e := t.encoder()
	start := e.StartPacket(sshraw.MsgKexECDHReply)
	ksOff := e.Open(4)
	n, err := t.hostKey.PublicKey(e.Rest())
	if err != nil {
		return err
	}
	e.Advance(n)
	e.Close(ksOff, 4)
	qsOff := e.Open(4)
	share := e.Reserve(t.kex.ServerShareLen)
	if share == nil {
		return e.Err()
	}
	sharedLen := t.kex.SharedLen
	nShare, nShared, err := t.exch.ServerSharedRekey(share, t.shared[:sharedLen], qc, t.cfg.Rand)
	if err != nil {
		return DisconnectError(sshraw.DisconnectKeyExchangeFailed)
	} else if nShare != len(share) || nShared != sharedLen {
		return lneto.ErrInvalidConfig // The Exchanger disagrees with its KeyExchange.
	}
	e.Close(qsOff, 4)
	err = t.ks.SetSecret(t.shared[:sharedLen], t.kex.HashedSecret)
	clear(t.shared[:])
	if err != nil {
		return err
	}
	t.ks.StartExchange()
	t.ks.HashString(t.vc[:t.vcLen])
	t.ks.HashString(t.vs[:t.vsLen-2]) // Without CR LF.
	t.ks.HashString(t.ic)
	t.ks.HashString(t.is)
	t.ks.HashString(t.wbuf[ksOff : ksOff+n])
	t.ks.HashString(qc)
	t.ks.HashString(share)
	t.ks.FinishExchange()

	sigOff := e.Open(4)
	e.Str(t.hostKey.Algorithm())
	innerOff := e.Open(4)
	dst := e.Rest()
	dst = dst[:max(0, len(dst)-sigSlack)]
	if n, err = t.hostKey.Sign(dst, t.ks.ExchangeHash()); err != nil {
		return err
	}
	e.Advance(n)
	e.Close(innerOff, 4)
	e.Close(sigOff, 4)
	if err = t.seal(&e, start); err != nil {
		return err
	}
	start = e.StartPacket(sshraw.MsgNewKeys)
	if err = t.seal(&e, start); err != nil {
		return err
	} else if err = t.write(&e); err != nil {
		return err
	}
	if t.strict {
		t.out.ResetSeq()
	}
	return t.ks.InstallKeys(&t.out, t.aeadOut, t.cipherOut.KeyLen, 'D', 'B')
}

// readKexPacket reads a packet during a key exchange, dropping IGNORE, DEBUG
// and UNIMPLEMENTED unless strict key exchange forbids them.
func (t *Transport) readKexPacket() ([]byte, error) {
	for {
		payload, err := t.readPacket()
		if err != nil {
			return nil, err
		}
		switch sshraw.MsgType(payload[0]) {
		case sshraw.MsgIgnore, sshraw.MsgDebug, sshraw.MsgUnimplemented:
			if t.strict && len(t.ks.SessionID()) == 0 {
				return nil, DisconnectError(sshraw.DisconnectProtocolError) // Strict: nothing else in the first key exchange.
			}
			continue
		case sshraw.MsgDisconnect:
			return nil, peerDisconnect(payload)
		}
		return payload, nil
	}
}

// readPacket reads and opens the next packet and returns its payload, which
// points into rbuf and is valid until the next read.
func (t *Transport) readPacket() ([]byte, error) {
	if err := t.fill(4); err != nil {
		return nil, err
	}
	n, err := t.in.WireLen(t.rbuf[t.rOff:t.rEnd])
	if err != nil {
		return nil, DisconnectError(sshraw.DisconnectProtocolError)
	} else if err = t.fill(n); err != nil {
		return nil, err
	}
	pkt := t.rbuf[t.rOff : t.rOff+n]
	t.rOff += n
	t.lastSeq = t.in.Seq()
	pf, err := t.in.Open(pkt)
	if err != nil {
		if t.in.HasKeys() {
			return nil, DisconnectError(sshraw.DisconnectMACError)
		}
		return nil, DisconnectError(sshraw.DisconnectProtocolError)
	}
	return pf.Payload(), nil
}

// fill reads until n bytes are buffered. It returns [io.EOF] if the stream
// ends with nothing buffered and [io.ErrUnexpectedEOF] if it ends mid packet.
func (t *Transport) fill(n int) error {
	for t.rEnd-t.rOff < n {
		if len(t.rbuf)-t.rOff < n {
			t.rEnd = copy(t.rbuf, t.rbuf[t.rOff:t.rEnd])
			t.rOff = 0
		}
		m, err := t.rw.Read(t.rbuf[t.rEnd:])
		t.rEnd += m
		if err != nil && t.rEnd-t.rOff < n {
			if err == io.EOF && t.rEnd != t.rOff {
				err = io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

// encoder returns an encoder that writes packets to wbuf.
func (t *Transport) encoder() sshraw.Encoder {
	var e sshraw.Encoder
	e.Reset(t.wbuf, 0)
	return e
}

// seal pads the packet started at start and protects it in place.
func (t *Transport) seal(e *sshraw.Encoder, start int) error {
	block, aad := sshraw.MinBlockSize, false
	if t.out.HasKeys() {
		block, aad = 16, true
	}
	pkt := e.EndPacket(start, block, aad, t.cfg.Rand)
	if pkt == nil {
		return e.Err()
	}
	sealed, err := t.out.Seal(pkt[:len(pkt):len(t.wbuf)-start])
	if err != nil {
		return err
	}
	e.Advance(len(sealed) - len(pkt))
	return e.Err()
}

// flush seals the packet started at start and sends it.
func (t *Transport) flush(e *sshraw.Encoder, start int) error {
	if err := t.seal(e, start); err != nil {
		return err
	}
	return t.write(e)
}

// write sends what e wrote.
func (t *Transport) write(e *sshraw.Encoder) error {
	if e.Err() != nil {
		return e.Err()
	}
	_, err := t.rw.Write(t.wbuf[:e.Len()])
	return err
}

func (t *Transport) writeDisconnect(reason sshraw.DisconnectReason, desc string) error {
	e := t.encoder()
	start := e.StartPacket(sshraw.MsgDisconnect)
	e.Uint32(uint32(reason))
	e.Str(desc)
	e.Str("") // Language tag.
	return t.flush(&e, start)
}

// fail sends the disconnect for err, marks the transport unusable and wipes its secrets.
func (t *Transport) fail(err error) error {
	switch d := err.(type) {
	case PeerDisconnectError:
		// Never answer a disconnect.
	case DisconnectError:
		t.writeDisconnect(sshraw.DisconnectReason(d), "") // Best effort.
	default:
		// A stream that ended leaves nobody to read a disconnect.
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			t.writeDisconnect(sshraw.DisconnectByApplication, "")
		}
	}
	t.Zeroize()
	t.state = stateFailed
	return err
}

func peerDisconnect(payload []byte) error {
	reason, _, err := sshraw.ParseDisconnect(payload)
	if err != nil {
		reason = sshraw.DisconnectProtocolError
	}
	return PeerDisconnectError(reason)
}

func reuse(buf []byte, n int) []byte {
	internal.SliceReuse(&buf, n)
	return buf[:n:n]
}

// DisconnectError is a fatal error reported to the peer with SSH_MSG_DISCONNECT.
type DisconnectError sshraw.DisconnectReason

func (d DisconnectError) Error() string {
	return "ssh: sent disconnect " + sshraw.DisconnectReason(d).StringConst() + " (" + strconv.Itoa(int(d)) + ")"
}

// PeerDisconnectError is the reason of an SSH_MSG_DISCONNECT received from the peer.
type PeerDisconnectError sshraw.DisconnectReason

func (d PeerDisconnectError) Error() string {
	return "ssh: received disconnect " + sshraw.DisconnectReason(d).StringConst() + " (" + strconv.Itoa(int(d)) + ")"
}
