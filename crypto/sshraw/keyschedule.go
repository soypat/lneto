package sshraw

import (
	"encoding/binary"
	"hash"
	"io"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/lcrypto"
	"github.com/soypat/lneto/crypto/internal/wire"
)

const (
	// largest digest the key schedule accepts. 64 for SHA-512.
	_maxHashSize = 64
	// largest encoded shared secret K: an mpint of a _maxHashSize secret with its zero byte.
	_maxK = 4 + 1 + _maxHashSize
)

// KeyLetter selects the key derived by [KeySchedule.Derive], RFC 4253 7.2.
type KeyLetter byte

const (
	IVClientToServer  KeyLetter = 'A'
	IVServerToClient  KeyLetter = 'B'
	KeyClientToServer KeyLetter = 'C'
	KeyServerToClient KeyLetter = 'D'
	MACClientToServer KeyLetter = 'E'
	MACServerToClient KeyLetter = 'F'
)

// IsValid returns true if KeyLetter is in range 'A'..'F'.
func (kv KeyLetter) IsValid() bool { return kv >= 'A' && kv <= 'F' }

// KeySchedule computes the exchange hash H of an ECDH style key exchange,
// RFC 5656 4, and derives keys from it, RFC 4253 7.2. It keeps the session
// identifier, the H of the first key exchange, across rekeys.
//
// A key exchange runs [KeySchedule.SetSecret], [KeySchedule.StartExchange],
// one [KeySchedule.HashString] per exchange hash field, [KeySchedule.FinishExchange],
// then derives keys and ends with [KeySchedule.WipeExchange].
type KeySchedule struct {
	h    hash.Hash
	size int // [hash.Hash.Size]

	k       [_maxK]byte        // Shared secret K encoded as mpint or string.
	hsum    [_maxHashSize]byte // Exchange hash H.
	sid     [_maxHashSize]byte // Session identifier.
	sum     [_maxHashSize]byte // Scratch digest.
	scratch [_maxHashSize]byte // Scratch key.
	iv      [12]byte           // Scratch IV.
	lenbuf  [4]byte            // String length prefix. Buffers passed to a hash escape, so it lives here.
	letter  [1]byte

	klen, hlen, sidlen uint8
}

// InstallCipherAEADKeys derives packet protection key and IV of the exchange and installs them on hc with aead, RFC 4253 7.2.
// This ensures the key lifetime is contained within this function call and cleared on return.
//   - keyLen is negotiated cipher's AEAD key length
//   - clientToServer is hc's direction: true for client to server, false for server to client
//   - strict is true when strict key exchange was agreed, see [HalfConn.Seq]
//
// On error hc is left untouched or Zeroize'd. InstallCipherAEADKeys is equivalent to (client to server shown)
//
//	var key [keyLen]byte
//	var iv [12]byte
//	ks.Derive(iv[:], IVClientToServer)
//	ks.Derive(key[:], KeyClientToServer)
//	aead.Rekey(key[:])
//	hc.SetCipherAEAD(aead, &iv, strict)
//	clear(key[:])
func (ks *KeySchedule) InstallCipherAEADKeys(hc *HalfConn, aead lcrypto.AEADCipher, keyLen int, clientToServer, strict bool) error {
	if err := ks.canInstall(keyLen); err != nil {
		return err
	}
	ivLetter, keyLetter := directionLetters(clientToServer)
	ks.Derive(ks.iv[:], ivLetter)
	err := hc.SetCipherAEAD(aead, &ks.iv, strict)
	clear(ks.iv[:])
	if err != nil {
		return err
	}
	return ks.rekey(hc, aead, keyLen, keyLetter)
}

// InstallCipherFrameKeys derives packet protection key of the exchange and installs it on hc with pc, RFC 4253 7.2.
// This ensures the key lifetime is contained within this function call and cleared on return.
// A [CipherFrame] derives its nonces from sequence numbers, so no IV is derived.
//   - keyLen is negotiated cipher's key length: 64 for chacha20-poly1305@openssh.com
//   - clientToServer is hc's direction: true for client to server, false for server to client
//   - strict is true when strict key exchange was agreed, see [HalfConn.Seq]
//
// On error hc is left untouched or Zeroize'd. InstallCipherFrameKeys is equivalent to (client to server shown)
//
//	var key [keyLen]byte
//	ks.Derive(key[:], KeyClientToServer)
//	pc.Rekey(key[:])
//	hc.SetCipherFrame(pc, strict)
//	clear(key[:])
func (ks *KeySchedule) InstallCipherFrameKeys(hc *HalfConn, pc CipherFrame, keyLen int, clientToServer, strict bool) error {
	if err := ks.canInstall(keyLen); err != nil {
		return err
	} else if err = hc.SetCipherFrame(pc, strict); err != nil {
		return err
	}
	_, keyLetter := directionLetters(clientToServer)
	return ks.rekey(hc, pc, keyLen, keyLetter)
}

// directionLetters returns the IV and encryption key letters of a direction, RFC 4253 7.2.
func directionLetters(clientToServer bool) (iv, key KeyLetter) {
	if clientToServer {
		return IVClientToServer, KeyClientToServer
	}
	return IVServerToClient, KeyServerToClient
}

// Configure uses h as the hash of the negotiated key exchange method and wipes all KeySchedule state.
func (ks *KeySchedule) Configure(h hash.Hash) error {
	if err := ks.UseHash(h); err != nil {
		return err
	}
	ks.Zeroize()
	return nil
}

// UseHash uses h keeping session identifier, typically after a rekey with a new negotiated hash.
func (ks *KeySchedule) UseHash(h hash.Hash) error {
	if h.Size() > _maxHashSize || h.Size() <= 0 {
		return lneto.ErrUnsupported
	}
	ks.h = h
	ks.size = h.Size()
	ks.WipeExchange()
	return nil
}

// Size returns hash digest size.
func (ks *KeySchedule) Size() int { return ks.size }

// SetSecret uses shared secret of key exchange and encodes it as K or mpint for classic ECDH.
// hashed=true when K is HASH(shared) such as mlkem768x25519-sha256. SetSecret must be called before StartExchange.
func (ks *KeySchedule) SetSecret(shared []byte, hashed bool) error {
	var e Encoder
	e.Reset(ks.k[:], 0)
	if hashed {
		ks.h.Reset()
		ks.h.Write(shared)
		ks.h.Sum(ks.sum[:0])
		e.String(ks.sum[:ks.size])
		clear(ks.sum[:])
	} else if len(shared) > _maxHashSize {
		return lneto.ErrUnsupported
	} else {
		e.MPInt(shared)
	}
	if e.Err() != nil {
		return e.Err()
	}
	ks.klen = uint8(e.Len())
	return nil
}

// StartExchange starts hashing a new exchange hash.
func (ks *KeySchedule) StartExchange() {
	ks.h.Reset()
	ks.hlen = 0
}

// HashString adds b to the exchange hash as a string.
func (ks *KeySchedule) HashString(b []byte) {
	binary.BigEndian.PutUint32(ks.lenbuf[:], uint32(len(b)))
	ks.h.Write(ks.lenbuf[:])
	ks.h.Write(b)
}

// FinishExchange adds K to hash and computers H. H of first key exchange of conn becomes session identifier.
func (ks *KeySchedule) FinishExchange() {
	ks.h.Write(ks.k[:ks.klen])
	ks.h.Sum(ks.hsum[:0])
	ks.hlen = uint8(ks.size)
	if ks.sidlen == 0 {
		ks.sid = ks.hsum
		ks.sidlen = ks.hlen
	}
}

// ExchangeHash returns H, which the server signs. It is empty outside a key exchange.
func (ks *KeySchedule) ExchangeHash() []byte { return ks.hsum[:ks.hlen] }

// SessionID returns the session identifier, empty before the first key exchange.
func (ks *KeySchedule) SessionID() []byte { return ks.sid[:ks.sidlen] }

// Derive stores key of letter to dst, see RFC 4253 7.2:
//
//	K1 = HASH(K || H || letter || session_id)
//	K2 = HASH(K || H || K1)
//	dst = K1 || K2 || ...
func (ks *KeySchedule) Derive(dst []byte, letter KeyLetter) {
	if ks.hlen == 0 {
		panic("sshraw: Derive without exchange hash")
	} else if !letter.IsValid() {
		panic("sshraw: invalid key letter")
	}
	ks.letter[0] = byte(letter)
	ks.h.Reset()
	ks.h.Write(ks.k[:ks.klen])
	ks.h.Write(ks.hsum[:ks.hlen])
	ks.h.Write(ks.letter[:])
	ks.h.Write(ks.sid[:ks.sidlen])
	ks.h.Sum(ks.sum[:0])
	n := copy(dst, ks.sum[:ks.size])
	for n < len(dst) {
		ks.h.Reset()
		ks.h.Write(ks.k[:ks.klen])
		ks.h.Write(ks.hsum[:ks.hlen])
		ks.h.Write(dst[:n])
		ks.h.Sum(ks.sum[:0])
		n += copy(dst[n:], ks.sum[:ks.size])
	}
	clear(ks.sum[:])
}

// canInstall checks keys of keyLen can be derived: a key exchange is under way and the key fits scratch.
func (ks *KeySchedule) canInstall(keyLen int) error {
	if keyLen <= 0 || keyLen > len(ks.scratch) {
		return lneto.ErrInvalidConfig
	} else if ks.hlen == 0 {
		return lneto.ErrBadState
	}
	return nil
}

// rekey derives the key of letter into scratch, rekeys c with it and clears it.
// On error hc, which c was installed on, is Zeroize'd.
func (ks *KeySchedule) rekey(hc *HalfConn, c interface{ Rekey([]byte) error }, keyLen int, letter KeyLetter) error {
	key := ks.scratch[:keyLen]
	ks.Derive(key, letter)
	err := c.Rekey(key)
	clear(key)
	if err != nil {
		hc.Zeroize() // Prevent halfconn/keysched half-state.
	}
	return err
}

// WipeExchange forgets K and H without wiping session identifier for later rekeying.
func (ks *KeySchedule) WipeExchange() {
	clear(ks.k[:])
	clear(ks.hsum[:])
	ks.klen, ks.hlen = 0, 0
	if ks.h != nil {
		ks.h.Reset()
	}
}

// Zeroize wipes KeySchedule data but does not remove hash to enable reuse.
func (ks *KeySchedule) Zeroize() {
	ks.WipeExchange()
	clear(ks.sid[:])
	clear(ks.sum[:])
	clear(ks.scratch[:])
	clear(ks.iv[:])
	ks.sidlen = 0
}

type encoder = wire.Encoder

// Encoder writes SSH structures to a fixed buffer, the counterpart of [decoder].
// A write past the end of buf sets err and all later writes are dropped, so
// callers check err once after writing.
type Encoder struct{ encoder }

// Bool writes 1 for true and 0 for false, the only values RFC 4251 5 allows to be sent.
func (e *Encoder) Bool(v bool) {
	var b uint8
	if v {
		b = 1
	}
	e.Uint8(b)
}

// str writes s without a length prefix. copy to nil is a no-op on failure.
func (e *Encoder) str(s string) { copy(e.Reserve(len(s)), s) }

func (e *Encoder) byte(b byte) { e.Uint8(b) }

// String writes v as a length prefixed string.
func (e *Encoder) String(v []byte) {
	e.Uint32(uint32(len(v)))
	e.Bytes(v)
}

// Str writes s as a length prefixed string, as String does for a byte slice.
func (e *Encoder) Str(s string) {
	e.Uint32(uint32(len(s)))
	e.str(s)
}

// NameList writes names as a name-list. A name that is not valid sets
// [lneto.ErrInvalidField] or [lneto.ErrInvalidLengthField].
func (e *Encoder) NameList(names ...string) {
	start := e.Open(4)
	for i, name := range names {
		if err := validateName(name); err != nil {
			e.Fail(err)
			return
		} else if i > 0 {
			e.Uint8(',')
		}
		e.str(name)
	}
	e.Close(start, 4)
}

// MPInt writes the unsigned big endian magnitude mag as an mpint, RFC 4251 5:
// without leading zero bytes and with a zero byte prepended when the high bit
// is set so the value does not read as negative.
func (e *Encoder) MPInt(mag []byte) {
	for len(mag) > 0 && mag[0] == 0 {
		mag = mag[1:]
	}
	pad := len(mag) > 0 && mag[0]&0x80 != 0
	if pad {
		e.Uint32(uint32(len(mag) + 1))
		e.Uint8(0)
	} else {
		e.Uint32(uint32(len(mag)))
	}
	e.Bytes(mag)
}

// StartPacket writes a binary packet header and the message type. The lengths
// and padding are written by EndPacket.
func (e *Encoder) StartPacket(typ MsgType) (start int) {
	start = e.Len()
	e.Advance(SizeHeader)
	e.Uint8(uint8(typ))
	return start
}

// EndPacket pads the packet started at start to blockSize with bytes read from
// rand, sets its lengths and returns the unprotected packet. blockSize is the
// cipher block size; values below [minBlockSize] mean [minBlockSize].
// aad is true when keys are installed: packet_length is then not part of the
// alignment, whether sent in the clear (aes-gcm@openssh.com) or encrypted with
// a key of its own (chacha20-poly1305@openssh.com). See [Frame.ValidateLength].
func (e *Encoder) EndPacket(start, blockSize int, aad bool, rand io.Reader) []byte {
	bs := max(blockSize, minBlockSize)
	if bs+minPadding-1 > 255 {
		e.Fail(lneto.ErrInvalidConfig)
	}
	if e.Err() != nil {
		return nil
	}
	covered := e.Len() - start
	if aad {
		covered -= 4
	}
	padLen := bs - covered%bs
	if padLen < minPadding {
		padLen += bs
	}
	pad := e.Reserve(padLen)
	if pad == nil {
		return nil
	} else if _, err := io.ReadFull(rand, pad); err != nil {
		e.Fail(err)
		return nil
	}
	pkt := e.Since(start)
	if len(pkt) > maxPacket {
		e.Fail(lneto.ErrInvalidLengthField)
		return nil
	}
	binary.BigEndian.PutUint32(pkt, uint32(len(pkt)-4))
	pkt[4] = byte(padLen)
	return pkt
}

func validateName[T ~string | ~[]byte](name T) error {
	if len(name) == 0 {
		return lneto.ErrInvalidField
	} else if len(name) > maxNameLen {
		return lneto.ErrInvalidLengthField
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; c <= ' ' || c > '~' || c == ',' {
			return lneto.ErrInvalidField
		}
	}
	return nil
}
