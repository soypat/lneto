package sshraw

import (
	"encoding/binary"
	"hash"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/lcrypto"
)

const (
	// largest digest the key schedule accepts. 64 for SHA-512.
	_maxHashSize = 64
	// largest encoded shared secret K: an mpint of a _maxHashSize secret with its zero byte.
	_maxK = 4 + 1 + _maxHashSize
)

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

// Configure takes h as the hash of the negotiated key exchange method and wipes
// all state, starting a new connection.
func (ks *KeySchedule) Configure(h hash.Hash) error {
	if err := ks.UseHash(h); err != nil {
		return err
	}
	ks.Zeroize()
	return nil
}

// UseHash takes h as the hash of the key exchange about to start, keeping the
// session identifier. A rekey may negotiate a method with another hash than
// the one of the first key exchange. It must not be called mid key exchange.
func (ks *KeySchedule) UseHash(h hash.Hash) error {
	if h.Size() > _maxHashSize || h.Size() <= 0 {
		return lneto.ErrUnsupported
	}
	ks.h = h
	ks.size = h.Size()
	ks.WipeExchange()
	return nil
}

// Size returns the digest size of the hash.
func (ks *KeySchedule) Size() int { return ks.size }

// SetSecret takes the raw shared secret of the key exchange and keeps it
// encoded as K. Classic ECDH methods encode it as an mpint, RFC 5656 4.
// hashed is true for methods whose K is the string HASH(shared), such as
// mlkem768x25519-sha256. SetSecret uses the hash, so it must be called before
// StartExchange. The caller wipes shared.
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

// FinishExchange adds K to the exchange hash and computes H. The H of the
// first key exchange of a connection becomes its session identifier.
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

// Derive fills dst with the key of letter, RFC 4253 7.2:
//
//	K1 = HASH(K || H || letter || session_id)
//	K2 = HASH(K || H || K1)
//	dst = K1 || K2 || ...
//
// Letters 'A' through 'F' are the client to server IV, server to client IV,
// client to server key, server to client key, and the MAC keys in that order.
// Derive panics outside a key exchange.
func (ks *KeySchedule) Derive(dst []byte, letter byte) {
	if ks.hlen == 0 {
		panic("sshraw: Derive without exchange hash")
	}
	ks.letter[0] = letter
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

// InstallKeys derives the key of keyLetter and the IV of ivLetter and installs
// them on hc with aead, so the key lifetime is contained within this call.
// keyLen is the AEAD key length of the negotiated cipher. On error hc is left
// untouched or Zeroize'd.
func (ks *KeySchedule) InstallKeys(hc *HalfConn, aead lcrypto.AEADCipher, keyLen int, keyLetter, ivLetter byte) error {
	if keyLen <= 0 || keyLen > len(ks.scratch) {
		return lneto.ErrInvalidConfig
	} else if ks.hlen == 0 {
		return lneto.ErrBadState
	}
	ks.Derive(ks.iv[:], ivLetter)
	err := hc.SetAEAD(aead, &ks.iv)
	clear(ks.iv[:])
	if err != nil {
		return err
	}
	key := ks.scratch[:keyLen]
	ks.Derive(key, keyLetter)
	err = aead.Rekey(key)
	clear(key)
	if err != nil {
		hc.Zeroize()
		return err
	}
	return nil
}

// WipeExchange forgets K and H once the keys of a key exchange are installed.
// The session identifier is kept for later rekeys and user authentication.
func (ks *KeySchedule) WipeExchange() {
	clear(ks.k[:])
	clear(ks.hsum[:])
	ks.klen, ks.hlen = 0, 0
	if ks.h != nil {
		ks.h.Reset()
	}
}

// Zeroize wipes all secrets including the session identifier. The hash is
// kept so the schedule can be reused for a new connection.
func (ks *KeySchedule) Zeroize() {
	ks.WipeExchange()
	clear(ks.sid[:])
	clear(ks.sum[:])
	clear(ks.scratch[:])
	clear(ks.iv[:])
	ks.sidlen = 0
}
