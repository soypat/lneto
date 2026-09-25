package tlsraw

import (
	"encoding/binary"
	"hash"

	"github.com/soypat/lneto"
)

const (
	labelPrefix = "tls13 "
	maxLabel    = len("c ap traffic")
)

const (
	// smallest digest the key schedule accepts. TLS 1.3 does not name a smaller hash suite.
	_minHashSize = 32
	// largest digest the key schedule accepts. 64 for SHA-512.
	_maxHashSize = 64
	// HMAC block of SHA-384 and SHA-512, the largest accepted.
	_maxBlockSize = 128
)

var zeroSecret [_maxHashSize]byte

// KeySchedule derives the TLS 1.3 secrets of RFC 8446 7.1 without PSK.
// It supports any hash.Hash it can fit in its memory and return [lneto.ErrUnsupported] during Reset otherwise.
type KeySchedule struct {
	transcript hash.Hash // Running hash of handshake messages, headers included.
	mac        hash.Hash // Scratch hash for HMAC, reset on every use.
	size       int       // [hash.Hash.Size]
	block      int       // [hash.Hash.BlockSize]

	secret  [_maxHashSize]byte                                               // Early, then handshake, then master secret.
	sum     [_maxHashSize]byte                                               // Scratch digest.
	scratch [_maxHashSize]byte                                               // Scratch
	empty   [_maxHashSize]byte                                               // Hash of the empty string, the "derived" context of RFC 8446 7.1.
	pad     [_maxBlockSize]byte                                              // HMAC key pad of block size.
	info    [2 + 1 + len(labelPrefix) + maxLabel + 1 + _maxHashSize + 1]byte // HkdfLabel and HKDF-Expand counter.

	paranoid bool
}

// Configure starts a new handshake at the early secret. transcript and mac must be distinct hashes.
func (ks *KeySchedule) Configure(transcript, mac hash.Hash, paranoid bool) error {
	size, block := mac.Size(), mac.BlockSize()
	if block < size || size != transcript.Size() || block != transcript.BlockSize() {
		return lneto.ErrInvalidConfig
	} else if block > _maxBlockSize || size < _minHashSize || size > _maxHashSize {
		return lneto.ErrUnsupported
	}
	ks.transcript = transcript
	ks.mac = mac
	ks.paranoid = paranoid
	ks.size = size
	ks.block = block
	mac.Reset()
	mac.Sum(ks.empty[:0]) // Empty hash for advance.
	ks.Zeroize()
	return nil
}

// Zeroize overwrites all memory used by keySchedule and calls [hash.Hash.Reset] on used hashers.
// The KeySchedule is zeroed before a FastReset call, so if configured it may be reused after Zeroize.
func (ks *KeySchedule) Zeroize() {
	*ks = KeySchedule{
		transcript: ks.transcript,
		mac:        ks.mac,
		paranoid:   ks.paranoid,
		size:       ks.size,
		block:      ks.block,
		empty:      ks.empty,
	}
	// Finish with Reset calls- who knows, maybe they block long enough for attacker to read? This order sounds safer :)
	// [sha256.Digest] does not overwrite all state... such is life. Maybe time for lcrypto...
	if ks.transcript != nil {
		ks.FastReset()
	}
}

// FastReset resets internal state allowing for a fast reuse of KeySchedule supposing Configure has been called previously.
// Zeroize can be called before FastReset for a clean reuse.
func (ks *KeySchedule) FastReset() {
	ks.transcript.Reset()
	ks.mac.Reset()
	ks.extract(zeroSecret[:ks.size], zeroSecret[:ks.size])
}

// Size returns the digest size of the schedule's hash. Size returns 0 before successful Reset.
func (ks *KeySchedule) Size() int { return ks.size }

// Finished writes to dst the verify_data of RFC 8446 4.4.4 for the transcript so far.
// Call [KeySchedule.Zeroize] after finishing use to ensure data deleted. dst and secret must be of length [KeySchedule.Size].
func (ks *KeySchedule) Finished(dst, secret []byte) {
	ks.mustSize(dst)
	ks.mustSize(secret)
	key := ks.scratch[:ks.size]
	ks.expandLabel(key, secret, "finished", nil)
	ks.transcriptSum(ks.sum[:0]) // Key is in ks.scratch.
	ks.hmacSum(key, ks.sum[:ks.size])
	copy(dst, ks.sum[:ks.size])
	ks.shh(key)
	ks.shh(ks.sum[:ks.size])
}

// AddMessage appends a handshake message, header included, to the transcript.
func (ks *KeySchedule) AddMessage(msg []byte) { ks.transcript.Write(msg) }

// TranscriptHash writes the hash of all messages added so far of length [KeySchedule.Size].
func (ks *KeySchedule) TranscriptHash(dst []byte) {
	ks.mustSize(dst)
	ks.transcriptSum(ks.sum[:0]) // Handoff through ks.sum: dst passed to hash.Hash would escape.
	copy(dst, ks.sum[:ks.size])
	ks.shh(ks.sum[:ks.size])
}

// transcriptSum writes the transcript hash to dst, which must be a field of ks.
func (ks *KeySchedule) transcriptSum(dst []byte) { ks.transcript.Sum(dst[:0]) }

// Handshake advances to the handshake secret with the key exchange's shared secret and writes
// the handshake traffic secrets. Call after adding the ServerHello.
func (ks *KeySchedule) Handshake(client, server, shared []byte) {
	ks.mustSize(client)
	ks.mustSize(server)
	ks.advance(shared)
	ks.trafficSecrets(client, server, "c hs traffic", "s hs traffic")
}

// Master advances to the master secret and writes the application traffic secrets.
// Call after adding the server Finished. client and server must be of length [KeySchedule.Size].
func (ks *KeySchedule) Master(client, server []byte) {
	ks.mustSize(client)
	ks.mustSize(server)
	ks.advance(zeroSecret[:ks.size])
	ks.trafficSecrets(client, server, "c ap traffic", "s ap traffic")
}

// Keys writes the record protection key and IV of a traffic secret, RFC 8446 7.3.
//
// len(key) is the AEAD's key length of the negotiated suite; len(secret)==[KeySchedule.Size]:
//   - TLS_AES_128_GCM_SHA256: len(key)==16
//   - TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256: len(key)==32
func (ks *KeySchedule) Keys(key, secret []byte, iv *[12]byte) {
	ks.mustSize(secret)
	ks.expandLabel(key, secret, "key", nil)
	ks.expandLabel(iv[:], secret, "iv", nil)
}

func (ks *KeySchedule) advance(ikm []byte) {
	salt := ks.scratch[:ks.size]
	ks.expandLabel(salt, ks.secret[:ks.size], "derived", ks.empty[:ks.size])
	ks.extract(salt, ikm)
	ks.shh(salt)
}

func (ks *KeySchedule) mustSize(s []byte) {
	if len(s) != ks.size {
		panic("tlsraw: keySchedule secret must be Size bytes")
	}
}

func (ks *KeySchedule) trafficSecrets(client, server []byte, clientLabel, serverLabel string) {
	ks.transcriptSum(ks.scratch[:])
	ks.expandLabel(client, ks.secret[:ks.size], clientLabel, ks.scratch[:ks.size])
	ks.expandLabel(server, ks.secret[:ks.size], serverLabel, ks.scratch[:ks.size])
	ks.shh(ks.scratch[:ks.size])
}

// extract sets the stage secret to HKDF-Extract(salt, ikm) of RFC 5869 2.2.
func (ks *KeySchedule) extract(salt, ikm []byte) {
	ks.hmacSum(salt, ikm)
	copy(ks.secret[:], ks.sum[:ks.size])
}

// expandLabel is HKDF-Expand-Label of RFC 8446 7.1. Output is limited to one
// HMAC block, which covers every length TLS 1.3
func (ks *KeySchedule) expandLabel(dst, secret []byte, label string, context []byte) {
	if len(dst) > ks.size || len(label) > maxLabel || len(context) > ks.size {
		panic("tls: expandLabel argument too long")
	}
	info := binary.BigEndian.AppendUint16(ks.info[:0], uint16(len(dst)))
	info = append(info, byte(len(labelPrefix)+len(label)))
	info = append(info, labelPrefix...)
	info = append(info, label...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	info = append(info, 1) // HKDF-Expand block counter.
	ks.hmacSum(secret, info)
	copy(dst, ks.sum[:ks.size])
	ks.shh(ks.sum[:ks.size])
}

// hmacSum writes HMAC(key, msg) of RFC 2104 to ks.sum. key must fit in one block.
func (ks *KeySchedule) hmacSum(key, msg []byte) {
	pad := ks.pad[:ks.block]
	if len(key) > len(pad) {
		panic("tls: HMAC key longer than block")
	}
	clear(pad)
	copy(pad, key)
	for i := range pad {
		pad[i] ^= 0x36
	}
	ks.mac.Reset()
	ks.mac.Write(pad)
	ks.mac.Write(msg)
	ks.mac.Sum(ks.sum[:0])
	for i := range pad {
		pad[i] ^= 0x36 ^ 0x5c
	}
	ks.mac.Reset()
	ks.mac.Write(pad)
	ks.mac.Write(ks.sum[:ks.size])
	ks.mac.Sum(ks.sum[:0])
	ks.shh(pad)
}

// shh dont tell secrets out loud. TODO: check if we've covered every place we can.
func (ks *KeySchedule) shh(data []byte) {
	if ks.paranoid {
		for i := range data {
			data[i] = 0
		}
	}
}
