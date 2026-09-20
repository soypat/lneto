package tlsraw

import (
	"encoding/binary"
	"hash"
)

const (
	labelPrefix = "tls13 "
	maxLabel    = len("c ap traffic")
)

// sizeSHA256 is the digest size of SHA-256. crypto/sha256 is not imported so that
// wire-format users of this package, e.g. pcap, do not link Go's crypto packages.
const sizeSHA256 = 32

var zeroSecret [32]byte

// emptySHA256 is SHA-256 of the empty string, the "derived" context of RFC 8446 7.1.
var emptySHA256 = [sizeSHA256]byte{
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
	0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
}

// KeySchedule derives the TLS 1.3 secrets of RFC 8446 7.1 for SHA-256 cipher suites without PSK.
// It does not allocate. Buffers passed to a hash.Hash escape to the heap, so all
// scratch space lives in the struct.
type KeySchedule struct {
	transcript hash.Hash                                              // Running hash of handshake messages, headers included.
	mac        hash.Hash                                              // Scratch hash for HMAC, reset on every use.
	secret     [32]byte                                               // Early, then handshake, then master secret.
	sum        [32]byte                                               // Scratch digest.
	scratch    [32]byte                                               // Scratch
	pad        [64]byte                                               // HMAC key pad, one SHA-256 block.
	info       [2 + 1 + len(labelPrefix) + maxLabel + 1 + 32 + 1]byte // HkdfLabel and HKDF-Expand counter.
	paranoid   bool
}

// Finished writes to dst the verify_data of RFC 8446 4.4.4 for the transcript so far.
// Call [keySchedule.Zeroize] after finishing use to ensure data deleted.
func (ks *KeySchedule) Finished(dst, secret *[32]byte) {
	key := ks.scratch[:]
	ks.expandLabel(key, secret[:], "finished", nil)
	ks.transcriptSum(&ks.sum) // Key is in ks.scratch.
	ks.hmacSum(key, ks.sum[:])
	*dst = ks.sum
	ks.shh(key)
	ks.shh(ks.sum[:])
}

// Reset starts a new handshake at the early secret. transcript and mac must be
// distinct SHA-256 hashes; they are reused across handshakes.
func (ks *KeySchedule) Reset(transcript, mac hash.Hash, paranoid bool) {
	if transcript.Size() != sizeSHA256 || mac.Size() != sizeSHA256 || mac.BlockSize() != len(ks.pad) {
		panic("tls: keySchedule requires SHA-256")
	}
	transcript.Reset()
	*ks = KeySchedule{transcript: transcript, mac: mac, paranoid: paranoid}
	ks.extract(zeroSecret[:], zeroSecret[:])
}

// AddMessage appends a handshake message, header included, to the transcript.
func (ks *KeySchedule) AddMessage(msg []byte) { ks.transcript.Write(msg) }

// TranscriptHash writes the hash of all messages added so far.
func (ks *KeySchedule) TranscriptHash(dst *[32]byte) {
	ks.transcriptSum(&ks.sum) // Handoff through ks.sum: dst passed to hash.Hash would escape.
	*dst = ks.sum
	ks.shh(ks.sum[:])
}

// transcriptSum writes the transcript hash to dst, which must be a field of ks.
func (ks *KeySchedule) transcriptSum(dst *[32]byte) { ks.transcript.Sum(dst[:0]) }

// Handshake advances to the handshake secret with the key exchange's shared secret and writes
// the handshake traffic secrets. Call after adding the ServerHello.
func (ks *KeySchedule) Handshake(client, server *[32]byte, shared []byte) {
	ks.advance(shared)
	ks.trafficSecrets(client, server, "c hs traffic", "s hs traffic")
}

// Master advances to the master secret and writes the application traffic secrets.
// Call after adding the server Finished.
func (ks *KeySchedule) Master(client, server *[32]byte) {
	ks.advance(zeroSecret[:])
	ks.trafficSecrets(client, server, "c ap traffic", "s ap traffic")
}

// Keys writes the record protection key and IV of a traffic secret, RFC 8446 7.3.
//   - AES128: len(key)==16
//   - AES256/ChaCha20: len(key)==32
func (ks *KeySchedule) Keys(key []byte, iv *[12]byte, secret *[32]byte) {
	ks.expandLabel(key, secret[:], "key", nil)
	ks.expandLabel(iv[:], secret[:], "iv", nil)
}

func (ks *KeySchedule) advance(ikm []byte) {
	salt := ks.scratch[:]
	ks.expandLabel(salt, ks.secret[:], "derived", emptySHA256[:])
	ks.extract(salt, ikm)
	ks.shh(salt)
}

func (ks *KeySchedule) trafficSecrets(client, server *[32]byte, clientLabel, serverLabel string) {
	ks.transcriptSum(&ks.scratch)
	ks.expandLabel(client[:], ks.secret[:], clientLabel, ks.scratch[:])
	ks.expandLabel(server[:], ks.secret[:], serverLabel, ks.scratch[:])
	ks.shh(ks.scratch[:])
}

// extract sets the stage secret to HKDF-Extract(salt, ikm) of RFC 5869 2.2.
func (ks *KeySchedule) extract(salt, ikm []byte) {
	ks.hmacSum(salt, ikm)
	ks.secret = ks.sum
}

// expandLabel is HKDF-Expand-Label of RFC 8446 7.1. Output is limited to one
// HMAC block, which covers every length TLS 1.3 derives with SHA-256.
func (ks *KeySchedule) expandLabel(dst, secret []byte, label string, context []byte) {
	if len(dst) > len(ks.sum) || len(label) > maxLabel || len(context) > len(ks.sum) {
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
	copy(dst, ks.sum[:])
	ks.shh(ks.sum[:])
}

// hmacSum writes HMAC(key, msg) of RFC 2104 to ks.sum. key must fit in one block.
func (ks *KeySchedule) hmacSum(key, msg []byte) {
	if len(key) > len(ks.pad) {
		panic("tls: HMAC key longer than block")
	}
	clear(ks.pad[:])
	copy(ks.pad[:], key)
	for i := range ks.pad {
		ks.pad[i] ^= 0x36
	}
	ks.mac.Reset()
	ks.mac.Write(ks.pad[:])
	ks.mac.Write(msg)
	ks.mac.Sum(ks.sum[:0])
	for i := range ks.pad {
		ks.pad[i] ^= 0x36 ^ 0x5c
	}
	ks.mac.Reset()
	ks.mac.Write(ks.pad[:])
	ks.mac.Write(ks.sum[:])
	ks.mac.Sum(ks.sum[:0])
}

// Zeroize overwrites all memory used by keySchedule and calls [hash.Hash.Reset] on used hashers.
// After Zeroize called Reset should be called before reuse.
func (ks *KeySchedule) Zeroize() {
	*ks = KeySchedule{
		transcript: ks.transcript,
		mac:        ks.mac,
		paranoid:   ks.paranoid,
	}
	// Finish with Reset calls- who knows, maybe they block long enough for attacker to read? This order sounds safer :)
	// [sha256.Digest] does not overwrite all state... such is life. Maybe time for lcrypto...
	if ks.transcript != nil {
		ks.transcript.Reset()
		ks.mac.Reset()
	}
}

// shh dont tell secrets out loud. TODO: check if we've covered every place we can.
func (ks *KeySchedule) shh(data []byte) {
	if ks.paranoid {
		for i := range data {
			data[i] = 0
		}
	}
}
