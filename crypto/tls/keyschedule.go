package tls

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

const (
	labelPrefix = "tls13 "
	maxLabel    = len("c ap traffic")
)

var zeroSecret [32]byte

// keySchedule derives the TLS 1.3 secrets of RFC 8446 7.1 for SHA-256 cipher suites without PSK.
// It does not allocate. Buffers passed to a hash.Hash escape to the heap, so all
// scratch space lives in the struct.
type keySchedule struct {
	transcript hash.Hash                                              // Running hash of handshake messages, headers included.
	mac        hash.Hash                                              // Scratch hash for HMAC, reset on every use.
	secret     [32]byte                                               // Early, then handshake, then master secret.
	sum        [32]byte                                               // Scratch digest.
	scratch    [32]byte                                               // Scratch
	pad        [64]byte                                               // HMAC key pad, one SHA-256 block.
	info       [2 + 1 + len(labelPrefix) + maxLabel + 1 + 32 + 1]byte // HkdfLabel and HKDF-Expand counter.
	paranoid   bool
}

// Finished returns the verify_data of RFC 8446 4.4.4 for the transcript so far.
// Call [keySchedule.Zeroize] after finishing use to ensure data deleted.
func (ks *keySchedule) Finished(secret *[32]byte) (verify [32]byte) {
	key := ks.scratch[:]
	ks.expandLabel(key, secret[:], "finished", nil)
	ks.TranscriptHash(&ks.sum) // Into ks.sum: a stack copy passed to hmacSum would escape.
	ks.hmacSum(key, ks.sum[:])
	ks.shh(key)
	return ks.sum
}

// Reset starts a new handshake at the early secret. transcript and mac must be
// distinct SHA-256 hashes; they are reused across handshakes.
func (ks *keySchedule) Reset(transcript, mac hash.Hash) {
	if transcript.Size() != sha256.Size || mac.Size() != sha256.Size || mac.BlockSize() != len(ks.pad) {
		panic("tls: keySchedule requires SHA-256")
	}
	transcript.Reset()
	*ks = keySchedule{transcript: transcript, mac: mac}
	ks.extract(zeroSecret[:], zeroSecret[:])
}

// AddMessage appends a handshake message, header included, to the transcript.
func (ks *keySchedule) AddMessage(msg []byte) { ks.transcript.Write(msg) }

// TranscriptHash writes the hash of all messages added so far.
func (ks *keySchedule) TranscriptHash(dst *[32]byte) {
	ks.transcript.Sum(dst[:0])
}

// Handshake advances to the handshake secret with the key exchange's shared secret and returns
// the handshake traffic secrets. Call after adding the ServerHello.
func (ks *keySchedule) Handshake(shared []byte) (client, server [32]byte) {
	ks.advance(shared)
	return ks.trafficSecrets("c hs traffic", "s hs traffic")
}

// Master advances to the master secret and returns the application traffic secrets.
// Call after adding the server Finished.
func (ks *keySchedule) Master() (client, server [32]byte) {
	ks.advance(zeroSecret[:])
	return ks.trafficSecrets("c ap traffic", "s ap traffic")
}

// trafficKeys are the TLS_AES_128_GCM_SHA256 record protection inputs of RFC 8446 7.3.
type trafficKeys struct {
	key [16]byte
	iv  [12]byte
}

// Keys derives the record protection inputs of a traffic secret.
func (ks *keySchedule) Keys(secret *[32]byte) (tk trafficKeys) {
	ks.expandLabel(tk.key[:], secret[:], "key", nil)
	ks.expandLabel(tk.iv[:], secret[:], "iv", nil)
	return tk
}

func (ks *keySchedule) advance(ikm []byte) {
	emptyHash := sha256.Sum256(nil)
	salt := ks.scratch[:]
	ks.expandLabel(salt, ks.secret[:], "derived", emptyHash[:])
	ks.extract(salt, ikm)
	ks.shh(salt)
}

func (ks *keySchedule) trafficSecrets(clientLabel, serverLabel string) (client, server [32]byte) {
	ks.TranscriptHash(&ks.scratch)
	ks.expandLabel(client[:], ks.secret[:], clientLabel, ks.scratch[:])
	ks.expandLabel(server[:], ks.secret[:], serverLabel, ks.scratch[:])
	ks.shh(ks.scratch[:])
	return client, server
}

// extract sets the stage secret to HKDF-Extract(salt, ikm) of RFC 5869 2.2.
func (ks *keySchedule) extract(salt, ikm []byte) {
	ks.hmacSum(salt, ikm)
	ks.secret = ks.sum
}

// expandLabel is HKDF-Expand-Label of RFC 8446 7.1. Output is limited to one
// HMAC block, which covers every length TLS 1.3 derives with SHA-256.
func (ks *keySchedule) expandLabel(dst, secret []byte, label string, context []byte) {
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
}

// hmacSum writes HMAC(key, msg) of RFC 2104 to ks.sum. key must fit in one block.
func (ks *keySchedule) hmacSum(key, msg []byte) {
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
func (ks *keySchedule) Zeroize() {
	*ks = keySchedule{
		transcript: ks.transcript,
		mac:        ks.mac,
	}
	// Finish with Reset calls- who knows, maybe they block long enough for attacker to read? This order sounds safer :)
	// [sha256.Digest] does not overwrite all state... such is life. Maybe time for lcrypto...
	ks.transcript.Reset()
	ks.mac.Reset()
}

// shh dont tell secrets out loud. TODO: check if we've covered every place we can.
func (ks *keySchedule) shh(data []byte) {
	if ks.paranoid {
		for i := range data {
			data[i] = 0
		}
	}
}
