package sshraw

import (
	"encoding/binary"
	"math"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/lcrypto"
)

// CipherFrame protects binary packets whose packet_length is encrypted, as
// chacha20-poly1305@openssh.com does, RFC 4253 6. It derives its nonce from the
// sequence number alone so callers cannot misuse nonces. A CipherFrame is
// owned by one [HalfConn] and need not be safe for concurrent use.
//
// Ciphers that encrypt packet_length are open to the Terrapin attack
// (CVE-2023-48795) unless strict key exchange is in use.
type CipherFrame interface { // TODO: rename lcrypto.CipherAEAD.
	// Rekey discards the current key and installs key, leaving the cipher ready for use.
	// Rekey must not hold the reference after returning.
	//
	// key is local: derived by the key schedule, never peer data.
	Rekey(key []byte) error
	// Zeroize wipes the key and any derived state, leaving the cipher unkeyed.
	Zeroize()
	// Overhead returns the size of the tag after each packet.
	Overhead() int // Implements [cipher.AEAD].
	// BlockSize returns the alignment of packets, packet_length excluded. See [Frame.ValidateLength].
	BlockSize() int
	// DecryptLength returns the packet_length of packet seq given its first 4 bytes on the wire.
	// The result is not authenticated: use it only to frame the packet, bounded by
	// [HalfConn.ValidateLength], and trust nothing of the packet until Open succeeds.
	DecryptLength(seq uint32, encLength [4]byte) uint32
	// Seal encrypts plaintext frame of packet seq in place, packet_length included,
	// and writes the tag to its last Overhead bytes.
	Seal(seq uint32, frame []byte)
	// Open authenticates frame of packet seq, tag included, and only then decrypts it
	// in place. On error frame is left unmodified.
	Open(seq uint32, frame []byte) error
}

// HalfConn protects binary packets in one direction after SetAEAD or SetFrameCipher is called, usually after [MsgNewKeys].
// HalfConn expects packets input via Seal and Open to be of their [Frame.WireLength].
// SetCipher* methods do not zero current ciphers- it is the responsibility of the user to call [HalfConn.Zeroize] responsibly.
type HalfConn struct {
	used     uint64 // Packets protected with the current key.
	cipherA  lcrypto.AEADCipher
	cipherF  CipherFrame
	seq      uint32
	overhead uint32 // Auth tag bytes after the packet a.k.a Message Authentication Code (MAC).
	// TODO: same as with tlsraw, benchmark if keeping a full byte-slice nonce state is better.
	nonce [12]byte // Nonce of the next packet.
	aead  bool     // cipherA is in use, else cipherF when cipherF!=nil.
}

// SetCipherAEAD installs aead, keyed with the derived key, and the matching IV. strict
// restarts sequence numbers, see [HalfConn.Seq]. HalfConn is zeroed excepting sequence number on failure.
func (hc *HalfConn) SetCipherAEAD(aead lcrypto.AEADCipher, iv *[12]byte, strict bool) error {
	overhead := aead.Overhead()
	if aead.NonceSize() != len(iv) || overhead != 16 { // All AEADs are 16.
		return lneto.ErrInvalidConfig
	}
	hc.overhead = uint32(overhead)
	hc.cipherA, hc.cipherF, hc.aead = aead, nil, true
	hc.nonce = *iv
	hc.newKey(strict)
	return nil
}

// SetCipherFrame installs pc, keyed with the derived key. strict restarts sequence
// numbers, see [HalfConn.Seq]. pc derives its nonces from sequence numbers and
// protects at most 2^32 packets, so no nonce repeats even across a wrap.
//
// Without strict key exchange a FrameCipher is open to the Terrapin attack
// (CVE-2023-48795); callers may want to refuse it then.
// HalfConn is zeroed excepting sequence number on failure.
func (hc *HalfConn) SetCipherFrame(cf CipherFrame, strict bool) error {
	overhead := cf.Overhead()
	if cf.BlockSize() != minBlockSize || overhead != 16 { // 16: omit support for encrypt->MAC.
		return lneto.ErrInvalidConfig
	}
	hc.overhead = uint32(overhead)
	hc.cipherA, hc.cipherF, hc.aead = nil, cf, false
	hc.newKey(strict)
	return nil
}

// newKey starts the lifetime of a key just installed. A sequence number restart
// only ever comes with a fresh key, so a FrameCipher never sees its nonce twice.
func (hc *HalfConn) newKey(strict bool) {
	hc.used = 0
	if strict {
		hc.seq = 0
	}
}

// Seq returns sequence number of next packet and is owned by HalfConn.
// It begins counting at 0 and is reset to 0 on strict key exchange (KEX). See HalfConn Set* method `strict` parameter.
func (hc *HalfConn) Seq() uint32 { return hc.seq }

// HasKeys reports whether SetAEAD or SetFrameCipher installed keys since the last Zeroize.
func (hc *HalfConn) HasKeys() bool { return hc.aead && hc.cipherA != nil || hc.cipherF != nil }

// useAEAD reports whether keys were installed by SetAEAD.
func (hc *HalfConn) useAEAD() bool    { return hc.aead }
func (hc *HalfConn) useFCipher() bool { return hc.cipherF != nil }

// Zeroize calls Zeroize method on ciphers and zeroes all other internal state and drops reference to cipher.
func (hc *HalfConn) Zeroize() {
	hc.zeroize(0)
}

// isZeroized returns true if HalfConn is in zeroized state with no installed cipher..
func (hc *HalfConn) isZeroized() bool {
	return !(hc.useAEAD() || hc.useFCipher())
}

// zeroize zeros struct and ciphers and sets seq.
func (hc *HalfConn) zeroize(seq uint32) {
	if hc.useAEAD() {
		hc.cipherA.Zeroize()
	} else if hc.useFCipher() {
		hc.cipherF.Zeroize()
	}
	*hc = HalfConn{seq: seq}
}

// Seal encrypts in-place a plaintext frame already checked with [Frame.ValidateSize] and returns its wire length.
// The frame must be exactly [Frame.WireLength] bytes long: when HalfConn is keyed
// the last [HalfConn.Overhead] bytes are space for the tag.
func (hc *HalfConn) Seal(pf Frame) (int, error) {
	pkt := pf.RawData()
	wl := pf.WireLength(hc.overhead)
	if wl != len(pkt) {
		return 0, lneto.ErrInvalidLengthField
	}
	if hc.useAEAD() {
		if hc.used == math.MaxUint64 {
			return 0, lneto.ErrExhausted
		}
		overhead := hc.Overhead()
		sealed := hc.cipherA.Seal(pkt[4:4], hc.nonce[:], pkt[4:len(pkt)-overhead], pkt[:4])
		hc.nextNonce()
		if len(sealed)+4 != len(pkt) {
			panic("ssh invariant violated")
		}
	} else if hc.useFCipher() {
		if hc.used >= 1<<32 {
			return 0, lneto.ErrExhausted // The nonce is the sequence number, which wraps at 2^32.
		}
		hc.cipherF.Seal(hc.seq, pkt)
		hc.used++
	}
	hc.seq++
	return len(pkt), nil
}

// Overhead returns size of auth tag (MAC) appended to packets.
func (hc *HalfConn) Overhead() int {
	return int(hc.overhead)
}

// BlockSize returns the alignment packets must meet, see [Frame.ValidateLength].
// Keyed alignment is the AES block size, the only AEAD this package supports being AES-GCM.
func (hc *HalfConn) BlockSize() int {
	if hc.useAEAD() {
		return sizeGCMBlock
	} else if hc.useFCipher() {
		return hc.cipherF.BlockSize()
	}
	return minBlockSize
}

// LenPacket extracts packet_length from a as-received frame before Open. Handles [CipherFrame] encrypted packet length.
// Does not mutate the frame.
func (hc *HalfConn) LenPacket(pf Frame) uint32 {
	if hc.useFCipher() {
		return hc.cipherF.DecryptLength(hc.seq, [4]byte(pf.RawData()[0:4]))
	}
	return pf.LenPacket()
}

// ValidateLength validates packet_length of as-received frame before [HalfConn.Open].
func (hc *HalfConn) ValidateLength(vld *lneto.Validator, pf Frame) {
	validateLength(vld, hc.LenPacket(pf), hc.overhead, uint32(hc.BlockSize()), len(pf.RawData()))
}

// Open authenticates and decrypts in-place a frame already checked with [HalfConn.ValidateLength]
// and returns its wire length. After Open the frame is plaintext and should be checked with
// [Frame.ValidateSize] before reading payload. The tag is left in place after the packet.
func (hc *HalfConn) Open(pf Frame) (n int, err error) {
	n = int(4 + hc.LenPacket(pf) + hc.overhead)
	if n > len(pf.RawData()) {
		return 0, lneto.ErrTruncatedFrame // Do not read past len into capacity.
	}
	if hc.useAEAD() {
		if hc.used == math.MaxUint64 {
			return 0, lneto.ErrExhausted
		}
		pkt := pf.RawData()
		ovh := hc.Overhead()
		plain, err := hc.cipherA.Open(pkt[4:4], hc.nonce[:], pkt[4:n], pkt[:4])
		if err != nil {
			return 0, err
		}
		if 4+len(plain) != n-ovh {
			panic("ssh invariant violation")
		}
		hc.nextNonce()
	} else if hc.useFCipher() {
		if hc.used >= 1<<32 {
			return 0, lneto.ErrExhausted // The nonce is the sequence number, which wraps at 2^32.
		}
		if err = hc.cipherF.Open(hc.seq, pf.RawData()[:n]); err != nil {
			return 0, err
		}
		hc.used++
	}
	hc.seq++
	return n, nil
}

// nextNonce advances the invocation counter, which wraps within its 64 bits
// leaving the fixed field alone, RFC 5647 7.1.
func (hc *HalfConn) nextNonce() {
	hc.used++
	binary.BigEndian.PutUint64(hc.nonce[4:], binary.BigEndian.Uint64(hc.nonce[4:])+1)
}
