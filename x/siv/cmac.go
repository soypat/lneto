// Package siv implements AES-SIV-CMAC authenticated encryption as specified
// in RFC 5297. The implementation is derived from the generic (non-asm) code
// in github.com/secure-io/siv-go (MIT licence, Copyright 2018 SecureIO).
//
// AES-SIV is a nonce-misuse-resistant AEAD: unlike AES-GCM it remains secure
// even when a nonce is accidentally reused, because the synthetic IV (SIV) is
// derived deterministically from the ciphertext. Repeated nonces degrade
// semantic security (an attacker learns that two plaintexts are identical) but
// do NOT break confidentiality or integrity.
//
// # NTS usage
//
// RFC 8915 (Network Time Security) mandates AEAD_AES_SIV_CMAC_256 for
// authenticated NTP packets. Use [NewAESSIVCMAC256] with the 32-byte keys
// exported by the NTS-KE TLS exchange.
package siv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"hash"
)

var errOpen = errors.New("siv: message authentication failed")

// NewAESSIVCMAC256 returns a [cipher.AEAD] implementing AES-SIV-CMAC-256 as
// required by RFC 8915. The key must be exactly 32 bytes: the first 16 bytes
// are used for the CMAC PRF and the last 16 bytes for the AES-CTR stream
// cipher.
//
// NonceSize returns 16 (one AES block). A nil or empty nonce is also accepted
// for deterministic (nonce-less) operation.
// Overhead returns 16 (the prepended SIV tag).
func NewAESSIVCMAC256(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, aes.KeySizeError(len(key))
	}
	return newSIVCMAC(key)
}

func newSIVCMAC(key []byte) (cipher.AEAD, error) {
	cmacKey := key[:len(key)/2]
	ctrKey := key[len(key)/2:]
	mac, err := newCMAC(cmacKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(ctrKey)
	if err != nil {
		return nil, err
	}
	return &aesSIVCMAC{mac: mac, block: block}, nil
}

type aesSIVCMAC struct {
	mac   hash.Hash
	block cipher.Block
}

func (c *aesSIVCMAC) NonceSize() int { return aes.BlockSize }
func (c *aesSIVCMAC) Overhead() int  { return aes.BlockSize }

func (c *aesSIVCMAC) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if n := len(nonce); n != 0 && n != c.NonceSize() {
		panic("siv: incorrect nonce length given to AES-SIV-CMAC")
	}
	ret := append(dst, make([]byte, c.Overhead()+len(plaintext))...)
	out := ret[len(dst):]
	siv := s2v(additionalData, nonce, plaintext, c.mac)
	copy(out, siv[:])
	iv := sivToIV(siv)
	ctrXOR(c.block, iv, out[len(siv):], plaintext)
	return ret
}

func (c *aesSIVCMAC) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if n := len(nonce); n != 0 && n != c.NonceSize() {
		panic("siv: incorrect nonce length given to AES-SIV-CMAC")
	}
	if len(ciphertext) < c.Overhead() {
		return dst, errOpen
	}
	var tag [16]byte
	copy(tag[:], ciphertext[:16])
	ciphertext = ciphertext[16:]

	ret := append(dst, make([]byte, len(ciphertext))...)
	plaintext := ret[len(dst):]

	iv := sivToIV(tag)
	ctrXOR(c.block, iv, plaintext, ciphertext)

	v := s2v(additionalData, nonce, plaintext, c.mac)
	if subtle.ConstantTimeCompare(v[:], tag[:]) != 1 {
		for i := range plaintext {
			plaintext[i] = 0
		}
		return dst, errOpen
	}
	return ret, nil
}

// s2v implements the S2V pseudo-random function from RFC 5297 §2.4.
// It accepts up to two associated data components (additionalData, nonce)
// matching the NTS usage pattern (RFC 8915 does not use nonce; pass nil).
func s2v(additionalData, nonce, plaintext []byte, mac hash.Hash) [16]byte {
	var zero, d, t [16]byte

	mac.Write(zero[:])
	mac.Sum(d[:0])
	mac.Reset()

	if len(additionalData) > 0 {
		mac.Write(additionalData)
		mac.Sum(t[:0])
		mac.Reset()
		dbl(&d)
		xor16(&d, &t)
	}
	if len(nonce) > 0 {
		mac.Write(nonce)
		mac.Sum(t[:0])
		mac.Reset()
		dbl(&d)
		xor16(&d, &t)
	}

	var last [16]byte
	if len(plaintext) >= 16 {
		n := len(plaintext) - 16
		mac.Write(plaintext[:n])
		copy(last[:], plaintext[n:])
		xor16(&last, &d)
	} else {
		copy(last[:], plaintext)
		last[len(plaintext)] = 0x80
		dbl(&d)
		xor16(&last, &d)
	}
	mac.Write(last[:])
	mac.Sum(last[:0])
	mac.Reset()
	return last
}

// sivToIV clears bits 31 and 63 of the SIV before use as an AES-CTR IV,
// per RFC 5297 §2.5.
func sivToIV(siv [16]byte) [16]byte {
	siv[8] &= 0x7f
	siv[12] &= 0x7f
	return siv
}

// ctrXOR encrypts/decrypts src into dst using AES-CTR with the given IV.
// Uses only stack allocations.
func ctrXOR(block cipher.Block, iv [16]byte, dst, src []byte) {
	var counter, keystream [16]byte
	copy(counter[:], iv[:])
	for len(src) > 0 {
		block.Encrypt(keystream[:], counter[:])
		n := min(len(src), 16)
		for i := range n {
			dst[i] = src[i] ^ keystream[i]
		}
		src = src[n:]
		dst = dst[n:]
		ctrIncrement(&counter)
	}
}

func ctrIncrement(b *[16]byte) {
	for i := 15; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

func xor16(dst, src *[16]byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

// dbl performs a GF(2^128) doubling of b, as defined in RFC 5297 §2.3.
func dbl(b *[16]byte) {
	var carry byte
	for i := 15; i >= 0; i-- {
		next := b[i] >> 7
		b[i] = b[i]<<1 | carry
		carry = next
	}
	b[15] ^= byte(subtle.ConstantTimeSelect(int(carry), 0x87, 0))
}
