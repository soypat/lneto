package siv

import (
	"crypto/aes"
	"crypto/cipher"
	"hash"
)

// newCMAC returns a [hash.Hash] implementing AES-CMAC (RFC 4493) using the
// given key. The key must be a valid AES key (16, 24 or 32 bytes).
func newCMAC(key []byte) (hash.Hash, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c := &aesCMAC{block: block}
	cmacSubkeys(block, &c.k1, &c.k2)
	return c, nil
}

// aesCMAC implements AES-CMAC per RFC 4493.
// It buffers the most-recently-seen block so that Sum can apply K1/K2
// to the final block without re-processing earlier blocks.
type aesCMAC struct {
	block  cipher.Block
	k1, k2 [16]byte
	x      [16]byte // running CBC-MAC state
	buf    [16]byte // buffered last block (possibly partial)
	bufLen int
}

func (c *aesCMAC) BlockSize() int { return 16 }
func (c *aesCMAC) Size() int      { return 16 }

func (c *aesCMAC) Reset() {
	c.x = [16]byte{}
	c.bufLen = 0
}

func (c *aesCMAC) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		if c.bufLen == 16 && len(p) > 0 {
			xor16(&c.x, &c.buf)
			c.block.Encrypt(c.x[:], c.x[:])
			c.bufLen = 0
		}
		n := copy(c.buf[c.bufLen:], p)
		c.bufLen += n
		p = p[n:]
	}
	return total, nil
}

func (c *aesCMAC) Sum(b []byte) []byte {
	tmp := *c
	var last [16]byte
	if tmp.bufLen == 16 {
		xor16(&tmp.x, &tmp.buf)
		xor16(&tmp.x, &tmp.k1)
	} else {
		copy(last[:], tmp.buf[:tmp.bufLen])
		last[tmp.bufLen] = 0x80
		xor16(&tmp.x, &last)
		xor16(&tmp.x, &tmp.k2)
	}
	tmp.block.Encrypt(tmp.x[:], tmp.x[:])
	return append(b, tmp.x[:]...)
}

// cmacSubkeys derives the two CMAC subkeys K1 and K2 per RFC 4493 §2.3.
func cmacSubkeys(block cipher.Block, k1, k2 *[16]byte) {
	var l [16]byte
	block.Encrypt(l[:], l[:])
	msb := l[0] >> 7
	shiftLeft1(k1, &l)
	if msb == 1 {
		k1[15] ^= 0x87
	}
	msb = k1[0] >> 7
	shiftLeft1(k2, k1)
	if msb == 1 {
		k2[15] ^= 0x87
	}
}

func shiftLeft1(dst, src *[16]byte) {
	var carry byte
	for i := 15; i >= 0; i-- {
		next := src[i] >> 7
		dst[i] = src[i]<<1 | carry
		carry = next
	}
}
