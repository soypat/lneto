package rfc8448

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"hash"

	"github.com/soypat/lneto/crypto/internal/lcrypto"
)

var (
	_ lcrypto.AEADCipher = (*gcmAEAD)(nil)
)

// errUnkeyed is returned by Open on a cipher that has not been keyed with Rekey.
var errUnkeyed = errors.New("rfc8448: AES-GCM used before Rekey")

// TLS_AES_128_GCM_SHA256 described as the wire value, key length and constructors
// a consumer needs to build its own cipher suite type, i.e: tlsauto.Suite. They
// live here rather than in tlsraw so that tlsraw keeps its crypto/* import-free
// guarantee; see TestNoCryptoImports.
const (
	AES128GCMSHA256ID     = 0x1301 // RFC 8446 B.4 wire value of TLS_AES_128_GCM_SHA256.
	AES128GCMSHA256KeyLen = 16     // AES-128 key length in bytes.
)

// NewSHA256 returns a SHA-256 hash for the key schedule.
func NewSHA256() hash.Hash { return sha256.New() }

// NewAES128GCM returns an unkeyed AES-GCM cipher. Rekey must be called before
// the first Seal or Open.
func NewAES128GCM() lcrypto.AEADCipher { return new(gcmAEAD) }

// gcmAEAD adapts the standard library's AES-GCM to [lcrypto.AEADCipher].
//
// Rekey allocates: crypto/aes cannot re-key an expanded AES key schedule in
// place, so a fresh cipher.AEAD is built on every key change. An in-house
// AES-GCM would not need to, which is the point of the Rekey method existing.
type gcmAEAD struct {
	aead cipher.AEAD
}

// NonceSize returns the AES-GCM nonce length. It is a constant, so it is valid
// to call on an unkeyed cipher, which is what lets [tlsraw.HalfConn.SetAEAD]
// validate a cipher before it is keyed.
func (*gcmAEAD) NonceSize() int { return 12 }

// Overhead returns the AES-GCM tag length. Constant, as with NonceSize.
func (*gcmAEAD) Overhead() int { return 16 }

// Seal panics if the cipher is unkeyed. cipher.AEAD.Seal has no error return
// and already panics on misuse, so this matches the standard library.
func (g *gcmAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if g.aead == nil {
		panic(errUnkeyed.Error())
	}
	return g.aead.Seal(dst, nonce, plaintext, additionalData)
}

func (g *gcmAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if g.aead == nil {
		return nil, errUnkeyed
	}
	return g.aead.Open(dst, nonce, ciphertext, additionalData)
}

func (g *gcmAEAD) Rekey(key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	g.aead = aead
	return nil
}

// Zeroize drops the cipher, leaving it unkeyed. It cannot wipe the key: the
// standard library's expanded AES key schedule is unreachable from here, so the
// old state is left to the garbage collector. Only an in-house AES-GCM can
// honour this method fully.
func (g *gcmAEAD) Zeroize() { g.aead = nil }
