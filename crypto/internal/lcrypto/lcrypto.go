// package lcrypto is an internal lneto package that provides
// abstractions over cryptographic constructs like ciphers
// and certificates.

package lcrypto

// AEADCipher is the subset of [crypto/cipher.AEAD] used by [tlsraw.HalfConn]; any cipher.AEAD
// satisfies it. it exists to prevent import of crypto/cipher which
// bring in init() functions in several package.
type AEADCipher interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}
