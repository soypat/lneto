// package lcrypto is an internal lneto package that provides
// abstractions over cryptographic constructs like ciphers
// and certificates.
package lcrypto

import "hash"

// AEADCipher is a superset of cipher.AEAD. It does not implement cipher.AEAD since
// there are no counterparts for Zeroize and Rekey which are needed for a heapless, secure implementation.
//
// crypto/cipher is not imported here so that wire-format users of this package,
// e.g. pcap, do not link Go's crypto packages and the init functions they carry.
type AEADCipher interface {
	NonceSize() int                                                     // NonceSize implements cipher.AEAD.
	Overhead() int                                                      // Overhead implements cipher.AEAD.
	Seal(dst, nonce, plaintext, additionalData []byte) []byte           // Seal implements cipher.AEAD.
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) // Open implements cipher.AEAD.

	// Rekey discards current key and installs a new one leaving cipher ready for use.
	Rekey(key []byte) error
	// Zeroize wipes the key and any derived state, leaving the cipher unkeyed.
	// After a call to Zeroize Rekey must be called to reuse AEADCipher.
	// The best most standard library packages can do is drop the reference so it can be garbage collected.
	Zeroize()
}

type Suite interface {
	// ID returns RFC 8446 B.4 wire value used to define cipher suite used.
	// Matched on offer for a TLS conn:
	//  for _, s := range conn.suites {
	//  	if s.ID() == offered { c.suite = s; break }
	//  }
	ID() uint16
	// NewAEAD returns an unkeyed record cipher. Callers call once
	// per connection and can reuse previously created ciphers.
	NewAEAD() AEADCipher
	// NewHash returns a hash for the suite's key schedule. It allocates, so
	// callers construct one per connection and call Reset to reuse it.
	NewHash() hash.Hash
	// KeyLen is the length in bytes of the key passed to [AEADCipher.Rekey].
	KeyLen() int
}
