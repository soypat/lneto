// package lcrypto is an internal lneto package that provides
// abstractions over cryptographic constructs like ciphers
// and certificates.
//
// # Conventions
//
// Interface implementations consist of:
//   - "Shared" like [Credential],[Verifier] which are consulted by several cryptographic
//     algorithm users such as several tls.Conn's. These should be safe for concurrent use.
//   - "Instances" like  [AEADCipher],[Exchanger] which are owned by a single consumer i.e: tls.Conn.
//     These are not necessarily safe for concurrent use.
//
// lcrypto does not say how Instances come to be: the consumer constructs them,
// as tlsauto's Suite and KeyExchange do, and keeps them for as long as it likes.
//
// This separation allows for Instance reuse throughout the lifetime of a consumer
// which may want to avoid allocating a Cipher for every action performed.
// For this reason lcrypto Instances usually have methods which deviate from standard library
// interfaces or other famous Go interfaces. Notably [AEADCipher] is a superset of cipher.AEAD
// with the addition of [AEADCipher.Rekey] and [AEADCipher.Zeroize] methods for reuse and security purposes, respectively.
package lcrypto

import (
	"io"
)

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

	// Rekey discards current key and installs a new one leaving cipher ready for use. Rekey must not hold the reference after returning.
	//
	// key is local: a traffic key derived by the key schedule, never peer data.
	Rekey(key []byte) error
	// Zeroize wipes the key and any derived state, leaving the cipher unkeyed.
	// After a call to Zeroize Rekey must be called to reuse AEADCipher.
	// The best most standard library packages can do is drop the reference so it can be garbage collected.
	Zeroize()
}

// Exchanger implements the core key exchange logic i.e: Diffie-Hellman or ML-KEM.
// Methods are named after the caller i.e:
// ClientGenerateRekey means the client calls this method to generate a key and rekey itself.
type Exchanger interface {
	// ClientGenerateRekey draws a fresh key from rand and
	// writes its public share into dstClientShare and rekeys itself. Calling it again rekeys in place so a
	// pooled connection need not build a new Exchanger.
	//
	// dstClientShare is transmitted to the server, who then would call [Exchanger.ServerSharedRekey] on dstClientShare as clientShare.
	ClientGenerateRekey(dstClientShare []byte, rand io.Reader) (n int, err error)

	// ServerSharedRekey writes the server key_share into dstServerShare: a fresh public key
	// for Diffie-Hellman, or a ciphertext encapsulated to clientShare for ML-KEM. It writes
	// the resulting shared secret into dstShared.
	//
	// dstServerShare is transmitted to the client who will then generate dstShared on their side. dstShared is not transmitted.
	ServerSharedRekey(dstServerShare, dstShared, clientShare []byte, rand io.Reader) (nShare, nShared int, err error)

	// ClientShared mixes the received serverShare with the generated key to create
	// the shared key it then writes into dstShared.
	//
	// serverShare contains the server's share.
	ClientShared(dstShared, serverShare []byte) (n int, err error)

	// Zeroize wipes the private key and any retained shared secret, leaving the Exchanger unkeyed.
	// ClientGenerateRekey or ServerSharedRekey must be called before reuse. Zeroing public state is optional.
	Zeroize()
}

// Credential models the local root of trust ([CertChain]) and the proof
// of ownership of that trust ([Credential.Scheme],[Credential.Sign]).
// Credential is the "offering" counterpart of the "receiving" [Verifier]
// during credential authentication.
type Credential interface {
	// CertChain is the local root of trust.
	CertChain

	// Scheme returns the RFC 8446 B.3.1.3 SignatureScheme used to sign, chosen
	// from those the peer offered or 0 if none supported.
	//
	// offered is remote: the peer's signature_algorithms extension, unvalidated.
	Scheme(offered []uint16) uint16

	// Sign writes the RFC 8446 4.4.3 CertificateVerify signature over msg into sig.
	// Implementations hash msg with the digest their [Credential.Scheme] names;
	// Ed25519 signs it whole. Entropy is the implementation's concern so a TPM
	// or HSM can hold its own.
	//
	// msg is the complete, unhashed 4.4.3 content: [64B pfx, context string,
	// 0x00, handshake transcript hash]. The padding and context domain-separate
	// the signature, so implementations sign msg as given and prepend nothing
	// of their own.
	Sign(sig, msg []byte, selectedScheme uint16) (n int, err error)
}

// Verifier judges the peer's identity. It subsumes trust anchors, identity
// matching (name or address) and expiry so the policy cannot be configured apart, and keeps
// X.509 parsing out of lneto. Counterpart of [Credential]. Verifier can be used concurrently.
type Verifier interface {
	// VerifyPeer returns nil to accept the peer. Nil return signals that sig is the leaf key's signature of msg under the scheme.
	// Do not retain or modify slices.
	//
	//  - chainView is remote [CertChain] and potentially adversarial.
	//  - scheme is peer's [Credential.Scheme] of CertificateVerify. VerifyPeer checks if it suits the leaf's key type.
	//  - peerIsServer=true signals chainView is server(peer) so leaf must allow serverAuth.
	//    peerIsServer=false when chainView is client presenting a certificate for mutual TLS (clientAuth).
	//  - expectName is expected DNS name or IP literal (i.e:"10.0.0.1") configured before connection when peerIsServer=true.
	//	- msg is RFC 8446 4.4.3 content: [64B pfx, context string, 0x00, handshake transcript hash]
	//  - sig is remote peer's [Credential.Sign]. Treat as adversarial.
	VerifyPeer(chainView CertChain, scheme uint16, peerIsServer bool, expectName, msg, sig []byte) error
}

// CertChain is a DER certificate chain ordered with server (leaf) certs first
// followed by intermediary CA certs (i.e: DigiCert, Let's Encrypt).
//
//   - local: stored locally and trusted as is the case with [Credential.CertChain].
//   - remote: Chains can also be received over the network as in the case of TLS, in which case
//     [Verifier.VerifyPeer] would be called on the CertChain before trusting it.
type CertChain interface {
	// NumCerts returns the number of certificates, leafs first.
	NumCerts() int
	// Cert writes the i'th (leafs first) DER certificate into dst. If dst is too short
	// Cert writes nothing and returns the required length with [io.ErrShortBuffer].
	Cert(dst []byte, i int) (n int, err error)
	// CertView returns the i'th (leafs first) DER certificate without copying. It is an alternative
	// to Cert used in cases where the caller knows the CertChain is in memory i.e: [Verifier.VerifyPeer].
	// CertView may choose to panic when not addressable, so a chain passed to
	// [Verifier.VerifyPeer] must implement it. Do not mutate returned slice.
	CertView(i int) ([]byte, error)
}
