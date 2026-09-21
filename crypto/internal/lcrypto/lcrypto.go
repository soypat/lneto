// package lcrypto is an internal lneto package that provides
// abstractions over cryptographic constructs like ciphers
// and certificates.
//
// # Conventions
//
// Interface implementations consist of:
//   - "Factories" like [Suite],[KeyExchange],[Verifier] which are shared among cryptographic
//     algorithm users such as several tls.Conn's. These should be safe for concurrent use.
//   - "Instances" like  [AEADCipher],[Exchanger] which are owned by a single consumer i.e: tls.Conn.
//     These are not necessarily safe for concurrent use.
//
// This separation allows for Instance reuse throughout the lifetime of a consumer
// which may want to avoid allocating a Cipher for every action performed.
// For this reason lcrypto Instances usually have methods which deviate from standard library
// interfaces or other famous Go interfaces. Notably [AEADCipher] is a superset of cipher.AEAD
// with the addition of [AEADCipher.Rekey] and [AEADCipher.Zeroize] methods for reuse and security purposes, respectively.
package lcrypto

import (
	"hash"
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

	// Rekey discards current key and installs a new one leaving cipher ready for use.
	//
	// key is local: a traffic key derived by the key schedule, never peer data.
	Rekey(key []byte) error
	// Zeroize wipes the key and any derived state, leaving the cipher unkeyed.
	// After a call to Zeroize Rekey must be called to reuse AEADCipher.
	// The best most standard library packages can do is drop the reference so it can be garbage collected.
	Zeroize()
}

// Suite is the concurrent-safe factory of a TLS 1.3 cipher suite, RFC 8446 B.4.
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

// KeyExchange is the concurrent-safe factory half of an ephemeral key agreement
// group, RFC 8446 4.2.8.
type KeyExchange interface {
	// ID returns the RFC 8446 B.3.1.4 NamedGroup wire value.
	ID() uint16
	// PubLen is the length of the key share written by [Exchanger.Generate],
	// and the expected length of the peer share passed to [Exchanger.Shared].
	PubLen() int
	// SharedLen is the length of the secret written by [Exchanger.Shared].
	SharedLen() int
	// NewExchanger returns an unkeyed key pair. Callers build one per
	// connection and call Generate again to reuse it.
	NewExchanger() Exchanger
}

// Exchanger holds one ephemeral key pair.
type Exchanger interface {
	// Generate discards any current key pair, draws a fresh one from rand and
	// writes its public share into dstPub. Calling it again rekeys in place so a
	// pooled connection need not build a new Exchanger.
	//
	// dstPub is transmitted to the peer, who then would call [Exchanger.Shared] on dstPub as peerPub.
	Generate(dstPub []byte, rand io.Reader) (n int, err error)
	// Shared writes the agreed secret for the peer's share into dst. It fails
	// if Generate has not been called, and on a peer share that is malformed
	// or, for the curve groups of RFC 7748, of small order.
	//
	// peerPub is received from remote peer who generated it via [Exchanger.Generate].
	Shared(dst, peerPub []byte) (n int, err error)
	// Zeroize wipes the private key and sensitive derived state, leaving the Exchanger unkeyed.
	// Generate must be called before reuse. Zeroing public and shared derived state is optional.
	Zeroize()
}

// Credential models the local root of trust ([CertChain]) and the proof
// of ownership of that trust ([Credential.Scheme],[Credential.Sign]).
// Credential is the "offering" counterpart of the "receiving" [Verifier]
// during credential authetication.
type Credential interface {
	// CertChain is the local root of trust.
	CertChain

	// Scheme returns the RFC 8448 SignatureScheme used to sign, chosen
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
	Sign(sig, msg []byte) (n int, err error)
}

// Verifier judges the peer's identity. It subsumes trust anchors, hostname
// matching and expiry so the policy cannot be configured apart, and keeps
// X.509 parsing out of lneto. Counterpart of [Credential]. Verifier can be used concurrently.
type Verifier interface {
	// VerifyPeer returns nil to accept the peer. It judges the chain (trust anchors, serverName,
	// expiry, key usage for the peer's role) and checks that sig is the leaf key's signature of msg
	// under scheme. A nil return is the only way a peer becomes authenticated. A bad signature on an
	// otherwise acceptable chain returns [lneto.ErrBadSignature].
	//
	//  - chainView is remote and potentially adversarial. Its certificates are read with [CertChain.CertView].
	//  - peerIsServer=true when chainView is the server in interaction, so the leaf must allow serverAuth.
	//    peerIsServer=false when chainView is a client presenting a certificate for mutual TLS (clientAuth).
	//  - scheme is the RFC 8446 B.3.1.3 SignatureScheme of the peer's CertificateVerify. The caller has
	//    checked it is one it offered; the implementation must check it suits the leaf's key type.
	//  - serverName is the name the leaf must match, the SNI sent by the client. Empty when peerIsServer=false.
	//  - msg is the complete, unhashed RFC 8446 4.4.3 content: [64B pfx, context string, 0x00,
	//    handshake transcript hash], built by the caller. Implementations verify msg as given.
	//  - sig is the signature from the peer's CertificateVerify, remote and potentially adversarial.
	//
	// chain, serverName, msg and sig are only valid for the duration of the call and must not be
	// retained or modified: they point into the caller's buffers, which are reused by the next connection.
	VerifyPeer(chainView CertChain, peerIsServer bool, scheme uint16, serverName, msg, sig []byte) error
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
	// CertView may choose to panic when not addressable. Do not mutate returned slice.
	CertView(i int) ([]byte, error)
}
