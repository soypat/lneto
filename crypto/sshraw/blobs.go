package sshraw

import (
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

// Parsers of the public key and signature blobs returned by [ParseKexECDHReply].
// Each returns views into its input and rejects trailing bytes. Only encoding
// is checked: keys are not validated and signatures are not verified.

const (
	nameEd25519    = "ssh-ed25519" // RFC 8709 4.
	nameRSA        = "ssh-rsa"     // RFC 4253 6.6. Also the key format of rsa-sha2-256 and rsa-sha2-512, RFC 8332 3.
	prefixECDSA    = "ecdsa-sha2-" // RFC 5656 3.1. Followed by the curve identifier.
	sizeEd25519Key = 32
)

// ParseSignature receives signature blob returning algorithm name and signature in algorithm encoding.
func ParseSignature(blob []byte) (alg, sig []byte, err error) {
	var dec decoder
	dec.Reset(blob)
	alg = dec.String()
	sig = dec.String()
	dec.end()
	if dec.IsFailed() {
		return nil, nil, dec.Err()
	}
	return alg, sig, nil
}

// ParseECDSASignature parses the sig of an ecdsa-sha2-* algorithm blob returned by ParseSignature.
func ParseECDSASignature(sig []byte) (r, s []byte, err error) {
	var dec decoder
	dec.Reset(sig)
	r = dec.MPInt()
	s = dec.MPInt()
	dec.end()
	if dec.IsFailed() {
		return nil, nil, dec.Err()
	}
	return r, s, nil
}

// ParseEd25519PublicKey parses an ssh-ed25519 public key blob returning the 32 byte key.
func ParseEd25519PublicKey(blob []byte) (key []byte, err error) {
	var dec decoder
	dec.Reset(blob)
	dec.alg(nameEd25519)
	key = dec.String()
	dec.end()
	if !dec.IsFailed() && len(key) != sizeEd25519Key {
		dec.Fail(lneto.ErrInvalidLengthField)
	}
	if dec.IsFailed() {
		return nil, dec.Err()
	}
	return key, nil
}

// ParseECDSAPublicKey parses an ecdsa-sha2-* public key blob returning curve identifier, i.e: "nistp256",
// and encoded point Q. Q is not checked to be on the curve.
func ParseECDSAPublicKey(blob []byte) (curve, q []byte, err error) {
	var dec decoder
	dec.Reset(blob)
	name := dec.String()
	curve = dec.String()
	q = dec.String()
	dec.end()
	if !dec.IsFailed() {
		if err := validateName(curve); err != nil {
			dec.Fail(err)
		} else if len(name) != len(prefixECDSA)+len(curve) || string(name[:len(prefixECDSA)]) != prefixECDSA ||
			!internal.BytesEqual(name[len(prefixECDSA):], curve) {
			dec.Fail(lneto.ErrInvalidField)
		}
	}
	if dec.IsFailed() {
		return nil, nil, dec.Err()
	}
	return curve, q, nil
}

// ParseRSAPublicKey parses an ssh-rsa public key blob, also used by rsa-sha2-256 and rsa-sha2-512,
// returning exponent e and modulus n as big endian magnitudes. Zero e or n is rejected.
func ParseRSAPublicKey(blob []byte) (e, n []byte, err error) {
	var dec decoder
	dec.Reset(blob)
	dec.alg(nameRSA)
	e = dec.MPInt()
	n = dec.MPInt()
	dec.end()
	if !dec.IsFailed() && (len(e) == 0 || len(n) == 0) {
		dec.Fail(lneto.ErrInvalidField)
	}
	if dec.IsFailed() {
		return nil, nil, dec.Err()
	}
	return e, n, nil
}
