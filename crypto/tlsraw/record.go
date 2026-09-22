package tlsraw

import (
	"encoding/binary"
	"math"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/lcrypto"
)

// HalfConn protects the records of one direction, RFC 8446 5.2. It works with any
// AEAD of the TLS 1.3 suites: 12 byte nonce and 16 byte tag, checked by SetAEAD.
// Seal and Open do not allocate and work in place. Buffers passed to an AEAD
// escape to the heap, so the nonce lives in the struct.
type HalfConn struct {
	aead  lcrypto.AEADCipher
	iv    [12]byte
	nonce [12]byte // Per-record nonce: iv XOR sequence number.
	seq   uint64
}

// SetAEAD installs the AEAD keyed with a traffic key and the matching IV, and
// restarts the sequence number. The caller owns construction of aead so that
// lneto never allocates cipher state.
func (hc *HalfConn) SetAEAD(aead lcrypto.AEADCipher, iv [12]byte) error {
	if aead.NonceSize() != len(iv) || aead.Overhead() != SizeAEADTag {
		return lneto.ErrInvalidConfig
	}
	hc.aead = aead
	hc.iv = iv
	hc.seq = 0
	return nil
}

// Seal protects the content in rec[SizeHeaderRecord:] in place and returns the
// complete record. rec's capacity must fit the content type byte and AEAD tag.
func (hc *HalfConn) Seal(rec []byte, ct ContentType) ([]byte, error) {
	if !hc.HasKeys() {
		return nil, lneto.ErrBadState // zeroed; Needs SetAEAD to install the keys.
	}
	overhead := 1 + hc.aead.Overhead()
	if len(rec) < SizeHeaderRecord {
		return nil, lneto.ErrShortBuffer
	} else if cap(rec)-len(rec) < overhead {
		return nil, lneto.ErrShortBuffer
	} else if len(rec)-SizeHeaderRecord > MaxPlaintext {
		return nil, lneto.ErrInvalidLengthField
	}
	if err := hc.nextNonce(); err != nil {
		return nil, err
	}
	rec = append(rec, byte(ct)) // TLSInnerPlaintext without padding.
	rec[0] = byte(ContentTypeApplicationData)
	binary.BigEndian.PutUint16(rec[1:3], VersionTLS12)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(rec)-SizeHeaderRecord+hc.aead.Overhead()))
	sealed := hc.aead.Seal(rec[SizeHeaderRecord:SizeHeaderRecord], hc.nonce[:], rec[SizeHeaderRecord:], rec[:SizeHeaderRecord])
	return rec[:SizeHeaderRecord+len(sealed)], nil
}

// Open decrypts a complete record in place and returns its content and real content type.
func (hc *HalfConn) Open(rec []byte) (content []byte, ct ContentType, err error) {
	if !hc.HasKeys() {
		return nil, 0, lneto.ErrBadState // zeroed; Needs SetAEAD to install the keys.
	}
	if len(rec) < SizeHeaderRecord+1+hc.aead.Overhead() {
		return nil, 0, lneto.ErrTruncatedFrame
	} else if ContentType(rec[0]) != ContentTypeApplicationData {
		return nil, 0, lneto.ErrInvalidField
	}
	n := int(binary.BigEndian.Uint16(rec[3:5]))
	if n != len(rec)-SizeHeaderRecord || n > MaxCiphertext {
		return nil, 0, lneto.ErrInvalidLengthField
	}
	if err = hc.nextNonce(); err != nil {
		return nil, 0, err
	}
	plain, err := hc.aead.Open(rec[SizeHeaderRecord:SizeHeaderRecord], hc.nonce[:], rec[SizeHeaderRecord:], rec[:SizeHeaderRecord])
	if err != nil {
		return nil, 0, err
	}
	// Content type is the last non-zero byte; zeros after it are padding.
	i := len(plain) - 1
	for i >= 0 && plain[i] == 0 {
		i--
	}
	if i < 0 {
		return nil, 0, lneto.ErrInvalidField
	}
	return plain[:i], ContentType(plain[i]), nil
}

// nextNonce sets the nonce of the next record and advances the sequence number.
func (hc *HalfConn) nextNonce() error {
	if hc.seq == math.MaxUint64 {
		return lneto.ErrExhausted // Sequence numbers must not wrap; rekey instead.
	}
	hc.nonce = hc.iv
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], hc.seq)
	for i := range seq {
		hc.nonce[4+i] ^= seq[i]
	}
	hc.seq++
	return nil
}

// HasKeys reports whether SetAEAD installed keys since the last Zeroize.
func (hc *HalfConn) HasKeys() bool { return hc.aead != nil }

// Zeroize forgets the keys. SetAEAD must be called before reuse.
func (hc *HalfConn) Zeroize() { *hc = HalfConn{} }
