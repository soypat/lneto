package sshraw

import (
	"encoding/binary"
	"math"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/lcrypto"
)

// HalfConn protects binary packets in one direction after SetAEAD is called, usually after [MsgNewKeys].
// HalfConn expects packets input via Seal and Open to be of their [Frame.WireLength]
type HalfConn struct {
	used     uint64 // Packets protected with the current key.
	aead     lcrypto.AEADCipher
	seq      uint32
	overhead uint32 // Auth tag bytes after the packet a.k.a Message Authentication Code (MAC).
	// TODO: same as with tlsraw, benchmark if keeping a full byte-slice nonce state is better.
	nonce [12]byte // Nonce of the next packet.
}

func (hc *HalfConn) SetAEAD(aead lcrypto.AEADCipher, iv *[12]byte) error {
	overhead := aead.Overhead()
	if aead.NonceSize() != len(iv) || overhead == 0 {
		return lneto.ErrInvalidConfig
	}
	hc.overhead = uint32(overhead)
	hc.aead = aead
	hc.nonce = *iv
	hc.used = 0
	return nil
}

// Seq returns the sequence number of the next packet.
func (hc *HalfConn) Seq() uint32 { return hc.seq }

// ResetSeq zeros sequence number. String key exchange does so after every [MsgNewKeys]. See Terrapin attack.
func (hc *HalfConn) ResetSeq() { hc.seq = 0 }

// HasKeys reports whether SetAEAD installed keys since the last Zeroize.
func (hc *HalfConn) HasKeys() bool { return hc.overhead != 0 }

// Zeroize forgets the keys and the sequence number.
func (hc *HalfConn) Zeroize() {
	if hc.HasKeys() {
		hc.aead.Zeroize()
	}
	*hc = HalfConn{}
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
	if hc.HasKeys() {
		if hc.used == math.MaxUint64 {
			return 0, lneto.ErrExhausted
		}
		overhead := hc.Overhead()
		sealed := hc.aead.Seal(pkt[4:4], hc.nonce[:], pkt[4:len(pkt)-overhead], pkt[:4])
		hc.nextNonce()
		if len(sealed)+4 != len(pkt) {
			panic("ssh invariant violated")
		}
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
	if hc.HasKeys() {
		return sizeGCMBlock
	}
	return minBlockSize
}

// Open authenticates and decrypts in-place a frame already checked with [Frame.ValidateLength]
// and returns its wire length. After Open the frame is plaintext and should be checked with
// [Frame.ValidateSize] before reading payload. The tag is left in place after the packet.
func (hc *HalfConn) Open(pf Frame) (n int, err error) {
	n = pf.WireLength(hc.overhead)
	if n > len(pf.RawData()) {
		return 0, lneto.ErrTruncatedFrame // Do not read past len into capacity.
	}
	if hc.HasKeys() {
		if hc.used == math.MaxUint64 {
			return 0, lneto.ErrExhausted
		}
		pkt := pf.RawData()
		ovh := hc.Overhead()
		plain, err := hc.aead.Open(pkt[4:4], hc.nonce[:], pkt[4:n], pkt[:4])
		if err != nil {
			return 0, err
		}
		if 4+len(plain) != n-ovh {
			panic("ssh invariant violation")
		}
		hc.nextNonce()
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
