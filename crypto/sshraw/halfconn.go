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
	overhead uint32 // gcmTag
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

// Seal encrypts a complete already-validated packet in-place and returns it as it goes on the wire.
// When HalfConn is keyed the PacketFrame will treat the last [HalfConn.Overhead] bytes as non-payload space for GCM tag.
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
		pkt = pkt[:4+len(sealed)]
	}
	hc.seq++
	return len(pkt), nil
}

func (hc *HalfConn) Overhead() int {
	return int(hc.overhead)
}

// Open authenticates and decrypts an already validated packet in-place of exactly [HalfConn.WireLen]
// bytes and returns plaintext frame.
func (hc *HalfConn) Open(pf Frame) (n int, err error) {
	n = pf.WireLength(hc.overhead)
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
