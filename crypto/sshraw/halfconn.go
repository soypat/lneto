package sshraw

import (
	"encoding/binary"
	"math"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/lcrypto"
)

const (
	// SizeGCMTag is the tag size of aes128-gcm@openssh.com and aes256-gcm@openssh.com.
	SizeGCMTag = 16
	// sizeGCMBlock is the AES block size, the alignment of AEAD packets.
	sizeGCMBlock = 16
	// minPacket is the smallest packet, packet_length included and MAC excluded, RFC 4253 6.
	minPacket = 16
)

// HalfConn protects the binary packets of one direction, RFC 4253 6. Until
// SetAEAD it passes packets through unprotected, as SSH does before the first
// SSH_MSG_NEWKEYS, while still counting their sequence numbers.
//
// The AEAD mode is aes-gcm@openssh.com, RFC 5647 7: packet_length is sent in
// the clear as additional data and the 12 byte nonce is a 4 byte fixed field
// followed by an 8 byte invocation counter incremented after every packet.
// The sequence number takes no part in it. Buffers passed to an AEAD escape to
// the heap, so the nonce lives in the struct.
type HalfConn struct {
	aead  lcrypto.AEADCipher
	nonce [12]byte // Nonce of the next packet.
	used  uint64   // Packets protected with the current key.
	seq   uint32
}

// SetAEAD installs the AEAD keyed with the derived key and the matching IV.
// The sequence number is not reset: it counts every packet of the connection
// unless strict key exchange resets it, see [HalfConn.ResetSeq]. The caller
// owns construction of aead so that lneto never allocates cipher state.
func (hc *HalfConn) SetAEAD(aead lcrypto.AEADCipher, iv *[12]byte) error {
	if aead.NonceSize() != len(iv) || aead.Overhead() != SizeGCMTag {
		return lneto.ErrInvalidConfig
	}
	hc.aead = aead
	hc.nonce = *iv
	hc.used = 0
	return nil
}

// Seq returns the sequence number of the next packet.
func (hc *HalfConn) Seq() uint32 { return hc.seq }

// ResetSeq sets the sequence number to zero. Strict key exchange does so after
// every SSH_MSG_NEWKEYS, which is the Terrapin attack countermeasure.
func (hc *HalfConn) ResetSeq() { hc.seq = 0 }

// HasKeys reports whether SetAEAD installed keys since the last Zeroize.
func (hc *HalfConn) HasKeys() bool { return hc.aead != nil }

// Zeroize forgets the keys and the sequence number, leaving hc unprotected.
func (hc *HalfConn) Zeroize() {
	if hc.HasKeys() {
		hc.aead.Zeroize()
	}
	*hc = HalfConn{}
}

// WireLen returns the number of bytes on the wire of the packet whose first 4
// bytes are hdr, MAC or tag included, so a reader knows how much to read
// before calling Open. It rejects lengths that are too large, too small or not
// aligned to the block size before any of the packet is read.
func (hc *HalfConn) WireLen(hdr []byte) (int, error) {
	if len(hdr) < 4 {
		return 0, lneto.ErrTruncatedFrame
	}
	plen := binary.BigEndian.Uint32(hdr)
	var tag, block, aligned uint32 = 0, MinBlockSize, plen + 4
	if hc.HasKeys() {
		tag, block, aligned = SizeGCMTag, sizeGCMBlock, plen
	}
	if plen > MaxPacket-4-tag {
		return 0, lneto.ErrInvalidLengthField
	} else if 4+plen < minPacket || aligned%block != 0 {
		return 0, lneto.ErrInvalidLengthField
	}
	return int(4 + plen + tag), nil
}

// Seal protects a complete packet, as returned by [Encoder.EndPacket], in place
// and returns it as it goes on the wire. With keys pkt's capacity must fit the
// tag and pkt must be padded for AEAD, that is with blockSize 16 and aad true.
func (hc *HalfConn) Seal(pkt []byte) ([]byte, error) {
	pf, err := NewPacketFrame(pkt)
	if err != nil {
		return nil, err
	} else if len(pf.RawData()) != len(pkt) {
		return nil, lneto.ErrInvalidLengthField
	}
	if !hc.HasKeys() {
		if err = pf.ValidateAlignment(MinBlockSize, false); err != nil {
			return nil, err
		}
		hc.seq++
		return pkt, nil
	}
	if err = pf.ValidateAlignment(sizeGCMBlock, true); err != nil {
		return nil, err
	} else if cap(pkt)-len(pkt) < SizeGCMTag {
		return nil, lneto.ErrShortBuffer
	} else if hc.used == math.MaxUint64 {
		return nil, lneto.ErrExhausted // Nonces must not repeat; rekey instead.
	}
	sealed := hc.aead.Seal(pkt[4:4], hc.nonce[:], pkt[4:], pkt[:4])
	hc.nextNonce()
	hc.seq++
	return pkt[:4+len(sealed)], nil
}

// Open authenticates and decrypts in place a packet of exactly [HalfConn.WireLen]
// bytes and returns its plaintext frame.
func (hc *HalfConn) Open(pkt []byte) (PacketFrame, error) {
	n, err := hc.WireLen(pkt)
	if err != nil {
		return PacketFrame{}, err
	} else if n != len(pkt) {
		return PacketFrame{}, lneto.ErrInvalidLengthField
	}
	if hc.HasKeys() {
		if hc.used == math.MaxUint64 {
			return PacketFrame{}, lneto.ErrExhausted
		}
		plain, err := hc.aead.Open(pkt[4:4], hc.nonce[:], pkt[4:], pkt[:4])
		if err != nil {
			return PacketFrame{}, err
		}
		pkt = pkt[:4+len(plain)]
		hc.nextNonce()
	}
	pf, err := NewPacketFrame(pkt)
	if err != nil {
		return PacketFrame{}, err
	}
	hc.seq++
	return pf, nil
}

// nextNonce advances the invocation counter, which wraps within its 64 bits
// leaving the fixed field alone, RFC 5647 7.1.
func (hc *HalfConn) nextNonce() {
	hc.used++
	binary.BigEndian.PutUint64(hc.nonce[4:], binary.BigEndian.Uint64(hc.nonce[4:])+1)
}
