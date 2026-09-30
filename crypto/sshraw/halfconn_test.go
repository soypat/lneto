package sshraw

import (
	"bytes"
	"cmp"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"go/build"
	"strings"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/rfc8448"
)

// TestNoCryptoImports guards against linking Go's crypto packages, as tlsraw
// does: their init functions carry FIPS self-tests TinyGo cannot eliminate.
func TestNoCryptoImports(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range pkg.Imports {
		if imp == "crypto" || strings.HasPrefix(imp, "crypto/") {
			t.Errorf("sshraw must not import %q; take the primitive from the caller instead", imp)
		}
	}
}

// ctrHMAC is a [CipherFrame] of chacha20-poly1305@openssh.com's shape built
// from the standard library, which has no importable ChaCha20: packet_length
// is encrypted under a key of its own, the rest under another, both with a
// nonce of the sequence number, and the tag covers the encrypted packet and
// is checked before anything is decrypted. It tests HalfConn, not a cipher.
type ctrHMAC struct {
	lenKey, bodyKey cipher.Block
	macKey          []byte
}

var _ CipherFrame = (*ctrHMAC)(nil)

func (c *ctrHMAC) Rekey(key []byte) (err error) {
	if len(key) != 64 {
		return errors.New("ctrHMAC: key must be 64 bytes")
	}
	c.bodyKey, err = aes.NewCipher(key[:16])
	if err == nil {
		c.lenKey, err = aes.NewCipher(key[16:32])
	}
	c.macKey = append(c.macKey[:0], key[32:]...)
	return err
}

func (c *ctrHMAC) Zeroize()       { *c = ctrHMAC{} }
func (c *ctrHMAC) Overhead() int  { return 16 }
func (c *ctrHMAC) BlockSize() int { return 8 } // As chacha20-poly1305@openssh.com.

func (c *ctrHMAC) xor(block cipher.Block, seq uint32, b []byte) {
	var iv [16]byte
	binary.BigEndian.PutUint64(iv[:], uint64(seq))
	cipher.NewCTR(block, iv[:]).XORKeyStream(b, b)
}

func (c *ctrHMAC) tag(seq uint32, sealed []byte) []byte {
	m := hmac.New(sha256.New, c.macKey)
	binary.Write(m, binary.BigEndian, seq)
	m.Write(sealed)
	return m.Sum(nil)[:c.Overhead()]
}

func (c *ctrHMAC) DecryptLength(seq uint32, encLength [4]byte) uint32 {
	c.xor(c.lenKey, seq, encLength[:])
	return binary.BigEndian.Uint32(encLength[:])
}

func (c *ctrHMAC) Seal(seq uint32, frame []byte) {
	n := len(frame) - c.Overhead()
	c.xor(c.lenKey, seq, frame[:4])
	c.xor(c.bodyKey, seq, frame[4:n])
	copy(frame[n:], c.tag(seq, frame[:n]))
}

func (c *ctrHMAC) Open(seq uint32, frame []byte) error {
	n := len(frame) - c.Overhead()
	if !hmac.Equal(frame[n:], c.tag(seq, frame[:n])) {
		return errors.New("ctrHMAC: bad tag")
	}
	c.xor(c.lenKey, seq, frame[:4])
	c.xor(c.bodyKey, seq, frame[4:n])
	return nil
}

const (
	testTag   = 16 // AES-GCM tag size.
	testBlock = 16 // AES block size.
)

// rawFrame returns a zeroed buffer of 4+plen+overhead bytes, at least [MinFrameSize], with packet_length and padding_length set.
func rawFrame(t *testing.T, plen uint32, padding uint8, overhead int) Frame {
	t.Helper()
	f, err := NewFrame(make([]byte, max(MinFrameSize, 4+int(plen)+overhead)))
	if err != nil {
		t.Fatal(err)
	}
	f.SetLenPacket(plen)
	f.SetLenPadding(padding)
	return f
}

// newPacket builds a plaintext packet carrying payload padded as RFC 4253 6 requires,
// with overhead bytes of spare room at the end for the tag.
func newPacket(t *testing.T, payload []byte, overhead, block int) Frame {
	t.Helper()
	unaligned := SizeHeader + len(payload)
	if overhead != 0 {
		unaligned -= 4 // AEAD excludes packet_length from alignment.
	}
	pad := block - unaligned%block
	if pad < minPadding {
		pad += block
	}
	plen := uint32(1 + len(payload) + pad)
	f := rawFrame(t, plen, uint8(pad), overhead)
	copy(f.Payload(), payload)
	for i := range f.Padding() {
		f.Padding()[i] = 0xa5
	}
	return f
}

func TestFrameValidateSize(t *testing.T) {
	const bigAligned = 34992 // Multiple of 16 that fits maxPacket without tag but not with it.
	tests := []struct {
		name     string
		plen     uint32
		padding  uint8
		overhead int
		short    int    // Bytes removed from the end of the buffer.
		block    uint32 // Block size when keyed; testBlock if zero.
		wantErr  bool
	}{
		{name: "unkeyed minimum", plen: 12, padding: 10},
		{name: "unkeyed aligned", plen: 28, padding: 8},
		{name: "unkeyed misaligned", plen: 16, padding: 4, wantErr: true},
		{name: "unkeyed too short", plen: 4, padding: 4, wantErr: true},
		{name: "zero length", plen: 0, padding: 4, wantErr: true},
		{name: "padding too small", plen: 12, padding: 3, wantErr: true},
		{name: "padding eats msgtype", plen: 12, padding: 11, wantErr: true},
		{name: "unkeyed truncated", plen: 12, padding: 10, short: 1, wantErr: true},
		{name: "keyed minimum", plen: 16, padding: 14, overhead: testTag},
		{name: "keyed aligned", plen: 32, padding: 4, overhead: testTag},
		{name: "keyed misaligned", plen: 36, padding: 4, overhead: testTag, wantErr: true},
		{name: "keyed misaligned to 8", plen: 24, padding: 4, overhead: testTag, wantErr: true},
		{name: "keyed truncated tag", plen: 32, padding: 4, overhead: testTag, short: 1, wantErr: true},
		{name: "keyed max exceeded by tag", plen: bigAligned, padding: 4, overhead: testTag, wantErr: true},
		// chacha20-poly1305@openssh.com: 8 byte alignment without packet_length; peers send 12 byte packets.
		{name: "keyed block 8 minimum", plen: 8, padding: 6, overhead: testTag, block: 8},
		{name: "keyed block 8 too short", plen: 0, padding: 4, overhead: testTag, block: 8, wantErr: true},
		{name: "keyed block 8 misaligned", plen: 12, padding: 4, overhead: testTag, block: 8, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := rawFrame(t, tc.plen, tc.padding, tc.overhead)
			f.LimitData(len(f.RawData()) - tc.short)
			block := uint32(minBlockSize)
			if tc.overhead != 0 {
				block = cmp.Or(tc.block, testBlock)
			}
			var vld lneto.Validator
			f.ValidateSize(&vld, uint32(tc.overhead), block)
			err := vld.ErrPop()
			if (err != nil) != tc.wantErr {
				t.Fatalf("got err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// keyed modes of HalfConn: packet_length in the clear (GCM) or encrypted (PacketCipher).
var keyedModes = []string{"gcm", "packet"}

func newKeyedPair(t *testing.T, mode string) (seal, open HalfConn) {
	t.Helper()
	installKeys(t, &seal, mode, false)
	installKeys(t, &open, mode, false)
	return seal, open
}

// installKeys installs on hc the fixed test keys of mode, the same on every call.
// strict restarts sequence numbers as strict key exchange does.
func installKeys(t *testing.T, hc *HalfConn, mode string, strict bool) {
	t.Helper()
	iv := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	var err error
	switch mode {
	case "gcm":
		aead := rfc8448.NewAES128GCM()
		if err = aead.Rekey(bytes.Repeat([]byte{0x11}, 16)); err == nil {
			err = hc.SetCipherAEAD(aead, &iv, strict)
		}
	case "packet":
		pc := new(ctrHMAC)
		if err = pc.Rekey(bytes.Repeat([]byte{0x22}, 64)); err == nil {
			err = hc.SetCipherFrame(pc, strict)
		}
	default:
		t.Fatal("unknown mode", mode)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// TestHalfConnStrictSeq checks installing keys restarts sequence numbers only
// with strict key exchange, RFC 4253 6.4 having them run across [MsgNewKeys].
// The restart coincides with the fresh key, so a FrameCipher never sees a
// sequence number, its nonce, twice under one key.
func TestHalfConnStrictSeq(t *testing.T) {
	for _, mode := range keyedModes {
		for _, strict := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/strict=%v", mode, strict), func(t *testing.T) {
				var hc HalfConn
				for range 2 { // Initial key exchange, then a rekey.
					// NEWKEYS is sent under the previous keys, or none.
					if _, err := hc.Seal(newPacket(t, []byte{byte(MsgNewKeys)}, hc.Overhead(), hc.BlockSize())); err != nil {
						t.Fatal(err)
					}
					before := hc.Seq()
					installKeys(t, &hc, mode, strict)
					if want := before * uint32(b2i(!strict)); hc.Seq() != want {
						t.Fatalf("seq=%d after installing keys, want %d", hc.Seq(), want)
					}
				}
			})
		}
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

type sealOpenCase struct {
	name        string
	keyed       bool // Runs in every keyed mode.
	payload     []byte
	sealShort   int               // Bytes removed from the frame before Seal.
	openShort   int               // Bytes removed from the sealed frame before Open. Tag bytes stay within cap.
	corrupt     func(wire []byte) // Mutates the sealed frame before Open.
	wantSealErr bool
	wantOpenErr bool
}

func TestHalfConnSealOpen(t *testing.T) {
	hello := []byte{byte(MsgIgnore), 'h', 'e', 'l', 'l', 'o'}
	large := bytes.Repeat([]byte{byte(MsgChannelData)}, 1000)
	tests := []sealOpenCase{
		{name: "unkeyed", payload: hello},
		{name: "unkeyed msgtype only", payload: hello[:1]},
		{name: "unkeyed large", payload: large},
		{name: "keyed", keyed: true, payload: hello},
		{name: "keyed msgtype only", keyed: true, payload: hello[:1]},
		{name: "keyed large", keyed: true, payload: large},
		{name: "keyed no tag room", keyed: true, payload: hello, sealShort: testTag, wantSealErr: true},
		{name: "unkeyed open truncated", payload: large, openShort: 1, wantOpenErr: true},
		{name: "keyed open truncated", keyed: true, payload: hello, openShort: 1, wantOpenErr: true},
		{
			name: "keyed tampered padding_length", keyed: true, payload: hello, wantOpenErr: true,
			corrupt: func(wire []byte) { wire[4] ^= 1 },
		},
		{
			name: "keyed tampered tag", keyed: true, payload: hello, wantOpenErr: true,
			corrupt: func(wire []byte) { wire[len(wire)-1] ^= 1 },
		},
		{
			name: "keyed tampered packet_length", keyed: true, payload: large, wantOpenErr: true,
			corrupt: func(wire []byte) { wire[3] ^= 0x10 }, // Authenticated, whether in the clear or encrypted.
		},
	}
	for _, tc := range tests {
		modes := []string{"unkeyed"}
		if tc.keyed {
			modes = keyedModes
		}
		for _, mode := range modes {
			t.Run(tc.name+"/"+mode, func(t *testing.T) { testSealOpen(t, mode, tc) })
		}
	}
}

func testSealOpen(t *testing.T, mode string, tc sealOpenCase) {
	const packets = 3 // Several packets per case so nonce and seq must stay in step.
	var sealer, opener HalfConn
	if tc.keyed {
		sealer, opener = newKeyedPair(t, mode)
	}
	overhead, block := sealer.Overhead(), sealer.BlockSize()
	for i := range packets {
		f := newPacket(t, tc.payload, overhead, block)
		wantPadding := append([]byte(nil), f.Padding()...)
		f.LimitData(len(f.RawData()) - tc.sealShort)
		n, err := sealer.Seal(f)
		if tc.wantSealErr {
			if err == nil {
				t.Fatal("expected seal error")
			} else if sealer.Seq() != 0 {
				t.Fatalf("seq advanced on failed seal: %d", sealer.Seq())
			}
			return
		} else if err != nil {
			t.Fatalf("pkt %d: seal: %v", i, err)
		} else if n != len(f.RawData()) {
			t.Fatalf("pkt %d: sealed %d bytes, want %d", i, n, len(f.RawData()))
		}
		wire := f.RawData()[:n]
		if tc.keyed && bytes.Contains(wire, tc.payload) {
			t.Fatalf("pkt %d: payload not encrypted", i)
		}
		if tc.corrupt != nil {
			tc.corrupt(wire)
		}

		got, err := NewFrame(wire[:n-tc.openShort])
		if err == nil {
			_, err = opener.Open(got)
		}
		if tc.wantOpenErr {
			if err == nil {
				t.Fatal("expected open error")
			} else if opener.Seq() != 0 {
				t.Fatalf("seq advanced on failed open: %d", opener.Seq())
			}
			return
		} else if err != nil {
			t.Fatalf("pkt %d: open: %v", i, err)
		}
		var vld lneto.Validator
		got.ValidateSize(&vld, uint32(opener.Overhead()), uint32(opener.BlockSize()))
		if err = vld.ErrPop(); err != nil {
			t.Fatalf("pkt %d: validate opened: %v", i, err)
		} else if !bytes.Equal(got.Payload(), tc.payload) {
			t.Fatalf("pkt %d: payload %q, want %q", i, got.Payload(), tc.payload)
		} else if !bytes.Equal(got.Padding(), wantPadding) {
			t.Fatalf("pkt %d: padding mismatch", i)
		}
	}
	if sealer.Seq() != packets || opener.Seq() != packets {
		t.Fatalf("seq sealer=%d opener=%d, want %d", sealer.Seq(), opener.Seq(), packets)
	}
}

// TestHalfConnLength checks HalfConn reads packet_length from where each mode
// keeps it, before Open: the frame in the clear, or decrypted by the PacketCipher.
func TestHalfConnLength(t *testing.T) {
	// Block sizes of each mode as a peer pads to them. With 8 byte blocks the
	// payload length gives packets aligned to 8 but not 16, past MinFrameSize.
	blocks := map[string]int{"unkeyed": minBlockSize, "gcm": sizeGCMBlock, "packet": 8}
	payload := append([]byte{byte(MsgIgnore)}, bytes.Repeat([]byte{'x'}, 12)...)
	for _, mode := range append([]string{"unkeyed"}, keyedModes...) {
		t.Run(mode, func(t *testing.T) {
			var sealer, opener HalfConn
			if mode != "unkeyed" {
				sealer, opener = newKeyedPair(t, mode)
			}
			if opener.BlockSize() != blocks[mode] {
				t.Fatalf("BlockSize=%d, want %d", opener.BlockSize(), blocks[mode])
			}
			f := newPacket(t, payload, sealer.Overhead(), blocks[mode])
			plen := f.LenPacket()
			n, err := sealer.Seal(f)
			if err != nil {
				t.Fatal(err)
			}
			wire := f.RawData()[:n]
			if encrypted := mode == "packet"; encrypted != (f.LenPacket() != plen) {
				t.Fatalf("packet_length on wire %d, plaintext %d: encrypted=%v", f.LenPacket(), plen, encrypted)
			} else if got := opener.LenPacket(f); got != plen {
				t.Fatalf("LenPacket=%d, want %d", got, plen)
			}
			var vld lneto.Validator
			if opener.ValidateLength(&vld, f); vld.HasError() {
				t.Fatalf("ValidateLength: %v", vld.ErrPop())
			}
			short, err := NewFrame(wire[:n-1])
			if err != nil {
				t.Fatal(err)
			} else if opener.ValidateLength(&vld, short); !errors.Is(vld.ErrPop(), lneto.ErrTruncatedFrame) {
				t.Fatal("ValidateLength accepted a truncated frame")
			}
			if _, err = opener.Open(f); err != nil {
				t.Fatal(err)
			} else if f.LenPacket() != plen {
				t.Fatalf("opened packet_length=%d, want %d", f.LenPacket(), plen)
			}
		})
	}
}

// TestHalfConnPacketCipherOpenFails checks a failed Open leaves the frame as
// it was and that sequence numbers out of step, as after a one-sided strict
// key exchange restart, fail authentication: the nonce is the sequence number.
func TestHalfConnPacketCipherOpenFails(t *testing.T) {
	payload := bytes.Repeat([]byte{byte(MsgChannelData)}, 40)
	for _, tc := range []struct {
		name    string
		corrupt func(wire []byte)
		resetAt bool // Sealer restarts its sequence number after the first packet.
	}{
		{name: "tampered length", corrupt: func(wire []byte) { wire[0] ^= 0x80 }},
		{name: "tampered body", corrupt: func(wire []byte) { wire[8] ^= 1 }},
		{name: "one-sided strict restart", resetAt: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sealer, opener := newKeyedPair(t, "packet")
			seal := func() Frame {
				f := newPacket(t, payload, sealer.Overhead(), sealer.BlockSize())
				if _, err := sealer.Seal(f); err != nil {
					t.Fatal(err)
				}
				return f
			}
			f := seal()
			if tc.resetAt {
				if _, err := opener.Open(f); err != nil {
					t.Fatal(err)
				}
				installKeys(t, &sealer, "packet", true) // Same key, so only the sequence numbers disagree.
				f = seal()                              // Sealed as packet 0, opened as packet 1.
			} else {
				tc.corrupt(f.RawData())
			}
			wire := append([]byte(nil), f.RawData()...)
			seq := opener.Seq()
			if _, err := opener.Open(f); err == nil {
				t.Fatal("expected open error")
			} else if !bytes.Equal(f.RawData(), wire) {
				t.Fatal("failed Open modified the frame")
			} else if opener.Seq() != seq {
				t.Fatalf("failed Open advanced seq to %d", opener.Seq())
			}
		})
	}
}
