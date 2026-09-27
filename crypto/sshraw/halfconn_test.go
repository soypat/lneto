package sshraw_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/lcrypto"
	"github.com/soypat/lneto/crypto/internal/rfc8448"
	ssh "github.com/soypat/lneto/crypto/sshraw"
)

func newGCM(t *testing.T, key []byte) lcrypto.AEADCipher {
	t.Helper()
	aead := rfc8448.NewAES128GCM()
	if err := aead.Rekey(key); err != nil {
		t.Fatal(err)
	}
	return aead
}

// encodePacket writes an IGNORE packet carrying data into a buffer with room for a tag.
func encodePacket(t *testing.T, data []byte, block int, aad bool) []byte {
	t.Helper()
	var e ssh.Encoder
	buf := make([]byte, 4+ssh.MaxPacket)
	e.Reset(buf, 0)
	start := e.StartPacket(ssh.MsgIgnore)
	e.String(data)
	pkt := e.EndPacket(start, block, aad, fillReader(0x55))
	if e.Err() != nil {
		t.Fatal(e.Err())
	}
	return pkt
}

func TestHalfConnPlaintext(t *testing.T) {
	var out, in ssh.HalfConn
	for i := range 3 {
		pkt := encodePacket(t, []byte("hello"), ssh.MinBlockSize, false)
		want := append([]byte{}, pkt...)
		sealed, err := out.Seal(pkt)
		if err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(sealed, want) {
			t.Fatalf("plaintext Seal changed packet: %x", sealed)
		} else if out.Seq() != uint32(i+1) {
			t.Fatalf("seq=%d, want %d", out.Seq(), i+1)
		}
		n, err := in.WireLen(sealed[:4])
		if err != nil || n != len(sealed) {
			t.Fatalf("WireLen=%d %v, want %d", n, err, len(sealed))
		}
		pf, err := in.Open(sealed)
		if err != nil {
			t.Fatal(err)
		} else if pf.MsgType() != ssh.MsgIgnore || in.Seq() != uint32(i+1) {
			t.Fatalf("msg=%v seq=%d", pf.MsgType(), in.Seq())
		}
	}
	in.ResetSeq()
	if in.Seq() != 0 {
		t.Errorf("seq=%d after ResetSeq", in.Seq())
	}
}

// TestHalfConnGCM checks aes-gcm@openssh.com against the standard library: the
// packet length is additional data and the nonce is a fixed field followed by an
// invocation counter that increments per packet and wraps within its 64 bits,
// RFC 5647 7.1.
func TestHalfConnGCM(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	iv := [12]byte{1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}
	block, _ := aes.NewCipher(key)
	ref, _ := cipher.NewGCM(block)

	var out, in ssh.HalfConn
	if err := out.SetAEAD(newGCM(t, key), &iv); err != nil {
		t.Fatal(err)
	} else if err = in.SetAEAD(newGCM(t, key), &iv); err != nil {
		t.Fatal(err)
	} else if !out.HasKeys() {
		t.Fatal("HasKeys false after SetAEAD")
	}
	nonce := iv
	for i := range 4 {
		data := bytes.Repeat([]byte{byte(i)}, 10*i)
		pkt := encodePacket(t, data, 16, true)
		plain := append([]byte{}, pkt...)
		sealed, err := out.Seal(pkt)
		if err != nil {
			t.Fatal(err)
		}
		want := ref.Seal(append([]byte{}, plain[:4]...), nonce[:], plain[4:], plain[:4])
		if !bytes.Equal(sealed, want) {
			t.Fatalf("packet %d: sealed=%x\nwant %x", i, sealed, want)
		}
		binary.BigEndian.PutUint64(nonce[4:], binary.BigEndian.Uint64(nonce[4:])+1)

		n, err := in.WireLen(sealed[:4])
		if err != nil || n != len(sealed) {
			t.Fatalf("WireLen=%d %v, want %d", n, err, len(sealed))
		}
		pf, err := in.Open(sealed)
		if err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(pf.RawData(), plain) {
			t.Fatalf("opened=%x, want %x", pf.RawData(), plain)
		}
	}
	if nonce[0] != 1 || nonce[3] != 4 {
		t.Fatal("test bug: counter carried into fixed field")
	}

	// Tampering with the unencrypted length is caught by the tag.
	pkt, _ := out.Seal(encodePacket(t, nil, 16, true))
	pkt[3] ^= 0x10
	if _, err := in.Open(pkt); err == nil {
		t.Error("tampered length opened")
	}

	allocs := testing.AllocsPerRun(10, func() {
		pkt := encodePacketNoAlloc(allocBuf, 16)
		sealed, _ := out.Seal(pkt)
		in.Open(sealed)
	})
	if allocs != 0 {
		t.Errorf("Seal+Open allocs=%v, want 0", allocs)
	}
	out.Zeroize()
	if out.HasKeys() || out.Seq() != 0 {
		t.Error("Zeroize kept keys or seq")
	}
	if _, err := out.Seal(encodePacket(t, nil, ssh.MinBlockSize, false)); err != nil {
		t.Errorf("Zeroize'd HalfConn is plaintext: %v", err)
	}
}

var allocBuf = make([]byte, 256)

func encodePacketNoAlloc(buf []byte, block int) []byte {
	var e ssh.Encoder
	e.Reset(buf, 0)
	start := e.StartPacket(ssh.MsgIgnore)
	return e.EndPacket(start, block, true, fillReader(0))
}

func TestHalfConnErrors(t *testing.T) {
	var plain ssh.HalfConn
	var gcm ssh.HalfConn
	var iv [12]byte
	if err := gcm.SetAEAD(newGCM(t, make([]byte, 16)), &iv); err != nil {
		t.Fatal(err)
	}
	hdr := func(plen uint32) []byte { return binary.BigEndian.AppendUint32(nil, plen) }
	for _, tc := range []struct {
		name string
		hc   *ssh.HalfConn
		hdr  []byte
		want error
	}{
		{"short", &plain, []byte{0, 0, 0}, lneto.ErrTruncatedFrame},
		{"plain misaligned", &plain, hdr(13), lneto.ErrInvalidLengthField},
		{"plain too big", &plain, hdr(ssh.MaxPacket), lneto.ErrInvalidLengthField},
		{"plain too small", &plain, hdr(4), lneto.ErrInvalidLengthField},
		{"gcm misaligned", &gcm, hdr(12 + 8), lneto.ErrInvalidLengthField},
		{"gcm too big", &gcm, hdr(ssh.MaxPacket &^ 15), lneto.ErrInvalidLengthField},
		{"gcm zero", &gcm, hdr(0), lneto.ErrInvalidLengthField},
	} {
		if _, err := tc.hc.WireLen(tc.hdr); !errors.Is(err, tc.want) {
			t.Errorf("%s: err=%v, want %v", tc.name, err, tc.want)
		}
	}
	if n, err := plain.WireLen(hdr(12)); err != nil || n != 16 {
		t.Errorf("plain WireLen=%d %v, want 16", n, err)
	} else if n, err = gcm.WireLen(hdr(16)); err != nil || n != 4+16+16 {
		t.Errorf("gcm WireLen=%d %v, want 36", n, err)
	}

	// Seal needs room for the tag and an aligned packet.
	pkt := encodePacket(t, nil, 16, true)
	if _, err := gcm.Seal(pkt[:len(pkt):len(pkt)]); !errors.Is(err, lneto.ErrShortBuffer) {
		t.Errorf("no tag room: err=%v, want %v", err, lneto.ErrShortBuffer)
	}
	if _, err := gcm.Seal(encodePacket(t, nil, 8, false)); !errors.Is(err, lneto.ErrInvalidLengthField) {
		t.Errorf("misaligned seal: err=%v, want %v", err, lneto.ErrInvalidLengthField)
	}
	// Open wants exactly the bytes WireLen reported.
	sealed, _ := plain.Seal(encodePacket(t, nil, 8, false))
	if _, err := plain.Open(append(sealed, 0)); !errors.Is(err, lneto.ErrInvalidLengthField) {
		t.Errorf("open with extra byte: err=%v", err)
	}

	var bad ssh.HalfConn
	if err := bad.SetAEAD(shortNonceAEAD{}, &iv); !errors.Is(err, lneto.ErrInvalidConfig) {
		t.Errorf("SetAEAD short nonce: err=%v, want %v", err, lneto.ErrInvalidConfig)
	}
}

type shortNonceAEAD struct{ lcrypto.AEADCipher }

func (shortNonceAEAD) NonceSize() int { return 8 }
func (shortNonceAEAD) Overhead() int  { return 16 }
