package sshraw

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/soypat/lneto"
)

// TestInstallPacketCipher checks InstallPacketCipher keys a PacketCipher with
// the key of the letter given, as deriving and rekeying by hand does.
func TestInstallPacketCipher(t *testing.T) {
	const keyLen = 64 // chacha20-poly1305@openssh.com: two 256 bit keys.
	var ks KeySchedule
	if err := ks.Configure(sha256.New()); err != nil {
		t.Fatal(err)
	}
	var hc HalfConn
	if err := ks.InstallCipherFrameKeys(&hc, new(ctrHMAC), keyLen, 'C', false); !errors.Is(err, lneto.ErrBadState) {
		t.Fatalf("before exchange err=%v, want %v", err, lneto.ErrBadState)
	}
	if err := ks.SetSecret(bytes.Repeat([]byte{0x80}, 32), false); err != nil {
		t.Fatal(err)
	}
	ks.StartExchange()
	ks.HashString([]byte("SSH-2.0-test"))
	ks.FinishExchange()
	if err := ks.InstallCipherFrameKeys(&hc, new(ctrHMAC), 65, 'C', false); !errors.Is(err, lneto.ErrInvalidConfig) {
		t.Fatalf("oversized key err=%v, want %v", err, lneto.ErrInvalidConfig)
	}

	if err := ks.InstallCipherFrameKeys(&hc, new(ctrHMAC), keyLen, 'C', false); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, keyLen)
	ks.Derive(key, 'C')
	var want HalfConn
	pc := new(ctrHMAC)
	if err := pc.Rekey(key); err != nil {
		t.Fatal(err)
	} else if err = want.SetCipherFrame(pc, false); err != nil {
		t.Fatal(err)
	}
	payload := []byte{byte(MsgIgnore), 'k'}
	a := newPacket(t, payload, hc.Overhead(), hc.BlockSize())
	b := newPacket(t, payload, want.Overhead(), want.BlockSize())
	if _, err := hc.Seal(a); err != nil {
		t.Fatal(err)
	} else if _, err = want.Seal(b); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(a.RawData(), b.RawData()) {
		t.Fatalf("installed packet %x, want %x", a.RawData(), b.RawData())
	}
}
