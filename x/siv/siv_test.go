package siv

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// RFC 5297 Appendix A test vectors for AES-SIV-CMAC-256.
var aesSIVTests = []struct {
	key, plaintext, additionalData, nonce, ciphertext string
}{
	{
		key:            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		plaintext:      "112233445566778899aabbccddee",
		additionalData: "101112131415161718191a1b1c1d1e1f2021222324252627",
		nonce:          "",
		ciphertext:     "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c",
	},
	{
		key:            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		plaintext:      "",
		additionalData: "",
		nonce:          "",
		ciphertext:     "f2007a5beb2b8900c588a7adf599f172",
	},
	{
		key:            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		plaintext:      "00112233445566778899aabbccddeeff",
		additionalData: "",
		nonce:          "",
		ciphertext:     "f304f912863e303d5b540e5057c7010c942ffaf45b0e5ca5fb9a56a5263bb065",
	},
	{
		key:            "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
		plaintext:      "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
		additionalData: "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
		nonce:          "09f911029d74e35bd84156c5635688c0",
		ciphertext:     "85825e22e90cf2ddda2c548dc7c1b6310dcdaca0cebf9dc6cb90583f5bf1506e02cd48832b00e4e598b2b22a53e6199d4df0c1666a35a0433b250dc134d776",
	},
}

func TestAESSIVCMAC256_Vectors(t *testing.T) {
	for i, tc := range aesSIVTests {
		key := mustDecodeHex(tc.key)
		if len(key) != 32 {
			t.Skipf("vector %d: key length %d not 32, skipping (not AES-SIV-CMAC-256)", i, len(key))
		}
		plaintext := mustDecodeHex(tc.plaintext)
		ad := mustDecodeHex(tc.additionalData)
		var nonce []byte
		if tc.nonce != "" {
			nonce = mustDecodeHex(tc.nonce)
		}
		want := mustDecodeHex(tc.ciphertext)

		aead, err := NewAESSIVCMAC256(key)
		if err != nil {
			t.Fatalf("vector %d: NewAESSIVCMAC256: %v", i, err)
		}

		got := aead.Seal(nil, nonce, plaintext, ad)
		if !bytes.Equal(got, want) {
			t.Errorf("vector %d: Seal mismatch\n got  %x\n want %x", i, got, want)
		}

		dec, err := aead.Open(nil, nonce, got, ad)
		if err != nil {
			t.Errorf("vector %d: Open failed: %v", i, err)
		}
		if !bytes.Equal(dec, plaintext) {
			t.Errorf("vector %d: Open roundtrip mismatch", i)
		}
	}
}

func TestAESSIVCMAC256_TamperedCiphertextRejected(t *testing.T) {
	key := mustDecodeHex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	plaintext := []byte("hello world")
	ad := []byte("authenticated data")
	aead, _ := NewAESSIVCMAC256(key)
	ct := aead.Seal(nil, nil, plaintext, ad)
	ct[0] ^= 0xff
	if _, err := aead.Open(nil, nil, ct, ad); err == nil {
		t.Fatal("expected error for tampered ciphertext, got nil")
	}
}

func TestAESSIVCMAC256_WrongKeySize(t *testing.T) {
	if _, err := NewAESSIVCMAC256(make([]byte, 16)); err == nil {
		t.Fatal("expected error for 16-byte key")
	}
	if _, err := NewAESSIVCMAC256(make([]byte, 64)); err == nil {
		t.Fatal("expected error for 64-byte key")
	}
}

// TestAESCMAC_RFC4493 verifies the AES-CMAC subkey derivation and MAC output
// against the RFC 4493 Appendix D test vectors.
var cmacTests = []struct {
	key, msg, tag string
}{
	{
		key: "2b7e151628aed2a6abf7158809cf4f3c",
		msg: "",
		tag: "bb1d6929e95937287fa37d129b756746",
	},
	{
		key: "2b7e151628aed2a6abf7158809cf4f3c",
		msg: "6bc1bee22e409f96e93d7e117393172a",
		tag: "070a16b46b4d4144f79bdd9dd04a287c",
	},
	{
		key: "2b7e151628aed2a6abf7158809cf4f3c",
		msg: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
		tag: "dfa66747de9ae63030ca32611497c827",
	},
	{
		key: "2b7e151628aed2a6abf7158809cf4f3c",
		msg: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
		tag: "51f0bebf7e3b9d92fc49741779363cfe",
	},
}

func TestAESCMAC_RFC4493(t *testing.T) {
	for i, tc := range cmacTests {
		key := mustDecodeHex(tc.key)
		msg := mustDecodeHex(tc.msg)
		want := mustDecodeHex(tc.tag)
		mac, err := newCMAC(key)
		if err != nil {
			t.Fatalf("vector %d: newCMAC: %v", i, err)
		}
		mac.Write(msg)
		got := mac.Sum(nil)
		if !bytes.Equal(got, want) {
			t.Errorf("vector %d: CMAC mismatch\n got  %x\n want %x", i, got, want)
		}
	}
}

// TestAESCMAC_IncrementalWrite verifies that fragmented writes produce the
// same MAC as a single write.
func TestAESCMAC_IncrementalWrite(t *testing.T) {
	key := mustDecodeHex("2b7e151628aed2a6abf7158809cf4f3c")
	msg := mustDecodeHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	mac, _ := newCMAC(key)
	mac.Write(msg)
	want := mac.Sum(nil)
	mac.Reset()
	for _, b := range msg {
		mac.Write([]byte{b})
	}
	got := mac.Sum(nil)
	if !bytes.Equal(got, want) {
		t.Errorf("incremental CMAC mismatch\n got  %x\n want %x", got, want)
	}
}

func BenchmarkAESSIVCMAC256_Seal_64(b *testing.B) {
	benchmarkSeal(b, 64)
}

func BenchmarkAESSIVCMAC256_Seal_1024(b *testing.B) {
	benchmarkSeal(b, 1024)
}

func benchmarkSeal(b *testing.B, size int) {
	b.Helper()
	key := make([]byte, 32)
	aead, _ := NewAESSIVCMAC256(key)
	pt := make([]byte, size)
	dst := make([]byte, 0, size+aes.BlockSize)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for b.Loop() {
		dst = aead.Seal(dst[:0], nil, pt, nil)
	}
}

// TestChacha20Poly1305Interface ensures that x/crypto ChaCha20-Poly1305
// satisfies cipher.AEAD so it can be used as a test AEAD in x/nts tests.
func TestChacha20Poly1305Interface(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	ct := aead.Seal(nil, nonce, []byte("test"), nil)
	if _, err := aead.Open(nil, nonce, ct, nil); err != nil {
		t.Fatal(err)
	}
}
