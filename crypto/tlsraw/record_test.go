package tlsraw

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/lcrypto"
)

// TestHalfConn checks SetAEAD validation, Overhead, and Seal and Open against a
// record built by a peer with the raw AEAD. The peer record exists even when
// Seal refuses the content or cannot produce it (Seal never pads), so Open is
// exercised on what a keyed peer could send, RFC 8446 5.2.
func TestHalfConn(t *testing.T) {
	key := make([]byte, 16)
	var iv [12]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range iv {
		iv[i] = byte(0xa0 + i)
	}
	gcm := func(t *testing.T) lcrypto.AEADCipher { return newGCM(t, key) }
	stub := func(tag int) func(*testing.T) lcrypto.AEADCipher {
		return func(*testing.T) lcrypto.AEADCipher { return &stubAEAD{tag: tag, nonce: 12} }
	}
	tests := []struct {
		name           string
		aead           func(t *testing.T) lcrypto.AEADCipher
		content        int // Content length before the content type byte.
		padding        int // Zero bytes after the content type byte, peer record only.
		capShort       int // Bytes the Seal buffer's spare capacity falls short of Overhead.
		wantSetAEADErr error
		wantOverhead   int
		wantSealErr    error
		wantOpenErr    error
	}{
		{name: "gcm", aead: gcm, content: 5, wantOverhead: 17},
		{name: "ccm8", aead: stub(8), content: 5, wantOverhead: 9},
		{name: "empty content", aead: stub(8), wantOverhead: 9},
		{name: "tag 7", aead: stub(7), wantSetAEADErr: lneto.ErrInvalidConfig},
		{name: "tag 17", aead: stub(17), wantSetAEADErr: lneto.ErrInvalidConfig},
		{name: "tag 0", aead: stub(0), wantSetAEADErr: lneto.ErrInvalidConfig},
		{name: "tag negative", aead: stub(-1), wantSetAEADErr: lneto.ErrInvalidConfig},
		{name: "tag uint16 overflow", aead: stub(1 << 16), wantSetAEADErr: lneto.ErrInvalidConfig},
		{name: "nonce 8", aead: func(*testing.T) lcrypto.AEADCipher { return &stubAEAD{tag: 16, nonce: 8} }, wantSetAEADErr: lneto.ErrInvalidConfig},
		{name: "short buffer", aead: stub(8), content: 5, capShort: 1, wantOverhead: 9, wantSealErr: lneto.ErrShortBuffer},
		{name: "max", aead: gcm, content: MaxPlaintext, wantOverhead: 17},
		{name: "max padded", aead: gcm, content: 100, padding: MaxPlaintext - 100, wantOverhead: 17},
		{name: "content over", aead: gcm, content: MaxPlaintext + 1, wantOverhead: 17, wantSealErr: lneto.ErrInvalidLengthField, wantOpenErr: lneto.ErrInvalidLengthField},
		{name: "padding over", aead: gcm, content: 100, padding: MaxPlaintext - 99, wantOverhead: 17, wantOpenErr: lneto.ErrInvalidLengthField},
		{name: "ccm8 content over", aead: stub(8), content: MaxPlaintext + 1, wantOverhead: 9, wantSealErr: lneto.ErrInvalidLengthField, wantOpenErr: lneto.ErrInvalidLengthField},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sealer, opener HalfConn
			err := sealer.SetAEAD(tt.aead(t), &iv)
			if !errors.Is(err, tt.wantSetAEADErr) {
				t.Fatalf("SetAEAD err=%v, want %v", err, tt.wantSetAEADErr)
			} else if got := sealer.Overhead(); got != tt.wantOverhead {
				t.Fatalf("Overhead=%d, want %d", got, tt.wantOverhead)
			} else if err != nil {
				if sealer.HasKeys() {
					t.Error("rejected AEAD was installed")
				}
				return
			}
			if err = opener.SetAEAD(tt.aead(t), &iv); err != nil {
				t.Fatal(err)
			}
			content := bytes.Repeat([]byte{'a'}, tt.content)

			// Peer record. Sequence number 0 makes the nonce the IV.
			peer := tt.aead(t)
			inner := tt.content + 1 + tt.padding
			want := make([]byte, SizeHeaderRecord+inner, SizeHeaderRecord+inner+peer.Overhead())
			copy(want[SizeHeaderRecord:], content)
			want[SizeHeaderRecord+tt.content] = byte(ContentTypeApplicationData)
			want[0] = byte(ContentTypeApplicationData)
			binary.BigEndian.PutUint16(want[1:3], VersionTLS12)
			binary.BigEndian.PutUint16(want[3:5], uint16(inner+peer.Overhead()))
			sealed := peer.Seal(want[SizeHeaderRecord:SizeHeaderRecord], iv[:], want[SizeHeaderRecord:], want[:SizeHeaderRecord])
			want = want[:SizeHeaderRecord+len(sealed)]

			rec := make([]byte, SizeHeaderRecord+tt.content, SizeHeaderRecord+tt.content+sealer.Overhead()-tt.capShort)
			copy(rec[SizeHeaderRecord:], content)
			rec, err = sealer.Seal(rec, ContentTypeApplicationData)
			if !errors.Is(err, tt.wantSealErr) {
				t.Errorf("Seal err=%v, want %v", err, tt.wantSealErr)
			} else if err == nil && tt.padding == 0 && !bytes.Equal(rec, want) {
				t.Errorf("Seal record=%x, want %x", rec, want)
			}

			got, ct, err := opener.Open(want)
			if !errors.Is(err, tt.wantOpenErr) {
				t.Fatalf("Open err=%v, want %v", err, tt.wantOpenErr)
			} else if err != nil {
				return
			}
			if ct != ContentTypeApplicationData {
				t.Errorf("content type=%d, want application data", ct)
			} else if !bytes.Equal(got, content) {
				t.Errorf("content length=%d, want %d", len(got), len(content))
			}
		})
	}
}

// TestEncoderSealRecord checks SealRecord seals as HalfConn.Seal does and leaves
// the Encoder after the sealed record, ready for the next one.
func TestEncoderSealRecord(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	var iv [12]byte
	content := []byte("hello")
	var direct, viaEnc HalfConn
	if err := direct.SetAEAD(newGCM(t, key), &iv); err != nil {
		t.Fatal(err)
	} else if err = viaEnc.SetAEAD(newGCM(t, key), &iv); err != nil {
		t.Fatal(err)
	}
	rec := make([]byte, SizeHeaderRecord, SizeHeaderRecord+len(content)+direct.Overhead())
	rec[0] = byte(ContentTypeApplicationData)
	binary.BigEndian.PutUint16(rec[1:3], VersionTLS12)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(content)))
	rec = append(rec, content...)
	want, err := direct.Seal(rec, ContentTypeApplicationData)
	if err != nil {
		t.Fatal(err)
	}

	const prefix = 3
	buf := make([]byte, prefix+len(want)+1)
	var e Encoder
	e.Reset(buf, prefix)
	start := e.StartRecord(ContentTypeApplicationData)
	e.Bytes(content)
	e.EndRecord(start)
	e.SealRecord(&viaEnc, start, ContentTypeApplicationData)
	e.Uint8(0xff) // Next write lands after the record.
	if e.Err() != nil {
		t.Fatal(e.Err())
	} else if got := buf[prefix : len(buf)-1]; !bytes.Equal(got, want) {
		t.Fatalf("record %x, want %x", got, want)
	} else if e.Len() != len(buf) || buf[len(buf)-1] != 0xff {
		t.Fatalf("Len=%d, want %d", e.Len(), len(buf))
	}

	e.Reset(make([]byte, len(want)-1), 0) // No room for the tag.
	start = e.StartRecord(ContentTypeApplicationData)
	e.Bytes(content)
	e.EndRecord(start)
	e.SealRecord(&viaEnc, start, ContentTypeApplicationData)
	if !errors.Is(e.Err(), lneto.ErrShortBuffer) {
		t.Fatalf("short buffer err=%v, want %v", e.Err(), lneto.ErrShortBuffer)
	}
}

// stubAEAD is an insecure AEAD with configurable tag and nonce sizes, for suites
// such as CCM_8 that the standard library does not implement. Like crypto/cipher
// it reallocates dst when its capacity is short.
type stubAEAD struct{ tag, nonce int }

func (s *stubAEAD) NonceSize() int       { return s.nonce }
func (s *stubAEAD) Overhead() int        { return s.tag }
func (*stubAEAD) Rekey(key []byte) error { return nil }
func (*stubAEAD) Zeroize()               {}
func (s *stubAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	n := len(dst) + len(plaintext) + s.tag
	if cap(dst) < n {
		dst = append(make([]byte, 0, n), dst...)
	}
	out := dst[:n]
	copy(out[len(dst):], plaintext)
	stubTag(out[n-s.tag:], nonce, plaintext, additionalData)
	return out
}
func (s *stubAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < s.tag {
		return nil, lneto.ErrTruncatedFrame
	}
	plain := ciphertext[:len(ciphertext)-s.tag]
	want := make([]byte, s.tag)
	stubTag(want, nonce, plain, additionalData)
	if !bytes.Equal(want, ciphertext[len(plain):]) {
		return nil, lneto.ErrInvalidField
	}
	return append(dst, plain...), nil
}

// stubTag fills tag with an FNV-1a digest of its inputs.
func stubTag(tag, nonce, plaintext, additionalData []byte) {
	h := uint64(14695981039346656037)
	for _, b := range [][]byte{nonce, plaintext, additionalData} {
		for _, c := range b {
			h = (h ^ uint64(c)) * 1099511628211
		}
	}
	for i := range tag {
		tag[i] = byte(h >> (8 * (i % 8)))
	}
}
