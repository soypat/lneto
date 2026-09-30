package sshraw

import (
	"bytes"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/rfc8448"
)

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
		short    int // Bytes removed from the end of the buffer.
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
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := rawFrame(t, tc.plen, tc.padding, tc.overhead)
			f.LimitData(len(f.RawData()) - tc.short)
			block := uint32(minBlockSize)
			if tc.overhead != 0 {
				block = testBlock
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

func newKeyedPair(t *testing.T) (seal, open HalfConn) {
	t.Helper()
	key := bytes.Repeat([]byte{0x11}, 16)
	iv := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	for _, hc := range []*HalfConn{&seal, &open} {
		aead := rfc8448.NewAES128GCM()
		if err := aead.Rekey(key); err != nil {
			t.Fatal(err)
		}
		if err := hc.SetAEAD(aead, &iv); err != nil {
			t.Fatal(err)
		}
	}
	return seal, open
}

func TestHalfConnSealOpen(t *testing.T) {
	const packets = 3 // Several packets per case so nonce and seq must stay in step.
	hello := []byte{byte(MsgIgnore), 'h', 'e', 'l', 'l', 'o'}
	large := bytes.Repeat([]byte{byte(MsgChannelData)}, 1000)
	tests := []struct {
		name        string
		keyed       bool
		payload     []byte
		sealShort   int               // Bytes removed from the frame before Seal.
		openShort   int               // Bytes removed from the sealed frame before Open. Tag bytes stay within cap.
		corrupt     func(wire []byte) // Mutates the sealed frame before Open.
		wantSealErr bool
		wantOpenErr bool
	}{
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
			corrupt: func(wire []byte) { wire[3] ^= 0x10 }, // Still aligned, AAD no longer authenticates.
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var sealer, opener HalfConn
			if tc.keyed {
				sealer, opener = newKeyedPair(t)
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
		})
	}
}
