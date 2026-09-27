package sshraw_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/soypat/lneto"
	ssh "github.com/soypat/lneto/crypto/sshraw"
)

// fillReader fills reads with a constant so padding is deterministic.
type fillReader byte

func (r fillReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(r)
	}
	return len(b), nil
}

// packet builds a binary packet with the given padding length and payload,
// declaring packet_length as the true length plus delta.
func packet(padLen int, payload []byte, delta int) []byte {
	plen := 1 + len(payload) + padLen
	pkt := binary.BigEndian.AppendUint32(nil, uint32(plen+delta))
	pkt = append(pkt, byte(padLen))
	pkt = append(pkt, payload...)
	return append(pkt, make([]byte, padLen)...)
}

func TestNewPacketFrame(t *testing.T) {
	ignore := []byte{byte(ssh.MsgIgnore), 0, 0, 0, 0}
	huge := binary.BigEndian.AppendUint32(nil, ssh.MaxPacket-4+1)
	huge = append(huge, make([]byte, ssh.MaxPacket)...)
	for _, tc := range []struct {
		name string
		pkt  []byte
		want error
	}{
		{"valid", packet(6, ignore, 0), nil},
		{"min padding", packet(ssh.MinPadding, ignore, 0), nil},
		{"short header", []byte{0, 0, 0, 12}, lneto.ErrTruncatedFrame},
		{"length overruns", packet(6, ignore, +1), lneto.ErrTruncatedFrame},
		{"length too big", huge, lneto.ErrInvalidLengthField},
		{"length 32bit overflow", append([]byte{0xff, 0xff, 0xff, 0xff, 4}, make([]byte, 64)...), lneto.ErrInvalidLengthField},
		{"padding too short", packet(ssh.MinPadding-1, ignore, 0), lneto.ErrInvalidLengthField},
		{"no payload", packet(8, nil, 0), lneto.ErrInvalidLengthField},
		{"padding overruns", packet(8, ignore, -8), lneto.ErrInvalidLengthField},
	} {
		pf, err := ssh.NewPacketFrame(tc.pkt)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err=%v, want %v", tc.name, err, tc.want)
			continue
		} else if err != nil {
			continue
		}
		if pf.MsgType() != ssh.MsgIgnore {
			t.Errorf("%s: msg type=%v, want %v", tc.name, pf.MsgType(), ssh.MsgIgnore)
		} else if !bytes.Equal(pf.Payload(), ignore) {
			t.Errorf("%s: payload=%x, want %x", tc.name, pf.Payload(), ignore)
		} else if len(pf.RawData()) != len(tc.pkt) {
			t.Errorf("%s: raw length=%d, want %d", tc.name, len(pf.RawData()), len(tc.pkt))
		}
	}
	// Bytes past packet_length belong to the MAC or the next packet.
	pkt := append(packet(6, ignore, 0), 1, 2, 3)
	pf, err := ssh.NewPacketFrame(pkt)
	if err != nil {
		t.Fatal(err)
	} else if len(pf.RawData()) != len(pkt)-3 {
		t.Errorf("raw length=%d, want %d", len(pf.RawData()), len(pkt)-3)
	}
}

func TestPacketFrameValidateAlignment(t *testing.T) {
	ignore := []byte{byte(ssh.MsgIgnore), 0, 0, 0, 0}
	for _, tc := range []struct {
		name  string
		pkt   []byte
		block int
		aad   bool
		want  error
	}{
		// 4+1+5+6 = 16.
		{"plain 8", packet(6, ignore, 0), 8, false, nil},
		{"plain 16", packet(6, ignore, 0), 16, false, nil},
		{"plain below min block", packet(6, ignore, 0), 0, false, nil},
		{"plain misaligned", packet(7, ignore, 0), 8, false, lneto.ErrInvalidLengthField},
		// 1+5+10 = 16, packet_length excluded.
		{"aad 16", packet(10, ignore, 0), 16, true, nil},
		{"aad misaligned", packet(6, ignore, 0), 16, true, lneto.ErrInvalidLengthField},
	} {
		pf, err := ssh.NewPacketFrame(tc.pkt)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if err = pf.ValidateAlignment(tc.block, tc.aad); !errors.Is(err, tc.want) {
			t.Errorf("%s: err=%v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestEncoderPacket(t *testing.T) {
	for _, tc := range []struct {
		block int
		aad   bool
	}{
		{0, false}, {8, false}, {16, false}, {8, true}, {16, true},
	} {
		for payloadLen := range 40 {
			var e ssh.Encoder
			buf := make([]byte, 128)
			e.Reset(buf, 0)
			start := e.StartPacket(ssh.MsgIgnore)
			e.String(bytes.Repeat([]byte{'x'}, payloadLen))
			pkt := e.EndPacket(start, tc.block, tc.aad, fillReader(0xaa))
			if e.Err() != nil {
				t.Fatalf("block=%d aad=%v len=%d: %v", tc.block, tc.aad, payloadLen, e.Err())
			}
			pf, err := ssh.NewPacketFrame(pkt)
			if err != nil {
				t.Fatalf("block=%d aad=%v len=%d: %v", tc.block, tc.aad, payloadLen, err)
			} else if err = pf.ValidateAlignment(tc.block, tc.aad); err != nil {
				t.Fatalf("block=%d aad=%v len=%d: %v", tc.block, tc.aad, payloadLen, err)
			} else if len(pf.RawData()) != len(pkt) {
				t.Fatalf("raw length=%d, want %d", len(pf.RawData()), len(pkt))
			} else if pf.MsgType() != ssh.MsgIgnore || len(pf.Payload()) != 1+4+payloadLen {
				t.Fatalf("payload=%x", pf.Payload())
			} else if pad := pf.Padding(); len(pad) < ssh.MinPadding || len(pad) >= ssh.MinPadding+max(tc.block, ssh.MinBlockSize) {
				t.Fatalf("block=%d aad=%v len=%d: padding length %d", tc.block, tc.aad, payloadLen, len(pad))
			} else if !bytes.Equal(pad, bytes.Repeat([]byte{0xaa}, len(pad))) {
				t.Fatalf("padding=%x not from rand", pad)
			}
		}
	}
}

func TestEncoderPacketErrors(t *testing.T) {
	var e ssh.Encoder
	buf := make([]byte, 16)
	e.Reset(buf, 0)
	start := e.StartPacket(ssh.MsgIgnore)
	e.String([]byte("hello")) // 5+1+4+5 = 15, padding does not fit.
	if pkt := e.EndPacket(start, 8, false, fillReader(0)); pkt != nil || !errors.Is(e.Err(), lneto.ErrShortBuffer) {
		t.Errorf("pkt=%x err=%v, want nil %v", pkt, e.Err(), lneto.ErrShortBuffer)
	}
	buf = make([]byte, 64)
	e.Reset(buf, 0)
	start = e.StartPacket(ssh.MsgIgnore)
	if pkt := e.EndPacket(start, MaxBadBlock, false, fillReader(0)); pkt != nil || !errors.Is(e.Err(), lneto.ErrInvalidConfig) {
		t.Errorf("pkt=%x err=%v, want nil %v", pkt, e.Err(), lneto.ErrInvalidConfig)
	}
}

// MaxBadBlock is a block size whose padding cannot fit padding_length.
const MaxBadBlock = 256
