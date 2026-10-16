package sshraw

import (
	"bytes"
	"testing"

	"github.com/soypat/lneto"
)

// TestEncoderTypes checks the RFC 4251 5 data types against hand encoded bytes.
func TestEncoderTypes(t *testing.T) {
	var e Encoder
	buf := make([]byte, 64)
	e.Reset(buf, 0)
	e.Bool(true)
	e.Str("ab")
	e.String([]byte{7})
	e.NameList("x", "yz")
	e.NameList()
	e.MPInt([]byte{0, 0x80}) // Leading zero dropped, sign byte added.
	e.MPInt([]byte{0, 0})
	want := []byte{
		1,
		0, 0, 0, 2, 'a', 'b',
		0, 0, 0, 1, 7,
		0, 0, 0, 4, 'x', ',', 'y', 'z',
		0, 0, 0, 0,
		0, 0, 0, 2, 0, 0x80,
		0, 0, 0, 0,
	}
	if e.IsFailed() {
		t.Fatal("encode failed")
	} else if got := buf[:e.Len()]; !bytes.Equal(got, want) {
		t.Fatalf("encoded %x, want %x", got, want)
	} else if len(e.Rest()) != len(buf)-len(want) {
		t.Fatalf("Rest len=%d, want %d", len(e.Rest()), len(buf)-len(want))
	}
	e.NameList("bad name")
	if !e.IsFailed() {
		t.Fatal("invalid name did not fail")
	}
}

// TestEncoderPacket checks EndPacket pads to the block size, with packet_length
// excluded from alignment when keyed, and sets both lengths.
func TestEncoderPacket(t *testing.T) {
	for _, tc := range []struct {
		block int
		aad   bool
	}{{0, false}, {16, false}, {8, true}, {16, true}} {
		var e Encoder
		buf := make([]byte, 64)
		e.Reset(buf, 2)
		start := e.StartPacket(MsgIgnore)
		e.Str("k")
		pkt := e.EndPacket(start, tc.block, tc.aad, bytes.NewReader(bytes.Repeat([]byte{0xaa}, 64)))
		if e.IsFailed() {
			t.Fatal("encode failed")
		}
		pf, err := NewFrame(pkt)
		if err != nil {
			t.Fatal(err)
		}
		var vld lneto.Validator
		overhead := 0
		if tc.aad {
			overhead = 1 // Any nonzero overhead selects keyed alignment; frame carries no tag here.
			pkt = append(pkt, 0)
			pf, _ = NewFrame(pkt)
		}
		pf.ValidateLength(&vld, uint32(overhead), uint32(tc.block))
		if err = vld.ErrPop(); err != nil {
			t.Fatalf("block=%d aad=%v: %v", tc.block, tc.aad, err)
		} else if &pkt[0] != &buf[2] || e.Len() != 2+len(pkt)-overhead {
			t.Fatalf("packet not at start or Len=%d", e.Len())
		} else if pkt[5] != byte(MsgIgnore) || pkt[len(pkt)-1-overhead] != 0xaa {
			t.Fatalf("bad packet %x", pkt)
		}
	}
	var e Encoder
	e.Reset(make([]byte, 12), 0)
	start := e.StartPacket(MsgIgnore)
	e.EndPacket(start, 16, false, bytes.NewReader(make([]byte, 64)))
	if !e.IsFailed() {
		t.Fatal("short buffer did not fail")
	}
}
