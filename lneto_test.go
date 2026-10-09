package lneto_test

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"os"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
)

func TestTCPMarshalUnmarshal(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var gen ltesto.PacketGen
	gen.RandomizeAddrs(rng)
	const maxSize = 4096
	src := make([]byte, maxSize)
	dst := make([]byte, maxSize)
	for range 512 {
		src = gen.AppendRandomIPv4TCPPacket(src[:0], rng, tcp.Segment{
			SEQ:     tcp.Value(rng.Int()),
			ACK:     tcp.Value(rng.Int()),
			DATALEN: tcp.Size(rng.Intn(256)),
			WND:     tcp.Size(rng.Intn(1024)),
			Flags:   tcp.FlagACK,
		})
		dst = dst[:len(src)]
		testMoveTCPPacket(t, src, dst)
		if !internal.BytesEqual(src, dst) {
			t.Fatal("mismatching data")
		}
	}
}

func testMoveTCPPacket(t *testing.T, src, dst []byte) {
	if len(src) != len(dst) {
		panic("expect src and dst same length")
	}
	efrm, err := ethernet.NewFrame(src)
	if err != nil {
		t.Fatal(err)
	}
	epl := efrm.Payload()
	ifrm, err := ipv4.NewFrame(epl)
	if err != nil {
		t.Fatal(err)
	}
	ipl := ifrm.Payload()
	tfrm, err := tcp.NewFrame(ipl)
	if err != nil {
		t.Fatal(err)
	}

	efrm2, _ := ethernet.NewFrame(dst)
	*efrm2.DestinationHardwareAddr() = *efrm.DestinationHardwareAddr()
	*efrm2.SourceHardwareAddr() = *efrm.SourceHardwareAddr()
	efrm2.SetEtherType(efrm.EtherTypeOrSize())
	if efrm.IsVLAN() {
		efrm2.SetVLAN(efrm.VLAN())
	}
	ifrm2, _ := ipv4.NewFrame(efrm2.Payload())
	ifrm2.SetVersionAndIHL(ifrm.VersionAndIHL())
	ifrm2.SetToS(ifrm.ToS())
	ifrm2.SetFlags(ifrm.Flags())
	ifrm2.SetTotalLength(ifrm.TotalLength())
	ifrm2.SetID(ifrm.ID())
	ifrm2.SetTTL(ifrm.TTL())
	ifrm2.SetProtocol(ifrm.Protocol())
	ifrm2.SetCRC(ifrm.CRC())
	*ifrm2.SourceAddr() = *ifrm.SourceAddr()
	*ifrm2.DestinationAddr() = *ifrm.DestinationAddr()

	tfrm2, _ := tcp.NewFrame(ifrm2.Payload())
	tfrm2.SetSourcePort(tfrm.SourcePort())
	tfrm2.SetDestinationPort(tfrm.DestinationPort())
	tfrm2.SetSeq(tfrm.Seq())
	tfrm2.SetAck(tfrm.Ack())
	tfrm2.SetOffsetAndFlags(tfrm.OffsetAndFlags())
	tfrm2.SetWindowSize(tfrm.WindowSize())
	tfrm2.SetCRC(tfrm.CRC())
	tfrm2.SetUrgentPtr(tfrm.UrgentPtr())

	copy(ifrm2.Options(), ifrm.Options())
	copy(tfrm2.Options(), tfrm.Options())
	copy(tfrm2.Payload(), tfrm.Payload())

	elen := efrm.HeaderLength()
	if !internal.BytesEqual(src[:elen], dst[:elen]) {
		t.Fatalf("Ethernet header mismatch\n%x\n%x", src[:elen], dst[:elen])
	}
	ilen := ifrm.HeaderLength()
	if !internal.BytesEqual(src[elen:elen+20], dst[elen:elen+20]) {
		t.Fatalf("IPv4 header mismatch\n%x\n%x", src[elen:elen+20], dst[elen:elen+20])
	}
	ipoptLen := len(ifrm.Options())
	if !internal.BytesEqual(ifrm.Options(), ifrm2.Options()) {
		t.Fatalf("IPv4 options mismatch\n%x\n%x", ifrm.Options(), ifrm2.Options())
	} else if ipoptLen > 0 && &ifrm.Options()[0] != &src[elen+20] {
		t.Fatal("IPv4 options start pointer mismatch")
	}

	tlen := tfrm.HeaderLength()
	toff := elen + ilen + ipoptLen
	if !internal.BytesEqual(src[toff:toff+tlen], dst[toff:toff+tlen]) {
		t.Fatalf("TCP header mismatch\n%x\n%x", src[toff:toff+tlen], dst[toff:toff+tlen])
	}
	payload := tfrm.Payload()

	if !internal.BytesEqual(payload, tfrm2.Payload()) {
		t.Fatalf("payload mismatch %d %d", len(payload), len(tfrm2.Payload()))
	}
}

func TestIPv4TCPChecksum(t *testing.T) {
	var tcpPackets = [][]byte{
		{0xc0, 0xff, 0xee, 0x00, 0xde, 0xad, 0x4e, 0x8b, 0x3a, 0xf9, 0xfb, 0x6b, 0x08, 0x00, 0x45, 0x00,
			0x00, 0x3c, 0x01, 0xbe, 0x40, 0x00, 0x40, 0x06, 0xa3, 0xaa, 0xc0, 0xa8, 0x0a, 0x01, 0xc0, 0xa8,
			0x0a, 0x02, 0xe7, 0x0a, 0x00, 0x50, 0x40, 0x60, 0xd5, 0xcc, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
			0xfa, 0xf0, 0x62, 0xbc, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0xbb, 0xac,
			0x9b, 0xca, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07},
		{0xc0, 0xff, 0xee, 0x00, 0xde, 0xad, 0x4e, 0x8b, 0x3a, 0xf9, 0xfb, 0x6b, 0x08, 0x00, 0x45, 0x00,
			0x00, 0x3c, 0xfa, 0xfd, 0x40, 0x00, 0x40, 0x06, 0xaa, 0x6a, 0xc0, 0xa8, 0x0a, 0x01, 0xc0, 0xa8,
			0x0a, 0x02, 0xe7, 0x0e, 0x00, 0x50, 0x9c, 0xdc, 0xfe, 0x05, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
			0xfa, 0xf0, 0xde, 0x02, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0xbb, 0xac,
			0x9b, 0xca, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07},
	}
	var vld lneto.Validator
	for _, tcpPacket := range tcpPackets {
		efrm, _ := ethernet.NewFrame(tcpPacket)
		efrm.ValidateSize(&vld)
		ifrm, _ := ipv4.NewFrame(efrm.Payload())
		ifrm.ValidateSize(&vld)
		tfrm, _ := tcp.NewFrame(ifrm.Payload())
		tfrm.ValidateExceptCRC(&vld)
		if err := vld.ErrPop(); err != nil {
			t.Fatal(err)
		}
		wantCRC := ifrm.CRC()
		// Zero the CRC field so its value does not add to the final result.
		ifrm.SetCRC(0)
		gotCRC := ifrm.CalculateHeaderCRC()
		if wantCRC != gotCRC {
			t.Errorf("IPv4 CRC miscalculated. want %x, got %x", wantCRC, gotCRC)
		}
		wantCRC = tfrm.CRC()
		var crc lneto.CRC791
		ifrm.CRCWriteTCPPseudo(&crc)
		// Zero the CRC field so its value does not add to the final result.
		tfrm.SetCRC(0)
		gotCRC = crc.PayloadSum16(tfrm.RawData())
		if wantCRC != gotCRC {
			t.Errorf("TCP CRC miscalculated. want %x, got %x", wantCRC, gotCRC)
		}
	}
}

func TestNoDeps(t *testing.T) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	const expect = "module github.com/soypat/lneto\n\ngo 1.2"
	if !bytes.HasPrefix(data, []byte(expect)) {
		t.Fatalf("unexpected go.mod file:\nexpect:%sx\ngot:%s", expect, string(data))
	}
	if bytes.Contains(data, []byte("require")) {
		t.Fatal("no dependencies allowed in lneto")
	}
}

// TestCRC791Properties checks RFC 1071 behaviour of CRC791 over random data.
func TestCRC791Properties(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	buf := make([]byte, 256)
	for i := 0; i < 2000; i++ {
		n := 2 + rng.Intn(len(buf)-2)
		data := buf[:n]
		rng.Read(data)

		// Receiver verification: sender zeroes the checksum field, computes
		// the checksum and stores it. Summing the whole packet must yield zero.
		off := 2 * rng.Intn(n/2)
		data[off], data[off+1] = 0, 0
		var crc lneto.CRC791
		sum := lneto.NeverZeroSum(crc.PayloadSum16(data))
		binary.BigEndian.PutUint16(data[off:], sum)
		if got := crc.PayloadSum16(data); got != 0 {
			t.Fatalf("n=%d off=%d: verification sum got %#x, want 0", n, off, got)
		}

		// PayloadSum16 must not mutate running state.
		if got := crc.Sum16(); got != 0xffff {
			t.Fatalf("PayloadSum16 mutated state: Sum16()=%#x", got)
		}

		// Odd length is zero padded: appending a zero byte changes nothing.
		want := crc.PayloadSum16(data)
		if n%2 == 1 {
			padded := append(data[:n:n], 0)
			if got := crc.PayloadSum16(padded); got != want {
				t.Fatalf("n=%d: padded sum %#x != odd sum %#x", n, got, want)
			}
		}

		// Split invariance: arbitrary even-sized chunks give the same result.
		rest := data
		for len(rest) > 1 {
			chunk := 2 * rng.Intn(len(rest)/2+1)
			crc.WriteEven(rest[:chunk])
			rest = rest[chunk:]
		}
		if got := crc.PayloadSum16(rest); got != want {
			t.Fatalf("n=%d: chunked sum %#x != one-shot %#x", n, got, want)
		}

		// AddUint32/AddUint16 equivalent to writing big-endian bytes.
		crc.Reset()
		even := data[:n&^1]
		wantEven := crc.PayloadSum16(even)
		j := 0
		for ; j+4 <= len(even); j += 4 {
			crc.AddUint32(binary.BigEndian.Uint32(even[j:]))
		}
		if j < len(even) {
			crc.AddUint16(binary.BigEndian.Uint16(even[j:]))
		}
		if got := crc.Sum16(); got != wantEven {
			t.Fatalf("n=%d: AddUint sum %#x, want %#x", n, got, wantEven)
		}

		// Byte order independence (RFC 1071 §2B): swapping bytes of every
		// 16-bit word yields the byte-swapped checksum.
		crc.Reset()
		swapped := make([]byte, len(even))
		for j := 0; j < len(even); j += 2 {
			swapped[j], swapped[j+1] = even[j+1], even[j]
		}
		wantSwapped := wantEven<<8 | wantEven>>8
		if got := crc.PayloadSum16(swapped); got != wantSwapped {
			t.Fatalf("n=%d: swapped sum %#x, want %#x", n, got, wantSwapped)
		}
	}
}

// TestCRC791NegativeZero checks data whose ones' complement sum is 0xffff
// (negative zero). Raw checksum is 0x0000, which UDP reserves for "no checksum",
// so NeverZeroSum must transmit 0xffff instead and it must still verify.
func TestCRC791NegativeZero(t *testing.T) {
	data := []byte{0x12, 0x34, 0xed, 0xcb, 0, 0} // 0x1234+0xedcb = 0xffff; last word is checksum field.
	var crc lneto.CRC791
	raw := crc.PayloadSum16(data)
	if raw != 0 {
		t.Fatalf("raw checksum got %#x, want 0", raw)
	}
	sum := lneto.NeverZeroSum(raw)
	if sum != 0xffff {
		t.Fatalf("NeverZeroSum(0) got %#x, want 0xffff", sum)
	}
	binary.BigEndian.PutUint16(data[4:], sum)
	if got := crc.PayloadSum16(data); got != 0 {
		t.Fatalf("verification sum got %#x, want 0", got)
	}
}
