package lneto_test

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/tcp"
)

func TestTCPMarshalUnmarshal(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var gen ltesto.PacketGen
	gen.RandomizeAddrs(rng)
	const maxSize = 4096
	src := make([]byte, maxSize)
	dst := make([]byte, maxSize)
	for i := 0; i < 512; i++ {
		src = gen.AppendRandomIPv4TCPPacket(src[:0], rng, tcp.Segment{
			SEQ:     tcp.Value(rng.Int()),
			ACK:     tcp.Value(rng.Int()),
			DATALEN: tcp.Size(rng.Intn(256)),
			WND:     tcp.Size(rng.Intn(1024)),
			Flags:   tcp.FlagACK,
		})
		dst = dst[:len(src)]
		testMoveTCPPacket(t, src, dst)
		if !bytes.Equal(src, dst) {
			t.Fatal("mismatching data")
		}
	}
}

func testMoveTCPPacket(t *testing.T, src, dst []byte) {
	if len(src) != len(dst) {
		panic("expect src and dst same length")
	}
	efrm, err := lneto.NewEthFrame(src)
	if err != nil {
		t.Fatal(err)
	}
	epl := efrm.Payload()
	ifrm, err := lneto.NewIPv4Frame(epl)
	if err != nil {
		t.Fatal(err)
	}
	ipl := ifrm.Payload()
	tfrm, err := lneto.NewTCPFrame(ipl)
	if err != nil {
		t.Fatal(err)
	}

	efrm2, _ := lneto.NewEthFrame(dst)
	*efrm2.DestinationHardwareAddr() = *efrm.DestinationHardwareAddr()
	*efrm2.SourceHardwareAddr() = *efrm.SourceHardwareAddr()
	efrm2.SetEtherType(efrm.EtherTypeOrSize())
	if efrm.EtherTypeOrSize() == lneto.EtherTypeVLAN {
		efrm2.SetVLANTag(efrm.VLANTag())
		efrm2.SetVLANEtherType(efrm.VLANEtherType())
	}

	ifrm2, _ := lneto.NewIPv4Frame(efrm2.Payload())
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

	tfrm2, _ := lneto.NewTCPFrame(ifrm2.Payload())
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
	if !bytes.Equal(src[:elen], dst[:elen]) {
		t.Fatalf("Ethernet header mismatch\n%x\n%x", src[:elen], dst[:elen])
	}
	ilen := ifrm.HeaderLength()
	if !bytes.Equal(src[elen:elen+20], dst[elen:elen+20]) {
		t.Fatalf("IPv4 header mismatch\n%x\n%x", src[elen:elen+20], dst[elen:elen+20])
	}
	ipoptLen := len(ifrm.Options())
	if !bytes.Equal(ifrm.Options(), ifrm2.Options()) {
		t.Fatalf("IPv4 options mismatch\n%x\n%x", ifrm.Options(), ifrm2.Options())
	} else if ipoptLen > 0 && &ifrm.Options()[0] != &src[elen+20] {
		t.Fatal("IPv4 options start pointer mismatch")
	}

	tlen := tfrm.HeaderLength()
	toff := elen + ilen + ipoptLen
	if !bytes.Equal(src[toff:toff+tlen], dst[toff:toff+tlen]) {
		t.Fatalf("TCP header mismatch\n%x\n%x", src[toff:toff+tlen], dst[toff:toff+tlen])
	}
	payload := tfrm.Payload()

	if !bytes.Equal(payload, tfrm2.Payload()) {
		t.Fatalf("payload mismatch %d %d", len(payload), len(tfrm2.Payload()))
	}
}
