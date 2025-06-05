package pcap

import (
	"math"
	"math/rand"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
)

func TestCap(t *testing.T) {
	const mtu = 1500
	const httpBody = "{200,ok}"
	var buf [mtu]byte
	var gen ltesto.PacketGen
	rng := rand.New(rand.NewSource(1))
	gen.RandomizeAddrs(rng)
	pkt := gen.AppendRandomIPv4TCPPacket(buf[:0], rng, tcp.Segment{
		SEQ:     100,
		ACK:     200,
		DATALEN: 256,
		WND:     1024,
		Flags:   tcp.FlagFIN, //tcp.FlagSYN | tcp.FlagACK | tcp.FlagPSH,
	})
	var hdr httpraw.Header
	hdr.SetStatus("200", "OK")
	hdr.Set("Cookie", "ABC=123")
	pkt, _ = hdr.AppendResponse(pkt)
	pkt = append(pkt, httpBody...)
	var pbreak PacketBreakdown
	frames, err := pbreak.CaptureEthernet(nil, pkt, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Ethernet+IPv4+TCP+HTTP = 4 frames
	if len(frames) != 4 {
		t.Errorf("want 4 frames, got %d", len(frames))
	}
	getClass := func(frame Frame, class FieldClass) uint64 {
		idx, err := frame.FieldByClass(class)
		if err != nil {
			return 0xffff_ffff_ffff_ffff
		}
		v, _ := frame.FieldAsUint(idx, pkt)
		return v
	}
	getName := func(frame Frame, name string) uint64 {
		for i := range frame.Fields {
			if frame.Fields[i].Name == name {
				v, _ := frame.FieldAsUint(i, pkt)
				return v
			}
		}
		return math.MaxUint64
	}
	getClassData := func(frame Frame, class FieldClass) []byte {
		idx, err := frame.FieldByClass(class)
		if err != nil {
			return nil
		}
		v, _ := frame.AppendField(nil, idx, pkt)
		return v
	}
	efrm, _ := ethernet.NewFrame(pkt)
	pefrm := frames[0]
	pifrm := frames[1]
	ptfrm := frames[2]
	phfrm := frames[3]
	gotEproto := ethernet.Type(getClass(pefrm, FieldClassProto))
	if gotEproto != efrm.EtherTypeOrSize() {
		t.Errorf("want %s ethernet type, got %s", efrm.EtherTypeOrSize().String(), gotEproto.String())
	}

	ifrm, _ := ipv4.NewFrame(efrm.Payload())
	gotIproto := lneto.IPProto(getClass(pifrm, FieldClassProto))
	if gotIproto != ifrm.Protocol() {
		t.Errorf("want %s IP proto, got %s", ifrm.Protocol().String(), gotIproto.String())
	}
	gotToS := ipv4.ToS(getName(pifrm, "Type of Service"))
	wantToS := ifrm.ToS()
	if gotToS != wantToS {
		t.Errorf("want %x IP ToS, got %x", wantToS, gotToS)
	}
	gotIflags := ipv4.Flags(getClass(pifrm, FieldClassFlags))
	if gotIflags != ifrm.Flags() {
		t.Errorf("want %x IP flags, got %x", ifrm.Flags(), gotIflags)
	}
	gotVersion := getClass(pifrm, FieldClassVersion)
	wantVersion, _ := ifrm.VersionAndIHL()
	if gotVersion != uint64(wantVersion) {
		t.Errorf("want %d IP version, got %d", wantVersion, gotVersion)
	}

	tfrm, _ := tcp.NewFrame(ifrm.Payload())
	gotTCPFlags := tcp.Flags(getClass(ptfrm, FieldClassFlags))
	wantHeaderLen, wantTCPflags := tfrm.OffsetAndFlags()
	if gotTCPFlags != wantTCPflags {
		t.Errorf("want %s TCP flags, got %s", wantTCPflags.String(), gotTCPFlags.String())
	}
	wanDstPort := gen.DstTCP
	wantSrcPort := gen.SrcTCP
	gotSrcPort := uint16(getClass(ptfrm, FieldClassSrc))
	gotDstPort := uint16(getClass(ptfrm, FieldClassDst))
	if wantSrcPort != gotSrcPort {
		t.Errorf("want %d TCP src port, got %d", wantSrcPort, gotSrcPort)
	}
	if wanDstPort != gotDstPort {
		t.Errorf("want %d TCP dst port, got %d", wanDstPort, gotDstPort)
	}
	gotHeaderLen := getClass(ptfrm, FieldClassSize)
	if gotHeaderLen != uint64(wantHeaderLen) {
		t.Errorf("want %d TCP header length, got %d", wantHeaderLen, gotHeaderLen)
	}
	gotBody := getClassData(phfrm, FieldClassPayload)
	if string(gotBody) != httpBody {
		t.Errorf("want %q HTTP body, got %q", httpBody, gotBody)
	}
}
