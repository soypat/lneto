package lneto

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/soypat/tseq/lneto/tcp"
)

func TestTCPMarshalUnmarshal(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var gen packetGen
	gen.randomizeAddrs(rng)
	const maxSize = 4096
	src := make([]byte, maxSize)
	dst := make([]byte, maxSize)
	for i := 0; i < 512; i++ {
		src = gen.appendRandomIPv4TCPPacket(src[:0], rng)
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
	efrm, err := NewEthFrame(src)
	if err != nil {
		t.Fatal(err)
	}
	epl := efrm.Payload()
	ifrm, err := NewIPv4Frame(epl)
	if err != nil {
		t.Fatal(err)
	}
	ipl := ifrm.Payload()
	tfrm, err := NewTCPFrame(ipl)
	if err != nil {
		t.Fatal(err)
	}

	efrm2, _ := NewEthFrame(dst)
	*efrm2.DestinationHardwareAddr() = *efrm.DestinationHardwareAddr()
	*efrm2.SourceHardwareAddr() = *efrm.SourceHardwareAddr()
	efrm2.SetEtherType(efrm.EtherTypeOrSize())
	if efrm.EtherTypeOrSize() == EtherTypeVLAN {
		efrm2.SetVLANTag(efrm.VLANTag())
		efrm2.SetVLANEtherType(efrm.VLANEtherType())
	}

	ifrm2, _ := NewIPv4Frame(efrm2.Payload())
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

	tfrm2, _ := NewTCPFrame(ifrm2.Payload())
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

type packetGen struct {
	srcMAC, dstMAC   [6]byte // hardware address
	srcIPv4, dstIPv4 [4]byte // address
	srcTCP, dstTCP   uint16  // ports
}

func (gen *packetGen) randomizeAddrs(rng *rand.Rand) {
	rng.Read(gen.srcMAC[:])
	rng.Read(gen.dstMAC[:])
	rng.Read(gen.srcIPv4[:])
	rng.Read(gen.dstIPv4[:])
	ports := rng.Uint32()
	gen.srcTCP = uint16(ports)
	gen.dstTCP = uint16(ports >> 16)
}

func (gen *packetGen) appendRandomIPv4TCPPacket(dst []byte, rng *rand.Rand) []byte {
	ri := rng.Int()
	var (
		isVLAN     = ri&(1<<0) != 0
		hasIPOpt   = ri&(1<<1) != 0
		hasTCPOpt  = ri&(1<<2) != 0
		hasPayload = ri&(1<<3) != 0
	)
	var etherType EtherType = EtherTypeIPv4
	var ipOpts []byte
	if hasIPOpt {
		ipOpts = []byte{1, 2, 3, 4}
	}
	ethsize := 14
	if isVLAN {
		etherType = EtherTypeVLAN
		ethsize = 18
	}
	var tcpOpts []byte
	if hasTCPOpt {
		tcpOpts = []byte{byte(tcp.OptSACKPermitted), 0, 1, 0}
	}
	var payloadLen int
	if hasPayload {
		payloadLen = (ri >> 16) % 1024
	}
	ipOptWLen := sizeWord(len(ipOpts))
	tcpOptWlen := sizeWord(len(tcpOpts))
	off := len(dst)
	dst = append(dst, make([]byte, ethsize+sizeHeaderIPv4+4*int(ipOptWLen)+sizeHeaderTCP+4*int(tcpOptWlen)+payloadLen)...)
	efrm, err := NewEthFrame(dst[off:])
	if err != nil {
		panic(err)
	}
	*efrm.DestinationHardwareAddr() = gen.dstMAC
	*efrm.SourceHardwareAddr() = gen.srcMAC

	efrm.SetEtherType(etherType)
	if isVLAN {
		efrm.SetVLANEtherType(EtherTypeIPv4)
		efrm.SetVLANTag(1 << 4)
	}
	ethernetPayload := efrm.Payload()
	ifrm, err := NewIPv4Frame(ethernetPayload)
	if err != nil {
		panic(err)
	}
	ifrm.SetVersionAndIHL(4, sizeWord(20+len(ipOpts)))
	ifrm.SetToS(192)
	ifrm.SetTotalLength(uint16(len(ethernetPayload)))
	ifrm.SetID(uint16(rng.Uint32()))
	ifrm.SetFlags(0x4001) // Don't fragment.
	ifrm.SetTTL(64)
	ifrm.SetProtocol(IPProtoTCP)
	*ifrm.SourceAddr() = gen.srcIPv4
	*ifrm.DestinationAddr() = gen.dstIPv4
	ifrm.SetCRC(ifrm.CalculateHeaderCRC())

	ipPayload := ifrm.Payload()
	tfrm, err := NewTCPFrame(ipPayload)
	if err != nil {
		panic(err)
	}
	tfrm.SetSourcePort(gen.srcTCP)
	tfrm.SetDestinationPort(gen.dstTCP)
	tfrm.SetSeq(tcp.Value(rng.Uint32()))
	tfrm.SetAck(tcp.Value(rng.Uint32()))
	wlen := sizeWord(sizeHeaderTCP + len(tcpOpts))
	tfrm.SetOffsetAndFlags(wlen, tcp.Flags(rng.Uint32()))
	tfrm.SetWindowSize(uint16(rng.Uint32()))
	urgPtr := uint16(rng.Uint32())
	tfrm.SetUrgentPtr(urgPtr)
	tcpPayload := tfrm.Payload()
	var firstPayloadByte byte
	if len(tcpPayload) > 0 {
		rng.Read(tcpPayload)
		firstPayloadByte = tcpPayload[0]
	}
	// Set Variable section of data.
	copy(ifrm.Options(), ipOpts)
	copy(tfrm.Options(), tcpOpts)
	switch {
	case gen.srcTCP != tfrm.SourcePort():
		panic("IP options overwrite TCP header")
	case !bytes.Equal(ifrm.Options(), ipOpts):
		panic("bad ip options written, ensure ip options length is multiple of 4")
	case !bytes.Equal(tfrm.Options(), tcpOpts):
		panic("bad tcp options written, ensure tcp options length is multiple of 4")
	case *ifrm.DestinationAddr() != gen.dstIPv4:
		panic("IP options overwrite own header")
	case tfrm.UrgentPtr() != urgPtr:
		panic("TCP options overwrite urgent pointer field?")
	case len(tcpPayload) > 0 && firstPayloadByte != tcpPayload[0]:
		panic("TCP options overwrite payload")
	}
	err = efrm.ValidateSize()
	if err != nil {
		panic(err)
	}
	err = ifrm.ValidateSize()
	if err != nil {
		panic(err)
	}
	err = tfrm.ValidateSize()
	if err != nil {
		panic(err)
	}
	return dst
}

func sizeWord(l int) uint8 {
	return uint8((l + 3) / 4)
}
