package ltesto

import (
	"bytes"
	"math"
	"math/rand"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
)

const (
	sizeHeaderIPv4      = 20
	sizeHeaderTCP       = 20
	sizeHeaderEthNoVLAN = 14
	sizeHeaderUDP       = 8
	sizeHeaderARPv4     = 28
	sizeHeaderIPv6      = 40
)

type PacketGen struct {
	SrcMAC, DstMAC   [6]byte // hardware address
	SrcIPv4, DstIPv4 [4]byte // address
	SrcTCP, DstTCP   uint16  // ports
	EnableVLAN       bool
}

func (gen *PacketGen) RandomizeAddrs(rng *rand.Rand) {
	rng.Read(gen.SrcMAC[:])
	rng.Read(gen.DstMAC[:])
	rng.Read(gen.SrcIPv4[:])
	rng.Read(gen.DstIPv4[:])
	ports := rng.Uint32()
	gen.SrcTCP = uint16(ports)
	gen.DstTCP = uint16(ports >> 16)
}

func (gen *PacketGen) AppendRandomIPv4TCPPacket(dst []byte, rng *rand.Rand, seg tcp.Segment) []byte {
	if seg.WND > math.MaxUint16 {
		panic("TCP segment window overflow")
	} else if seg.DATALEN > 2048 {
		panic("too long datalen")
	}
	ri := rng.Int()
	var (
		isVLAN    = ri&(1<<0) != 0
		hasIPOpt  = ri&(1<<1) != 0
		hasTCPOpt = ri&(1<<2) != 0
	)
	var etherType ethernet.Type = ethernet.TypeIPv4
	var ipOpts []byte
	if hasIPOpt {
		ipOpts = []byte{1, 2, 3, 4}
	}
	ethsize := 14
	if gen.EnableVLAN && isVLAN {
		etherType = ethernet.TypeVLAN
		ethsize = 18
	}
	var tcpOpts []byte
	if hasTCPOpt {
		tcpOpts = []byte{byte(tcp.OptSACKPermitted), 0, 1, 0}
	}

	ipOptWLen := sizeWord(len(ipOpts))
	tcpOptWlen := sizeWord(len(tcpOpts))
	off := len(dst)
	dst = append(dst, make([]byte, ethsize+sizeHeaderIPv4+4*int(ipOptWLen)+sizeHeaderTCP+4*int(tcpOptWlen)+int(seg.DATALEN))...)
	efrm, err := ethernet.NewFrame(dst[off:])
	if err != nil {
		panic(err)
	}
	*efrm.DestinationHardwareAddr() = gen.DstMAC
	*efrm.SourceHardwareAddr() = gen.SrcMAC

	efrm.SetEtherType(etherType)
	if isVLAN {
		efrm.SetVLANEtherType(ethernet.TypeIPv4)
		efrm.SetVLANTag(1 << 4)
	}
	ethernetPayload := efrm.Payload()
	ifrm, err := ipv4.NewFrame(ethernetPayload)
	if err != nil {
		panic(err)
	}
	ifrm.SetVersionAndIHL(4, sizeWord(20+len(ipOpts)))
	ifrm.SetToS(192)
	ifrm.SetTotalLength(uint16(len(ethernetPayload)))
	ifrm.SetID(uint16(rng.Uint32()))
	ifrm.SetFlags(0x4001) // Don't fragment.
	ifrm.SetTTL(64)
	ifrm.SetProtocol(lneto.IPProtoTCP)
	*ifrm.SourceAddr() = gen.SrcIPv4
	*ifrm.DestinationAddr() = gen.DstIPv4
	// Zero the CRC field so its value does not add to the final result.
	ifrm.SetCRC(0)
	crcValue := ifrm.CalculateHeaderCRC()
	ifrm.SetCRC(crcValue)

	ipPayload := ifrm.Payload()
	tfrm, err := tcp.NewFrame(ipPayload)
	if err != nil {
		panic(err)
	}
	tfrm.SetSourcePort(gen.SrcTCP)
	tfrm.SetDestinationPort(gen.DstTCP)
	tfrm.SetSeq(seg.SEQ)
	tfrm.SetAck(seg.ACK)
	wlen := sizeWord(sizeHeaderTCP + len(tcpOpts))
	tfrm.SetOffsetAndFlags(wlen, seg.Flags)
	tfrm.SetWindowSize(uint16(seg.WND))
	urgPtr := uint16(rng.Uint32())
	tfrm.SetUrgentPtr(urgPtr)
	tcpPayload := tfrm.Payload()
	var firstPayloadByte byte
	if len(tcpPayload) > 0 {
		rng.Read(tcpPayload)
		firstPayloadByte = tcpPayload[0]
		if len(tcpPayload) != int(seg.DATALEN) {
			panic("incorrect payload length calculation")
		}
	}
	// Set Variable section of data.
	copy(ifrm.Options(), ipOpts)
	copy(tfrm.Options(), tcpOpts)
	var crc lneto.CRC791
	ifrm.CRCWriteTCPPseudo(&crc)
	// Zero the CRC field so its value does not add to the final result.
	tfrm.SetCRC(0)
	crcValue = crc.PayloadSum16(tfrm.RawData())
	tfrm.SetCRC(crcValue)
	switch {
	case gen.SrcTCP != tfrm.SourcePort():
		panic("IP options overwrite TCP header")
	case !bytes.Equal(ifrm.Options(), ipOpts):
		panic("bad ip options written, ensure ip options length is multiple of 4")
	case !bytes.Equal(tfrm.Options(), tcpOpts):
		panic("bad tcp options written, ensure tcp options length is multiple of 4")
	case *ifrm.DestinationAddr() != gen.DstIPv4:
		panic("IP options overwrite own header")
	case tfrm.UrgentPtr() != urgPtr:
		panic("TCP options overwrite urgent pointer field?")
	case len(tcpPayload) > 0 && firstPayloadByte != tcpPayload[0]:
		panic("TCP options overwrite payload")
	}
	var vld lneto.Validator
	efrm.ValidateSize(&vld)
	if err = vld.ErrPop(); err != nil {
		panic(err)
	}
	ifrm.ValidateExceptCRC(&vld)
	if err = vld.ErrPop(); err != nil {
		panic(err)
	}
	tfrm.ValidateSize(&vld)
	if err = vld.ErrPop(); err != nil {
		panic(err)
	}
	return dst
}

func sizeWord(l int) uint8 {
	return uint8((l + 3) / 4)
}
