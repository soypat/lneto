package internet

import (
	"io"
	"log/slog"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

// stackip4 is NOT a StackNode implementation.
// It is meant to be embedded within StackNodes.
// var _ lneto.StackNode = (*stackip4)(nil)

type stackip4 struct {
	ip4             [4]byte
	ipID            uint16
	acceptMulticast bool
	handlers        handlers
	vld             *lneto.Validator
}

func (sb *stackip4) reset(vld *lneto.Validator, maxNodes int) {
	*sb = stackip4{
		ip4:             [4]byte{},
		ipID:            1,
		acceptMulticast: false,
		handlers:        sb.handlers,
		vld:             vld,
	}
	sb.handlers.reset("stackip4", maxNodes)
}

func (sb *stackip4) Demux(carrierData []byte, offset int) error {
	debugLog("ip:demux")
	sb.handlers.info("StackIP.Demux:start")
	frame := carrierData[offset:] // we don't care about carrier data in IP.
	ifrm, err := ipv4.NewFrame(frame)
	if err != nil {
		return err
	}
	dst := ifrm.DestinationAddr()
	if sb.ip4 != ([4]byte{}) && *dst != sb.ip4 {
		if !sb.acceptMulticast || dst[0]&0xF0 != 0xE0 {
			sb.handlers.debug("ip:not-for-us")
			return lneto.ErrPacketDrop // Not meant for us.
		}
	}

	sb.vld.ResetErr()
	ifrm.ValidateExceptCRC(sb.vld)
	if err = sb.vld.ErrPop(); err != nil {
		sb.handlers.error("ip:Demux.validate")
		return err
	}

	if ifrm.CalculateHeaderCRC() != 0 {
		sb.handlers.error("ip:demux.crc")
		return lneto.ErrBadCRC
	}
	off := ifrm.HeaderLength()
	totalLen := ifrm.TotalLength()
	proto := ifrm.Protocol()
	node := sb.handlers.nodeByProto(uint16(proto))
	// nodeIdx := getNodeByProto(sb.handlers, uint16(proto))
	if node == nil {
		// Drop packet.
		sb.handlers.info("ip:demux.drop", internal.SlogAddr4("dstaddr", ifrm.DestinationAddr()), slog.String("proto", ifrm.Protocol().String()))
		return lneto.ErrPacketDrop
	}
	// Incoming CRC Validation of common IP Protocols.
	var crc lneto.CRC791
	switch proto {
	case lneto.IPProtoTCP:
		ifrm.CRCWriteTCPPseudo(&crc)
		if crc.PayloadSum16(ifrm.Payload()) != 0 {
			sb.handlers.error("ip:demux.tcpcrc")
			return lneto.ErrBadCRC
		}
	case lneto.IPProtoUDP:
		ufrm, err := udp.NewFrame(ifrm.Payload())
		if err != nil {
			return err
		}
		ufrm.ValidateSize(sb.vld)
		if err = sb.vld.ErrPop(); err != nil {
			sb.handlers.error("ip:demux.udpvalidatesize")
			return err
		}
		frameLen := ufrm.Length()
		ifrm.CRCWriteUDPPseudo(&crc, frameLen)
		if crc.PayloadSum16(ufrm.RawData()[:frameLen]) != 0 {
			sb.handlers.error("ip:demux.udpcrc")
			return lneto.ErrBadCRC
		}
	}
	sb.handlers.info("ipDemux", slog.String("ipproto", proto.String()), slog.Int("plen", int(totalLen)))
	err = node.callbacks.Demux(frame[:totalLen], off)
	if sb.handlers.tryHandleError(node, err) {
		sb.handlers.info("ipclose", slog.String("proto", proto.String()))
		err = nil
	}
	return err
}

func (sb *stackip4) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	frame := carrierData[offsetToFrame:]
	if len(frame) < ipv4.MinimumMTU {
		return 0, io.ErrShortBuffer
	}
	ifrm, _ := ipv4.NewFrame(frame)
	const ihl = 5
	const headerlen = ihl * 4
	const dontFrag = 0x4000
	ifrm.SetVersionAndIHL(4, ihl)
	ifrm.SetToS(0)
	seed := (sb.ipID + 1) ^ uint16(sb.ip4[0])
	id := internal.Prand16(seed)
	ifrm.SetID(id)
	ifrm.SetFlags(dontFrag)
	ifrm.SetTTL(64)
	*ifrm.SourceAddr() = sb.ip4
	sb.ipID = id
	// Children (TCP/UDP) start at offset headerlen (20 bytes after IP header start).
	// offsetToIP is 0 relative to this slice (frame), children's frame starts at headerlen.
	node, n, err := sb.handlers.encapsulateAny(carrierData, offsetToFrame, offsetToFrame+headerlen)
	if n == 0 {
		return n, err
	}
	proto := lneto.IPProto(node.proto)
	totalLen := n + headerlen
	ifrm.SetTotalLength(uint16(totalLen))
	ifrm.SetProtocol(proto)
	// Zero the CRC field so its value does not add to the final result.
	ifrm.SetCRC(0)
	crcValue := ifrm.CalculateHeaderCRC()
	ifrm.SetCRC(crcValue)
	// Calculate CRC for our newly generated packet.
	var crc lneto.CRC791
	payload := ifrm.Payload()
	switch proto {
	case lneto.IPProtoTCP:
		ifrm.CRCWriteTCPPseudo(&crc)
		tfrm, _ := tcp.NewFrame(payload)
		// Zero the CRC field so its value does not add to the final result.
		tfrm.SetCRC(0)
		crcValue = crc.PayloadSum16(payload)
		tfrm.SetCRC(crcValue)
	case lneto.IPProtoUDP:
		ufrm, _ := udp.NewFrame(payload)
		ifrm.CRCWriteUDPPseudo(&crc, uint16(n))
		ufrm.SetLength(uint16(n))
		// Zero the CRC field so its value does not add to the final result.
		ufrm.SetCRC(0)
		crcValue = lneto.NeverZeroSum(crc.PayloadSum16(payload))
		ufrm.SetCRC(crcValue)
	}
	return totalLen, err
}

func (sb *stackip4) SetAcceptMulticast(accept bool) {
	sb.acceptMulticast = accept
}
func (sb *stackip4) Addr4() [4]byte { return sb.ip4 }
func (sb *stackip4) SetAddr4(ip4 [4]byte) {
	sb.ip4 = ip4
}
func (sb *stackip4) Protocol() uint64 { return uint64(ethernet.TypeIPv4) }

func (sb *stackip4) LocalPort() uint16 { return 0 }
