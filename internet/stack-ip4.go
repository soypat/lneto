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

type StackIPv4 struct {
	connID uint64
	stackip4
}

func (stackip4 *StackIPv4) Reset(vld *lneto.Validator, maxNodes int) error {
	stackip4.reset4(vld, maxNodes)
	return nil
}

func (stackip *StackIPv4) ConnectionID() *uint64 {
	return &stackip.connID
}

func (stackip *StackIPv4) Protocol() uint64 {
	return uint64(ethernet.TypeIPv4)
}

func (stackip *StackIPv4) LocalPort() uint16 { return 0 }

func (stackip *StackIPv4) SetLogger(logger *slog.Logger) {
	stackip.stackip4.handlers.log = logger
}

func (stackip *StackIPv4) Demux(carrierData []byte, offset int) error {
	debugLog("ip:demux")
	return stackip.stackip4.demux4(carrierData, offset)
}

func (stackip *StackIPv4) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (n int, err error) {
	if offsetToFrame != offsetToIP {
		return 0, lneto.ErrBug
	}
	return stackip.stackip4.encapsulate4(carrierData, offsetToIP)
}

type stackip4 struct {
	handlers        handlers
	vld             *lneto.Validator
	ipID            uint16
	ip4             [4]byte
	acceptMulticast bool
}

func (si4 *stackip4) reset4(vld *lneto.Validator, maxNodes int) {
	*si4 = stackip4{
		ip4:             [4]byte{},
		ipID:            1,
		acceptMulticast: false,
		handlers:        si4.handlers,
		vld:             vld,
	}
	si4.handlers.reset("stackip4", maxNodes)
}

func (si4 *stackip4) Register4(h lneto.StackNode) error {
	proto := h.Protocol()
	if proto > 255 {
		return lneto.ErrInvalidConfig
	}
	return si4.handlers.registerByPortProto(nodeFromStackNode(h, h.LocalPort(), proto, nil))
}

func (si4 *stackip4) IsRegistered4(proto lneto.IPProto) bool {
	return si4.handlers.nodeByProto(uint16(proto)) != nil
}

func (si4 *stackip4) SetAcceptMulticast4(accept bool) {
	si4.acceptMulticast = accept
}
func (si4 *stackip4) Addr4() [4]byte { return si4.ip4 }
func (si4 *stackip4) SetAddr4(ip4 [4]byte) {
	si4.ip4 = ip4
}

func (si4 *stackip4) demux4(carrierData []byte, offset int) error {
	debugLog("ip4:demux")
	si4.handlers.info("demux:start")
	frame := carrierData[offset:] // we don't care about carrier data in IP.
	ifrm, err := ipv4.NewFrame(frame)
	if err != nil {
		return err
	}
	dst := ifrm.DestinationAddr()
	if si4.ip4 != ([4]byte{}) && *dst != si4.ip4 {
		if !si4.acceptMulticast || !internal.IsMulticastIPAddr(dst[:]) {
			si4.handlers.debug("ip:not-for-us")
			return lneto.ErrPacketDrop // Not meant for us.
		}
	}

	si4.vld.ResetErr()
	ifrm.ValidateExceptCRC(si4.vld)
	if err = si4.vld.ErrPop(); err != nil {
		si4.handlers.error("ip:Demux.validate")
		return err
	}

	if ifrm.CalculateHeaderCRC() != 0 {
		si4.handlers.error("ip:demux.crc")
		return lneto.ErrBadCRC
	}
	off := ifrm.HeaderLength()

	proto := ifrm.Protocol()
	node := si4.handlers.nodeByProto(uint16(proto))
	// nodeIdx := getNodeByProto(sb.handlers, uint16(proto))
	if node == nil {
		// Drop packet.
		si4.handlers.info("ip:demux.drop", internal.SlogAddr4("dstaddr", ifrm.DestinationAddr()), slog.String("proto", ifrm.Protocol().String()))
		return lneto.ErrPacketDrop
	}
	// Incoming CRC Validation of common IP Protocols.
	var crc lneto.CRC791
	switch proto {
	case lneto.IPProtoTCP:
		ifrm.CRCWriteTCPPseudo(&crc)
		if crc.PayloadSum16(ifrm.Payload()) != 0 {
			si4.handlers.error("ip:demux.tcpcrc")
			return lneto.ErrBadCRC
		}
	case lneto.IPProtoUDP:
		ufrm, err := udp.NewFrame(ifrm.Payload())
		if err != nil {
			return err
		}
		ufrm.ValidateSize(si4.vld)
		if err = si4.vld.ErrPop(); err != nil {
			si4.handlers.error("ip:demux.udpvalidatesize")
			return err
		}
		frameLen := ufrm.Length()
		ifrm.CRCWriteUDPPseudo(&crc, frameLen)
		if crc.PayloadSum16(ufrm.RawData()[:frameLen]) != 0 {
			si4.handlers.error("ip:demux.udpcrc")
			return lneto.ErrBadCRC
		}
	}
	totalLen := ifrm.TotalLength()
	si4.handlers.info("ipDemux", slog.String("ipproto", proto.String()), slog.Int("tlen", int(totalLen)))
	err = node.callbacks.Demux(frame[:totalLen], off)
	if si4.handlers.tryHandleError(node, err) {
		si4.handlers.info("ipclose", slog.String("proto", proto.String()))
		err = nil
	}
	return err
}

func (si4 *stackip4) encapsulate4(carrierData []byte, offsetToIP int) (int, error) {
	frame := carrierData[offsetToIP:]
	if len(frame) < ipv4.MinimumMTU {
		return 0, io.ErrShortBuffer
	}
	ifrm, _ := ipv4.NewFrame(frame)
	const ihl = 5
	const headerlen = ihl * 4
	const dontFrag = 0x4000
	ifrm.SetVersionAndIHL(4, ihl)
	ifrm.SetToS(0)
	seed := (si4.ipID + 1) ^ uint16(si4.ip4[0])
	id := internal.Prand16(seed)
	ifrm.SetID(id)
	ifrm.SetFlags(dontFrag)
	ifrm.SetTTL(64)
	*ifrm.SourceAddr() = si4.ip4
	si4.ipID = id
	// Children (TCP/UDP) start at offset headerlen (20 bytes after IP header start).
	// offsetToIP is 0 relative to this slice (frame), children's frame starts at headerlen.
	node, n, err := si4.handlers.encapsulateAny(carrierData, offsetToIP, offsetToIP+headerlen)
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
