package internet

import (
	"io"
	"log/slog"
	"net/netip"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

var _ lneto.StackNode = (*StackIP)(nil)

type StackIP6 struct {
	connID          uint64
	ipID            uint16
	ip4             [4]byte
	ip6             [16]byte
	acceptMulticast bool
	validator       *lneto.Validator
	handlers        handlers
}

func (sb *StackIP6) Reset(vld *lneto.Validator, maxNodes int) error {
	if maxNodes <= 0 {
		return lneto.ErrInvalidConfig
	}
	sb.handlers.reset("StackIP66", maxNodes)
	*sb = StackIP6{
		connID:          sb.connID + 1,
		validator:       sb.validator,
		handlers:        sb.handlers,
		acceptMulticast: sb.acceptMulticast,
	}
	return nil
}

func (sb *StackIP6) SetAddr4(ip4 [4]byte)  { sb.ip4 = ip4 }
func (sb *StackIP6) SetAddr6(ip4 [16]byte) { sb.ip6 = ip4 }
func (sb *StackIP6) Addr4() [4]byte        { return sb.ip4 }
func (sb *StackIP6) Addr6() [16]byte       { return sb.ip6 }

func (sb *StackIP6) ConnectionID() *uint64 {
	return &sb.connID
}

func (sb *StackIP6) Protocol() uint64 {
	return uint64(ethernet.TypeIPv4) // Only support ipv4 for now.
}

func (sb *StackIP6) LocalPort() uint16 { return 0 }

func (sb *StackIP6) Addr() netip.Addr {
	return netip.AddrFrom4(sb.ip4)
}

func (sb *StackIP6) SetAcceptMulticast(accept bool) {
	sb.acceptMulticast = accept
}

func (sb *StackIP6) SetLogger(logger *slog.Logger) {
	sb.handlers.log = logger
}

func (sb *StackIP6) Demux(carrierData []byte, offset int) error {
	debugLog("ip:demux")
	sb.handlers.info("StackIP6.Demux:start")
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

	sb.validator.ResetErr()
	ifrm.ValidateExceptCRC(sb.validator)
	if err = sb.validator.ErrPop(); err != nil {
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
		ufrm.ValidateSize(sb.validator)
		if err = sb.validator.ErrPop(); err != nil {
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

func (sb *StackIP6) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
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
	seed := sb.ipID ^ uint16(sb.connID)
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

func (sb *StackIP6) Register(h lneto.StackNode) error {
	proto := h.Protocol()
	if proto > 255 {
		return lneto.ErrInvalidConfig
	}
	return sb.handlers.registerByPortProto(nodeFromStackNode(h, h.LocalPort(), proto, nil))
}

func (sb *StackIP6) IsRegistered(proto lneto.IPProto) bool {
	return sb.handlers.nodeByProto(uint16(proto)) != nil
}

func (sb *StackIP6) recvicmp(icmpData []byte) error {
	var crc lneto.CRC791
	if crc.PayloadSum16(icmpData) != 0 {
		return lneto.ErrBadCRC
	}
	return nil
}
