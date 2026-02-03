package internet

import (
	"errors"
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

var _ StackNode = (*StackIP)(nil)

type StackIP struct {
	connID    uint64
	ipID      uint16
	ip        [4]byte
	validator lneto.Validator
	handlers  handlers
}

func (sb *StackIP) Reset(addr netip.Addr, maxNodes int) error {
	if maxNodes <= 0 {
		return errZeroMaxNodesArg
	}
	err := sb.SetAddr(addr)
	if err != nil {
		return err
	}
	sb.handlers.reset("StackIP", maxNodes)
	*sb = StackIP{
		connID:    sb.connID + 1,
		validator: sb.validator,
		handlers:  sb.handlers,
		ip:        sb.ip,
	}
	return nil
}

func (sb *StackIP) SetAddr(addr netip.Addr) error {
	if !addr.IsValid() {
		return errors.New("invalid IP")
	} else if !addr.Is4() {
		return errors.New("require IPv4")
	}
	sb.ip = addr.As4()
	return nil
}

func (sb *StackIP) ConnectionID() *uint64 {
	return &sb.connID
}

func (sb *StackIP) Protocol() uint64 {
	return uint64(ethernet.TypeIPv4) // Only support ipv4 for now.
}

func (sb *StackIP) LocalPort() uint16 { return 0 }

func (sb *StackIP) Addr() netip.Addr {
	return netip.AddrFrom4(sb.ip)
}

func (sb *StackIP) SetLogger(logger *slog.Logger) {
	sb.handlers.log = logger
}

func (sb *StackIP) Demux(carrierData []byte, offset int) error {
	sb.handlers.info("StackIP.Demux:start")
	frame := carrierData[offset:] // we don't care about carrier data in IP.
	ifrm, err := ipv4.NewFrame(frame)
	if err != nil {
		return err
	}
	dst := ifrm.DestinationAddr()
	if sb.ip != ([4]byte{}) && *dst != sb.ip {
		sb.handlers.debug("ip:not-for-us")
		return lneto.ErrPacketDrop // Not meant for us.
	}

	sb.validator.ResetErr()
	ifrm.ValidateExceptCRC(&sb.validator)
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
	if proto == lneto.IPProtoICMP {
		return sb.recvicmp(ifrm.RawData(), ifrm.HeaderLength())
	}
	node := sb.handlers.nodeByProto(uint16(proto))
	// nodeIdx := getNodeByProto(sb.handlers, uint16(proto))
	if node == nil {
		// Drop packet.
		sb.handlers.info("ip:demux.drop", slog.String("dstaddr", netip.AddrFrom4(*ifrm.DestinationAddr()).String()), slog.String("proto", ifrm.Protocol().String()))
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
		ufrm, err := udp.NewBoundedFrame(ifrm.Payload())
		if err != nil {
			return err
		}
		ifrm.CRCWriteUDPPseudo(&crc, ufrm.Length())
		if crc.PayloadSum16(ufrm.RawData()) != 0 {
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

func (sb *StackIP) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	frame := carrierData[offsetToFrame:]
	if len(frame) < 256 {
		return 0, io.ErrShortBuffer
	}
	ifrm, _ := ipv4.NewFrame(frame)
	const ihl = 5
	const headerlen = ihl * 4
	const dontFrag = 0x4000
	ifrm.SetVersionAndIHL(4, ihl)
	ifrm.SetToS(0)
	seed := sb.ipID + uint16(sb.connID)
	id := internal.Prand16(seed)
	ifrm.SetID(id)
	ifrm.SetFlags(dontFrag)
	ifrm.SetTTL(64)
	*ifrm.SourceAddr() = sb.ip
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

func (sb *StackIP) Register(h StackNode) error {
	proto := h.Protocol()
	if proto > 255 {
		return errInvalidProto
	}
	return sb.handlers.registerByPortProto(nodeFromStackNode(h, h.LocalPort(), proto, nil))
}

func (sb *StackIP) recvicmp(carrierData []byte, offset int) error {
	frameData := carrierData[offset:]
	var crc lneto.CRC791
	if crc.PayloadSum16(frameData) != 0 {
		return errors.New("ICMP CRC mismatch")
	}
	return nil
}

type logger struct {
	log *slog.Logger
}

func (l logger) error(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.log, slog.LevelError, msg, attrs...)
}
func (l logger) info(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.log, slog.LevelInfo, msg, attrs...)
}
func (l logger) warn(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.log, slog.LevelWarn, msg, attrs...)
}
func (l logger) debug(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.log, slog.LevelDebug, msg, attrs...)
}
func (l logger) trace(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.log, internal.LevelTrace, msg, attrs...)
}
