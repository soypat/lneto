package internet

import (
	"log/slog"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ipv6"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

// stackip6 is NOT a StackNode implementation.
// It is meant to be embedded within StackNodes.
// var _ lneto.StackNode = (*stackip6)(nil)

type stackip6 struct {
	handlers        handlers
	vld             *lneto.Validator
	ip6             [16]byte
	acceptMulticast bool
}

func (si6 *stackip6) Register6(h lneto.StackNode) error {
	proto := h.Protocol()
	if proto > 255 {
		return lneto.ErrInvalidConfig
	}
	return si6.handlers.registerByPortProto(nodeFromStackNode(h, h.LocalPort(), proto, nil))
}

func (si6 *stackip6) IsRegistered6(proto lneto.IPProto) bool {
	return si6.handlers.nodeByProto(uint16(proto)) != nil
}

func (si6 *stackip6) SetAcceptMulticast6(accept bool) { si6.acceptMulticast = accept }
func (si6 *stackip6) Addr6() [16]byte                 { return si6.ip6 }
func (si6 *stackip6) SetAddr6(ip6 [16]byte)           { si6.ip6 = ip6 }

func (si6 *stackip6) reset6(vld *lneto.Validator, maxNodes int) {
	*si6 = stackip6{
		handlers: si6.handlers,
		vld:      vld,
	}
	si6.handlers.reset("stackip6", maxNodes)
}

func (si6 *stackip6) demux6(carrierData []byte, offset int) error {
	debugLog("ip6:demux")
	si6.handlers.info("StackIP6.Demux:start")
	ifrm, err := ipv6.NewFrame(carrierData[offset:])
	if err != nil {
		return err
	}
	dst := ifrm.DestinationAddr()
	if si6.ip6 != ([16]byte{}) && *dst != si6.ip6 {
		if !si6.acceptMulticast || dst[0] != 0xFF {
			si6.handlers.debug("ip6:not-for-us")
			return lneto.ErrPacketDrop
		}
	}

	si6.vld.ResetErr()
	ifrm.ValidateSize(si6.vld)
	if err = si6.vld.ErrPop(); err != nil {
		si6.handlers.error("ip6:Demux.validate")
		return err
	}

	proto := ifrm.NextHeader()
	node := si6.handlers.nodeByProto(uint16(proto))
	if node == nil {
		si6.handlers.info("ip6:demux.drop", slog.String("proto", proto.String()))
		return lneto.ErrPacketDrop
	}
	payload := ifrm.Payload()
	var crc lneto.CRC791
	switch proto {
	case lneto.IPProtoTCP:
		ifrm.CRCWritePseudo(&crc)
		if crc.PayloadSum16(payload) != 0 {
			si6.handlers.error("ip6:demux.tcpcrc")
			return lneto.ErrBadCRC
		}
	case lneto.IPProtoUDP:
		ufrm, err := udp.NewFrame(payload)
		if err != nil {
			return err
		}
		ufrm.ValidateSize(si6.vld)
		if err = si6.vld.ErrPop(); err != nil {
			si6.handlers.error("ip6:demux.udpvalidatesize")
			return err
		}
		ifrm.CRCWritePseudo(&crc)
		if crc.PayloadSum16(payload) != 0 {
			si6.handlers.error("ip6:demux.udpcrc")
			return lneto.ErrBadCRC
		}
	}
	const headerlen = 40
	plen := ifrm.PayloadLength()
	si6.handlers.info("ip6Demux", slog.String("ipproto", proto.String()), slog.Int("plen", int(plen)))
	err = node.callbacks.Demux(carrierData[offset:offset+headerlen+int(plen)], headerlen)
	if si6.handlers.tryHandleError(node, err) {
		si6.handlers.info("ip6close", slog.String("proto", proto.String()))
		err = nil
	}
	return err
}

func (si6 *stackip6) encapsulate6(carrierData []byte, offsetToIP int) (int, error) {
	ifrm, err := ipv6.NewFrame(carrierData[offsetToIP:])
	if err != nil {
		return 0, err
	}
	// Set default parameters which node is free to change.
	ifrm.SetVersionTrafficAndFlow(6, 0, 0)
	ifrm.SetHopLimit(64)
	*ifrm.SourceAddr() = si6.ip6
	const headerlen = 40
	node, n, err := si6.handlers.encapsulateAny(carrierData, offsetToIP, offsetToIP+headerlen)
	if n == 0 {
		return n, err
	}
	proto := lneto.IPProto(node.proto)
	ifrm.SetNextHeader(proto)
	ifrm.SetPayloadLength(uint16(n))
	var crc lneto.CRC791
	payload := ifrm.Payload()
	switch proto {
	case lneto.IPProtoTCP:
		ifrm.CRCWritePseudo(&crc)
		tfrm, _ := tcp.NewFrame(payload)
		tfrm.SetCRC(0)
		tfrm.SetCRC(crc.PayloadSum16(payload))
	case lneto.IPProtoUDP:
		ufrm, _ := udp.NewFrame(payload)
		ufrm.SetLength(uint16(n))
		ifrm.CRCWritePseudo(&crc)
		ufrm.SetCRC(0)
		ufrm.SetCRC(lneto.NeverZeroSum(crc.PayloadSum16(payload)))
	}
	return headerlen + n, err
}
