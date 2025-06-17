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
	handlers  []node
	logger
}

func (sb *StackIP) Reset(addr netip.Addr) error {
	err := sb.SetAddr(addr)
	if err != nil {
		return err
	}
	*sb = StackIP{
		connID:    sb.connID + 1,
		validator: sb.validator,
		handlers:  sb.handlers[:0],
		logger:    sb.logger,
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

func (sb *StackIP) Demux(carrierData []byte, offset int) error {
	sb.info("StackIP.Demux:start")
	frame := carrierData[offset:] // we don't care about carrier data in IP.
	ifrm, err := ipv4.NewFrame(frame)
	if err != nil {
		return err
	}
	dst := ifrm.DestinationAddr()
	if *dst != sb.ip {
		return nil // Not meant for us.
	}

	sb.validator.ResetErr()
	ifrm.ValidateExceptCRC(&sb.validator)
	if err = sb.validator.ErrPop(); err != nil {
		return err
	}
	gotCRC := ifrm.CRC()
	wantCRC := ifrm.CalculateHeaderCRC()
	if gotCRC != wantCRC {
		sb.error("StackIP:Demux:crc-mismatch", slog.Uint64("want", uint64(wantCRC)), slog.Uint64("got", uint64(gotCRC)))
		return errors.New("IPv4 CRC mismatch")
	}
	off := ifrm.HeaderLength()
	totalLen := ifrm.TotalLength()
	proto := ifrm.Protocol()
	nodeIdx := getNodeByProto(sb.handlers, uint16(proto))
	if nodeIdx < 0 {
		// Drop packet.
		sb.info("iprecv:drop", slog.String("dstaddr", netip.AddrFrom4(*ifrm.DestinationAddr()).String()), slog.String("proto", ifrm.Protocol().String()))
		return nil
	}
	// Incoming CRC Validation of common IP Protocols.
	var crc lneto.CRC791
	switch proto {
	case lneto.IPProtoTCP:
		ifrm.CRCWriteTCPPseudo(&crc)
		tfrm, err := tcp.NewFrame(ifrm.Payload())
		if err != nil {
			return err
		}
		tfrm.CRCWrite(&crc)
		if crc.Sum16() != tfrm.CRC() {
			return errors.New("TCP CRC mismatch")
		}
	case lneto.IPProtoUDP:
		ifrm.CRCWriteUDPPseudo(&crc)
		ufrm, err := udp.NewFrame(ifrm.Payload())
		if err != nil {
			return err
		}
		ufrm.CRCWriteIPv4(&crc)
		if crc.Sum16() != ufrm.CRC() {
			return errors.New("UDP CRC mismatch")
		}
	}
	sb.info("ipDemux", slog.String("ipproto", proto.String()), slog.Int("plen", int(totalLen)))
	err = sb.handlers[nodeIdx].demux(frame[:totalLen], off)
	if handleNodeError(&sb.handlers, nodeIdx, err) {
		sb.info("ipclose", slog.String("proto", proto.String()))
		err = nil
	}
	return err
}

func (sb *StackIP) Encapsulate(carrierData []byte, frameOffset int) (int, error) {
	frame := carrierData[frameOffset:]
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
	*ifrm.SourceAddr() = sb.ip
	sb.ipID = id
	for i := range sb.handlers {
		h := &sb.handlers[i]
		proto := lneto.IPProto(h.proto)
		n, err := h.encapsulate(frame[:], headerlen)
		if err != nil {
			if handleNodeError(&sb.handlers, i, err) {
				println("NODE REMOVED", proto.String(), h.port)
				h.destroy()
			}
			sb.error("StackIP:handle", slog.String("proto", proto.String()), slog.String("err", err.Error()))
			continue
		} else if n == 0 {
			continue
		}
		totalLen := n + headerlen
		ifrm.SetTotalLength(uint16(totalLen))
		ifrm.SetTTL(64)
		ifrm.SetProtocol(proto)
		ifrm.SetCRC(ifrm.CalculateHeaderCRC())
		// Calculate CRC for our newly generated packet.
		var crc lneto.CRC791
		switch proto {
		case lneto.IPProtoTCP:
			ifrm.CRCWriteTCPPseudo(&crc)
			tfrm, _ := tcp.NewFrame(ifrm.Payload())
			tfrm.CRCWrite(&crc)
			tfrm.SetCRC(crc.Sum16())
		case lneto.IPProtoUDP:
			ifrm.CRCWriteUDPPseudo(&crc)
			ufrm, _ := udp.NewFrame(ifrm.Payload())
			ufrm.SetLength(uint16(n))
			ufrm.CRCWriteIPv4(&crc)
			ufrm.SetCRC(crc.Sum16())
			if n != int(ufrm.Length()) {
				sb.error("StackIP:encaps", slog.Int("n", n), slog.Int("un", int(ufrm.Length())))
				return 0, errors.New("invalid UDP length")
			}
		}
		return totalLen, nil
	}
	return 0, nil
}

func (sb *StackIP) Register(h StackNode) error {
	proto := h.Protocol()
	if proto > 255 {
		return errInvalidProto
	}
	sb.handlers = append(sb.handlers, node{
		demux:       h.Demux,
		encapsulate: h.Encapsulate,
		proto:       uint16(proto),
	})
	return nil
}

func (sb *StackIP) RegisterTCPConn(conn *tcp.Conn) error {
	if conn.LocalPort() == 0 {
		return errZeroPort
	}
	sb.handlers = append(sb.handlers, node{
		demux:       conn.Demux,
		encapsulate: conn.Encapsulate,
		proto:       uint16(lneto.IPProtoTCP),
		port:        conn.LocalPort(),
	})
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
