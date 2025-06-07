package internet

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
)

var _ StackNode = (*StackIP)(nil)

type StackIP struct {
	connID    uint64
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
		goto DROP
	}
	{
		sb.validator.ResetErr()
		ifrm.ValidateExceptCRC(&sb.validator)
		if err = sb.validator.Err(); err != nil {
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
		for i := range sb.handlers {
			h := &sb.handlers[i]
			proto := ifrm.Protocol()
			if h.proto == uint16(proto) {
				sb.info("ipDemux", slog.String("ipproto", proto.String()), slog.Int("plen", int(totalLen)))
				err = h.demux(frame[:totalLen], off)
				if err == net.ErrClosed {
					sb.info("ipclose", slog.String("proto", proto.String()))
					sb.handlers = slices.Delete(sb.handlers, i, i+1)
				}
				return err
			}
		}
	}

DROP:
	sb.info("iprecv:drop", slog.String("dstaddr", netip.AddrFrom4(*ifrm.DestinationAddr()).String()), slog.String("proto", ifrm.Protocol().String()))
	return nil
}

func (sb *StackIP) Encapsulate(carrierData []byte, frameOffset int) (int, error) {
	frame := carrierData[frameOffset:]
	if len(frame) < 256 {
		return 0, io.ErrShortBuffer
	}
	ifrm, _ := ipv4.NewFrame(frame)
	const ihl = 5
	const headerlen = ihl * 4
	ifrm.SetVersionAndIHL(4, 5)
	ifrm.SetToS(0)
	ifrm.SetID(0)
	*ifrm.SourceAddr() = sb.ip
	for i := range sb.handlers {
		h := &sb.handlers[i]
		proto := lneto.IPProto(h.proto)
		n, err := h.encapsulate(frame[:], headerlen)
		if err != nil {
			sb.error("StackIP:handle", slog.String("proto", proto.String()), slog.String("err", err.Error()))
			continue
		}
		if n > 0 {
			const dontFrag = 0x4000
			totalLen := n + headerlen
			ifrm.SetTotalLength(uint16(totalLen))
			ifrm.SetFlags(dontFrag)
			ifrm.SetTTL(64)
			ifrm.SetProtocol(proto)
			ifrm.SetCRC(ifrm.CalculateHeaderCRC())
			if ifrm.Protocol() == lneto.IPProtoTCP {
				var crc lneto.CRC791
				ifrm.CRCWriteTCPPseudo(&crc)
				tfrm, _ := tcp.NewFrame(ifrm.Payload())
				tfrm.CRCWrite(&crc)
				tfrm.SetCRC(crc.Sum16())
				sb.info("StackIP:send", slog.String("ip", ifrm.String()), slog.String("tcp", tfrm.String()))
			}
			return totalLen, nil
		}
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

func (sb *StackIP) RegisterTCPConn(conn *TCPConn) error {
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
