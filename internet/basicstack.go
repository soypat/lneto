package internet

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
)

type StackBasic struct {
	ip        [4]byte
	validator lneto.Validator
	handlers  []handler
	logger
}

type handler struct {
	recv   func([]byte, int) error
	handle func([]byte, int) (int, error)
	proto  lneto.IPProto
	port   uint16
}

func (sb *StackBasic) SetAddr(addr netip.Addr) {
	if !addr.Is4() {
		panic("only support IPv4")
	}
	sb.ip = addr.As4()
}

func (sb *StackBasic) Addr() netip.Addr {
	return netip.AddrFrom4(sb.ip)
}

func (sb *StackBasic) Recv(frame []byte) error {
	sb.info("StackBasic.Recv:start")
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
			sb.error("IPv4Stack:Recv:crc-mismatch", slog.Uint64("want", uint64(wantCRC)), slog.Uint64("got", uint64(gotCRC)))
			return errors.New("IPv4 CRC mismatch")
		}
		off := ifrm.HeaderLength()
		totalLen := ifrm.TotalLength()
		for i := range sb.handlers {
			h := &sb.handlers[i]
			proto := ifrm.Protocol()
			if h.proto == proto {
				sb.info("iprecv", slog.String("ipproto", proto.String()), slog.Int("plen", int(totalLen)))
				err = h.recv(frame[:totalLen], off)
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

func (sb *StackBasic) Handle(frame []byte) (int, error) {
	if len(frame) < 256 {
		return 0, io.ErrShortBuffer
	}
	ifrm, _ := ipv4.NewFrame(frame)
	const ihl = 5
	const headerlen = ihl * 4
	ifrm.SetVersionAndIHL(4, 5)
	*ifrm.SourceAddr() = sb.ip
	ifrm.SetToS(0)
	ifrm.SetID(0)
	for i := range sb.handlers {
		h := &sb.handlers[i]
		n, err := h.handle(frame[:], headerlen)
		if err != nil {
			sb.error("IPv4Stack:handle", slog.String("proto", h.proto.String()), slog.String("err", err.Error()))
			continue
		}
		if n > 0 {
			const dontFrag = 0x4000
			totalLen := n + headerlen
			ifrm.SetTotalLength(uint16(totalLen))
			ifrm.SetFlags(dontFrag)
			ifrm.SetTTL(64)
			ifrm.SetProtocol(h.proto)
			ifrm.SetCRC(ifrm.CalculateHeaderCRC())
			if ifrm.Protocol() == lneto.IPProtoTCP {
				var crc lneto.CRC791
				ifrm.CRCWriteTCPPseudo(&crc)
				tfrm, _ := tcp.NewFrame(ifrm.Payload())
				tfrm.CRCWrite(&crc)
				tfrm.SetCRC(crc.Sum16())
				sb.info("IPv4Stack:send", slog.String("ip", ifrm.String()), slog.String("tcp", tfrm.String()))
			}
			return totalLen, nil
		}
	}
	return 0, nil
}

func (sb *StackBasic) RegisterTCPConn(conn *TCPConn) error {
	if conn.LocalPort() == 0 {
		return errors.New("undefined local port")
	}
	sb.handlers = append(sb.handlers, handler{
		recv:   conn.RecvIP,
		handle: conn.HandleIP,
		proto:  lneto.IPProtoTCP,
		port:   conn.LocalPort(),
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
