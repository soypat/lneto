package internet

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"

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

func (sb *StackBasic) Recv(frame []byte) error {
	ifrm, err := ipv4.NewFrame(frame)
	if err != nil {
		return err
	}
	dst := ifrm.DestinationAddr()
	if *dst != sb.ip {
		return errors.New("packet not for us")
	}
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
		if h.proto == ifrm.Protocol() {
			return h.recv(frame[:totalLen], off)
		}
	}
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
			ifrm.SetCRC(ifrm.CalculateHeaderCRC())
			if ifrm.Protocol() == lneto.IPProtoTCP {
				tfrm, _ := tcp.NewFrame(ifrm.Payload())
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
		proto:  lneto.IPProtoIPv4,
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
