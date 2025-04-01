package internet

import (
	"errors"
	"io"
	"log/slog"

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
	proto  lneto.IPProto
	port   uint16
	recv   func([]byte, int) error
	handle func([]byte, int) (int, error)
}

func (is *StackBasic) Recv(frame []byte) error {
	ifrm, err := ipv4.NewFrame(frame)
	if err != nil {
		return err
	}
	if *ifrm.DestinationAddr() != is.ip {
		return errors.New("packet not for us")
	}
	is.validator.ResetErr()
	ifrm.ValidateExceptCRC(&is.validator)
	if err = is.validator.Err(); err != nil {
		return err
	}
	gotCRC := ifrm.CRC()
	wantCRC := ifrm.CalculateHeaderCRC()
	if gotCRC != wantCRC {
		is.error("IPv4Stack:Recv:crc-mismatch", slog.Uint64("want", uint64(wantCRC)), slog.Uint64("got", uint64(gotCRC)))
		return errors.New("IPv4 CRC mismatch")
	}
	off := ifrm.HeaderLength()
	totalLen := ifrm.TotalLength()
	for i := range is.handlers {
		h := &is.handlers[i]
		if h.proto == ifrm.Protocol() {
			return h.recv(frame[:totalLen], off)
		}
	}
	return nil
}

func (is *StackBasic) Handle(frame []byte) (int, error) {
	if len(frame) < 256 {
		return 0, io.ErrShortBuffer
	}
	ifrm, _ := ipv4.NewFrame(frame)
	const ihl = 5
	const headerlen = ihl * 4
	ifrm.SetVersionAndIHL(4, 5)
	*ifrm.SourceAddr() = is.ip
	ifrm.SetToS(0)
	for i := range is.handlers {
		h := &is.handlers[i]
		proto := lneto.IPProto(h.proto)
		ifrm.SetProtocol(proto)
		if len(h.raddr) == 4 {
			copy(ifrm.DestinationAddr()[:], h.raddr)
		} else {
			copy(ifrm.DestinationAddr()[:], "\x00\x00\x00\x00")
		}

		n, err := h.handle(frame[:], headerlen)
		if err != nil {
			is.error("IPv4Stack:handle", slog.String("proto", proto.String()), slog.String("err", err.Error()))
			continue
		}
		if n > 0 {
			const dontFrag = 0x4000
			totalLen := n + headerlen
			ifrm.SetTotalLength(uint16(totalLen))
			ifrm.SetID(0)
			ifrm.SetFlags(dontFrag)
			ifrm.SetTTL(64)
			ifrm.SetCRC(ifrm.CalculateHeaderCRC())
			if ifrm.Protocol() == lneto.IPProtoTCP {
				tfrm, _ := tcp.NewFrame(ifrm.Payload())
				is.info("IPv4Stack:send", slog.String("ip", ifrm.String()), slog.String("tcp", tfrm.String()))
			}
			return totalLen, nil
		}
	}
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
