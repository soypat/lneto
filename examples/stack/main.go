package main

import (
	"errors"
	"io"
	"log"
	"log/slog"
	"math/rand"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/tcp"
)

func main() {
	const mtu = 1500
	rng := rand.New(rand.NewSource(1))
	var gen ltesto.PacketGen
	gen.RandomizeAddrs(rng)
	slogger := logger{slog.Default()}
	lStack := LinkStack{
		logger: slogger,
		mac:    gen.DstMAC,
		mtu:    mtu,
	}
	iStack := &IPv4Stack{
		ip:     gen.DstIPv4,
		logger: slogger,
	}
	tStack := &TCPStack{
		logger: slogger,
	}
	pStack := &TCPPort{
		handler: tcp.Handler{},
	}
	iss := tcp.Value(100)
	txbuf := make([]byte, mtu)
	rxbuf := make([]byte, mtu)
	err := pStack.handler.SetBuffers(txbuf, rxbuf, 3)
	if err != nil {
		log.Fatal(err)
	}
	err = pStack.handler.Open(gen.DstTCP, iss)
	if err != nil {
		log.Fatal(err)
	}
	err = iStack.Register(tStack, &gen.SrcIPv4)
	if err != nil {
		log.Fatal(err)
	}
	err = lStack.Register(iStack, gen.SrcMAC)
	if err != nil {
		log.Fatal(err)
	}
	err = tStack.Register(pStack, pStack.handler.LocalPort())
	if err != nil {
		log.Fatal(err)
	}
	seg := tcp.Segment{
		SEQ:     300,
		ACK:     iss,
		DATALEN: 0,
		WND:     256,
		Flags:   tcp.FlagSYN,
	}
	buf := make([]byte, lStack.mtu)
	packet := gen.AppendRandomIPv4TCPPacket(buf[:0], rng, seg)
	err = lStack.RecvEth(packet)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("success receiving packet")
	n, err := lStack.HandleEth(buf)
	if err != nil {
		log.Fatal(n, err)
	} else if n > 0 {
		log.Println("success sending packet")
	} else {
		log.Println("no packet sent")
	}
}

type Handler interface {
	Protocol() uint32
	Recv(frame []byte, off int) error
	Handle(dstAndFrame []byte, dstOff int) (int, error)
}

// handler is abstraction of a frame marshaller.
type handler struct {
	raddr  []byte
	recv   func([]byte, int) error
	handle func([]byte, int) (int, error)
	proto  uint32
	lport  uint16
}

type LinkStack struct {
	handlers []handler
	logger
	mac [6]byte
	mtu uint16
}

func (ls *LinkStack) Register(h Handler, remoteHWAddr [6]byte) error {
	proto := h.Protocol()
	for i := range ls.handlers {
		if proto == ls.handlers[i].proto {
			return errors.New("protocol already registered")
		}
	}
	// Pattern to add a handler and reuse underlying memory.
	ls.handlers = append(ls.handlers, handler{})
	hh := &ls.handlers[len(ls.handlers)-1]
	hh.handle = h.Handle
	hh.recv = h.Recv
	hh.proto = proto
	hh.raddr = append(hh.raddr[:0], remoteHWAddr[:]...)
	return nil
}

func (ls *LinkStack) RecvEth(ethFrame []byte) (err error) {
	efrm, err := lneto.NewEthFrame(ethFrame)
	if err != nil {
		return err
	}
	if !efrm.IsBroadcast() && ls.mac != *efrm.DestinationHardwareAddr() {
		return errors.New("packet MAC mismatch")
	}
	var vld lneto.Validator
	efrm.ValidateSize(&vld)
	if err := vld.Err(); err != nil {
		return err
	}
	etype := efrm.EtherTypeOrSize()
	for i := range ls.handlers {
		h := &ls.handlers[i]
		if h.proto == uint32(etype) {
			return h.recv(efrm.Payload(), 0)
		}
	}
	return nil
}

func (ls *LinkStack) HandleEth(dst []byte) (n int, err error) {
	if len(dst) < int(ls.mtu) {
		return 0, io.ErrShortBuffer
	}
	for i := range ls.handlers {
		h := &ls.handlers[i]
		n, err = h.handle(dst[:ls.mtu], 14)
		if err != nil {
			ls.error("handling", slog.String("proto", lneto.EtherType(h.proto).String()), slog.String("err", err.Error()))
			continue
		}
		if n > 0 {
			// Found packet
			efrm, _ := lneto.NewEthFrame(dst[:14])
			copy(efrm.DestinationHardwareAddr()[:], h.raddr)
			*efrm.SourceHardwareAddr() = ls.mac
			efrm.SetEtherType(lneto.EtherType(h.proto))
			return n + 14, nil
		}
	}
	return 0, err
}

type IPv4Stack struct {
	ip        [4]byte
	validator lneto.Validator
	handlers  []handler
	logger
}

func (is *IPv4Stack) Protocol() uint32 { return uint32(lneto.EtherTypeIPv4) }

func (is *IPv4Stack) Register(h Handler, remoteAddr *[4]byte) error {
	proto := h.Protocol()
	for i := range is.handlers {
		if proto == is.handlers[i].proto {
			return errors.New("protocol already registered")
		}
	}
	// Pattern to add a handler and reuse underlying memory.
	is.handlers = append(is.handlers, handler{})
	hh := &is.handlers[len(is.handlers)-1]
	hh.handle = h.Handle
	hh.recv = h.Recv
	hh.proto = proto
	if remoteAddr != nil {
		// Remote IP address specified.
		hh.raddr = append(hh.raddr, remoteAddr[:]...)
	}
	return nil
}

func (is *IPv4Stack) Recv(ethFrame []byte, ipOff int) error {
	ifrm, err := lneto.NewIPv4Frame(ethFrame[ipOff:])
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
		if h.proto == uint32(ifrm.Protocol()) {
			return h.recv(ethFrame[ipOff:totalLen], off)
		}
	}
	return nil
}

func (is *IPv4Stack) Handle(ethFrame []byte, ipOff int) (int, error) {
	if len(ethFrame)-ipOff < 256 {
		return 0, io.ErrShortBuffer
	}
	ifrm, _ := lneto.NewIPv4Frame(ethFrame[ipOff:])
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

		n, err := h.handle(ethFrame[ipOff:], headerlen)
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
			return totalLen, nil
		}
	}
	return 0, nil
}

type TCPStack struct {
	validator lneto.Validator
	handlers  []handler
	logger
}

func (ts *TCPStack) Protocol() uint32 { return uint32(lneto.IPProtoTCP) }

func (ts *TCPStack) Register(h Handler, lport uint16) error {
	if lport == 0 {
		return errors.New("got zero port")
	}
	ts.handlers = append(ts.handlers, handler{})
	hh := &ts.handlers[len(ts.handlers)-1]
	hh.handle = h.Handle
	hh.recv = h.Recv
	hh.lport = lport
	return nil
}

func (ts *TCPStack) Recv(ipFrame []byte, tcpOff int) error {
	ipVersion := ipFrame[0] >> 4
	if ipVersion != 4 && ipVersion != 6 {
		return errors.New("invalid IP version")
	}
	tfrm, err := lneto.NewTCPFrame(ipFrame[tcpOff:])
	if err != nil {
		return err
	}
	lport := tfrm.DestinationPort()
	var h *handler
	for i := range ts.handlers {
		if lport == ts.handlers[i].lport {
			h = &ts.handlers[i]
			break
		}
	}
	if h == nil {
		return errors.New("port not found")
	}
	ts.validator.ResetErr()
	tfrm.ValidateSize(&ts.validator)
	if err = ts.validator.Err(); err != nil {
		return err
	}
	var crc uint16
	switch ipVersion {
	case 4:
		ifrm, _ := lneto.NewIPv4Frame(ipFrame)
		crc = tfrm.CalculateIPv4CRC(ifrm)
	case 6:
		ifrm, _ := lneto.NewIPv6Frame(ipFrame)
		crc = tfrm.CalculateIPv6CRC(ifrm)
	}
	gotCRC := tfrm.CRC()
	if crc != gotCRC {
		ts.error("TCPStack:Recv:crc-mismatch", slog.Uint64("lport", uint64(lport)), slog.Uint64("want", uint64(crc)), slog.Uint64("got", uint64(gotCRC)))
		return errors.New("TCP crc mismatch")
	}
	return h.recv(ipFrame[tcpOff:], 0)
}

func (ts *TCPStack) Handle(ipFrame []byte, tcpOff int) (n int, err error) {
	ipVersion := ipFrame[0] >> 4
	if ipVersion != 4 && ipVersion != 6 {
		return 0, errors.New("invalid IP version")
	}
	var h *handler
	for i := range ts.handlers {
		h = &ts.handlers[i]
		n, err = h.handle(ipFrame[tcpOff:], 0)
		if err != nil {
			if err == io.EOF {
				ts.handlers = removeHandler(ts.handlers, i)
				err = nil
			} else {
				ts.error("TCPStack:Handle", slog.Uint64("lport", uint64(h.lport)))
				continue
			}
		}
		if n > 0 {
			break
		}
	}
	if n == 0 {
		return 0, err
	}
	// TCP packet written.
	tfrm, _ := lneto.NewTCPFrame(ipFrame[tcpOff : tcpOff+n])
	ts.validator.ResetErr()
	tfrm.ValidateSize(&ts.validator) // Perform basic validation.
	if err = ts.validator.Err(); err != nil {
		return 0, err
	}
	var crc uint16
	switch ipVersion {
	case 4:
		ifrm, _ := lneto.NewIPv4Frame(ipFrame)
		crc = tfrm.CalculateIPv4CRC(ifrm)
	case 6:
		ifrm, _ := lneto.NewIPv6Frame(ipFrame)
		crc = tfrm.CalculateIPv6CRC(ifrm)
	}
	tfrm.SetCRC(crc)
	return tcpOff + n, nil
}

type TCPPort struct {
	handler tcp.Handler
}

func (tp *TCPPort) Protocol() uint32 { return uint32(lneto.IPProtoTCP) }

func (tp *TCPPort) Recv(tcpFrame []byte, off int) error {
	if off != 0 {
		return errors.New("TCP API expected 0 offset")
	}
	return tp.handler.Recv(tcpFrame)
}

func (tp *TCPPort) Handle(tcpFrame []byte, off int) (n int, err error) {
	if off != 0 {
		return 0, errors.New("TCP API expected 0 offset")
	}
	return tp.handler.Send(tcpFrame)
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

func removeHandler(handlers []handler, idxRemoved int) []handler {
	return append(handlers[:idxRemoved], handlers[idxRemoved+1:]...)
}

func addHandler(handlers []handler, h Handler, remoteAddr []byte, lport uint16) []handler {
	// Pattern to add a handler and reuse underlying memory.
	handlers = append(handlers, handler{})
	hh := &handlers[len(handlers)-1]
	hh.handle = h.Handle
	hh.recv = h.Recv
	hh.proto = h.Protocol()
	if remoteAddr != nil {
		// Remote IP address specified.
		hh.raddr = append(hh.raddr, remoteAddr[:]...)
	}
	hh.lport = lport
	return handlers
}
