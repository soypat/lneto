package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/ipv6"
	"github.com/soypat/lneto/tcp"
)

const (
	mtu       = 2048
	iface     = "192.168.10.1/24"
	stackIP   = "192.168.10.2"
	stackPort = 80
	iss       = 100
)

var stackHWAddr = [6]byte{0xc0, 0xff, 0xee, 0x00, 0xde, 0xad}

func main() {
	ip := netip.MustParseAddr(stackIP)
	iface := netip.MustParsePrefix(iface)
	if !iface.Contains(ip) {
		log.Fatal("interface does not contain stack address")
	}
	addrPort := netip.AddrPortFrom(ip, stackPort)
	slogger := logger{slog.Default()}
	lStack, handler, err := NewEthernetTCPStack(stackHWAddr, addrPort, slogger)
	if err != nil {
		log.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	handler.SetLoggers(logger, logger)

	err = handler.OpenListen(addrPort.Port(), iss)
	if err != nil {
		log.Fatal(err)
	}

	tap := ltesto.NewHTTPTapClient("http://127.0.0.1:7070")
	defer tap.Close()

	fmt.Println("hosting server at ", addrPort.String())
	var buf [mtu]byte
	for {
		nread, err := tap.Read(buf[:])
		if err != nil {
			slogger.error("tap-err", slog.String("err", err.Error()))
			log.Fatal(err)
		} else if nread > 0 {
			err = lStack.RecvEth(buf[:nread])
			if err != nil {
				slogger.error("recv", slog.String("err", err.Error()), slog.Int("plen", nread))
			} else {
				slogger.info("recv", slog.Int("plen", nread))
			}
		}
		nw, err := lStack.HandleEth(buf[:])
		if err != nil {
			slogger.error("handle", slog.String("err", err.Error()))
		} else if nw > 0 {
			_, err = tap.Write(buf[:nw])
			if err != nil {
				log.Fatal(err)
			} else {
				slogger.info("write", slog.Int("plen", nw))
			}
		}
		if nread == 0 && nw == 0 {
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func NewEthernetTCPStack(mac [6]byte, ip netip.AddrPort, slogger logger) (*LinkStack, *tcp.Handler, error) {
	lStack := LinkStack{
		logger: slogger,
		mac:    mac,
		mtu:    mtu,
	}
	ipStack := &IPv4Stack{
		ip:     ip.Addr().As4(),
		logger: slogger,
	}
	tcpStack := &TCPStack{
		logger: slogger,
	}
	tcpPortStack := &TCPPort{
		handler: tcp.Handler{},
	}
	proto := ethernet.TypeIPv4
	if ip.Addr().Is6() {
		proto = ethernet.TypeIPv6
	}
	arphandler, err := arp.NewHandler(arp.HandlerConfig{
		HardwareAddr: mac[:],
		ProtocolAddr: ip.Addr().AsSlice(),
		MaxQueries:   1,
		MaxPending:   1,
		HardwareType: 1,
		ProtocolType: proto,
	})
	if err != nil {
		return nil, nil, err
	}
	arpStack := ARPStack{
		handler: *arphandler,
	}

	port := ip.Port()
	txbuf := make([]byte, mtu)
	rxbuf := make([]byte, mtu)
	err = tcpPortStack.handler.SetBuffers(txbuf, rxbuf, 3)
	if err != nil {
		return nil, nil, err
	}
	err = ipStack.Register(tcpStack, nil)
	if err != nil {
		return nil, nil, err
	}
	err = lStack.Register(ipStack, mac)
	if err != nil {
		return nil, nil, err
	}
	err = lStack.Register(&arpStack, [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	if err != nil {
		return nil, nil, err
	}
	err = tcpStack.Register(tcpPortStack, port)
	if err != nil {
		return nil, nil, err
	}
	return &lStack, &tcpPortStack.handler, nil
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

	efrm, err := ethernet.NewFrame(ethFrame)
	if err != nil {
		return err
	}
	etype := efrm.EtherTypeOrSize()
	dstaddr := efrm.DestinationHardwareAddr()
	if !efrm.IsBroadcast() && ls.mac != *dstaddr {
		return fmt.Errorf("incoming %s mismatch hwaddr %s", etype.String(), net.HardwareAddr(dstaddr[:]).String())
	}
	var vld lneto.Validator
	efrm.ValidateSize(&vld)
	if err := vld.Err(); err != nil {
		return err
	}

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
			ls.error("handling", slog.String("proto", ethernet.Type(h.proto).String()), slog.String("err", err.Error()))
			continue
		}
		if n > 0 {
			// Found packet
			efrm, _ := ethernet.NewFrame(dst[:14])
			copy(efrm.DestinationHardwareAddr()[:], h.raddr)
			*efrm.SourceHardwareAddr() = ls.mac
			efrm.SetEtherType(ethernet.Type(h.proto))

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

func (is *IPv4Stack) Protocol() uint32 { return uint32(ethernet.TypeIPv4) }

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

	ifrm, err := ipv4.NewFrame(ethFrame[ipOff:])
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
	ifrm, _ := ipv4.NewFrame(ethFrame[ipOff:])
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
			if ifrm.Protocol() == lneto.IPProtoTCP {
				tfrm, _ := tcp.NewFrame(ifrm.Payload())
				is.info("IPv4Stack:send", slog.String("ip", ifrm.String()), slog.String("tcp", tfrm.String()))
			}
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
	tfrm, err := tcp.NewFrame(ipFrame[tcpOff:])
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
	crc := tcpChecksum(ipFrame, len(tfrm.RawData()))
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
			ipFrame = ipFrame[:tcpOff+n]
			break
		}
	}
	if n == 0 {
		return 0, err
	}
	// TCP packet written.
	tfrm, _ := tcp.NewFrame(ipFrame[tcpOff:])

	ts.validator.ResetErr()
	tfrm.ValidateSize(&ts.validator) // Perform basic validation.
	if err = ts.validator.Err(); err != nil {
		return 0, err
	}
	crc := tcpChecksum(ipFrame, n)
	tfrm.SetCRC(crc)
	return n, nil
}

type ARPStack struct {
	handler arp.Handler
}

func (as *ARPStack) Protocol() uint32 { return uint32(ethernet.TypeARP) }

func (as *ARPStack) Recv(EtherFrame []byte, arpOff int) error {
	afrm, _ := arp.NewFrame(EtherFrame[arpOff:])
	slog.Info("recv", slog.String("in", afrm.String()))
	return as.handler.Recv(EtherFrame[arpOff:])
}

func (as *ARPStack) Handle(EtherFrame []byte, arpOff int) (int, error) {
	n, err := as.handler.Send(EtherFrame[arpOff:])
	if err != nil || n == 0 {
		return 0, err
	}
	afrm, _ := arp.NewFrame(EtherFrame[arpOff:])
	hwaddr, _ := afrm.Target()
	efrm, _ := ethernet.NewFrame(EtherFrame)
	copy(efrm.DestinationHardwareAddr()[:], hwaddr)
	slog.Info("handle", slog.String("out", afrm.String()))
	return n, err
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

func tcpChecksum(ipFrame []byte, tcpPayload int) uint16 {
	version := ipFrame[0] >> 4
	var tfrm tcp.Frame
	var crc lneto.CRC791
	switch version {
	case 4:
		ifrm, _ := ipv4.NewFrame(ipFrame)
		crc.Write(ifrm.SourceAddr()[:])
		crc.Write(ifrm.DestinationAddr()[:])
		crc.AddUint16(uint16(tcpPayload))
		crc.AddUint16(6)
		tfrm, _ = tcp.NewFrame(ifrm.Payload())
	case 6:
		i6frm, _ := ipv6.NewFrame(ipFrame)
		crc.Write(i6frm.SourceAddr()[:])
		crc.Write(i6frm.DestinationAddr()[:])
		crc.AddUint32(uint32(tcpPayload))
		crc.AddUint32(6)
		i6frm.CRCWritePseudo(&crc)
		tfrm, _ = tcp.NewFrame(i6frm.Payload())
	default:
		panic("invalid IP version")
	}
	tfrm.CRCWrite(&crc)
	return crc.Sum16()
}
