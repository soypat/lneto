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
	"github.com/soypat/lneto/internet"
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

func NewEthernetTCPStack(mac [6]byte, ip netip.AddrPort, slogger logger) (*LinkStack, *internet.TCPConn, error) {
	var err error
	lStack := LinkStack{
		logger: slogger,
		mac:    mac,
		mtu:    mtu,
	}

	var ipStack internet.StackBasic
	addr := ip.Addr()
	addr4 := addr.As4()
	_ = addr4
	ipStack.SetAddr(addr)
	lStack.Register(handler{
		raddr: nil, //addr4[:],
		recv: func(b []byte, i int) error {
			return ipStack.Recv(b[i:])
		},
		handle: func(b []byte, i int) (int, error) {
			return ipStack.Handle(b[i:])
		},
		proto: uint32(lneto.IPProtoIPv4),
		lport: 0,
	})
	var conn internet.TCPConn
	err = conn.Configure(&internet.TCPConnConfig{
		RxBuf:             make([]byte, mtu),
		TxBuf:             make([]byte, mtu),
		TxPacketQueueSize: 3,
		Logger:            slog.Default(),
	})
	if err != nil {
		return nil, nil, err
	}
	err = conn.OpenListen(ip.Port(), 100)
	if err != nil {
		return nil, nil, err
	}
	err = ipStack.RegisterTCPConn(&conn)
	if err != nil {
		return nil, nil, err
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

	err = lStack.Register(ipStack, mac)
	if err != nil {
		return nil, nil, err
	}
	return &lStack, &conn, nil
}

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

func (ls *LinkStack) Register(h handler) error {
	proto := h.proto
	for i := range ls.handlers {
		if proto == ls.handlers[i].proto {
			return errors.New("protocol already registered")
		}
	}
	ls.handlers = append(ls.handlers, h)
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
