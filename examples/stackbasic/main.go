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
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/internet"
	"github.com/soypat/lneto/ipv4"
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
	lg := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	slogger := logger{lg}

	lStack, handler, err := NewEthernetTCPStack(stackHWAddr, addrPort, slogger)
	if err != nil {
		log.Fatal(err)
	}

	err = handler.OpenListen(addrPort.Port(), iss)
	if err != nil {
		log.Fatal(err)
	}

	tap := ltesto.NewHTTPTapClient("http://127.0.0.1:7070")
	defer tap.Close()

	fmt.Println("hosting server at ", addrPort.String())
	var buf [mtu]byte
	var hdr httpraw.Header
	for {
		nread, err := tap.Read(buf[:])
		if err != nil {
			slogger.error("tap-err", slog.String("err", err.Error()))
			log.Fatal(err)
		} else if nread > 0 {
			debugEthPacket(nil, "IN ", buf[:nread])
			err = lStack.RecvEth(buf[:nread])
			if err != nil {
				slogger.error("recv", slog.String("err", err.Error()), slog.Int("plen", nread))
			}
		}
		nw, err := lStack.HandleEth(buf[:])
		debugEthPacket(nil, "OUT", buf[:nw])
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
		if handler.State() == tcp.StateEstablished {
			data := handler.BufferedInput()
			if data > 0 {
				n, err := handler.Read(buf[:])
				if err != nil {
					slogger.error("tcp-read", slog.String("err", err.Error()))
				} else {
					hdr.Reset(buf[:n])
					err = hdr.Parse(false)
					if err != nil {
						slogger.error("http-parse", slog.String("err", err.Error()))
					} else {
						fmt.Println(hdr.String())
					}
				}
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
		proto: ethernet.TypeIPv4,
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
		MaxQueries:   4,
		MaxPending:   4,
		HardwareType: 1,
		ProtocolType: proto,
	})
	if err != nil {
		return nil, nil, err
	}
	arpStack := ARPStack{
		handler: *arphandler,
	}
	err = lStack.Register(handler{
		recv:   arpStack.Recv,
		handle: arpStack.Handle,
		proto:  ethernet.TypeARP,
	})
	if err != nil {
		return nil, nil, err
	}
	return &lStack, &conn, nil
}

type handler struct {
	raddr  []byte
	recv   func([]byte, int) error
	handle func([]byte, int) (int, error)
	proto  ethernet.Type
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
	var vld lneto.Validator
	if !efrm.IsBroadcast() && ls.mac != *dstaddr {
		goto DROP
	}
	efrm.ValidateSize(&vld)
	if err := vld.Err(); err != nil {
		return err
	}

	for i := range ls.handlers {
		h := &ls.handlers[i]
		if h.proto == etype {
			return h.recv(efrm.Payload(), 0)
		}
	}
DROP:
	ls.info("LinkStack:drop-packet", slog.String("dsthw", net.HardwareAddr(dstaddr[:]).String()), slog.String("ethertype", efrm.EtherTypeOrSize().String()))
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

func debugEthPacket(logger *slog.Logger, prefix string, b []byte) {
	frm, err := ethernet.NewFrame(b)
	if err != nil {
		return
	}
	if frm.EtherTypeOrSize() != ethernet.TypeIPv4 {
		return
	}
	ihdr, err := ipv4.NewFrame(frm.Payload())
	if err != nil {
		return
	}
	if ihdr.Protocol() != lneto.IPProtoTCP {
		return
	}
	thdr, err := tcp.NewFrame(ihdr.Payload())
	if err != nil {
		return
	}
	fmt.Println(prefix, ihdr.String()+" TCP:"+thdr.String())
	payload := thdr.Payload()
	if len(payload) > 0 {
		fmt.Println("PAYLOAD:", string(payload))
	}
}
