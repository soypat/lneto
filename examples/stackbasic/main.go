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
	"runtime"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/internet"
	"github.com/soypat/lneto/internet/pcap"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
)

const (
	stackIP   = "192.168.10.2"
	stackPort = 80
	iss       = 100
)

var stackHWAddr = [6]byte{0xc0, 0xff, 0xee, 0x00, 0xde, 0xad}

func main() {
	ip := netip.MustParseAddr(stackIP)
	tap := ltesto.NewHTTPTapClient("http://127.0.0.1:7070")

	ippfx, _ := tap.IPMask()
	if !ippfx.Contains(ip) {
		log.Fatal("interface does not contain stack address")
	}
	addrPort := netip.AddrPortFrom(ip, stackPort)
	lg := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	slogger := logger{lg}
	gatewayMAC, _ := tap.HardwareAddress6()
	mtu, _ := tap.MTU()
	lStack, handler, err := NewEthernetTCPStack(stackHWAddr, gatewayMAC, addrPort, uint16(mtu), slogger)
	if err != nil {
		log.Fatal(err)
	}

	err = handler.OpenListen(addrPort.Port(), iss)
	if err != nil {
		log.Fatal(err)
	}

	defer tap.Close()
	tap.ReadDiscard() // Discard all unread content.
	fmt.Println("hosting server at ", addrPort.String(), "over tap interface of mtu:", mtu, "prefix:", ippfx, "gateway:", net.HardwareAddr(gatewayMAC[:]).String())
	buf := make([]byte, mtu)
	var hdr httpraw.Header
	hdr.Reset(make([]byte, 0, 1024))
	const standbyDuration = 5 * time.Second
	lastHit := time.Now().Add(-standbyDuration)
	var cap pcap.PacketBreakdown
	for {
		nread, err := tap.Read(buf[:])
		if err != nil {
			slogger.error("tap-err", slog.String("err", err.Error()))
			log.Fatal(err)
		} else if nread > 0 {
			frames, err := cap.CaptureEthernet(nil, buf[:nread], 0)
			if err == nil {
				flags := getTCPFlags(frames, buf[:nread])
				if flags == 0 {
					fmt.Println("IN", time.Now().Format("15:04:05.000"), frames)
				} else {
					fmt.Println("IN", time.Now().Format("15:04:05.000"), frames, flags.String())
				}
			}
			err = lStack.RecvEth(buf[:nread])
			if err != nil {
				slogger.error("recv", slog.String("err", err.Error()), slog.Int("plen", nread))
			}
		}
		doHTTP(handler, &hdr)
		nw, err := lStack.HandleEth(buf[:])
		if err != nil {
			slogger.error("handle", slog.String("err", err.Error()))
		} else if nw > 0 {
			frames, err := cap.CaptureEthernet(nil, buf[:nread], 0)
			if err == nil {
				flags := getTCPFlags(frames, buf[:nread])
				if flags == 0 {
					fmt.Println("OU", time.Now().Format("15:04:05.000"), frames)
				} else {
					fmt.Println("OU", time.Now().Format("15:04:05.000"), frames, flags.String())
				}
			}
			_, err = tap.Write(buf[:nw])
			if err != nil {
				log.Fatal(err)
			}
		}
		hit := nread > 0 || nw > 0
		if hit {
			// slogger.info("exchange", slog.Int("read", nread), slog.Int("nwrite", nw))
			lastHit = time.Now()
		} else {
			if time.Since(lastHit) > standbyDuration {
				time.Sleep(5 * time.Millisecond)
			} else {
				runtime.Gosched()
			}
		}
	}
}

func doHTTP(conn *tcp.Conn, hdr *httpraw.Header) error {
	const asRequest = false
	if conn.State() != tcp.StateEstablished || conn.BufferedInput() == 0 {
		return nil // No data yet.
	}
	fmt.Println("state is established; check request and send response")
	_, err := hdr.ReadFromLimited(conn, hdr.BufferFree())
	if err != nil {
		return err
	}
	needMore, err := hdr.TryParse(asRequest)
	if err != nil {
		if !needMore {
			fmt.Println("IT's SO GOVER")
			conn.Close()
		}
		return err
	}
	// HTTP parsed succesfully!
	fmt.Println("GOT HTTP:\n", hdr.String())
	fmt.Println("sending response...")
	hdr.Reset(nil)
	hdr.SetStatus("200", "OK")
	data := `{"ok":true}`
	response, err := hdr.AppendResponse(nil)
	if err != nil {
		return err
	}
	response = append(response, data...)
	_, err = conn.Write(response)
	if err != nil {
		return err
	}
	err = conn.Close()
	if err != nil {
		return err
	}
	return nil
}

func NewEthernetTCPStack(ourMAC, gwMAC [6]byte, ip netip.AddrPort, mtu uint16, slogger logger) (*LinkStack, *tcp.Conn, error) {
	var err error
	lStack := LinkStack{
		logger: slogger,
		mac:    ourMAC,
		mtu:    mtu,
		gwmac:  gwMAC,
	}

	var ipStack internet.StackIP
	addr := ip.Addr()
	addr4 := addr.As4()
	_ = addr4
	ipStack.SetAddr(addr)
	lStack.Register(handler{
		raddr:  nil, //addr4[:],
		recv:   ipStack.Demux,
		handle: ipStack.Encapsulate,
		proto:  ethernet.TypeIPv4,
		lport:  0,
	})
	var conn tcp.Conn
	err = conn.Configure(&tcp.ConnConfig{
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
	err = ipStack.Register(&conn)
	if err != nil {
		return nil, nil, err
	}
	proto := ethernet.TypeIPv4
	if ip.Addr().Is6() {
		proto = ethernet.TypeIPv6
	}
	var narp arp.Handler
	err = narp.Reset(arp.HandlerConfig{
		HardwareAddr: ourMAC[:],
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
		handler: narp,
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
	mac   [6]byte
	gwmac [6]byte
	mtu   uint16
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
	if err := vld.ErrPop(); err != nil {
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
	mtu := ls.mtu
	if len(dst) < int(mtu) {
		return 0, io.ErrShortBuffer
	}
	efrm, err := ethernet.NewFrame(dst)
	if err != nil {
		return 0, err
	}
	copy(efrm.DestinationHardwareAddr()[:], ls.gwmac[:]) // default set the gateway.
	for i := range ls.handlers {
		h := &ls.handlers[i]
		n, err = h.handle(dst[:mtu], 14)
		if err != nil {
			ls.error("handling", slog.String("proto", ethernet.Type(h.proto).String()), slog.String("err", err.Error()))
			continue
		}
		if n > 0 {
			// Found packet
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
	return as.handler.Demux(EtherFrame, arpOff)
}

func (as *ARPStack) Handle(EtherFrame []byte, arpOff int) (int, error) {
	n, err := as.handler.Encapsulate(EtherFrame, arpOff)
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

func debugHex(b []byte) string {
	var d []byte
	for i := 0; i < len(b); i++ {
		c1 := tblhex[b[i]&0xf]
		c2 := tblhex[b[i]>>4]
		d = append(d, c2, c1, ' ')
	}
	return string(d)
}

const tblhex = "0123456789abcdef"

func getTCPFlags(frames []pcap.Frame, pkt []byte) (flags tcp.Flags) {
	for i := range frames {
		if frames[i].Protocol != lneto.IPProtoTCP {
			continue
		}
		iflags, err := frames[i].FieldByClass(pcap.FieldClassFlags)
		if err != nil {
			return 0
		}
		v, err := frames[i].FieldAsUint(iflags, pkt)
		if err != nil {
			return 0
		}
		return tcp.Flags(v)
	}
	return 0
}
