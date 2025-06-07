package main

import (
	"fmt"
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
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/internet"
	"github.com/soypat/lneto/internet/pcap"
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

	ippfx := tap.IPPrefix()
	if !ippfx.Contains(ip) {
		log.Fatal("interface does not contain stack address")
	}
	addrPort := netip.AddrPortFrom(ip, stackPort)
	lg := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	gatewayMAC := tap.HardwareAddr6()
	mtu := tap.MTU()
	stack, err := NewEthernetTCPStack(stackHWAddr, gatewayMAC, addrPort, uint16(mtu))
	if err != nil {
		log.Fatal(err)
	}
	handler, err := stack.OpenPassiveTCP(addrPort.Port(), iss)
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
			lg.Error("tap-err", slog.String("err", err.Error()))
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
			err = stack.ethernet.Demux(buf[:nread], 0)
			if err != nil {
				lg.Error("recv", slog.String("err", err.Error()), slog.Int("plen", nread))
			}
		}
		doHTTP(handler, &hdr)
		nw, err := stack.ethernet.Encapsulate(buf[:], 0)
		if err != nil {
			lg.Error("handle", slog.String("err", err.Error()))
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

func doHTTP(conn *internet.TCPConn, hdr *httpraw.Header) error {
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

type Stack struct {
	ethernet internet.StackLinkLayer
	ip       internet.StackIP
	tcpports internet.StackPorts
	arp      internet.NodeARP

	onlyConn internet.TCPConn
}

func (stack *Stack) OpenPassiveTCP(port uint16, iss tcp.Value) (*internet.TCPConn, error) {
	mtu := stack.ethernet.MTU()
	conn := new(internet.TCPConn)
	err := conn.Configure(&internet.TCPConnConfig{
		RxBuf:             make([]byte, mtu),
		TxBuf:             make([]byte, mtu),
		TxPacketQueueSize: 3,
	})
	if err != nil {
		return nil, err
	}
	err = conn.OpenListen(port, iss)
	if err != nil {
		return nil, err
	}
	err = stack.tcpports.Register(conn)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func NewEthernetTCPStack(ourMAC, gwMAC [6]byte, ip netip.AddrPort, mtu uint16) (*Stack, error) {
	var stack Stack
	var err error
	err = stack.ethernet.Reset6(ourMAC, gwMAC, int(mtu))
	if err != nil {
		return nil, err
	}
	err = stack.ip.Reset(ip.Addr())
	if err != nil {
		return nil, err
	}
	stack.tcpports.Reset(uint64(lneto.IPProtoTCP), 2)
	ipaddr := ip.Addr().As4()
	err = stack.arp.Reset(arp.HandlerConfig{
		HardwareAddr: ourMAC[:],
		ProtocolAddr: ipaddr[:],
		MaxQueries:   2,
		MaxPending:   2,
		HardwareType: 1,
		ProtocolType: ethernet.TypeIPv4,
	})
	if err != nil {
		return nil, err
	}

	// Register stacks and nodes.
	err = stack.ethernet.Register(&stack.arp)
	if err != nil {
		return nil, err
	}
	err = stack.ethernet.Register(&stack.ip)
	if err != nil {
		return nil, err
	}
	err = stack.ip.Register(&stack.tcpports)
	if err != nil {
		return nil, err
	}
	return &stack, nil
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
