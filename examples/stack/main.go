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

	var stack Stack
	err := stack.Reset(stackHWAddr, gatewayMAC, addrPort.Addr(), mtu)
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

type Stack struct {
	ethernet internet.StackEthernet
	ip       internet.StackIP
	tcpports internet.StackPorts
	arp      internet.NodeARP
}

func (stack *Stack) Reset(ourMAC, gwMAC [6]byte, ip netip.Addr, mtu int) (err error) {
	err = stack.ethernet.Reset6(ourMAC, gwMAC, mtu)
	if err != nil {
		return err
	}
	err = stack.ip.Reset(ip)
	if err != nil {
		return err
	}
	stack.tcpports.Reset(uint64(lneto.IPProtoTCP), 2)
	ipaddr := ip.As4()
	err = stack.arp.Reset(arp.HandlerConfig{
		HardwareAddr: ourMAC[:],
		ProtocolAddr: ipaddr[:],
		MaxQueries:   2,
		MaxPending:   2,
		HardwareType: 1,
		ProtocolType: ethernet.TypeIPv4,
	})
	if err != nil {
		return err
	}

	// Register stacks and nodes.
	err = stack.ethernet.Register(&stack.arp)
	if err != nil {
		return err
	}
	err = stack.ethernet.Register(&stack.ip)
	if err != nil {
		return err
	}
	err = stack.ip.Register(&stack.tcpports)
	if err != nil {
		return err
	}
	return nil
}

func (stack *Stack) Recv(b []byte) error {
	return stack.ethernet.Demux(b, 0)
}

func (stack *Stack) Send(b []byte) (int, error) {
	return stack.ethernet.Encapsulate(b, 0)
}

func (stack *Stack) OpenPassiveTCP(port uint16, iss tcp.Value) (*tcp.Conn, error) {
	mtu := stack.ethernet.MTU()
	conn := new(tcp.Conn)
	err := conn.Configure(&tcp.ConnConfig{
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
