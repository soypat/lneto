package main

import (
	"crypto/rand"
	"encoding/binary"
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

	ippfx, _ := tap.IPMask()
	if !ippfx.Contains(ip) {
		log.Fatal("interface does not contain stack address")
	}
	addrPort := netip.AddrPortFrom(ip, stackPort)
	lg := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	gatewayMAC, _ := tap.HardwareAddress6()
	mtu, _ := tap.MTU()

	var stack Stack
	err := stack.Reset(stackHWAddr, gatewayMAC, addrPort.Addr(), mtu)
	if err != nil {
		log.Fatal(err)
	}
	listener, err := stack.OpenTCPListener(addrPort.Port())
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
	var conn *tcp.Conn
	accepted := 0
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
		if conn == nil && listener.NumberOfReadyToAccept() > 0 {
			conn, err = listener.TryAccept()
			if err != nil {
				lg.Error("tryaccept", slog.String("err", err.Error()))
			}
			accepted++
			hdr.Reset(nil)
			lg.Info("ACCEPT!")
		}
		if conn != nil {
			done, err := doHTTP(conn, &hdr)
			if done {
				lg.Info("close forever")
				conn.Close()
				conn = nil
			}
			if err != nil {
				lg.Error("doHTTP", slog.String("err", err.Error()))
			}
		}

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

func doHTTP(conn *tcp.Conn, hdr *httpraw.Header) (done bool, err error) {
	const asRequest = false
	if conn.State() != tcp.StateEstablished || conn.BufferedInput() == 0 {
		return false, nil // No data yet.
	}
	fmt.Println("state is established; check request and send response")
	_, err = hdr.ReadFromLimited(conn, hdr.BufferFree())
	if err != nil {
		return false, err
	}
	needMore, err := hdr.TryParse(asRequest)
	if needMore {
		return false, nil
	} else if err != nil {
		return true, err
	}
	// HTTP parsed succesfully!
	fmt.Println("GOT HTTP:\n", hdr.String())
	fmt.Println("sending response...")
	hdr.Reset(nil)
	hdr.SetStatus("200", "OK")
	data := `{"ok":true}`
	response, err := hdr.AppendResponse(nil)
	if err != nil {
		return true, err
	}
	response = append(response, data...)
	_, err = conn.Write(response)
	if err != nil {
		return true, err
	}
	err = conn.Close()
	if err != nil {
		return true, err
	}
	return true, nil
}

type Stack struct {
	ethernet internet.StackEthernet
	ip       internet.StackIP
	tcpports internet.StackPorts
	arp      arp.Handler
}

func (stack *Stack) Reset(ourMAC, gwMAC [6]byte, ip netip.Addr, mtu int) (err error) {
	const maxNodes = 8
	err = stack.ethernet.Reset6(ourMAC, gwMAC, mtu, maxNodes)
	if err != nil {
		return err
	}
	err = stack.ip.Reset(ip, maxNodes)
	if err != nil {
		return err
	}
	stack.tcpports.ResetTCP(maxNodes)
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

func (stack *Stack) OpenTCPListener(port uint16) (*internet.NodeTCPListener, error) {
	var listener internet.NodeTCPListener
	err := listener.Reset(port, naiveTCPPool{})
	if err != nil {
		return nil, err
	}
	err = stack.tcpports.Register(&listener)
	if err != nil {
		return nil, err
	}
	return &listener, nil
}

func (stack *Stack) OpenPassiveTCP(port uint16, iss tcp.Value) (*tcp.Conn, error) {
	mtu := stack.ethernet.MTU()
	conn := new(tcp.Conn)
	err := conn.Configure(tcp.ConnConfig{
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

type naiveTCPPool struct {
}

func (naiveTCPPool) GetTCP() (*tcp.Conn, tcp.Value) {
	var buf [4]byte
	rand.Read(buf[:])
	randVal := binary.LittleEndian.Uint32(buf[:])
	var conn tcp.Conn
	err := conn.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, 1024),
		TxBuf:             make([]byte, 1024),
		TxPacketQueueSize: 3,
		Logger:            slog.Default(),
	})
	if err != nil {
		panic(err)
	}
	return &conn, tcp.Value(randVal)
}

func (naiveTCPPool) PutTCP(*tcp.Conn) {}
