package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/internet/pcap"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/x/xnet"
)

var softRand = time.Now().Unix()

func main() {
	err := run()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("success")
}

func run() (err error) {
	var (
		flagInterface     = "tap0"
		flagUseHTTP       = false
		flagHostToResolve = ""
		flagRequestedIP   = ""
		flagDoNTP         = false
		flagHTTPGet       = false
		flagNoPcap        = false
		flagPprof         = false
	)
	flag.BoolVar(&flagHTTPGet, "httpget", flagHTTPGet, "Do an HTTP GET request ")
	flag.StringVar(&flagInterface, "i", flagInterface, "Interface to use. Either tap* or the name of an existing interface to bridge to.")
	flag.BoolVar(&flagUseHTTP, "ihttp", flagUseHTTP, "Use HTTP tap interface.")
	flag.StringVar(&flagHostToResolve, "host", flagHostToResolve, "Hostname to resolve via DNS.")
	flag.StringVar(&flagRequestedIP, "addr", flagRequestedIP, "IP address to request via DHCP.")
	flag.BoolVar(&flagDoNTP, "ntp", flagDoNTP, "Do NTP round and print result time")
	flag.BoolVar(&flagNoPcap, "nopcap", flagNoPcap, "Disable pcap logging.")
	flag.BoolVar(&flagPprof, "pprof", flagPprof, "Enable CPU profiling.")
	flag.Parse()
	if flagPprof {
		var b bytes.Buffer
		pprof.StartCPUProfile(&b)
		defer func() {
			pprof.StopCPUProfile()
			os.WriteFile("xnet.pprof", b.Bytes(), 0777)
		}()
	}
	fmt.Println("softrand", softRand)
	_, err = dns.NewName(flagHostToResolve)
	if err != nil {
		flag.Usage()
		return err
	}
	var iface ltesto.Interface
	if flagUseHTTP {
		iface = ltesto.NewHTTPTapClient("http://127.0.0.1:7070")
	} else {
		if strings.HasPrefix(flagInterface, "tap") {
			tap, err := internal.NewTap(flagInterface, netip.MustParsePrefix("192.168.1.1/24"))
			if err != nil {
				return err
			}
			iface = tap
		} else {
			bridge, err := internal.NewBridge(flagInterface)
			if err != nil {
				return err
			}
			err = bridge.SetReadTimeout(5 * time.Millisecond)
			if err != nil {
				return err
			}
			iface = bridge
		}
	}
	defer iface.Close()

	nicHW, err := iface.HardwareAddress6()
	if err != nil {
		return err
	}
	brHW := nicHW
	mtu, err := iface.MTU()
	if err != nil {
		return err
	}

	nicAddr, err := iface.IPMask()
	if err != nil {
		return err
	}
	fmt.Println("NIC hardware address:", net.HardwareAddr(nicHW[:]).String(), "bridgeHW:", net.HardwareAddr(brHW[:]).String(), "mtu:", mtu, "addr:", nicAddr.String())
	var stack xnet.StackAsync
	err = stack.Reset(xnet.StackConfig{
		Hostname:        "xnet-test",
		RandSeed:        softRand,
		HardwareAddress: brHW,
		MTU:             uint16(mtu),
		MaxTCPConns:     1,
	})
	if err != nil {
		return err
	}

	// Loop goroutine.
	go func() {
		lastAction := time.Now()
		buf := make([]byte, math.MaxUint16) // Generic-receive Offload (GRO) can aggregate packets.
		var cap pcap.PacketBreakdown
		var frames []pcap.Frame
		pf := pcap.Formatter{
			FilterClasses: []pcap.FieldClass{pcap.FieldClassFlags, pcap.FieldClassOperation, pcap.FieldClassDst, pcap.FieldClassSrc, pcap.FieldClassAddress, pcap.FieldClassTimestamp},
		}
		var pfbuf []byte
		logFrames := func(context string, pkt []byte) error {
			if flagNoPcap {
				return nil
			}
			frames, err = cap.CaptureEthernet(frames[:0], pkt, 0)
			if err != nil {
				pkt := hex.EncodeToString(pkt)
				slog.Error(err.Error(), slog.Any("pkt", pkt))
				return err
			}
			pfbuf = fmt.Appendf(pfbuf[:0], "%-3s %3d", context, len(pkt))
			pfbuf = append(pfbuf, ' ', '[')
			pfbuf, err = pf.FormatFrames(pfbuf, frames, pkt)
			pfbuf = bytes.ReplaceAll(pfbuf, stack.Addr().AppendTo(nil), []byte("us"))
			pfbuf = bytes.ReplaceAll(pfbuf, ethernet.AppendAddr(nil, stack.HardwareAddress()), []byte("us"))
			pfbuf = append(pfbuf, ']', '\n')
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(pfbuf)
			return err
		}
		for {
			nwrite, err := stack.Encapsulate(buf[:], -1, 0)
			if err != nil {
				log.Println("ERR:ENCAPSULATE", err)
			} else if nwrite > 0 {
				err = logFrames("OUT", buf[:nwrite])
				if err != nil {
					log.Println("ERR:OUTLOG", err)
				}
				n, err := iface.Write(buf[:nwrite])
				if err != nil {
					log.Fatal("groutine encapsulate:", err)
				} else if n != nwrite {
					log.Fatalf("mismatch written bytes %d!=%d", nwrite, n)
				}
			}

			clear(buf[:nwrite])
			// Poll before read if interface supports it, to avoid blocking indefinitely.
			ready, err := tryPoll(iface, 5*time.Millisecond)
			if err != nil {
				log.Fatal("goroutine poll:", err)
			}
			if !ready {
				continue
			}
			nread, err := iface.Read(buf)
			if err != nil {
				log.Fatal("groutine read:", err)
			} else if nread > 0 {
				err = stack.Demux(buf[:nread], 0)
				if !errors.Is(err, lneto.ErrPacketDrop) {
					// Only skip logging packet in case of dropped packet.
					err = logFrames("IN", buf[:nread])
					if err != nil {
						log.Println("ERR:INLOG", err)
					}
				}
			}
			clear(buf[:nread])
			if nread == 0 && nwrite == 0 && time.Since(lastAction) > 4*time.Second {
				time.Sleep(5 * time.Millisecond)
			} else {
				lastAction = time.Now()
				runtime.Gosched()
			}
		}
	}()

	rstack := stack.StackRetrying(5 * time.Millisecond)

	const (
		dhcpTimeout = 6 * time.Second
		dhcpRetries = 2
	)
	timeDHCP := timer("DHCP request completed")
	results, err := rstack.DoDHCPv4([4]byte{192, 168, 1, 96}, dhcpTimeout, dhcpRetries)
	if err != nil {
		return fmt.Errorf("DHCP failed: %w", err)
	}
	timeDHCP()
	err = stack.AssimilateDHCPResults(results)
	if err != nil {
		return fmt.Errorf("assimilating DHCP results: %w", err)
	}
	slog.Info("dhcp-complete", slog.String("assignedIP", results.AssignedAddr.String()), slog.String("routerIP", results.Router.String()), slog.Any("DNS", results.DNSServers), slog.Any("subnet", results.Subnet.String()))
	const (
		arpTimeout = 2 * time.Second
		arpRetries = 2
	)
	const (
		internetTimeout = 3 * time.Second
		internetRetries = 2
	)
	timeResolveRouterHW := timer("Router ARP resolution")
	routerHw, err := rstack.DoResolveHardwareAddress6(results.Router, arpTimeout, arpRetries)
	if err != nil {
		return fmt.Errorf("ARP resolution of router failed: %w", err)
	}
	timeResolveRouterHW()
	stack.SetGateway6(routerHw)
	if flagDoNTP {
		timeLookupNTP := timer("NTP IP lookup")
		const ntpHost = "pool.ntp.org"
		addrs, err := rstack.DoLookupIP(ntpHost, internetTimeout, internetRetries)
		if err != nil {
			return fmt.Errorf("NTP address lookup of %q failed: %w", ntpHost, err)
		}
		timeLookupNTP()
		timeNTP := timer("NTP exchange")
		offset, err := rstack.DoNTP(addrs[0], internetTimeout, internetRetries)
		if err != nil {
			return fmt.Errorf("NTP address lookup of %q failed: %w", ntpHost, err)
		}
		timeNTP()
		relative := "behind"
		if offset < 0 {
			relative = "ahead"
		}
		fmt.Println("NTP completed. You are", offset.Abs().String(), relative, "of the NTP server")
	}
	timeResolveIP := timer("resolve " + flagHostToResolve)
	addrs, err := rstack.DoLookupIP(flagHostToResolve, internetTimeout, internetRetries)
	if err != nil {
		return fmt.Errorf("DNS of host %q failed: %w", flagHostToResolve, err)
	}
	timeResolveIP()
	fmt.Printf("DNS resolution of %q complete and resolved to %v\n", flagHostToResolve, addrs)
	var conn tcp.Conn
	conn.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, mtu),
		TxBuf:             make([]byte, mtu),
		TxPacketQueueSize: 3,
	})
	if flagHTTPGet {
		timeHTTPCreate := timer("create HTTP GET request")
		var hdr httpraw.Header
		hdr.SetMethod("GET")
		hdr.SetRequestURI("/")
		hdr.SetProtocol("HTTP/1.1")
		hdr.Set("Host", flagHostToResolve)
		hdr.Set("User-Agent", "lneto")
		hdr.Set("Accept-Language", "en-US,en;q=0.5")
		hdr.Set("Connection", "close") // Encourage server to close connection after it finishes sending response.
		req, err := hdr.AppendRequest(nil)
		if err != nil {
			return err
		}
		timeHTTPCreate()

		timeTCPDial := timer("TCP dial (handshake)")
		const tcpDialTimeout = 8 * time.Second // Was 60 * time.Minute causing 3.6s sleep per iteration!
		target := netip.AddrPortFrom(addrs[0], 80)
		err = rstack.DoDialTCP(&conn, uint16(softRand&0xefff)+1024, target, tcpDialTimeout, internetRetries)
		if err != nil {
			return fmt.Errorf("TCP failed: %w", err)
		}
		timeTCPDial()
		timeHTTPSend := timer("send HTTP request")
		conn.SetDeadline(time.Now().Add(internetTimeout))
		_, err = conn.Write(req)
		timeHTTPSend()
		timeHTTPRcv := timer("recv http request")
		if err != nil {
			return err
		}
		rxbuf := make([]byte, 2048)

		var page []byte
		for {
			var n int
			n, err = conn.Read(rxbuf)
			page = append(page, rxbuf[:n]...)
			if err != nil {
				break
			}
			ptrimmed := bytes.TrimSpace(page)
			if bytes.EqualFold(ptrimmed[len(ptrimmed)-7:], []byte("</html>")) {
				// We've received the last part of the HTML. we're done.
				break
			}
		}
		if len(page) == 0 {
			return err
		}
		timeHTTPRcv()
		os.Stdout.Write(page)
	}
	return nil
}

func clear(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

func timer(context string) func() {
	start := time.Now()
	return func() {
		elapsed := time.Since(start)
		fmt.Printf("[%s] %s\n", prettyDuration(elapsed), context)
	}
}

func prettyDuration(d time.Duration) string {
	switch {
	case d < time.Microsecond:
		// Print as is.
	case d < time.Millisecond:
		d = d.Round(time.Microsecond)
	case d < time.Second:
		d = d.Round(time.Millisecond)
	case d < 10*time.Second:
		d = d.Round(100 * time.Millisecond)
	case d < 10*time.Minute:
		d = d.Round(1000 * time.Millisecond)
	case d < time.Hour:
		d = d.Round(time.Minute)
	}
	return d.String()
}

func tryPoll(iface ltesto.Interface, poll time.Duration) (dataMayBeReady bool, _ error) {
	if poller, ok := iface.(interface {
		Poll(time.Duration) (bool, error)
	}); ok {
		ready, err := poller.Poll(poll)
		return ready, err
	}
	dataMayBeReady = true
	return dataMayBeReady, nil
}
