//go:build !tinygo && linux

package main

import (
	"bytes"
	_ "embed"
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
	"strconv"
	"strings"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/internet/pcap"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/x/xnet"
)

//go:embed index.html
var indexhtml string

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
		flagInterface = "tap0"
		flagUseHTTP   = false
		flagNoPcap    = false
		flagPort      = 80
	)
	flag.StringVar(&flagInterface, "i", flagInterface, "Interface to use. Either tap* or the name of an existing interface to bridge to.")
	flag.BoolVar(&flagUseHTTP, "ihttp", flagUseHTTP, "Use HTTP tap interface.")
	flag.BoolVar(&flagNoPcap, "nopcap", flagNoPcap, "Disable pcap logging.")
	flag.IntVar(&flagPort, "port", flagPort, "Port to listen on.")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "httpserver is a minimal HTTP server using the lneto networking stack.\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	fmt.Println("softrand", softRand)
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
	mtu, err := iface.MTU()
	if err != nil {
		return err
	}
	nicAddr, err := iface.IPMask()
	if err != nil {
		return err
	}
	fmt.Println("NIC hardware address:", net.HardwareAddr(nicHW[:]).String(), "mtu:", mtu, "addr:", nicAddr.String())

	var stack xnet.StackAsync
	err = stack.Reset(xnet.StackConfig{
		Hostname:        "httpserver",
		RandSeed:        softRand,
		HardwareAddress: nicHW,
		MTU:             uint16(mtu),
		MaxTCPConns:     1000,
	})
	if err != nil {
		return err
	}

	// Loop goroutine handles packet encapsulation/decapsulation.
	go func() {
		lastAction := time.Now()
		buf := make([]byte, math.MaxUint16)
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
					log.Fatal("goroutine encapsulate:", err)
				} else if n != nwrite {
					log.Fatalf("mismatch written bytes %d!=%d", nwrite, n)
				}
			}

			clear(buf[:nwrite])
			ready, err := tryPoll(iface, 5*time.Millisecond)
			if err != nil {
				log.Fatal("goroutine poll:", err)
			}
			if !ready {
				continue
			}
			nread, err := iface.Read(buf)
			if err != nil {
				log.Fatal("goroutine read:", err)
			} else if nread > 0 {
				err = stack.Demux(buf[:nread], 0)
				if !errors.Is(err, lneto.ErrPacketDrop) {
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
	slog.Info("dhcp-complete", slog.String("assignedIP", results.AssignedAddr.String()), slog.String("routerIP", results.Router.String()))

	const (
		arpTimeout = 2 * time.Second
		arpRetries = 2
	)
	timeResolveRouterHW := timer("Router ARP resolution")
	routerHw, err := rstack.DoResolveHardwareAddress6(results.Router, arpTimeout, arpRetries)
	if err != nil {
		return fmt.Errorf("ARP resolution of router failed: %w", err)
	}
	timeResolveRouterHW()
	stack.SetGateway6(routerHw)

	svPort := uint16(flagPort)
	fmt.Printf("Listening on %s:%d\n", stack.Addr().String(), svPort)

	// Serve connections in a loop.
	for {
		var conn tcp.Conn
		conn.Configure(tcp.ConnConfig{
			RxBuf:             make([]byte, mtu),
			TxBuf:             make([]byte, mtu),
			TxPacketQueueSize: 3,
		})
		err = stack.ListenTCP(&conn, svPort)
		if err != nil {
			return fmt.Errorf("listen TCP: %w", err)
		}
		fmt.Println("waiting for connection...")

		// Wait for TCP handshake to complete.
		deadline := time.Now().Add(60 * time.Second)
		for conn.State() != tcp.StateEstablished {
			if time.Now().After(deadline) {
				conn.Abort()
				fmt.Println("listen timeout, retrying...")
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if conn.State() != tcp.StateEstablished {
			continue
		}
		fmt.Println("connection established from", net.IP(conn.RemoteAddr()).String())
		go func() {
			err = handleConnection(&conn)
			if err != nil {
				fmt.Println("handle error:", err)
			}
		}()
	}
}

func handleConnection(conn *tcp.Conn) error {
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Read HTTP request.
	var hdr httpraw.Header
	var needMore bool = true
	for needMore {
		_, err := hdr.ReadFromLimited(conn, 1024)
		if err != nil {
			return fmt.Errorf("reading request: %w", err)
		}
		const asResponse = false
		needMore, err = hdr.TryParse(asResponse)
		if err != nil && !needMore {
			return fmt.Errorf("parsing request: %w", err)
		}
	}

	method := string(hdr.Method())
	uri := string(hdr.RequestURI())
	fmt.Printf("< %s %s\n", method, uri)

	// Build response body.

	// Build HTTP response.
	var resp httpraw.Header
	resp.SetProtocol("HTTP/1.1")
	resp.SetStatus("200", "OK")
	resp.Set("Content-Type", "text/html")
	resp.Set("Content-Length", strconv.Itoa(len(indexhtml)))
	resp.Set("Connection", "close")
	response, err := resp.AppendResponse(nil)
	if err != nil {
		return fmt.Errorf("building response: %w", err)
	}
	response = append(response, indexhtml...)

	// Send response.
	_, err = conn.Write(response)
	if err != nil {
		return fmt.Errorf("writing response: %w", err)
	}
	err = conn.Flush()
	if err != nil {
		return fmt.Errorf("flushing response: %w", err)
	}
	fmt.Printf("> %d bytes sent\n", len(response))

	conn.Close()
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
