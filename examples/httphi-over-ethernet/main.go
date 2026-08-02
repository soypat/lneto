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
	"sync/atomic"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/http/httphi"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/internet/pcap"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/x/xnet"
)

//go:embed index.html
var indexhtml string

// Router memory. The router allocates all of it on Configure and never again,
// so these are the whole cost of serving HTTP over the stack.
const (
	httpConnMemoryUse = 4 * 1024
	// One exchange is allocated per worker, and a worker holds its exchange for
	// the whole request, so this is what bounds requests served at once.
	numWorkers = 2
	// requestTimeout drops a peer that opens a connection and then stalls,
	// rather than letting it hold one of the workers.
	requestTimeout = 10 * time.Second
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
		Hostname:          "httpserver",
		RandSeed:          softRand,
		HardwareAddress:   nicHW,
		MTU:               uint16(mtu),
		MaxActiveTCPPorts: 1000,
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

			pfbuf = bytes.ReplaceAll(pfbuf, ipv4.AppendFormatAddr(nil, stack.Addr4()), []byte("us"))
			pfbuf = bytes.ReplaceAll(pfbuf, ethernet.AppendAddr(nil, stack.HardwareAddr()), []byte("us"))
			pfbuf = append(pfbuf, ']', '\n')
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(pfbuf)
			return err
		}
		for {
			nwrite, err := stack.EgressEthernet(buf[:])
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
				err = stack.IngressEthernet(buf[:nread])
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

	rstack := stack.StackRetrying(stackBackoff)

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
	slog.Info("dhcp-complete", slog.String("assignedIP", string(ipv4.AppendFormatAddr(nil, results.AssignedAddr4))), slog.String("routerIP", results.Router.String()))

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
	stack.SetGatewayHardwareAddr(routerHw)

	svPort := uint16(flagPort)
	fmt.Printf("Listening on %s:%d\n", ipv4.AppendFormatAddr(nil, stack.Addr4()), svPort)

	// Routes are registered before Configure: the router reads the mux to size
	// the exchanges it allocates, and refuses a mux with nothing registered.
	server := httpServer{start: time.Now()}
	// "{$}" matches the empty path and nothing else, so anything unregistered
	// gets a 404 rather than the index page.
	server.handle("GET /{$}", server.index)
	server.handle("GET /stats", server.stats)

	var router httphi.Router
	cfg := httphi.DefaultRouterConfig(numWorkers, httpConnMemoryUse, server.mux.MaxPathValues())
	cfg.Logger = slog.Default()
	err = router.Configure(&server.mux, cfg)
	if err != nil {
		return fmt.Errorf("configuring HTTP router: %w", err)
	}
	defer router.Shutdown()

	// Serve connections in a loop.
	for {
		var conn tcp.Conn
		conn.Configure(tcp.ConnConfig{
			RxBuf:             make([]byte, mtu),
			TxBuf:             make([]byte, mtu),
			TxPacketQueueSize: 3,
			RWBackoff:         tcpBackoff,
		})
		err = stack.ListenTCP4(&conn, svPort)
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
		// The connection owns the idle policy: a peer that stalls fails its read
		// instead of holding a worker. conn is declared inside the loop, so the
		// worker keeps serving this one while the next iteration listens anew.
		conn.SetDeadline(time.Now().Add(requestTimeout))
		err = router.Handle(&conn)
		if err != nil {
			// Every worker is busy. Dropping is the backpressure that keeps the
			// stack's memory bounded, see numWorkers.
			slog.Warn("dropped connection", slog.String("err", err.Error()))
			conn.Abort()
		}
	}
}

// httpServer holds what the handlers answer with. Routes are registered on its
// mux before [httphi.Router.Configure] runs, which reads the mux to size the
// path values every exchange must hold.
type httpServer struct {
	mux    httphi.MuxSlice
	served atomic.Uint64
	start  time.Time
}

// handle registers handler and wraps it in the logging and counting every
// request goes through, i.e: the "< GET /" line this example has always printed.
func (sv *httpServer) handle(pattern string, handler httphi.HandlerFunc) {
	sv.mux.Handle(pattern, func(exch *httphi.Exchange) {
		sv.served.Add(1)
		fmt.Printf("< %s %s\n", exch.RequestMethodRaw(), exch.RequestTarget())
		handler(exch)
	})
}

// index serves the embedded page. The body goes straight to the connection, so
// only its header ever sits in the exchange's buffer and the page's size does
// not enter into how the router is configured.
func (sv *httpServer) index(exch *httphi.Exchange) {
	exch.RespondString(httphi.StatusOK, "text/html", indexhtml)
}

// stats reports what the stack has served, which is the quickest way to tell a
// working link from a page that came out of a browser cache.
func (sv *httpServer) stats(exch *httphi.Exchange) {
	var buf [128]byte
	body := append(buf[:0], "requests served: "...)
	body = strconv.AppendUint(body, sv.served.Load(), 10)
	body = append(body, "\nuptime: "...)
	body = append(body, prettyDuration(time.Since(sv.start))...)
	body = append(body, '\n')
	exch.Respond(httphi.StatusOK, "text/plain", body)
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

func stackBackoff(consecutiveBackoffs uint) time.Duration {
	if consecutiveBackoffs < 10 {
		return time.Millisecond
	}
	return 10 * time.Millisecond
}

func tcpBackoff(consecutiveBackoffs uint) time.Duration {
	const (
		minWait        = uint32(time.Microsecond)
		maxWait        = 5 * uint32(time.Millisecond)
		maxShift       = 22
		_overflowCheck = minWait << maxShift
	)
	shifted := minWait << min(consecutiveBackoffs, maxShift)
	wait := min(shifted, maxWait)
	return time.Duration(wait)
}
