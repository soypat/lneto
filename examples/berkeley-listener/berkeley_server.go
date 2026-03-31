//go:build !tinygo && linux

package main

import (
	"bytes"
	"context"
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
	"syscall"
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

const pollTime = 5 * time.Millisecond

var softRand = time.Now().Unix()

var mockStack = new(xnet.StackAsync)

const indexhtml = "<html><body><h1>Berkeley Stack HTTP Server</h1></body></html>"

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	var (
		flagInterface  = "tap0"
		flagUseHTTP    = false
		flagNoPcap     = false
		flagPort       = 8080
		flagPoolSize   = 16
		flagMockClient = false
	)
	flag.StringVar(&flagInterface, "i", flagInterface, "Interface to use. Either tap* or the name of an existing interface to bridge to.")
	flag.BoolVar(&flagUseHTTP, "ihttp", flagUseHTTP, "Use HTTP tap interface.")
	flag.BoolVar(&flagNoPcap, "nopcap", flagNoPcap, "Disable pcap logging.")
	flag.IntVar(&flagPort, "port", flagPort, "Port to listen on.")
	flag.IntVar(&flagPoolSize, "pool", flagPoolSize, "TCP pool size for Berkeley listener.")
	flag.BoolVar(&flagMockClient, "mockclient", flagMockClient, "Run an in-memory mock client that issues a single HTTP request to the berkeley listener")
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
			if err = bridge.SetReadTimeout(5 * time.Millisecond); err != nil {
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
	if err := stack.Reset(xnet.StackConfig{
		Hostname:        "berkeley-http",
		RandSeed:        softRand,
		HardwareAddress: nicHW,
		MTU:             uint16(mtu),
		MaxTCPConns:     1024,
	}); err != nil {
		return err
	}

	// Packet loop goroutine (encapsulate/demux)
	go func() {
		lastAction := time.Now()
		buf := make([]byte, math.MaxUint16)
		var cap pcap.PacketBreakdown
		var frames []pcap.Frame
		pf := pcap.Formatter{FilterClasses: []pcap.FieldClass{pcap.FieldClassFlags, pcap.FieldClassOperation, pcap.FieldClassDst, pcap.FieldClassSrc, pcap.FieldClassAddress, pcap.FieldClassTimestamp}}
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
				if err = logFrames("OUT", buf[:nwrite]); err != nil {
					log.Println("ERR:OUTLOG", err)
				}
				n, err := iface.Write(buf[:nwrite])
				if err != nil {
					log.Fatal("goroutine encapsulate:", err)
				} else if n != nwrite {
					log.Fatalf("mismatch written bytes %d!=%d", nwrite, n)
				}
				if flagMockClient && mockStack.Addr().IsValid() {
					mockStack.Demux(buf[:nwrite], 0)
				}
			}
			if flagMockClient && mockStack.Addr().IsValid() {
				n, _ := mockStack.Encapsulate(buf[:], -1, 0)
				if n > 0 {
					stack.Demux(buf[:n], 0)
				}
			}

			clear(buf[:nwrite])
			ready, err := tryPoll(iface, pollTime)
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
					if err = logFrames("IN", buf[:nread]); err != nil {
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

	// Create blocking + Berkeley stack
	blocking := stack.StackBlocking(5 * time.Millisecond)
	berkeley := blocking.StackBerkeley(xnet.StackGoConfig{
		ListenerPoolConfig: xnet.TCPPoolConfig{
			PoolSize:           flagPoolSize,
			QueueSize:          3,
			TxBufSize:          mtu,
			RxBufSize:          mtu,
			EstablishedTimeout: 5 * time.Second,
			ClosingTimeout:     5 * time.Second,
		},
	})

	// Perform DHCP to get address.
	rstack := stack.StackRetrying(5 * time.Millisecond)
	const dhcpTimeout = 6 * time.Second
	const dhcpRetries = 2
	results, err := rstack.DoDHCPv4([4]byte{192, 168, 1, 96}, dhcpTimeout, dhcpRetries)
	if err != nil {
		return fmt.Errorf("DHCP failed: %w", err)
	}
	if err = stack.AssimilateDHCPResults(results); err != nil {
		return fmt.Errorf("assimilating DHCP results: %w", err)
	}
	slog.Info("dhcp-complete", slog.String("assignedIP", results.AssignedAddr.String()), slog.String("routerIP", results.Router.String()))

	// Resolve router HW and set gateway
	routerHw, err := rstack.DoResolveHardwareAddress6(results.Router, 2*time.Second, 2)
	if err != nil {
		return fmt.Errorf("ARP resolution of router failed: %w", err)
	}
	// Set gateway on the async stack (exported API).
	stack.SetGateway6(routerHw)

	// Create Berkeley listener via SocketNetip
	laddr := netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(flagPort))
	ctx := context.Background()
	// sock type for STREAM is 1 (unexported constant in xnet), pass literal here.
	c, err := berkeley.SocketNetip(ctx, "tcp", syscall.AF_INET, 1, laddr, netip.AddrPort{})
	if err != nil {
		return fmt.Errorf("creating berkeley socket: %w", err)
	}
	ln, ok := c.(net.Listener)
	if !ok {
		return fmt.Errorf("berkeley socket did not return net.Listener")
	}
	defer ln.Close()

	fmt.Printf("Listening (Berkeley) on %s:%d\n", stack.Addr().String(), flagPort)

	// Optionally run an in-memory mock client that dials the berkeley listener
	if flagMockClient {
		go mockClient(&stack, uint16(flagPort), results.Subnet)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		fmt.Println("connection established from", conn.RemoteAddr().String())
		go func(c net.Conn) {
			if err := handleConnNet(c); err != nil {
				fmt.Println("handle error:", err)
			}
		}(conn)
	}
}

func handleConnNet(conn net.Conn) error {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	var hdr httpraw.Header
	needMore := true
	for needMore {
		_, err := hdr.ReadFromLimited(conn, 1024)
		if err != nil {
			return fmt.Errorf("reading request: %w", err)
		}
		var asResponse = false
		needMore, err = hdr.TryParse(asResponse)
		if err != nil && !needMore {
			return fmt.Errorf("parsing request: %w", err)
		}
	}
	method := string(hdr.Method())
	uri := string(hdr.RequestURI())
	fmt.Printf("< %s %s\n", method, uri)

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

	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("writing response: %w", err)
	}
	if flusher, ok := conn.(interface{ Close() error }); ok {
		_ = flusher.Close()
	}
	return nil
}

func clear(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

func tryPoll(iface ltesto.Interface, poll time.Duration) (dataMayBeReady bool, _ error) {
	if poller, ok := iface.(interface {
		Poll(time.Duration) (bool, error)
	}); ok {
		ready, err := poller.Poll(poll)
		return ready, err
	}
	return true, nil
}

func mockClient(stack *xnet.StackAsync, port uint16, subnet netip.Prefix) {
	target := netip.AddrPortFrom(stack.Addr(), port)
	err := mockStack.Reset(xnet.StackConfig{
		StaticAddress:   subnet.Addr().Next(),
		MaxTCPConns:     1,
		HardwareAddress: stack.Gateway6(),
		Hostname:        "the-other",
		MTU:             uint16(stack.MTU()),
		RandSeed:        int64(stack.Prand32()),
	})
	if err != nil {
		panic(err.Error())
	}
	var mockConn tcp.Conn
	err = mockConn.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, 2048),
		TxBuf:             make([]byte, 2048),
		TxPacketQueueSize: 4,
		Logger:            slog.Default(),
	})
	if err != nil {
		panic(err.Error())
	}
	err = mockStack.DialTCP(&mockConn, 1337, target)
	if err != nil {
		panic(err.Error())
	}
	deadline := time.Now().Add(time.Second)
	for time.Since(deadline) < 0 {
		runtime.Gosched()
		state := mockConn.State()
		if state == tcp.StateEstablished {
			break
		}
	}
	if mockConn.State() != tcp.StateEstablished {
		panic("mock client deadline exceeded to establish")
	}

	var hdr httpraw.Header
	hdr.SetMethod("GET")
	hdr.SetRequestURI("/")
	hdr.SetProtocol("HTTP/1.1")
	hdr.Set("Host", stack.Addr().String())
	hdr.Set("User-Agent", "lneto-mock")
	hdr.Set("Connection", "close")
	req, err := hdr.AppendRequest(nil)
	if err != nil {
		fmt.Println("mockclient: build request:", err)
		mockConn.Close()
		return
	}
	mockConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := mockConn.Write(req); err != nil {
		fmt.Println("mockclient: write error:", err)
		mockConn.Close()
		return
	}
	_ = mockConn.Flush()
	// Read response
	rx := make([]byte, 4096)
	var page []byte
	for {
		n, err := mockConn.Read(rx)
		if n > 0 {
			page = append(page, rx[:n]...)
		}
		if err != nil {
			break
		}
	}
	fmt.Println("mockclient: received response:\n", string(page))
	mockConn.Close()
}
