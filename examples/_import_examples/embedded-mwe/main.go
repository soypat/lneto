// Embedded minimal working example: joins WiFi through lneto's x/netdev
// interfaces and acquires an IPv4 address over DHCP. Board support lives in hal-*.go.
// Write newline separated SSID and password to wifi.credentials, then:
//
//	tinygo flash -target pico-w -monitor .
//	tinygo flash -target xiao-esp32c3 -monitor .
package main

import (
	"context"
	_ "embed"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/soypat/lneto/http/httphi"
	"github.com/soypat/lneto/x/xnet"
)

const (
	kB                  = 1 << 10 // kilobyte
	numHTTPProcs        = 4       // number of goroutines spawned for serving HTTP requests.
	numBytesPerHTTPProc = 2 * kB  // HTTP memory buffers used per HTTP conn.
	udpEchoBufSize      = 1500    // Largest datagram echoed; fits any datagram at MTU 1500.
)

var (
	// Ignore wifi credentials for UTP/RJ45 cabled devices, can be empty file.
	//go:embed wifi.credentials
	credentials string
	// remove windows CRLF "\r\n" and trailing newline.
	credentialsNormalized = strings.TrimSuffix(strings.ReplaceAll(credentials, "\r\n", "\n"), "\n")
)

func main() {
	time.Sleep(time.Second) // Let serial monitor attach.
	ssid, password, _ := strings.Cut(credentialsNormalized, "\n")
	connParams, err := NewConnectParams(ssid, password)
	failIfErr("setting conn params (devices needing auth)", err)
	stack, runner, err := SetupDevice(connParams)
	failIfErr("setting up device", err)
	ctx := context.Background()
	go ServeHTTP(ctx, stack, 80)
	go ServeUDPEcho(ctx, stack, 7) // RFC 862 echo port.
	for {
		runner.PrintDebug()
		time.Sleep(2 * time.Second)
	}
}

func ServeHTTP(ctx context.Context, stack *xnet.Netstack, port uint16) {
	c, err := stack.Socket(ctx, "tcp", xnet.AF_INET, xnet.SOCK_STREAM, netip.AddrPortFrom(netip.Addr{}, port), netip.AddrPort{})
	if err != nil {
		fail("tcp listener socket", err)
		return
	}
	l, ok := c.(net.Listener)
	if !ok {
		fail("listener interface cast failed", nil)
		return
	}
	var mux httphi.MuxSlice
	mux.Handle("GET /", func(ex *httphi.Exchange) {
		ex.RespondString(200, "", "hello!")
	})
	mux.Handle("GET /user/{route}", func(ex *httphi.Exchange) {
		route := ex.PathValue("route")
		ex.Respond(200, "", route)
	})
	var router httphi.Router
	err = router.Configure(&mux, httphi.DefaultRouterConfig(numHTTPProcs, numBytesPerHTTPProc, mux.MaxPathValues()))
	if err != nil {
		fail("router config", err)
	}
	for ctx.Err() == nil {
		conn, err := l.Accept()
		if err != nil {
			fail("listener accept", err)
			return
		}
		err = router.Handle(conn)
		if err != nil {
			conn.Close() // remember to close connections if not handled by router.
			println("router handling failed", err)
			continue
		}
	}
	fail("context ended while serving HTTP", ctx.Err())
}

func ServeUDPEcho(ctx context.Context, stack *xnet.Netstack, port uint16) {
	c, err := stack.Socket(ctx, "udp", xnet.AF_INET, xnet.SOCK_DGRAM, netip.AddrPortFrom(netip.Addr{}, port), netip.AddrPort{})
	if err != nil {
		fail("udp listener socket", err)
		return
	}
	pc, ok := c.(net.PacketConn) // Unconnected UDP socket (no remote address) is a net.PacketConn.
	if !ok {
		fail("packet conn interface cast failed", nil)
		return
	}
	defer pc.Close()
	buf := make([]byte, udpEchoBufSize)
	for ctx.Err() == nil {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			fail("udp read", err)
			return
		}
		_, err = pc.WriteTo(buf[:n], raddr)
		if err != nil {
			println("udp echo write failed", err.Error())
		}
	}
	fail("context ended while serving UDP echo", ctx.Err())
}
