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
	"net/netip"
	"strings"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/x/netdev"
	"github.com/soypat/lneto/x/xnet"
)

var (
	//go:embed wifi.credentials
	credentials string
	// remove windows CRLF "\r\n" and trailing newline.
	credentialsNormalized = strings.TrimSuffix(strings.ReplaceAll(credentials, "\r\n", "\n"), "\n")
	wifiParams            ConnectParams
)

func main() {
	time.Sleep(time.Second) // Let serial monitor attach.
	ssid, password, ok := strings.Cut(credentialsNormalized, "\n")
	if !ok {
		fail("must write newline separated ssid/password in wifi.credentials", nil)
	}
	wifiParams = NewConnectParams(ssid, password)

	// Link: power up chip and join network. Some chips only know their MAC after joining.
	var dev Netdev
	failIfErr("device init", dev.Init())
	dev.LinkNotify(onLinkChange)
	failIfErr("link connect", dev.LinkConnect(wifiParams))
	hw, err := dev.HardwareAddr6()
	failIfErr("hardware addr", err)

	// Stack: protocol state and sockets.
	var stack xnet.Netstack
	failIfErr("stack reset", stack.Reset(stackConfig(hw)))
	failIfErr("icmp enable", stack.EnableICMP(true))

	// Runner: moves frames between device and stack.
	var iface netdev.Interface[ConnectParams]
	failIfErr("iface init", iface.Init(&dev, &dev, netdev.InterfaceConfig{}))
	var runner netdev.Runner[ConnectParams]
	failIfErr("runner config", runner.Configure(netdev.RunnerConfig[ConnectParams]{
		Buffers: iface.RunnerBuffers(2),
		Backoff: backoff,
		Flags:   dev.RunnerFlags(),
	}))
	go func() {
		failIfErr("runner", runner.Run(context.Background(), &iface, &stack))
	}()

	// Application: request address and report runner state.
	assigned, gateway, subnetBits, err := stack.EnableDHCP(context.Background(), true, netip.Addr{})
	failIfErr("dhcp", err)
	println("assigned", assigned.String(), "gateway", gateway.String(), "subnet", subnetBits)
	for {
		runner.PrintDebug()
		time.Sleep(2 * time.Second)
	}
}

func stackConfig(hw [6]byte) xnet.NetstackConfig {
	return xnet.NetstackConfig{
		StackConfig: xnet.StackConfig{
			Entropy:           Entropy,
			RandSeed:          time.Now().UnixNano() | 1,
			Hostname:          "lneto-mwe",
			MaxActiveTCPPorts: 4,
			MaxActiveUDPPorts: 4,
			ICMPQueueLimit:    1,
			MTU:               1500,
			PassivePeers:      4,
			HardwareAddress:   hw,
		},
		BackoffStack: backoff,
		TCPPoolConfig: xnet.TCPPoolConfig{
			PoolSize:           4,
			QueueSize:          4,
			TxBufSize:          2048,
			RxBufSize:          512,
			NewBackoff:         func() lneto.BackoffStrategy { return backoff },
			EstablishedTimeout: 5 * time.Second,
			ClosingTimeout:     3 * time.Second,
		},
	}
}

// compile-time interface checks.
var _ lneto.BackoffStrategy = backoff
var _ netdev.Stack = (*xnet.Netstack)(nil)

func backoff(consecutiveBackoffs uint) time.Duration {
	return 5 * time.Millisecond
}

// onLinkChange requests one immediate reconnect when link drops.
func onLinkChange(connected bool) (retries int, reconnectParams ConnectParams) {
	println("link connected:", connected)
	if !connected {
		return 1, wifiParams
	}
	return 0, ConnectParams{}
}

func failIfErr(msg string, err error) {
	if err != nil {
		fail(msg, err)
	}
	println("PASS", msg)
}

func fail(msg string, err error) {
	var errstr string
	if err != nil {
		errstr = err.Error()
	}
	for {
		println("FAIL:", msg, errstr)
		time.Sleep(time.Second)
	}
}
