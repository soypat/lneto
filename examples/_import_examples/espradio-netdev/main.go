// Example showing how to use the ESP32 WiFi radio through lneto's netdev
// package. This mirrors the picow-netdev example and demonstrates the
// standardised DevEthernet+Netlink interface that works across hardware targets.
//
// Build and flash:
//
//	tinygo flash -target xiao-esp32c3 \
//	  -ldflags="-X main.ssid=YourSSID -X main.password=YourPassword" \
//	  -monitor ./examples/esp32-netdev
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
	"tinygo.org/x/espradio"
)

var (
	//go:embed wifi.credentials
	credentials string
	// remove windows CRLF "\r\n" and trailing newline.
	credentialsNormalized = strings.TrimSuffix(strings.ReplaceAll(credentials, "\r\n", "\n"), "\n")

	globConnectParams espradio.STAConfig

	poolCfg = xnet.TCPPoolConfig{
		PoolSize:           4,
		QueueSize:          4,
		TxBufSize:          2048,
		RxBufSize:          512,
		NewBackoff:         func() lneto.BackoffStrategy { return backoff },
		NanoTime:           func() int64 { return time.Now().UnixNano() },
		EstablishedTimeout: 5 * time.Second,
		ClosingTimeout:     3 * time.Second,
	}
)

func main() {
	time.Sleep(time.Second)
	ssid, password, ok := strings.Cut(credentialsNormalized, "\n")
	if !ok {
		fail("must write newline separated ssid/password in wifi.credentials", nil)
	}
	globConnectParams.SSID = ssid
	globConnectParams.Password = password
	var dev EspDev
	dev.radioConfig = espradio.Config{Logging: espradio.LogLevelError}

	// LinkConnect runs Enable+Start+Connect+StartNetDev. It must complete
	// before HardwareAddr6 is called because the MAC is only readable after
	// Enable() initialises the WiFi hardware.
	err := dev.LinkConnect(globConnectParams)
	failIfErr("wifi connect", err)

	hw, err := dev.HardwareAddr6()
	failIfErr("hardware addr", err)

	var stack xnet.Netstack
	err = stack.Reset(xnet.StackConfig{
		RandSeed:          time.Now().UnixNano() | 1,
		Hostname:          "esp32-lneto",
		MaxActiveTCPPorts: 4,
		MaxActiveUDPPorts: 4,
		ICMPQueueLimit:    1,
		HardwareAddress:   hw,
	}, backoff, poolCfg)
	failIfErr("stack reset", err)

	dev.LinkNotify(userNotify)
	var iface netdev.Interface[espradio.STAConfig]
	err = iface.Init(&dev, &dev, netdev.InterfaceConfig{})
	failIfErr("init iface", err)

	var runner netdev.Runner[espradio.STAConfig]
	go func() {
		if err := runner.Run(context.Background(), iface, &stack, backoff); err != nil {
			failIfErr("runner", err)
		}
	}()

	assigned, gatewayRt, subnetBits, err := stack.EnableDHCP(context.Background(), true, netip.Addr{})
	failIfErr("enable dhcp", err)
	println("assigned=", assigned.String(), "gateway=", gatewayRt.String(), "subnet=", subnetBits)

	select {}
}

// compile-time interface checks.
var _ lneto.BackoffStrategy = backoff
var _ netdev.Stack = (*xnet.Netstack)(nil)
var _ netdev.DevEthernet = (*EspDev)(nil)
var _ netdev.Netlink[espradio.STAConfig] = (*EspDev)(nil)

func backoff(consecutiveBackoffs uint) time.Duration {
	return 5 * time.Millisecond
}

func userNotify(connected bool) (retries int, reconnectParams espradio.STAConfig) {
	if !connected {
		return 1, globConnectParams
	}
	return 0, espradio.STAConfig{}
}

// EspDev adapts [espradio.NetDev] to [netdev.DevEthernet] and wraps the
// ESP32 WiFi bring-up sequence (Enable/Start/Connect/StartNetDev) as [netdev.Netlink].
//
// The same struct implements both interfaces so a single pointer can be passed
// to [netdev.Interface.Init] for both the netlink and device arguments, matching
// the pattern used by the picow-netdev example.
type EspDev struct {
	nd          *espradio.NetDev
	radioConfig espradio.Config
	notifyCb    netdev.NotifyCallback[espradio.STAConfig]
}

// LinkConnect implements [netdev.Netlink].
// Runs Enable→Start→Connect→StartNetDev. nd is nil until this returns successfully.
func (d *EspDev) LinkConnect(cfg espradio.STAConfig) error {
	if err := espradio.Enable(d.radioConfig); err != nil {
		return err
	}
	if err := espradio.Start(); err != nil {
		return err
	}
	if err := espradio.Connect(cfg); err != nil {
		return err
	}
	nd, err := espradio.StartNetDev()
	if err != nil {
		return err
	}
	d.nd = nd
	return nil
}

// LinkDisconnect implements [netdev.Netlink].
func (d *EspDev) LinkDisconnect() {}

// LinkNotify implements [netdev.Netlink].
func (d *EspDev) LinkNotify(cb netdev.NotifyCallback[espradio.STAConfig]) {
	d.notifyCb = cb
}

// HardwareAddr6 implements [netdev.DevEthernet].
func (d *EspDev) HardwareAddr6() ([6]byte, error) {
	return d.nd.HardwareAddr6()
}

// SendOffsetEthFrame implements [netdev.DevEthernet].
// ESP32 has no frame prefix offset, so buf is passed directly to [espradio.NetDev.SendEthFrame].
func (d *EspDev) SendOffsetEthFrame(buf []byte) error {
	return d.nd.SendEthFrame(buf)
}

// SetEthRecvHandler implements [netdev.DevEthernet].
// Adapts the error-less netdev handler signature to espradio's error-returning one.
func (d *EspDev) SetEthRecvHandler(handler func(rxEthframe []byte)) {
	if handler == nil {
		d.nd.SetEthRecvHandler(nil)
		return
	}
	d.nd.SetEthRecvHandler(func(pkt []byte) error {
		handler(pkt)
		return nil
	})
}

// EthPoll implements [netdev.DevEthernet].
//
// espradio.NetDev.EthPoll both pops a frame from the C ring buffer into buf
// AND synchronously calls the registered rxHandler with that frame. Returning
// the non-zero byte count here as well would trigger the Runner's "device uses
// both paths" guard. We therefore drain the ring (calling the handler) and
// return (0, 0, err) so the Runner sees only the handler-based receive path.
func (d *EspDev) EthPoll(buf []byte) (ethFrameOff, ethernetBytes int, err error) {
	_, err = d.nd.EthPoll(buf)
	return 0, 0, err
}

// MaxFrameSizeAndOffset implements [netdev.DevEthernet].
// ESP32 transmits frames with no prefix offset.
func (d *EspDev) MaxFrameSizeAndOffset() (maxFrameSize int, frameOff int) {
	return d.nd.MaxFrameSize(), 0
}

func failIfErr(msg string, err error) {
	if err != nil {
		fail(msg, err)
	}
	println(msg, "PASS")
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
