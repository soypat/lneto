package main

import (
	"context"
	_ "embed"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/soypat/cyw43439"
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/x/netdev"
	"github.com/soypat/lneto/x/xnet"
)

var (
	//go:embed wifi.credentials
	credentials string
	// remove windows CRLF "\r\n" and trailing newline.
	credentialsNormalized = strings.TrimSuffix(strings.ReplaceAll(credentials, "\r\n", "\n"), "\n")
	globConnectParams     ConnectParams
	poolCfg               = xnet.TCPPoolConfig{
		PoolSize:           5,
		QueueSize:          5,
		TxBufSize:          2048,
		RxBufSize:          2048,
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
	globConnectParams.Passphrase = password

	dev := Netdev{
		dev: cyw43439.NewPicoWDevice(),
	}
	err := dev.dev.Init(cyw43439.DefaultWifiConfig())
	failIfErr("init cyw43439", err)
	hw, _ := dev.HardwareAddr6()
	var stack xnet.Netstack
	err = stack.Reset(xnet.StackConfig{
		RandSeed:          time.Now().UnixNano() | 1,
		Hostname:          "lneto-pico",
		MaxActiveTCPPorts: 4,
		MaxActiveUDPPorts: 4,
		ICMPQueueLimit:    1,
		MTU:               1500,
		HardwareAddress:   hw,
	}, backoff, poolCfg)
	failIfErr("stack reset", err)
	err = stack.EnableICMP(true)
	failIfErr("icmp enable", err)
	err = dev.LinkConnect(globConnectParams)
	failIfErr("wifi join", err)

	var iface netdev.Interface[ConnectParams]
	var runner netdev.Runner[ConnectParams]
	dev.LinkNotify(userNotify)
	err = iface.Init(&dev, &dev, netdev.InterfaceConfig{})
	failIfErr("init iface", err)

	go func() {
		err := runner.Configure(netdev.RunnerConfig[ConnectParams]{
			Buffers: [][]byte{make([]byte, cyw43439.MaxFrameSize)},
			Backoff: backoff,
		})
		if err != nil {
			failIfErr("runnerconfig", err)
		}
		if err := runner.Run(context.Background(), iface, &stack); err != nil {
			failIfErr("runner", err)
		}
	}()
	assigned, gatewayRt, subnetBits, err := stack.EnableDHCP(context.Background(), true, netip.Addr{})
	failIfErr("enable dhcp", err)
	println("assigned=", assigned.String(), "gateway=", gatewayRt.String(), "subnet", subnetBits)
	select {}
}

// compile-time guarantee of interface implementation.
var _ lneto.BackoffStrategy = backoff
var _ netdev.Stack = (*xnet.Netstack)(nil)

func backoff(consecutiveBackoffs uint) (sleepOrFlag time.Duration) {
	return 5 * time.Millisecond
}

func userNotify(connected bool) (retries int, connectParams ConnectParams) {
	if !connected {
		return 1, globConnectParams
	}
	return 0, ConnectParams{}
}

var _ netdev.DevEthernet = (*Netdev)(nil)
var _ netdev.Netlink[ConnectParams] = (*Netdev)(nil)

type Netdev struct {
	dev      *cyw43439.Device
	notifyCb netdev.NotifyCallback[ConnectParams]
}

type ConnectParams struct {
	SSID string
	cyw43439.JoinOptions
}

func (nl *Netdev) Netflags() (flags net.Flags) {
	flags |= net.FlagUp
	if nl.dev.IsLinkUp() {
		flags |= net.FlagRunning
	}
	return flags
}

// LinkConnect implements [netdev.Netlink].
func (nl *Netdev) LinkConnect(connectParams ConnectParams) error {
	return nl.dev.Join(connectParams.SSID, connectParams.JoinOptions)
}

// LinkDisconnect implements [netdev.Netlink].
func (nl *Netdev) LinkDisconnect() {
	// Not implemented by cyw43439 package.
}

// LinkNotify implements [netdev.Netlink].
func (nl *Netdev) LinkNotify(cb netdev.NotifyCallback[ConnectParams]) {
	nl.notifyCb = cb
}

// HardwareAddr6 implements [netdev.DevEthernet].
func (d *Netdev) HardwareAddr6() ([6]byte, error) {
	return d.dev.HardwareAddr6()
}

// SendEthFrameOffset implements [netdev.DevEthernet].
func (d *Netdev) SendOffsetEthFrame(offsetTxEthFrame []byte) error {
	return d.dev.SendEth(offsetTxEthFrame)
}

// SetRecvHandler implements [netdev.DevEthernet].
//
// This device is poll-driven: frames are returned through EthPoll, so the async
// receive handler is unused. EthPoll and SetEthRecvHandler are mutually exclusive.
func (d *Netdev) SetEthRecvHandler(handler func(rxEthframe []byte)) {}

// EthPoll implements [netdev.DevEthernet].
func (d *Netdev) EthPoll(buf []byte) (ethFrameOff, ethernetBytes int, err error) {
	return d.dev.EthPoll(buf)
}

// MaxFrameSizeAndOffset implements [netdev.DevEthernet].
func (d *Netdev) MaxFrameSizeAndOffset() (maxFrameSize int, frameOff int) {
	return cyw43439.MaxFrameSize, 0
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
		println(msg, errstr)
		time.Sleep(time.Second)
	}
}
