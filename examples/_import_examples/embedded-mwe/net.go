package main

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/x/netdev"
	"github.com/soypat/lneto/x/xnet"
)

// compile-time interface checks.
var _ lneto.BackoffStrategy = backoff
var _ netdev.Stack = (*xnet.Netstack)(nil)

func SetupDevice(connParams connectParams) (*xnet.Netstack, *netdev.Runner[ConnectParams], error) {
	// Link: power up chip and join network. Some chips only know their MAC after joining.
	var dev Netdev
	err := dev.Init()
	if err != nil {
		return nil, nil, makeErr("device init", err)
	}
	err = dev.LinkConnect(connParams)
	if err != nil {
		return nil, nil, makeErr("link connect", err)
	}
	hw, err := dev.HardwareAddr6()
	if err != nil {
		return nil, nil, makeErr("hardware addr", err)
	}
	// Stack: protocol state and sockets.
	var stack xnet.Netstack
	err = stack.Reset(stackConfig(hw))
	if err != nil {
		return nil, nil, makeErr("stack reset", err)
	}
	err = stack.EnableICMP(true)
	if err != nil {
		return nil, nil, makeErr("enabling icmp", err)
	}
	// Runner: moves frames between device and stack.
	var iface netdev.Interface[ConnectParams]
	err = iface.Init(&dev, &dev, netdev.InterfaceConfig{})
	if err != nil {
		return nil, nil, makeErr("netdev iface init", err)
	}
	var runner netdev.Runner[ConnectParams]
	err = runner.Configure(netdev.RunnerConfig[ConnectParams]{
		Buffers: iface.RunnerBuffers(2),
		Backoff: backoff,
		Flags:   dev.RunnerFlags(),
	})
	if err != nil {
		return nil, nil, makeErr("netdev runner config", err)
	}
	go func() {
		nfail := 0
		for {
			err = runner.Run(context.Background(), &iface, &stack)
			if err != nil {
				nfail++
				for nfail > 5 {
					println("runner goroutine failed too many times, end net loop:", err.Error())
					time.Sleep(time.Second)
				}
				println("runner goroutine failure:", err.Error())
			}
		}
	}()
	// Application: request address and report runner state.
	assigned, gateway, subnetBits, err := stack.EnableDHCP(context.Background(), true, netip.Addr{})
	if err != nil {
		return nil, nil, makeErr("dhcp enable", err)
	}
	println("assigned", assigned.String(), "gateway", gateway.String(), "subnet", subnetBits)
	return &stack, &runner, nil
}

func backoff(consecutiveBackoffs uint) time.Duration {
	return 5 * time.Millisecond
}

// onLinkChange requests one immediate reconnect when link drops.
func onLinkChange(connected bool) (retries int, reconnectParams ConnectParams) {
	println("link connected:", connected)
	if !connected {
		return 1, connParams
	}
	return 0, ConnectParams{}
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

func makeErr(ctx string, err error) error {
	return errors.New(ctx + ": " + err.Error())
}
