//go:build rp2040 || rp2350

package main

import (
	"machine"
	"time"

	"github.com/soypat/cyw43439"
	"github.com/soypat/lneto/x/netdev"
)

// CYW43439 is pumped by EthPoll but delivers frames to the handler whenever
// the bus is serviced, including ioctl transactions outside EthPoll.
const runnerFlags = netdev.RunnerInterfacePoll | netdev.RunnerInterfaceAsync

type connectParams struct {
	SSID string
	cyw43439.JoinOptions
}

func newConnectParams(ssid, password string) ConnectParams {
	return connectParams{SSID: ssid, JoinOptions: cyw43439.JoinOptions{Passphrase: password}}
}

type device struct {
	cyw *cyw43439.Device
}

func (d *device) init() error {
	d.cyw = cyw43439.NewPicoWDevice()
	return d.cyw.Init(cyw43439.DefaultWifiConfig())
}

func (d *device) linkConnect(params ConnectParams) error {
	return d.cyw.Join(params.SSID, params.JoinOptions)
}

// cyw43439 package does not implement leaving a network nor report link changes.
func (d *device) linkDisconnect()                                    {}
func (d *device) linkNotify(cb netdev.NotifyCallback[ConnectParams]) {}

func (d *device) hardwareAddr6() ([6]byte, error) {
	return d.cyw.HardwareAddr6()
}

func (d *device) sendOffsetEthFrame(offsetTxEthFrame []byte) error {
	return d.cyw.SendEth(offsetTxEthFrame)
}

func (d *device) setEthRecvHandler(handler func(rxEthframe []byte)) {
	d.cyw.RecvEthHandle(handler)
}

// Only pumps the bus: runnerFlags is async so received frames always go to handler.
func (d *device) ethPoll(buf []byte) (ethFrameOff, ethernetBytes int, err error) {
	_, err = d.cyw.PollOne()
	return 0, 0, err
}

func (d *device) maxFrameSizeAndOffset() (maxFrameSize int, frameOff int) {
	return 2048, 0
}

func entropy(b []byte) (int, error) {
	// TODO(soypat): Pico2 does have some PRNG that is better than this...
	for i := range b {
		v, _ := machine.GetRNG() // On RP2040 this is not great, so we take other sources.
		b[i] = uint8(machine.ReadTemperature()) ^ uint8(time.Now().Nanosecond()) ^ uint8(v)
	}
	return len(b), nil
}
