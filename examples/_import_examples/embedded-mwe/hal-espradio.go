//go:build esp32 || esp32c3 || esp32s3

package main

import (
	"github.com/soypat/lneto/x/netdev"
	"tinygo.org/x/espradio"
)

// ESP32 frames are only delivered from inside EthPoll.
const runnerFlags = netdev.RunnerInterfacePoll

type connectParams = espradio.STAConfig

func newConnectParams(ssid, password string) ConnectParams {
	return connectParams{SSID: ssid, Password: password}
}

type device struct {
	link espradio.Link
	nd   *espradio.NetDev // nil until first successful LinkConnect.
}

// Radio Enable+Start is done by first LinkConnect.
func (d *device) init() error {
	d.link.Config = espradio.Config{Logging: espradio.LogLevelError}
	return nil
}

func (d *device) linkConnect(params ConnectParams) error {
	err := d.link.LinkConnect(params)
	if err != nil {
		return err
	}
	d.nd = d.link.NetDev()
	return nil
}

func (d *device) linkDisconnect() {
	d.link.LinkDisconnect()
}

func (d *device) linkNotify(cb netdev.NotifyCallback[ConnectParams]) {
	d.link.LinkNotify(cb)
}

func (d *device) hardwareAddr6() ([6]byte, error) {
	return d.nd.HardwareAddr6()
}

func (d *device) sendOffsetEthFrame(offsetTxEthFrame []byte) error {
	return d.nd.SendOffsetEthFrame(offsetTxEthFrame)
}

func (d *device) setEthRecvHandler(handler func(rxEthframe []byte)) {
	d.nd.SetEthRecvHandler(handler)
}

func (d *device) ethPoll(buf []byte) (ethFrameOff, ethernetBytes int, err error) {
	return d.nd.EthPoll(buf)
}

func (d *device) maxFrameSizeAndOffset() (maxFrameSize int, frameOff int) {
	return d.nd.MaxFrameSizeAndOffset()
}

func entropy(b []byte) (int, error) {
	return readRNG(b)
}
