package main

import (
	"github.com/soypat/lneto/x/netdev"
)

// Netdev is the board WiFi chip, used as both link and Ethernet device of a [netdev.Interface].
// Each hal-<board>.go file defines device, connectParams, newConnectParams and runnerFlags
// to implement the behavior documented here.
type Netdev struct {
	dev device
}

// ConnectParams are the board link parameters passed to LinkConnect.
type ConnectParams = connectParams

var (
	_ netdev.DevEthernet            = (*Netdev)(nil)
	_ netdev.Netlink[ConnectParams] = (*Netdev)(nil)
)

// NewConnectParams converts WiFi credentials to board link parameters.
func NewConnectParams(ssid, password string) ConnectParams {
	return newConnectParams(ssid, password)
}

// Init powers up the chip so LinkConnect can run. Must be called first.
func (d *Netdev) Init() error {
	return d.dev.init()
}

// RunnerFlags returns how a [netdev.Runner] must drive device reception.
func (d *Netdev) RunnerFlags() netdev.RunnerFlags {
	return runnerFlags
}

// LinkConnect joins the network and blocks until success or failure. It does not retry.
// Ethernet methods are only valid after first successful LinkConnect.
func (d *Netdev) LinkConnect(params ConnectParams) error {
	return d.dev.linkConnect(params)
}

// LinkDisconnect leaves the network. No-op if unsupported by chip.
func (d *Netdev) LinkDisconnect() {
	d.dev.linkDisconnect()
}

// LinkNotify sets callback run on link up/down outside LinkConnect. Never called if chip does not report link changes.
func (d *Netdev) LinkNotify(cb netdev.NotifyCallback[ConnectParams]) {
	d.dev.linkNotify(cb)
}

// HardwareAddr6 returns the chip MAC address.
func (d *Netdev) HardwareAddr6() ([6]byte, error) {
	return d.dev.hardwareAddr6()
}

// SendOffsetEthFrame transmits an Ethernet frame without FCS starting at the offset given by MaxFrameSizeAndOffset.
func (d *Netdev) SendOffsetEthFrame(offsetTxEthFrame []byte) error {
	return d.dev.sendOffsetEthFrame(offsetTxEthFrame)
}

// SetEthRecvHandler sets the callback receiving Ethernet frames. Old handler is not called after return.
func (d *Netdev) SetEthRecvHandler(handler func(rxEthframe []byte)) {
	d.dev.setEthRecvHandler(handler)
}

// EthPoll services the chip once. With no handler set a received frame is written to buf;
// with a handler set buf is nil and frames go to the handler.
func (d *Netdev) EthPoll(buf []byte) (ethFrameOff, ethernetBytes int, err error) {
	return d.dev.ethPoll(buf)
}

// MaxFrameSizeAndOffset returns Rx buffer size and the frame offset expected by SendOffsetEthFrame.
func (d *Netdev) MaxFrameSizeAndOffset() (maxFrameSize int, frameOff int) {
	return d.dev.maxFrameSizeAndOffset()
}

// Entropy reads cryptographically secure randomness into b.
// Some devices have lackluster entropy sources, so mileage may vary.
func Entropy(b []byte) (int, error) {
	return entropy(b)
}
