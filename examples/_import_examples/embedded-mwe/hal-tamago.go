//go:build tamago

package main

import (
	csrng "crypto/rand"

	"github.com/soypat/lneto/x/netdev"
)

// Runner pops frames from NIC descriptor ring in EthPoll, no IRQ handler wiring.
const runnerFlags = netdev.RunnerInterfacePoll

// Wired NICs have no association step, WiFi credentials are ignored.
type connectParams struct{}

func newConnectParams(ssid, password string) ConnectParams {
	return connectParams{}
}

// nic is implemented by TamaGo NIC drivers, i.e: *enet.ENET and *virtio.Net.
// newNIC is defined in hal-tamago-<board>.go.
type nic interface {
	Receive(buf []byte) (n int, err error)
	Transmit(buf []byte) error
}

type device struct {
	nic nic
	mac [6]byte
}

func (d *device) init() (err error) {
	d.nic, d.mac, err = newNIC()
	return err
}

func (d *device) linkConnect(params ConnectParams) error { return nil }

func (d *device) linkDisconnect() {}

func (d *device) linkNotify(cb netdev.NotifyCallback[ConnectParams]) {}

func (d *device) hardwareAddr6() ([6]byte, error) { return d.mac, nil }

func (d *device) sendOffsetEthFrame(offsetTxEthFrame []byte) error {
	return d.nic.Transmit(offsetTxEthFrame)
}

// Poll-only runnerFlags: Runner never installs a handler.
func (d *device) setEthRecvHandler(handler func(rxEthframe []byte)) {}

func (d *device) ethPoll(buf []byte) (ethFrameOff, ethernetBytes int, err error) {
	n, err := d.nic.Receive(buf)
	return 0, n, err
}

// MTU 1500 plus Ethernet header, VLAN tag and FCS.
func (d *device) maxFrameSizeAndOffset() (maxFrameSize int, frameOff int) {
	return 1500 + 18, 0
}

// crypto/rand is backed by SoC RNG (i.e: i.MX6 RNGB/DCP/CAAM, RDRAND) set up by board package.
func entropy(b []byte) (int, error) {
	return csrng.Read(b)
}
