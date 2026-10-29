//go:build linux && !baremetal

package main

import (
	csrng "crypto/rand"

	"github.com/soypat/lneto/x/netdev"
)

// TODO(soypat): add after adding AF_XDP.
const runnerFlags netdev.RunnerFlags = 0

type connectParams struct{}

func newConnectParams(ssid, password string) ConnectParams {
	return connectParams{}
}

type device struct{}

func (d *device) init() error { return nil }

func (d *device) linkConnect(params ConnectParams) error { return nil }

func (d *device) linkDisconnect() {}

func (d *device) linkNotify(cb netdev.NotifyCallback[ConnectParams]) {}

func (d *device) hardwareAddr6() ([6]byte, error) { return [6]byte{}, nil }

func (d *device) sendOffsetEthFrame(offsetTxEthFrame []byte) error { return nil }

func (d *device) setEthRecvHandler(handler func(rxEthframe []byte)) {}

func (d *device) ethPoll(buf []byte) (ethFrameOff, ethernetBytes int, err error) {
	return 0, 0, nil
}

func (d *device) maxFrameSizeAndOffset() (maxFrameSize int, frameOff int) { return 0, 0 }

func entropy(b []byte) (int, error) {
	return csrng.Read(b)
}
