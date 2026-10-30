//go:build tamago && usbarmory

package main

import (
	_ "github.com/usbarmory/tamago/board/usbarmory/mk2"
	"github.com/usbarmory/tamago/soc/nxp/imx6ul"
)

func newNIC() (nic, [6]byte, error) {
	eth := imx6ul.ENET2
	if !imx6ul.Native {
		eth = imx6ul.ENET1 // QEMU emulates ENET1.
	}
	mac := [6]byte{0x1a, 0x55, 0x89, 0xa2, 0x69, 0x41} // Locally administered.
	eth.MAC = mac[:]
	err := eth.Init()
	if err != nil {
		return nil, mac, err
	}
	eth.Start()
	return eth, mac, nil
}
