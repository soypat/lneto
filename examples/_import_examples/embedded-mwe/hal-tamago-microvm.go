//go:build tamago && microvm

package main

import (
	vnet "github.com/usbarmory/go-net/virtio"
	"github.com/usbarmory/tamago/board/qemu/microvm"
	"github.com/usbarmory/tamago/kvm/virtio"
)

func newNIC() (nic, [6]byte, error) {
	dev := &vnet.Net{
		Transport:    &virtio.MMIO{Base: microvm.VIRTIO_NET0_BASE},
		IRQ:          microvm.VIRTIO_NET0_IRQ,
		HeaderLength: 10, // QEMU omits num_buffers field.
		MTU:          1500,
	}
	err := dev.Init()
	if err != nil {
		return nil, [6]byte{}, err
	}
	dev.Start()
	return dev, dev.Config().MAC, nil
}
