package netdev

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
)

type Interface[C any] struct {
	dev       DevEthernet
	netlink   Netlink[C]
	ip        netip.Prefix
	frameSize int
	frameOff  int
	mtu       int
	mac       [6]byte
}

// DevEthernet is an L2 capable device HAL. It is an abstraction
// for devices that send actively and are not polled by an external host.
//
// DevEthernet-specific initialization (WiFi join, PHY auto-negotiation,
// firmware loading) must complete BEFORE the device is used as a stack endpoint.
type DevEthernet interface {
	// HardwareAddr6 returns the device's 6-byte MAC address.
	// For PHY-only devices, returns the MAC provided at configuration.
	HardwareAddr6() ([6]byte, error)
	// SendEthFrameOffset transmits a complete Ethernet frame at offset given by [DevEthernet.MaxFrameSizeAndOffset].
	// The frame includes the Ethernet header but NOT the FCS/CRC
	// trailer (device or stack handles CRC as appropriate).
	// SendEthFrameOffset blocks until the transmission is queued succesfully
	// or finished sending. Should not be called concurrently
	// unless user is sure the driver supports it.
	SendOffsetEthFrame(offsetTxEthFrame []byte) error
	// SetRecvHandler registers the function called when an Ethernet
	// frame is received. Buffers needed by the device to operate efficiently
	// should be allocated on its side.
	SetEthRecvHandler(handler func(rxEthframe []byte) error)
	// EthPoll services the device. For poll-based devices (e.g. CYW43439
	// over SPI), reads from the bus and invokes the handler for each
	// received frame. Behaviour for interrupt driven devices is undefined
	// at the moment.
	EthPoll(buf []byte) (ethFrameOff, ethernetBytes int, err error)
	// MaxFrameSizeAndOffset returns the max complete device frame size
	// (including headers and any overhead) for buffer allocation.
	// The second value returned is the offset at which the ethernet frame
	// should be stored when being passed to [DevEthernet.SendOffsetEthFrame].
	// Buffers allocated should be maxEthernetFrameSize+frameOff where maxEthernetFrameSize
	// is usually 1500 but less or equal to maxFrameSize-frameOff.
	// MTU can be calculated doing:
	//  // mfu-(14+4+4) for:
	//  // ethernet header+ethernet CRC if present+ethernet VLAN overhead for VLAN support.
	//  mtu := dev.MaxFrameSizeAndOffset() - ethernet.MaxOverheadSize
	MaxFrameSizeAndOffset() (maxFrameSize int, frameOff int)
}

// Stack is an abstraction for a networking stack.
type Stack interface {
	// Configure configures this Stack with the argument mac, ip and gateway addresses.
	// The Stack must resolve the gateway hardware address if set.
	Configure(mac net.HardwareAddr, ip netip.Prefix, gw netip.Addr) error
	// EnableICMP enables responding/sending ICMP echo frames.
	EnableICMP() error
	// Socket is a berkeley socket abstraction. Returns an [net.Listener] or [net.Conn] depending on laddr/raddr combination.
	Socket(ctx context.Context, network string, family, sotype int, laddr, raddr netip.Addr) (c any, err error)
	// EgressPackets instructs Stack to write outgoing packets into bufs and writing the sizes into sizes.
	// offset can be used to tell the stack to start writing after an offset for each buffer.
	EgressPackets(bufs [][]byte, sizes []int, offset int) error
	// IngressPackets is called on incoming packets so the Stack can direct packets to
	// their respective node/connection and update internal state.
	// offset instructs the Stack to start reading packets at an offset.
	IngressPackets(bufs [][]byte, offset int) error
}

// Netlink represents the physical part of a network device which can connect/disconnect.
// One netlink may correspond to many network devices for interconnected systems.
type Netlink[C any] interface {
	// LinkConnect attempts to connect the Netlink if it was not already connected.
	// It will block until it succeeds/fails and not retry after returning.
	LinkConnect(connectParams C) error
	// LinkDisconnect disconnects the Netlink immediately.
	LinkDisconnect()
	// Link notify sets the callback to be executed after connection state
	// changes for the Netlink. The callback can signal an immediate reconnect is desired
	// by setting reconnectNowRetries to a positive integer. The netlink should then retry connection
	// immediately with the given reconnectParams. reconnectParams should not be nil if reconnectNowRetries is positive.
	LinkNotify(cb func(connected bool) (reconnectNowRetries int, reconnectParams C))
}

// InterfaceConfig mostly optional configuration.
type InterfaceConfig struct {
	// NetworkIP sets the network's IP range and this interface's IP address. See [netip.Prefix].
	// This field is optional if not using a networking stack.
	NetworkIP netip.Prefix
	// HardwareAddr6 overrides the device hardware address during Init.
	// This field is optional if [DevEthernet.HardwareAddr6] returns valid MAC.
	HardwareAddr6 [6]byte
	// MTU is the maximum ethernet payload size. Does not include ethernet header(14b) and FCS(4b).
	// If MTU is zero the default ipv4.MTU value of 1500 is used.
	MTU uint16
}

// Init initializes the interface from scratch with a netlink and device.
func (iface *Interface[C]) Init(netlink Netlink[C], dev DevEthernet, cfg InterfaceConfig) (err error) {
	if netlink == nil || dev == nil {
		return lneto.ErrInvalidConfig
	}
	if internal.IsZeroed(cfg.HardwareAddr6) {
		iface.mac, err = dev.HardwareAddr6()
		if err != nil {
			return err
		} else if internal.IsZeroed(iface.mac) {
			return lneto.ErrInvalidAddr
		}
	} else {
		iface.mac = cfg.HardwareAddr6
	}
	iface.frameSize, iface.frameOff = dev.MaxFrameSizeAndOffset()
	maxEthPayload := iface.frameSize - iface.frameOff
	if cfg.MTU == 0 {
		iface.mtu = min(1500, maxEthPayload)
	} else {
		iface.mtu = int(cfg.MTU)
	}
	if iface.mtu < ethernet.MinimumMTU || iface.mtu > ethernet.MaxMTU {
		return errors.New("bad DevEthernet max frame size and/or frame offset")
	}
	iface.ip = cfg.NetworkIP
	iface.dev = dev
	iface.netlink = netlink
	return nil
}

// HardwareAddr6 returns the hardware address the [Interface] was configured with.
func (iface *Interface[C]) HardwareAddr6() [6]byte {
	return iface.mac
}

// NetworkAddr returns the IP and subnet of the network behind the interface. See [netip.Prefix].
// May be unset/invalid.
func (iface *Interface[C]) NetworkAddr() netip.Prefix {
	return iface.ip
}

func (iface *Interface[C]) bufsize() int {
	return iface.frameOff + 14 + iface.mtu
}

func Run[C any](ctx context.Context, iface Interface[C], stack Stack, backoff lneto.BackoffStrategy, buf []byte) error {
	bufsize := iface.bufsize()
	if len(buf) < bufsize {
		return lneto.ErrShortBuffer
	}

	var handlerTriggered bool
	iface.dev.SetEthRecvHandler(func(rxEthframe []byte) error {
		var bufs [1][]byte = [1][]byte{rxEthframe}
		handlerTriggered = true
		err := stack.IngressPackets(bufs[:], 0)
		if err != nil {
			println("err stack ingress:", err.Error())
		}
		return nil
	})
	buf = buf[:bufsize]
	bufs := [1][]byte{buf}
	var sizes [1]int
	var backoffs uint
	irqDriven := false
	totalRxBytes := 0
	for ctx.Err() == nil {
		_, ethBytes, err := iface.dev.EthPoll(buf)
		totalRxBytes += ethBytes
		if err != nil {
			println("err iface.dev.EthPoll:", err.Error())
		} else if !irqDriven && totalRxBytes == 0 && handlerTriggered {
			irqDriven = true // Packet was processed
			println("driver is IRQ driven")
		}

		sizes[0] = 0
		err = stack.EgressPackets(bufs[:], sizes[:], iface.frameOff)
		sendPkt := sizes[0] > 0
		if sendPkt {
			err = iface.dev.SendOffsetEthFrame(buf)
			if err != nil {
				println("err iface.dev.send:", err.Error())
			}
		}
		if ethBytes == 0 && !sendPkt {
			backoff.Do(backoffs)
			backoffs++
		} else {
			backoffs = 0
		}
	}
	return ctx.Err()
}
