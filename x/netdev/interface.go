package netdev

import (
	"context"
	"errors"
	"net/netip"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
)

type Interface[C any] struct {
	dev     DevEthernet
	netlink Netlink[C]
	ip      netip.Prefix
	// Below are values calculated from [DevEthernet] return values to avoid recalculation.
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
	// should be allocated on its side. This function is mutually exclusive with EthPoll:
	// use on or the other to receive data.
	SetEthRecvHandler(handler func(rxEthframe []byte))
	// EthPoll services the device. For poll-based devices (e.g. CYW43439
	// over SPI), reads from the bus and invokes the handler for each
	// received frame. This method is mutually exclusive with SetEthRecvHandler:
	// use one or the other to receive data but not return data via both channels.
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
	// Configure(mac net.HardwareAddr, ip netip.Prefix, gw netip.Addr) error

	// EnableICMP enables responding/sending ICMP echo frames.
	EnableICMP(enabled bool) error
	// EnableDHCP enables DHCP on the device if enabled=true and performs a DHCP request.
	EnableDHCP(ctx context.Context, enabled bool, reqIP netip.Addr) (assigned netip.Addr, routerGW netip.Addr, subnetBits int, _ error)
	// Socket is a berkeley socket abstraction. Returns an [net.Listener] or [net.Conn] depending on laddr/raddr combination.
	Socket(ctx context.Context, network string, family, sotype int, laddr, raddr netip.AddrPort) (c any, err error)
	// EgressPackets instructs Stack to write outgoing packets into bufs and writing the sizes into sizes.
	// offset can be used to tell the stack to start writing after an offset for each buffer.
	// The size written into sizes includes only Ethernet frame size and so is independent of offset value.
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
	LinkNotify(cb NotifyCallback[C])
}

// NotifyCallback is a convenience type alias that serves mostly as semantic code documentation.
// NotifyCallback is called when a [Netlink] connects or disconnects from a network. The callback returns:
//   - reconnectNowRetries: Amount of times to attempt reconnection before giving up.
//   - reconnectParams: parameters to use in reconnection.
type NotifyCallback[C any] = func(connected bool) (reconnectNowRetries int, reconnectParams C)

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

// Init initializes the interface from scratch with a netlink and device. If Init fails all methods on Interface are unsafe to call (panic).
func (iface *Interface[C]) Init(netlink Netlink[C], dev DevEthernet, cfg InterfaceConfig) (err error) {
	if netlink == nil || dev == nil {
		return lneto.ErrInvalidConfig
	}
	maxFrameSize, frameOff := dev.MaxFrameSizeAndOffset()
	maxEthFrame := maxFrameSize - frameOff
	maxEthPayload := maxEthFrame - 14
	mtu := int(cfg.MTU)
	if mtu == 0 {
		mtu = min(1500, maxEthPayload)
	}
	if mtu > maxEthPayload {
		return errors.New("MTU exceeds max frame size")
	} else if mtu < ethernet.MinimumMTU || mtu > ethernet.MaxMTU {
		return errors.New("bad DevEthernet max frame size and/or frame offset. typical is 1500,0")
	}
	var mac [6]byte
	if internal.IsZeroed(cfg.HardwareAddr6) {
		mac, err = dev.HardwareAddr6()
		if err != nil {
			return err
		} else if internal.IsZeroed(mac) {
			return lneto.ErrInvalidAddr
		}
	} else {
		mac = cfg.HardwareAddr6
	}
	*iface = Interface[C]{
		dev:       dev,
		netlink:   netlink,
		ip:        cfg.NetworkIP,
		frameSize: maxFrameSize,
		frameOff:  frameOff,
		mtu:       mtu,
		mac:       mac,
	}
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
