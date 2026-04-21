package xnet

import (
	"context"
	"net/netip"

	"github.com/soypat/lneto/x/netdev"
)

// Netstack is a more modern outward facing API wrapper on StackAsync.
type Netstack struct {
	stack StackAsync
	//gstack references stack above.
	gstack StackGo
}

var _ netdev.Stack = (*Netstack)(nil)

// Configure configures this Stack with the argument mac, ip and gateway addresses.
// The Stack must resolve the gateway hardware address if set.
func (netstack *Netstack) Reset(cfg StackConfig) error {
	err := netstack.stack.Reset(cfg)
	if err != nil {
		return err
	}
	return nil
}

func (netstack *Netstack) IPAddr() netip.Addr {
	return netstack.stack.Addr()
}

// EnableICMP enables responding/sending ICMP echo frames.
func (netstack *Netstack) EnableICMP(enabled bool) error {
	return netstack.stack.EnableICMP(enabled)
}

// EnableDHCP
func (netstack *Netstack) EnableDHCP(enabled bool, requestAddr netip.Addr) (err error) {
	if enabled {
		err = netstack.stack.StartDHCPv4Request(requestAddr.As4())
	} else {
		netstack.stack.dhcp.Reset()
	}
	return err
}

// Socket is a berkeley socket abstraction. Returns an [net.Listener] or [net.Conn] depending on laddr/raddr combination.
func (netstack *Netstack) Socket(ctx context.Context, network string, family, sotype int, laddr, raddr netip.AddrPort) (c any, err error) {
	return netstack.gstack.SocketNetip(ctx, network, family, sotype, laddr, raddr)
}

// EgressPackets instructs Stack to write outgoing packets into bufs and writing the sizes into sizes not including initial offset.
// offset can be used to tell the stack to start writing after an offset for each buffer.
func (netstack *Netstack) EgressPackets(bufs [][]byte, sizes []int, offset int) (err error) {
	var err0 error
	for i := range bufs {
		sizes[i], err0 = netstack.stack.EgressEthernet(bufs[i][offset:])
		if sizes[i] == 0 {
			return err
		} else if err0 != nil {
			err = err0
		}
	}
	return err
}

// IngressPackets is called on incoming packets so the Stack can direct packets to
// their respective node/connection and update internal state.
// offset instructs the Stack to start reading packets at an offset.
func (netstack *Netstack) IngressPackets(bufs [][]byte, offset int) (err error) {
	for _, buf := range bufs {
		err0 := netstack.stack.IngressEthernet(buf[offset:])
		if err0 != nil {
			err = err0
		}
	}
	return err
}
