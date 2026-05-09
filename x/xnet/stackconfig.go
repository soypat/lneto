package xnet

import (
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internet"
)

func (cfg StackConfig) ConfigureLink(link *internet.StackEthernet, patchMAC func([]byte)) error {
	if internal.IsZeroed(cfg.GatewayHardwareAddress) {
		cfg.GatewayHardwareAddress = ethernet.BroadcastAddr()
	}
	const linkNodes = 2 // ARP and IP nodes
	ecfg := internet.StackEthernetConfig{
		MTU:         int(cfg.MTU),
		MaxNodes:    linkNodes, // ARP and IP nodes.
		MAC:         cfg.HardwareAddress,
		Gateway:     cfg.GatewayHardwareAddress,
		CRC32Update: cfg.EthernetTxCRC32Update,
		AppendCRC32: cfg.EthernetTxCRC32Update != nil,
	}

	err := link.Configure(ecfg)
	if err != nil {
		return err
	}
	link.SetAcceptMulticast(cfg.AcceptMulticast)
	if cfg.PassivePeers == 0 {
		link.OnEncapsulate(nil)
	} else {
		link.OnEncapsulate(patchMAC)
	}
	return nil
}

func (cfg *StackConfig) ConfigureIP(ip *internet.StackIP) error {
	var ipNodes = 3 // 3 IP protocols possible: UDP, TCP, ICMPv4.
	err := ip.Reset(cfg.StaticAddress4, ipNodes)
	if err != nil {
		return err
	}
	ip.SetAcceptMulticast4(cfg.AcceptMulticast)

	return nil
}
