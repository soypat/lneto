//go:build xnetdebug

package xnet

import "os"

var _pcap CapturePrinter

func init() {
	_pcap.Configure(os.Stdout, CapturePrinterConfig{
		NamespaceWidth: 3,
	})
}

func debugPacket(msg string, b []byte) {
	_pcap.PrintEthernet(msg, b)
}
