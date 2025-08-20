//go:build !tinygo

package internal

import "net"

func interfaceByName(name string) (*net.Interface, error) {
	return net.InterfaceByName(name)
}
