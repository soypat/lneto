//go:build tinygo

package internal

import (
	"errors"
	"net"
)

func interfaceByName(name string) (*net.Interface, error) {
	return nil, errors.New("net.InterfaceByName not implemented on TinyGo")
}
