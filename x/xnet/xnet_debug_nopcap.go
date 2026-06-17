//go:build !xnetdebug

package xnet

func debugPacket(msg string, b []byte) {}
