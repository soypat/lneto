package main

import (
	"errors"
	"io"

	"github.com/soypat/lneto"
)

func main() {

}

type LinkStack struct {
	mac [6]byte
	mtu uint16
}

func (ls *LinkStack) RecvEth(ethFrame []byte) (err error) {
	eframe, err := lneto.NewEthFrame(ethFrame)
	if err != nil {
		return err
	}
	if !eframe.IsBroadcast() && ls.mac != *eframe.DestinationHardwareAddr() {
		return errors.New("packet MAC mismatch")
	}

	// Convert to dynamic handling.
	etype := eframe.EtherTypeOrSize()
	if etype != lneto.EtherTypeARP && etype != lneto.EtherTypeIPv4 && etype != lneto.EtherTypeIPv6 {
		return nil
	}

	return nil
}

func (ls *LinkStack) HandleEth(dst []byte) (n int, err error) {
	if len(dst) < int(ls.mtu) {
		return 0, io.ErrShortBuffer
	}
	n, addr, etype, err := ls.handleUpper(dst[14:])
	if err != nil || n == 0 {
		return 0, err
	}
	eframe, _ := lneto.NewEthFrame(dst[:14])
	*eframe.DestinationHardwareAddr() = addr
	*eframe.SourceHardwareAddr() = ls.mac
	eframe.SetEtherType(etype)
	return 14 + n, nil
}

func (ls *LinkStack) handleUpper(dst []byte) (n int, dstAddr [6]byte, etype lneto.EtherType, err error) {
	return
}

type IPv4Stack struct {
	ip        [4]byte
	mtu       uint16
	validator lneto.Validator
}

func (is *IPv4Stack) Recv(ipframe []byte) error {
	iframe, err := lneto.NewIPv4Frame(ipframe)
	if err != nil {
		return err
	}
	if *iframe.DestinationAddr() != is.ip {
		return errors.New("packet not for us")
	}
	iframe.Validate(&is.validator)
	err = is.validator.Err()
	if err != nil {
		return err
	}
	return nil

}
