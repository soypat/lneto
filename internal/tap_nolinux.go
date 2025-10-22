//go:build !linux || tinygo

package internal

import (
	"errors"
	"net/netip"
)

type Tap struct {
}

func NewTap(name string, ip netip.Prefix) (*Tap, error) {
	return nil, errors.ErrUnsupported
}

func (tap *Tap) IPMask() (netip.Prefix, error) {
	return netip.Prefix{}, errors.ErrUnsupported
}
func (tap *Tap) Read(b []byte) (int, error) {
	return -1, errors.ErrUnsupported
}
func (tap *Tap) Write(b []byte) (int, error) {
	return -1, errors.ErrUnsupported
}
func (tap *Tap) Close() error {
	return errors.ErrUnsupported
}
func (tap *Tap) MTU() (int, error) {
	return -1, errors.ErrUnsupported
}
func (tap *Tap) HardwareAddress6() (hw [6]byte, err error) {
	return hw, errors.ErrUnsupported
}

type Bridge struct {
}

func NewBridge(name string) (*Bridge, error) {
	return nil, errors.ErrUnsupported
}
func (br *Bridge) Write(frame []byte) (int, error) {
	return -1, errors.ErrUnsupported
}
func (br *Bridge) Read(frame []byte) (int, error) {
	return -1, errors.ErrUnsupported
}
func (br *Bridge) Close() error {
	return errors.ErrUnsupported
}
func (tap *Bridge) MTU() (int, error) {
	return -1, errors.ErrUnsupported
}
func (tap *Bridge) HardwareAddress6() (hw [6]byte, err error) {
	return hw, errors.ErrUnsupported
}

func (br *Bridge) SetHardwareAddress6(hw [6]byte) error {
	return errors.ErrUnsupported
}

func (br *Bridge) IPMask() (netip.Prefix, error) {
	return netip.Prefix{}, errors.ErrUnsupported
}

func (br *Bridge) Addr() (netip.Addr, error) {
	return netip.Addr{}, errors.ErrUnsupported
}
