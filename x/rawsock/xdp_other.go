//go:build tinygo || !linux || !(amd64 || arm64)

package rawsock

import (
	"errors"
	"net/netip"
	"time"
)

// XDP is an AF_XDP socket. Unsupported on this platform.
type XDP struct{}

// Open is unsupported on this platform.
func (x *XDP) Open(cfg XDPConfig) error { return errors.ErrUnsupported }

func (x *XDP) Mode() XDPMode { return XDPModeAuto }
func (x *XDP) Close() error  { return errors.ErrUnsupported }

func (x *XDP) HardwareAddr6() ([6]byte, error)                   { return [6]byte{}, errors.ErrUnsupported }
func (x *XDP) MaxFrameSizeAndOffset() (int, int)                 { return 0, 0 }
func (x *XDP) SendOffsetEthFrame(frame []byte) error             { return errors.ErrUnsupported }
func (x *XDP) SetEthRecvHandler(handler func(rxEthframe []byte)) {}
func (x *XDP) EthPoll(buf []byte) (int, int, error)              { return 0, 0, errors.ErrUnsupported }

func (x *XDP) Read(b []byte) (int, error)               { return 0, errors.ErrUnsupported }
func (x *XDP) Write(b []byte) (int, error)              { return 0, errors.ErrUnsupported }
func (x *XDP) Poll(timeout time.Duration) (bool, error) { return false, errors.ErrUnsupported }
func (x *XDP) HardwareAddress6() ([6]byte, error)       { return [6]byte{}, errors.ErrUnsupported }
func (x *XDP) MTU() (int, error)                        { return 0, errors.ErrUnsupported }
func (x *XDP) IPMask() (netip.Prefix, error)            { return netip.Prefix{}, errors.ErrUnsupported }
