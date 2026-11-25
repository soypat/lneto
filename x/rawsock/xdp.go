package rawsock

import "errors"

// XDPMode is how an [XDP] socket attaches to its interface.
type XDPMode uint8

const (
	// XDPModeAuto picks the fastest mode the driver supports: zero-copy, then
	// driver copy, then generic.
	XDPModeAuto XDPMode = iota
	// XDPModeZeroCopy attaches in the driver and shares UMEM with the NIC.
	// Open fails if the driver does not support it.
	XDPModeZeroCopy
	// XDPModeDriver attaches in the driver and copies frames to and from UMEM.
	XDPModeDriver
	// XDPModeGeneric attaches after the kernel allocates an skb and copies
	// frames. Works on any interface. Turn GRO off on the interface: frames
	// it merges past the UMEM frame size are dropped.
	XDPModeGeneric
)

// String returns the mode name.
func (m XDPMode) String() string {
	switch m {
	case XDPModeAuto:
		return "auto"
	case XDPModeZeroCopy:
		return "zerocopy"
	case XDPModeDriver:
		return "driver"
	case XDPModeGeneric:
		return "generic"
	}
	return "unknown"
}

// XDPConfig configures an [XDP] socket. Used in [XDP.Open].
type XDPConfig struct {
	// Interface is the name of the NIC to attach to, e.g. "eth0". Required.
	Interface string
	// Queue is the NIC receive queue the socket binds to. Frames on other
	// queues reach the kernel as usual.
	Queue uint32
	// NumFrames is the number of UMEM frames, a power of two. Half receive,
	// half transmit. Zero means 4096.
	NumFrames uint32
	// FrameSize is the UMEM frame size, 2048 or 4096. Zero means 2048.
	FrameSize uint32
	// Mode selects how the socket attaches. Zero is [XDPModeAuto].
	Mode XDPMode
}

func (cfg XDPConfig) withDefaults() (XDPConfig, error) {
	if cfg.NumFrames == 0 {
		cfg.NumFrames = 4096
	}
	if cfg.FrameSize == 0 {
		cfg.FrameSize = 2048
	}
	switch {
	case cfg.Interface == "":
		return cfg, errors.New("xdp: missing interface")
	case cfg.NumFrames < 2 || cfg.NumFrames&(cfg.NumFrames-1) != 0:
		return cfg, errors.New("xdp: NumFrames must be a power of two")
	case cfg.FrameSize != 2048 && cfg.FrameSize != 4096:
		return cfg, errors.New("xdp: FrameSize must be 2048 or 4096")
	case cfg.Mode > XDPModeGeneric:
		return cfg, errors.New("xdp: invalid mode")
	}
	return cfg, nil
}
