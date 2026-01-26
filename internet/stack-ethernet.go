package internet

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
)

// StackEthernetConfig contains configuration parameters for [StackEthernet].
type StackEthernetConfig struct {
	// MTU is the Maximum Transmission Unit, representing the maximum ethernet
	// payload size in bytes (excluding the 14-byte ethernet header).
	// Standard ethernet MTU is 1500. Must be between 256 and 65535.
	MTU int
	// MaxNodes is the maximum number of protocol handlers (e.g., IP, ARP)
	// that can be registered with the stack. Must be greater than 0.
	MaxNodes int
	// MAC is the local hardware (MAC) address for this ethernet interface.
	MAC [6]byte
	// Gateway is the hardware (MAC) address of the default gateway.
	// Outgoing frames will be addressed to this MAC.
	Gateway [6]byte
	// AppendCRC32, if true, appends a 32-bit CRC to outgoing frames.
	// Only needed if the PHY does not handle CRC generation.
	AppendCRC32 bool
	// CRC32Update is a IEEE CRC32 implementation that should be provided if AppendCRC32 is set.
	CRC32Update func(crc uint32, p []byte) uint32
}

type StackEthernet struct {
	connID   uint64
	handlers handlers
	mac      [6]byte
	gwmac    [6]byte
	mtu      uint16
	// crcupdate set when crc32 has been configured to be appended.
	crcupdate func(crc uint32, p []byte) uint32
}

func (ls *StackEthernet) SetGateway6(gw [6]byte) {
	ls.gwmac = gw
}

func (ls *StackEthernet) Gateway6() (gw [6]byte) {
	return ls.gwmac
}

func (ls *StackEthernet) SetHardwareAddr6(mac [6]byte) {
	ls.mac = mac
}

func (ls *StackEthernet) HardwareAddr6() [6]byte {
	return ls.mac
}

// Reset6 resets the stack with the given parameters.
//
// Deprecated: Use [StackEthernet.Configure] instead.
func (ls *StackEthernet) Reset6(mac, gateway [6]byte, mtu, maxNodes int) error {
	return ls.Configure(StackEthernetConfig{
		MTU:      mtu,
		MaxNodes: maxNodes,
		MAC:      mac,
		Gateway:  gateway,
	})
}

// Configure resets and configures the ethernet stack with the given configuration.
// It validates the configuration parameters and resets internal state.
// The connection ID is incremented on each call to invalidate existing connections.
func (ls *StackEthernet) Configure(cfg StackEthernetConfig) error {
	if cfg.MTU > (math.MaxUint16-ethernet.MaxOverheadSize) || cfg.MTU < 256 {
		return errors.New("invalid MTU")
	} else if cfg.MaxNodes <= 0 {
		return errZeroMaxNodesArg
	} else if cfg.AppendCRC32 && cfg.CRC32Update == nil {
		return errors.New("need CRC32Update to append ethernet CRC")
	}
	ls.handlers.reset("StackEthernet", cfg.MaxNodes)
	*ls = StackEthernet{
		connID:   ls.connID + 1,
		handlers: ls.handlers,
		mac:      cfg.MAC,
		gwmac:    cfg.Gateway,
		mtu:      uint16(cfg.MTU),
	}
	if cfg.AppendCRC32 {
		ls.crcupdate = cfg.CRC32Update
	}
	return nil
}

func (ls *StackEthernet) MTU() int { return int(ls.mtu) }

func (ls *StackEthernet) ConnectionID() *uint64 { return &ls.connID }

func (ls *StackEthernet) LocalPort() uint16 { return 0 }

func (ls *StackEthernet) Protocol() uint64 { return 1 }

func (ls *StackEthernet) Register(h StackNode) error {
	proto := h.Protocol()
	if proto > math.MaxUint16 || proto <= 1500 {
		return errInvalidProto
	}
	return ls.handlers.registerByProto(nodeFromStackNode(h, 0, proto, nil))
}

func (ls *StackEthernet) Demux(carrierData []byte, frameOffset int) (err error) {
	pkt := carrierData[frameOffset:]
	efrm, err := ethernet.NewFrame(pkt)
	if err != nil {
		return err
	}
	etype := efrm.EtherTypeOrSize()
	dstaddr := efrm.DestinationHardwareAddr()
	var vld lneto.Validator
	if !efrm.IsBroadcast() && ls.mac != *dstaddr {
		goto DROP
	}
	efrm.ValidateSize(&vld)
	if vld.HasError() {
		return vld.ErrPop()
	}
	if h, err := ls.handlers.demuxByProto(efrm.Payload(), 0, uint16(etype)); h != nil {
		return err
	}
DROP:
	ls.handlers.info("LinkStack:drop-packet", slog.String("dsthw", net.HardwareAddr(dstaddr[:]).String()), slog.String("ethertype", efrm.EtherTypeOrSize().String()))
	return lneto.ErrPacketDrop
}

func (ls *StackEthernet) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (n int, err error) {
	mtu := ls.mtu
	dst := carrierData[offsetToFrame:]
	requiredSize := int(mtu) + 14
	if ls.crcupdate != nil {
		requiredSize += 4
	}
	if len(dst) < requiredSize {
		return 0, io.ErrShortBuffer
	}
	efrm, err := ethernet.NewFrame(dst)
	if err != nil {
		return 0, err
	}
	*efrm.DestinationHardwareAddr() = ls.gwmac
	var h *node
	// Children (IP/ARP) start at offset 14 (after ethernet header).
	// For IP: offsetToIP=14, offsetToFrame=14
	// For ARP: offsetToIP=-1, offsetToFrame=14 (but ARP ignores offsetToIP)
	// Clip carrierData to MTU to prevent writes beyond MTU limit.
	payloadOffset := offsetToFrame + 14
	mtuLimit := payloadOffset + int(mtu)
	h, n, err = ls.handlers.encapsulateAny(carrierData[:mtuLimit], payloadOffset, payloadOffset)
	if n == 0 {
		return n, err
	}
	// Found packet
	*efrm.SourceHardwareAddr() = ls.mac
	efrm.SetEtherType(ethernet.Type(h.proto))
	n += 14
	if ls.crcupdate != nil {
		crc := ls.crcupdate(0, carrierData[offsetToFrame:offsetToFrame+n])
		binary.LittleEndian.PutUint32(carrierData[offsetToFrame+n:], crc)
		n += 4
	}
	return n, err
}
