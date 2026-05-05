package icmpv6

import (
	"errors"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

var _ lneto.StackNode = (*NDPHandler)(nil)

const (
	ndpOptSourceLinkAddr = 1 // RFC 4861 §4.6.1
	ndpOptTargetLinkAddr = 2 // RFC 4861 §4.6.2
)

var (
	errNDPQueryPending  = errors.New("icmpv6: NDP query pending")
	errNDPQueryNotFound = errors.New("icmpv6: NDP query not found")
)

// NDPHandler implements Neighbor Discovery Protocol (RFC 4861) for a single
// IPv6 address, resolving IPv6 addresses to link-layer (MAC) addresses via
// Neighbor Solicitation and Neighbor Advertisement exchanges.
type NDPHandler struct {
	connID    uint64
	cache     ndpCache
	ourAddr   [16]byte
	ourMAC    [6]byte
	onresolve func(mac [6]byte, addr [16]byte)
}

type NDPHandlerConfig struct {
	Addr     [16]byte
	MAC      [6]byte
	MaxCache int
}

func (h *NDPHandler) Reset(cfg NDPHandlerConfig) error {
	if cfg.Addr == ([16]byte{}) || cfg.MAC == ([6]byte{}) || cfg.MaxCache <= 0 {
		return lneto.ErrInvalidConfig
	}
	*h = NDPHandler{
		connID:  h.connID + 1,
		cache:   h.cache,
		ourAddr: cfg.Addr,
		ourMAC:  cfg.MAC,
	}
	h.cache.reset(cfg.MaxCache)
	return nil
}

func (h *NDPHandler) LocalPort() uint16   { return 0 }
func (h *NDPHandler) Protocol() uint64    { return uint64(lneto.IPProtoIPv6ICMP) }
func (h *NDPHandler) ConnectionID() *uint64 { return &h.connID }

func (h *NDPHandler) SetOnResolveCallback(cb func(mac [6]byte, addr [16]byte)) {
	h.onresolve = cb
}

func (h *NDPHandler) UpdateAddr(addr [16]byte) { h.ourAddr = addr }

// AbortPending drops pending queries and incoming solicitations.
func (h *NDPHandler) AbortPending() {
	h.cache.clearFlags(ndpFlagPendingResponse|ndpFlagIncomplete, ndpFlagInUse)
}

// CacheSeed pre-populates the cache with a known addr→MAC mapping, making it
// immediately resolvable via [NDPHandler.CacheLookup] without an NDP exchange.
// Seeded entries are evicted before active user queries when the cache is full.
func (h *NDPHandler) CacheSeed(addr [16]byte, mac [6]byte) error {
	if addr == ([16]byte{}) {
		return lneto.ErrZeroDestination
	}
	e := h.cache.acquireNext()
	e.use(mac, addr, 0)
	return nil
}

// CacheLookup returns the MAC for addr if resolved.
// Returns [errNDPQueryPending] if a solicitation is in flight, [errNDPQueryNotFound] if no entry exists.
func (h *NDPHandler) CacheLookup(addr [16]byte) ([6]byte, error) {
	e := h.cache.Lookup(addr)
	if e == nil {
		return [6]byte{}, errNDPQueryNotFound
	} else if e.flags.hasAny(ndpFlagIncomplete) {
		return [6]byte{}, errNDPQueryPending
	}
	return e.mac, nil
}

// CacheRemove cancels a pending query or evicts a resolved entry for addr.
func (h *NDPHandler) CacheRemove(addr [16]byte) error {
	e := h.cache.Lookup(addr)
	if e == nil {
		return errNDPQueryNotFound
	}
	e.destroy()
	return nil
}

// StartQuery queues a Neighbor Solicitation to resolve addr to a MAC address.
// Use [NDPHandler.SetOnResolveCallback] to be notified asynchronously on resolution.
func (h *NDPHandler) StartQuery(addr [16]byte, triggerCallback bool) error {
	if addr == ([16]byte{}) {
		return lneto.ErrZeroDestination
	}
	e := h.cache.acquireNext()
	e.use([6]byte{}, addr, ndpFlagIncomplete|ndpFlagIncompletePendingQuery|ndpFlagPriority)
	if triggerCallback {
		e.flags |= ndpFlagResolveTriggersCallback
	}
	return nil
}

func (h *NDPHandler) Demux(carrierData []byte, frameOffset int) error {
	rawdata := carrierData[frameOffset:]
	if len(rawdata) < sizeNDPBase {
		return lneto.ErrTruncatedFrame
	}
	ifrm, err := NewFrame(rawdata)
	if err != nil {
		return err
	}
	tp := ifrm.Type()
	if tp != TypeNeighborSolicitation && tp != TypeNeighborAdvertisement {
		return lneto.ErrPacketDrop
	}
	ipEnabled := frameOffset >= 40
	var crc lneto.CRC791
	if ipEnabled {
		crc.WriteEven(carrierData[8:40]) // IPv6 src(16B) + dst(16B) pseudo-header
		crc.AddUint32(uint32(len(rawdata)))
		crc.AddUint32(uint32(lneto.IPProtoIPv6ICMP))
	}
	if crc.PayloadSum16(rawdata) != 0 {
		return lneto.ErrBadCRC
	}
	targetAddr := (*[16]byte)(rawdata[8:24])
	options := rawdata[24:]
	switch tp {
	case TypeNeighborSolicitation:
		if *targetAddr != h.ourAddr {
			return nil // Not for us.
		}
		mac, ok := parseLinkLayerOption(options, ndpOptSourceLinkAddr)
		if !ok {
			return lneto.ErrPacketDrop
		}
		var senderAddr [16]byte
		if ipEnabled {
			copy(senderAddr[:], carrierData[8:24]) // IPv6 source address
		}
		e := h.cache.acquireNext()
		e.use(mac, senderAddr, ndpFlagPendingResponse)

	case TypeNeighborAdvertisement:
		mac, ok := parseLinkLayerOption(options, ndpOptTargetLinkAddr)
		if !ok {
			return lneto.ErrPacketDrop
		}
		e := h.cache.Lookup(*targetAddr)
		if e == nil {
			return nil // Unsolicited or already evicted.
		}
		e.mac = mac
		e.flags &^= ndpFlagIncomplete | ndpFlagIncompletePendingQuery
		if e.flags.hasAny(ndpFlagResolveTriggersCallback) && h.onresolve != nil {
			h.onresolve(mac, *targetAddr)
		}
	}
	return nil
}

func (h *NDPHandler) Encapsulate(carrierData []byte, ipOffset, frameOffset int) (int, error) {
	buf := carrierData[frameOffset:]
	if len(buf) < sizeNDP {
		return 0, lneto.ErrShortBuffer
	}
	tp := TypeNeighborAdvertisement
	e := h.cache.getNextFlagged(ndpFlagPendingResponse) // Prioritize responses.
	if e == nil {
		e = h.cache.getNextFlagged(ndpFlagIncompletePendingQuery)
		if e == nil {
			return 0, nil
		}
		e.flags &^= ndpFlagIncompletePendingQuery
		tp = TypeNeighborSolicitation
	} else {
		e.flags &^= ndpFlagPendingResponse
	}
	n, err := e.put(buf, h.ourAddr, h.ourMAC, tp)
	if err != nil {
		return 0, err
	}
	ifrm, _ := NewFrame(buf)
	ifrm.SetCRC(0)
	if ipOffset >= 0 {
		var dst [16]byte
		switch tp {
		case TypeNeighborSolicitation:
			dst = solicitedNodeMulticast(e.addr)
		case TypeNeighborAdvertisement:
			dst = e.addr // unicast back to the node that solicited us
		}
		if err = internal.SetIPAddrs(carrierData[ipOffset:], 0, nil, dst[:]); err != nil {
			return 0, err
		}
		var crc lneto.CRC791
		crc.WriteEven(carrierData[ipOffset+8 : ipOffset+40])
		crc.AddUint32(uint32(n))
		crc.AddUint32(uint32(lneto.IPProtoIPv6ICMP))
		ifrm.SetCRC(crc.PayloadSum16(carrierData[frameOffset : frameOffset+n]))
	} else {
		var crc lneto.CRC791
		ifrm.SetCRC(crc.PayloadSum16(carrierData[frameOffset : frameOffset+n]))
	}
	return n, nil
}

// solicitedNodeMulticast returns the solicited-node multicast address for addr (RFC 4291 §2.7.1).
func solicitedNodeMulticast(addr [16]byte) [16]byte {
	return [16]byte{
		0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff,
		addr[13], addr[14], addr[15],
	}
}

// parseLinkLayerOption scans NDP options for the first option of optType
// and returns the embedded 6-byte Ethernet address.
func parseLinkLayerOption(options []byte, optType byte) ([6]byte, bool) {
	for len(options) >= sizeNDPOption {
		t := options[0]
		l := int(options[1]) * 8
		if l == 0 || l > len(options) {
			break
		}
		if t == optType && l >= sizeNDPOption {
			return [6]byte(options[2:8]), true
		}
		options = options[l:]
	}
	return [6]byte{}, false
}
