package icmpv6

import (
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

var _ lneto.StackNode = (*Client)(nil)

const (
	keyHashCompletedBit = 1 << 31
	keyHashSentBit      = 1 << 30
	keyHashBits         = (1 << 30) - 1
)

type ClientConfig struct {
	// Echo (ping) fields.
	ResponseQueueBuffer []byte
	ResponseQueueLimit  int
	HashSeed            uint32
	ID                  uint16
	// NDP fields; NDP is disabled when NDPCache == 0.
	OurAddr  [16]byte
	OurMAC   [6]byte
	NDPCache int
}

type Client struct {
	connid uint64
	magic  uint32
	_seq   uint16
	id     uint16

	outgoingEcho []struct {
		pattern []byte
		key     uint32
		size    uint16
		raddr   [16]byte
	}

	// responseLengths stores the length of responses received.
	// together they should add up to the written length of responseRing.
	incomingEcho []struct {
		length uint16
		id     uint16
		seq    uint16
		raddr  [16]byte
	}
	responseRing internal.Ring

	// NDP address resolution fields.
	ndpCache  ndpCache
	onresolve func(mac [6]byte, addr [16]byte)
	ourMAC    [6]byte
	ourIP     [16]byte
}

func (client *Client) Configure(cfg ClientConfig) error {
	echoOK := cfg.HashSeed != 0 && len(cfg.ResponseQueueBuffer) >= 16 && cfg.ResponseQueueLimit > 0
	ndpOK := cfg.NDPCache > 0
	if !echoOK && !ndpOK {
		return lneto.ErrInvalidConfig
	}
	client.connid++
	if echoOK {
		internal.SliceReuse(&client.outgoingEcho, cfg.ResponseQueueLimit)
		internal.SliceReuse(&client.incomingEcho, cfg.ResponseQueueLimit)
		client.responseRing = internal.Ring{Buf: cfg.ResponseQueueBuffer}
		client.magic = cfg.HashSeed
		client.id = cfg.ID
	}
	if ndpOK {
		client.ourIP = cfg.OurAddr
		client.ourMAC = cfg.OurMAC
		client.ndpCache.reset(cfg.NDPCache)
	}
	return nil
}

func (client *Client) Protocol() uint64    { return uint64(lneto.IPProtoIPv6ICMP) }
func (client *Client) LocalPort() uint16   { return 0 }
func (client *Client) ConnectionID() *uint64 { return &client.connid }

func (client *Client) Abort() {
	client.Reset()
	client.connid++
}

func (client *Client) Reset() {
	client.incomingEcho = client.incomingEcho[:0]
	client.outgoingEcho = client.outgoingEcho[:0]
	client.responseRing.Reset()
}

func (client *Client) Demux(carrierData []byte, frameOffset int) error {
	rawdata := carrierData[frameOffset:]
	ifrm, err := NewFrame(rawdata)
	if err != nil {
		return err
	}
	tp := ifrm.Type()
	ipEnabled := frameOffset >= 40
	var crc lneto.CRC791
	if ipEnabled {
		crc.WriteEven(carrierData[8:40]) // IPv6 src(16B)+dst(16B) pseudo-header
		crc.AddUint32(uint32(len(rawdata)))
		crc.AddUint32(uint32(lneto.IPProtoIPv6ICMP))
	}
	if crc.PayloadSum16(rawdata) != 0 {
		return lneto.ErrBadCRC
	}
	switch tp {
	case TypeEchoRequest, TypeEchoReply:
		return client.demuxEcho(carrierData, frameOffset)
	case TypeNeighborSolicitation, TypeNeighborAdvertisement:
		return client.demuxNDP(carrierData, frameOffset)
	default:
		return lneto.ErrPacketDrop
	}
}

func (client *Client) Encapsulate(carrierData []byte, ipOffset, frameOffset int) (int, error) {
	n, dst, err := client.encapsEcho(carrierData, frameOffset)
	if n == 0 && err == nil {
		n, dst, err = client.encapsNDP(carrierData, frameOffset)
	}
	if n == 0 || err != nil {
		return n, err
	}
	ifrm, _ := NewFrame(carrierData[frameOffset : frameOffset+n])
	ifrm.SetCRC(0)
	if ipOffset >= 0 {
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

// NDP public API — mirrors NDPHandler but on the unified Client.

func (client *Client) SetNDPResolveCallback(cb func(mac [6]byte, addr [16]byte)) {
	client.onresolve = cb
}

func (client *Client) NDPStartQuery(addr [16]byte, triggerCallback bool) error {
	if addr == ([16]byte{}) {
		return lneto.ErrZeroDestination
	}
	e := client.ndpCache.acquireNext()
	e.use([6]byte{}, addr, ndpFlagIncomplete|ndpFlagIncompletePendingQuery|ndpFlagPriority)
	if triggerCallback {
		e.flags |= ndpFlagResolveTriggersCallback
	}
	return nil
}

func (client *Client) NDPCacheLookup(addr [16]byte) ([6]byte, error) {
	e := client.ndpCache.Lookup(addr)
	if e == nil {
		return [6]byte{}, errNDPQueryNotFound
	} else if e.flags.hasAny(ndpFlagIncomplete) {
		return [6]byte{}, errNDPQueryPending
	}
	return e.mac, nil
}

func (client *Client) NDPCacheSeed(addr [16]byte, mac [6]byte) error {
	if addr == ([16]byte{}) {
		return lneto.ErrZeroDestination
	}
	e := client.ndpCache.acquireNext()
	e.use(mac, addr, 0)
	return nil
}

func (client *Client) NDPCacheRemove(addr [16]byte) error {
	e := client.ndpCache.Lookup(addr)
	if e == nil {
		return errNDPQueryNotFound
	}
	e.destroy()
	return nil
}
