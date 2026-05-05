package icmpv6

import (
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

var _ lneto.StackNode = (*Client)(nil) // Compile-time guarantee of interface implementation.

const (
	keyHashCompletedBit = 1 << 31
	keyHashSentBit      = 1 << 30
	keyHashBits         = (1 << 30) - 1
)

type ClientConfig struct {
	ResponseQueueBuffer []byte
	ResponseQueueLimit  int
	HashSeed            uint32
	// ID is used for Echo (ping) ID field setting.
	ID uint16
}

type Client struct {
	connid uint64
	magic  uint32
	_seq   uint16
	id     uint16

	// Echo(Ping) fields:

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

	// NDP Address resolution fields:

	ndpCache  ndpCache
	onresolve func(mac [6]byte, addr [16]byte)
	ourMAC    [6]byte
	ourIP     [16]byte
}

func (client *Client) Configure(cfg ClientConfig) error {
	if cfg.HashSeed == 0 || len(cfg.ResponseQueueBuffer) < 16 || cfg.ResponseQueueLimit <= 0 {
		return lneto.ErrInvalidConfig
	}
	client.connid++
	internal.SliceReuse(&client.outgoingEcho, cfg.ResponseQueueLimit)
	internal.SliceReuse(&client.incomingEcho, cfg.ResponseQueueLimit)
	client.responseRing = internal.Ring{Buf: cfg.ResponseQueueBuffer}
	client.magic = cfg.HashSeed
	client.id = cfg.ID
	return nil
}

func (client *Client) Protocol() uint64 { return uint64(lneto.IPProtoIPv6ICMP) }

func (client *Client) LocalPort() uint16 { return 0 }

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

func (client *Client) seq() uint16 {
	client._seq++
	return client._seq
}

func (client *Client) Demux(carrierData []byte, frameOffset int) (err error) {
	frm, err := NewFrame(carrierData[frameOffset:])
	if err != nil {
		return err
	}
	tp := frm.Type()
	// Can CRC be calculated here?
	switch tp {
	case TypeEchoReply, TypeEchoRequest:
		err = client.demuxEcho(carrierData, frameOffset)
	case TypeNeighborSolicitation, TypeNeighborAdvertisement:
	default:
		err = lneto.ErrUnsupported
	}
	return err
}

func (client *Client) Encapsulate(carrierData []byte, ipOffset, frameOffset int) (n int, err error) {
	// Switch statement to prioritize outgoing packet types over others.
	switch {
	case len(client.incomingEcho) > 0:
		fallthrough
	case len(client.outgoingEcho) > 0:
		n, err = client.encapsEcho(carrierData, ipOffset, frameOffset)
	}
	return 0, nil
}
