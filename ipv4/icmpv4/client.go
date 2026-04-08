package icmpv4

import (
	"slices"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

var _ lneto.StackNode = (*Client)(nil) // Compile-time guarantee of interface implementation.

const (
	keyHashCompletedBit = 1 << 31
	keyHashSentBit      = 1 << 30
	keyHashBits         = (1 << 30) - 1
)

type Client struct {
	connid uint64
	magic  uint32

	outgoingEcho []struct {
		// For every ping we send out stores hashes of the data (should include IP likely).
		pattern []byte
		key     uint32
		size    uint16
		ttl     uint8
	}

	// responseLengths stores the length of responses received.
	// together they should add up to the written length of responseRing.
	incomingEcho []struct {
		length uint16
		id     uint16
		seq    uint16
	}
	responseRing internal.Ring
}

type ClientConfig struct {
	ResponseQueueBuffer []byte
	ResponseQueueLimit  int
	HashSeed            uint32
}

func (client *Client) Configure(cfg ClientConfig) error {
	if cfg.HashSeed == 0 || len(cfg.ResponseQueueBuffer) < 16 || cfg.ResponseQueueLimit <= 0 {
		return lneto.ErrInvalidConfig
	}
	client.connid++
	internal.SliceReuse(&client.outgoingEcho, cfg.ResponseQueueLimit)
	client.responseRing = internal.Ring{Buf: cfg.ResponseQueueBuffer}
	client.magic = cfg.HashSeed
	return nil
}

func (client *Client) Protocol() uint64 { return uint64(lneto.IPProtoICMP) }

func (client *Client) LocalPort() uint16 { return 0 }

func (client *Client) ConnectionID() *uint64 { return &client.connid }

func (client *Client) Demux(carrierData []byte, frameOffset int) error {
	rawdata := carrierData[frameOffset:]
	ifrm, err := NewFrame(rawdata)
	if err != nil {
		return err
	}
	tp := ifrm.Type()
	if tp != TypeEcho && tp != TypeEchoReply {
		return lneto.ErrPacketDrop
	}
	var crc lneto.CRC791
	if crc.PayloadSum16(rawdata) != 0 {
		return lneto.ErrBadCRC
	}
	switch tp {
	case TypeEcho:
		// We received a ping request; not handled client-side.
		efrm := FrameEcho{Frame: ifrm}
		data := efrm.Data()
		n, werr := client.responseRing.Write(data)
		if werr != nil {
			err = werr
			break
		}
		v := internal.SliceReclaim(&client.incomingEcho)
		v.length = uint16(n)
		v.id = efrm.Identifier()
		v.seq = efrm.SequenceNumber()
	case TypeEchoReply:
		efrm := FrameEcho{Frame: ifrm}
		data := efrm.Data()
		hash := client.magichash(data, len(data)) & keyHashBits
		idx := client.pingidx(hash)
		if idx < 0 {
			err = lneto.ErrPacketDrop
			break
		}
		client.outgoingEcho[idx].key |= keyHashCompletedBit

	default:
		err = lneto.ErrPacketDrop
	}
	return err
}

func (client *Client) Encapsulate(carrierData []byte, ipOffset, frameOffset int) (int, error) {
	ifrm, err := NewFrame(carrierData[frameOffset:])
	if err != nil {
		return 0, err
	}

	// Put n bytes of ICMP data.
	var n int
	if len(client.incomingEcho) > 0 {
		// Priority: send echo reply.
		inc := client.incomingEcho[0]
		efrm := FrameEcho{Frame: ifrm}
		efrm.SetType(TypeEchoReply)
		efrm.SetIdentifier(inc.id)
		efrm.SetSequenceNumber(inc.seq)
		dataLen := int(inc.length)
		_, rerr := client.responseRing.Read(efrm.Data()[:dataLen])
		if rerr != nil {
			return 0, rerr
		}
		client.incomingEcho = slices.Delete(client.incomingEcho, 0, 1)
		n = sizeHeader + dataLen

	} else if len(client.outgoingEcho) > 0 {
		idx := 0
		for idx < len(client.outgoingEcho) {
			out := &client.outgoingEcho[idx]
			if out.key&keyHashSentBit == 0 {
				break
			}
			idx++
		}
		if idx >= len(client.outgoingEcho) {
			return 0, nil // No pending to send packet.
		}
		out := &client.outgoingEcho[idx]
		efrm := FrameEcho{Frame: ifrm}
		efrm.SetType(TypeEcho)
		efrm.SetIdentifier(0)
		efrm.SetSequenceNumber(0)
		pattern := out.pattern
		data := efrm.Data()
		size := int(out.size)
		written := 0
		for written+len(pattern) <= size && written+len(pattern) <= len(data) {
			copy(data[written:], pattern)
			written += len(pattern)
		}
		copy(data[written:written+size%len(pattern)], pattern)
		n = sizeHeader + size
	} else {
		return 0, nil
	}
	ifrm.buf = carrierData[frameOffset : frameOffset+n] // Raw buffer set.
	ifrm.SetCode(0)
	ifrm.SetCRC(0)
	var crc lneto.CRC791
	sum := crc.PayloadSum16(carrierData[frameOffset : frameOffset+n])
	ifrm.SetCRC(sum)
	return n, nil
}

func (client *Client) magichash(pattern []byte, size int) (hash uint32) {
	hash = client.magic
	i := 0
	n := len(pattern) / size
	for i < n {
		for _, b := range pattern {
			hash = hash*31 + uint32(b)
		}
		i++
	}
	n = len(pattern) % size
	for i = 0; i < n; i++ {
		hash = hash*31 + uint32(pattern[i])
	}
	return hash
}

func (client *Client) PingStart(pattern []byte, size uint16, ttl uint8) (key uint32, err error) {
	if int(size) < len(pattern) {
		return 0, lneto.ErrInvalidConfig
	}
	key = client.magichash(pattern, int(size)) & keyHashBits
	v := internal.SliceReclaim(&client.outgoingEcho)
	v.key = key
	v.size = size
	v.ttl = ttl
	v.pattern = append(v.pattern[:0], pattern...)
	return key, nil
}

func (client *Client) pingidx(key uint32) int {
	for i := range client.outgoingEcho {
		if client.outgoingEcho[i].key&keyHashBits == key {
			return i
		}
	}
	return -1
}

func (client *Client) PingPeek(key uint32) (completed, ok bool) {
	idx := client.pingidx(key)
	if idx >= 0 {
		return client.outgoingEcho[idx].key&keyHashCompletedBit != 0, true
	}
	return false, false
}

func (client *Client) PingPop(key uint32) (completed, ok bool) {
	idx := client.pingidx(key)
	if idx >= 0 {
		completed := client.outgoingEcho[idx].key&keyHashCompletedBit != 0
		client.outgoingEcho = slices.Delete(client.outgoingEcho, idx, idx+1)
		return completed, true
	}
	return false, false
}
