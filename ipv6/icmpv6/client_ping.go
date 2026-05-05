package icmpv6

import (
	"slices"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

func (client *Client) PingIncomingCapacity() int {
	return cap(client.incomingEcho)
}

func (client *Client) PingStart(remoteAddr [16]byte, pattern []byte, size uint16) (key uint32, err error) {
	if int(size) < len(pattern) || len(pattern) == 0 {
		return 0, lneto.ErrInvalidConfig
	} else if remoteAddr == [16]byte{} {
		return 0, lneto.ErrZeroDestination
	}
	free := cap(client.outgoingEcho) - len(client.outgoingEcho)
	if free == 0 {
		return 0, lneto.ErrExhausted
	}
	key = client.magichash(pattern, int(size)) & keyHashBits
	v := internal.SliceReclaim(&client.outgoingEcho)
	v.key = key
	v.size = size
	v.pattern = append(v.pattern[:0], pattern...)
	v.raddr = remoteAddr
	return key, nil
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

func (client *Client) pingidx(key uint32) int {
	for i := range client.outgoingEcho {
		if client.outgoingEcho[i].key&keyHashBits == key {
			return i
		}
	}
	return -1
}

func (client *Client) seq() uint16 {
	client._seq++
	return client._seq
}

func (client *Client) magichash(pattern []byte, size int) (hash uint32) {
	hash = client.magic
	i := 0
	n := size / len(pattern)
	for i < n {
		for _, b := range pattern {
			hash = hash*31 + uint32(b)
		}
		i++
	}
	n = size % len(pattern)
	for i = 0; i < n; i++ {
		hash = hash*31 + uint32(pattern[i])
	}
	return hash
}

// demuxEcho handles TypeEchoRequest and TypeEchoReply frames.
// CRC has already been verified by the caller (Client.Demux).
func (client *Client) demuxEcho(carrierData []byte, frameOffset int) error {
	rawdata := carrierData[frameOffset:]
	ifrm, _ := NewFrame(rawdata) // already validated by Demux
	tp := ifrm.Type()
	ipEnabled := frameOffset >= 40
	var raddr [16]byte
	if ipEnabled {
		src, _, _, _, _ := internal.GetIPAddr(carrierData)
		if len(src) == 16 {
			raddr = [16]byte(src)
		}
	}
	var err error
	switch tp {
	case TypeEchoRequest:
		free := cap(client.incomingEcho) - len(client.incomingEcho)
		if free == 0 {
			return lneto.ErrExhausted
		}
		efrm := FrameEcho{Frame: ifrm}
		data := efrm.Data()
		if len(data) == 0 {
			return lneto.ErrPacketDrop
		}
		n, werr := client.responseRing.Write(data)
		if werr != nil {
			err = werr
			break
		}
		v := internal.SliceReclaim(&client.incomingEcho)
		v.length = uint16(n)
		v.id = efrm.Identifier()
		v.seq = efrm.SequenceNumber()
		v.raddr = raddr

	case TypeEchoReply:
		efrm := FrameEcho{Frame: ifrm}
		data := efrm.Data()
		if len(data) == 0 {
			return lneto.ErrPacketDrop
		}
		hash := client.magichash(data, len(data)) & keyHashBits
		idx := client.pingidx(hash)
		if idx < 0 || (ipEnabled && client.outgoingEcho[idx].raddr != raddr) {
			err = lneto.ErrPacketDrop
			break
		}
		client.outgoingEcho[idx].key |= keyHashCompletedBit

	default:
		err = lneto.ErrPacketDrop
	}
	return err
}

// encapsEcho writes an echo reply or request frame into carrierData[frameOffset:].
// CRC and SetIPAddrs are handled by the caller (Client.Encapsulate).
func (client *Client) encapsEcho(carrierData []byte, frameOffset int) (n int, dst [16]byte, err error) {
	if len(client.incomingEcho) == 0 && len(client.outgoingEcho) == 0 {
		return 0, [16]byte{}, nil
	}
	ifrm, err := NewFrame(carrierData[frameOffset:])
	if err != nil {
		return 0, [16]byte{}, err
	}
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
			return 0, [16]byte{}, rerr
		}
		client.incomingEcho = slices.Delete(client.incomingEcho, 0, 1)
		n = sizeHeader + dataLen
		dst = inc.raddr
	} else {
		idx := 0
		for idx < len(client.outgoingEcho) && client.outgoingEcho[idx].key&keyHashSentBit != 0 {
			idx++
		}
		if idx >= len(client.outgoingEcho) {
			return 0, [16]byte{}, nil // No pending packet to send.
		}
		out := &client.outgoingEcho[idx]
		efrm := FrameEcho{Frame: ifrm}
		efrm.SetType(TypeEchoRequest)
		efrm.SetIdentifier(client.id)
		efrm.SetSequenceNumber(client.seq())
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
		out.key |= keyHashSentBit
		dst = out.raddr
	}
	ifrm.buf = carrierData[frameOffset : frameOffset+n]
	ifrm.SetCode(0)
	return n, dst, nil
}
