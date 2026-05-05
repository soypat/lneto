package icmpv6

import (
	"errors"

	"github.com/soypat/lneto"
)

const (
	ndpOptSourceLinkAddr = 1 // RFC 4861 §4.6.1
	ndpOptTargetLinkAddr = 2 // RFC 4861 §4.6.2
)

var (
	errNDPQueryPending  = errors.New("icmpv6: NDP query pending")
	errNDPQueryNotFound = errors.New("icmpv6: NDP query not found")
)

func (client *Client) demuxNDP(carrierData []byte, frameOffset int) error {
	rawdata := carrierData[frameOffset:]
	if len(rawdata) < sizeNDPBase {
		return lneto.ErrTruncatedFrame
	}
	ifrm, _ := NewFrame(rawdata) // already validated by Demux
	tp := ifrm.Type()
	targetAddr := (*[16]byte)(rawdata[8:24])
	options := rawdata[24:]
	ipEnabled := frameOffset >= 40
	switch tp {
	case TypeNeighborSolicitation:
		if *targetAddr != client.ourIP {
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
		e := client.ndpCache.acquireNext()
		e.use(mac, senderAddr, ndpFlagPendingResponse)

	case TypeNeighborAdvertisement:
		mac, ok := parseLinkLayerOption(options, ndpOptTargetLinkAddr)
		if !ok {
			return lneto.ErrPacketDrop
		}
		e := client.ndpCache.Lookup(*targetAddr)
		if e == nil {
			return nil // Unsolicited or already evicted.
		}
		e.mac = mac
		e.flags &^= ndpFlagIncomplete | ndpFlagIncompletePendingQuery
		if e.flags.hasAny(ndpFlagResolveTriggersCallback) && client.onresolve != nil {
			client.onresolve(mac, *targetAddr)
		}
	}
	return nil
}

func (client *Client) encapsNDP(carrierData []byte, frameOffset int) (n int, dst [16]byte, err error) {
	buf := carrierData[frameOffset:]
	if len(buf) < sizeNDP {
		return 0, [16]byte{}, lneto.ErrShortBuffer
	}
	tp := TypeNeighborAdvertisement
	e := client.ndpCache.getNextFlagged(ndpFlagPendingResponse) // Prioritize responses.
	if e == nil {
		e = client.ndpCache.getNextFlagged(ndpFlagIncompletePendingQuery)
		if e == nil {
			return 0, [16]byte{}, nil
		}
		e.flags &^= ndpFlagIncompletePendingQuery
		tp = TypeNeighborSolicitation
	} else {
		e.flags &^= ndpFlagPendingResponse
	}
	n, err = e.put(buf, client.ourIP, client.ourMAC, tp)
	if err != nil {
		return 0, [16]byte{}, err
	}
	switch tp {
	case TypeNeighborSolicitation:
		dst = solicitedNodeMulticast(e.addr)
	case TypeNeighborAdvertisement:
		dst = e.addr
	}
	return n, dst, nil
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
