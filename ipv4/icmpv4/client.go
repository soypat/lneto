package icmpv4

import (
	"slices"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

var _ lneto.StackNode = (*Client)(nil) // Compile-time guarantee of interface implementation.

const (
	keyHashCompletedBit = 1 << 31
	keyHashBits         = (1 << 31) - 1
)

type Client struct {
	connid uint64
	magic  uint32
	// For every ping we send out stores hashes of the data (should include IP likely).
	pendingPingResp []uint32

	responseRing internal.Ring
}

type ClientConfig struct {
	ResponseQueueBuffer []byte
	ResponseQueueLimit  int
}

func (client *Client) Configure()

func (client *Client) Protocol() uint64 { return uint64(lneto.IPProtoICMP) }

func (client *Client) LocalPort() uint16 { return 0 }

func (client *Client) ConnectionID() *uint64 { return &client.connid }

func (client *Client) Demux(carrierData []byte, frameOffset int) error {
	return nil
}

func (client *Client) Encapsulate(carrierData []byte, ipOffset, frameOffset int) (int, error) {

	return 0, nil
}

func (client *Client) magichash(pattern []byte, size uint16) uint32 {
	return 0
}

func (client *Client) PingStart(pattern []byte, size uint16, ttl uint8) (key uint32, err error) {
	key = client.magichash(pattern, size) & keyHashBits
	client.pendingPingResp = append(client.pendingPingResp, key)
	return key, nil
}

func (client *Client) pingidx(key uint32) int {
	for i, pending := range client.pendingPingResp {
		if pending&keyHashBits == key {
			return i
		}
	}
	return -1
}

func (client *Client) PingPeek(key uint32) (completed, notexist bool) {
	idx := client.pingidx(key)
	if idx >= 0 {
		return client.pendingPingResp[idx]&keyHashCompletedBit != 0, false
	}
	return false, true
}

func (client *Client) PingPop(key uint32) (completed, notexist bool) {
	idx := client.pingidx(key)
	if idx >= 0 {
		completed := client.pendingPingResp[idx]&keyHashCompletedBit != 0
		client.pendingPingResp = slices.Delete(client.pendingPingResp, idx, idx+1)
		return completed, true
	}
	return false, true
}
