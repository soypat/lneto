package internet

import (
	"github.com/soypat/lneto/ntp"
)

var _ StackNode = (*NodeNTPClient)(nil)

type NodeNTPClient struct {
	c ntp.Client
}

func (n *NodeNTPClient) Protocol() uint64 {
	return 0
}

func (n *NodeNTPClient) LocalPort() uint16 {
	return ntp.ClientPort
}

func (n *NodeNTPClient) ConnectionID() *uint64 {
	return n.c.ConnectionID()
}

func (n *NodeNTPClient) Demux(carrierData []byte, ntpOffset int) error {
	return nil
}

func (n *NodeNTPClient) Encapsulate(carrierData []byte, ntpOffset int) (int, error) {
	return 0, nil
}
