package dns

import (
	"errors"
	"fmt"
	"math"
	"net"

	"github.com/soypat/lneto"
)

type Client struct {
	connID          uint64
	txid            uint16
	msg             Message
	respFlags       HeaderFlags
	state           clientState
	enableRecursion bool
}

type ResolveConfig struct {
	Questions       []Question
	EnableRecursion bool
}

func (sudp *Client) Protocol() uint64 { return uint64(lneto.IPProtoUDP) }

func (sudp *Client) LocalPort() uint16 { return ClientPort }

func (sudp *Client) ConnectionID() *uint64 { return &sudp.connID }

func (c *Client) StartResolve(txid uint16, cfg ResolveConfig) error {
	nd := len(cfg.Questions)
	if nd > math.MaxUint16 {
		return errors.New("overflow uint16 in DNS questions")
	}
	c.reset(txid, dnsSendQuery, cfg.EnableRecursion)
	c.msg.LimitResourceDecoding(uint16(nd), uint16(nd), 0, 0)
	c.msg.AddQuestions(cfg.Questions)
	return nil
}

func (c *Client) Encapsulate(carrierData []byte, frameOffset int) (int, error) {
	if c.isClosed() {
		return 0, net.ErrClosed
	} else if c.state != dnsSendQuery {
		return 0, nil
	}

	msg := &c.msg
	frame := carrierData[frameOffset:]
	msglen := msg.Len()
	if msglen > uint16(len(frame)) {
		return 0, errCalcLen
	}

	data, err := msg.AppendTo(frame[:0], c.txid, NewClientHeaderFlags(OpCodeQuery, c.enableRecursion))
	if err != nil {
		return 0, err
	} else if len(data) > int(msglen) {
		return 0, fmt.Errorf("unexpected write %d v %d", len(data), msglen)
	}
	c.state = dnsAwaitResponse
	return len(data), nil
}

func (c *Client) Demux(carrierData []byte, frameOffset int) error {
	if c.isClosed() {
		return net.ErrClosed
	} else if c.state != dnsAwaitResponse {
		return nil
	}
	frame := carrierData[frameOffset:]
	f, err := NewFrame(frame)
	if err != nil {
		return err
	}
	flags := f.Flags()
	if f.TxID() != c.txid || !flags.IsResponse() {
		return nil // Not meant for our client.
	}
	c.respFlags = flags
	c.state = dnsDone
	msg := &c.msg
	_, incompleteButOK, err := msg.Decode(frame)
	if err != nil && !incompleteButOK {
		return err
	}
	return nil
}

func (c *Client) isClosed() bool {
	return c.state == dnsClosed || c.state == dnsAborted
}

func (c *Client) MessageCopyTo(dst *Message) (done bool, err error) {
	if !c.respFlags.IsResponse() {
		return false, nil
	}
	dst.CopyFrom(c.msg)
	rcode := c.respFlags.ResponseCode()
	if rcode != 0 {
		return true, rcode
	}
	return true, nil
}

func (c *Client) Answers() []Resource {
	if c.state != dnsDone {
		return nil
	}
	return c.msg.Answers
}

func (c *Client) Abort() {
	c.reset(0, 0, false)
}

func (c *Client) reset(txid uint16, state clientState, enableRecursion bool) {
	*c = Client{
		connID:          c.connID + 1,
		txid:            txid,
		msg:             c.msg,
		state:           state,
		enableRecursion: enableRecursion,
	}
	c.msg.Reset()
}

type clientState uint8

const (
	dnsClosed clientState = iota
	dnsSendQuery
	dnsAwaitResponse
	dnsDone
	dnsAborted
)
