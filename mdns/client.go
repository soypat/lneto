package mdns

import (
	"math"
	"net"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/internal"
)

const (
	// Port is the mDNS UDP port (RFC 6762 §1).
	Port = 5353

	// Default TTL for mDNS records (RFC 6762 §11).
	DefaultTTL uint32 = 120
	// classCacheFlush is bit 15 of the Class field, indicating the record
	// is from a unique source and should replace cached entries (RFC 6762 §10.2).
	classCacheFlush uint16 = 1 << 15
	mdnsTxID               = 0
	mdnsFlags              = 0
)

type querierState uint8

const (
	querierIdle          querierState = iota
	querierSendQuery                  // Query ready to be sent.
	querierAwaitResponse              // Waiting for answers.
	querierFailed                     // failed query
	querierDone                       // Answers collected.
)

// Client provides both querying and service multicast DNS functionality
// once configured and attached to MDNS port 5353.
//
// Clients are attached to MDNS ports and function until manual detachment
// due to their dual design: they double as a querier and service discovery.
type Client struct {
	connID uint64

	lport uint16
	// Query State:
	qstate querierState
	qcode  dns.RCode
	qerr   error
	// qmsg is used for queries to marshal/unmarshal our
	// outgoing queries and responses to our queries.
	qans []dns.Resource
	qqst []dns.Question
	// Response state:
	// TODO.
	resps []pendingResponse
	rmsg  dns.Message
}

// pendingResponse holds all the data necessary to effect an mdns pendingResponse.
type pendingResponse struct {
	state responderState
}

type ClientConfig struct {
	LocalPort uint16
}

func (c *Client) Configure(cfg ClientConfig) error {
	if cfg.LocalPort == 0 {
		return lneto.ErrZeroSource
	}
	c.reset(cfg.LocalPort)
	return nil
}

func (c *Client) Protocol() uint64 { return uint64(lneto.IPProtoUDP) }

func (c *Client) LocalPort() uint16 { return c.lport }

func (c *Client) ConnectionID() *uint64 { return &c.connID }

type ResolveConfig struct {
	Questions  []dns.Question
	MaxAnswers uint16
}

func (c *Client) StartResolve(cfg ResolveConfig) error {
	nq := len(cfg.Questions)
	if nq > math.MaxUint16 || nq == 0 || cfg.MaxAnswers == 0 {
		return lneto.ErrInvalidConfig
	}
	c.qreset(querierSendQuery)
	internal.SliceReuse(&c.qans, int(cfg.MaxAnswers))
	internal.SliceReuse(&c.qqst, nq)
	c.qqst = c.qqst[:nq]
	for i := range c.qqst {
		c.qqst[i].CopyFrom(cfg.Questions[i])
	}
	return nil
}

func (c *Client) reset(localport uint16) {
	*c = Client{
		connID: c.connID + 1,
		lport:  localport,
		// Ensure memory not lost:
		qqst:  c.qqst[:0],
		qans:  c.qans[:0],
		resps: c.resps[:0],
		rmsg:  c.rmsg,
	}
}

// qreset resets the current query state. It is only a partial reset of a Client.
func (c *Client) qreset(state querierState) {
	c.qstate = state
}

// Encapsulate writes an mDNS query packet into carrierData[offsetToFrame:].
// The mDNS query has txid=0, no recursion desired, and no opcode (RFC 6762 §18.1).
func (c *Client) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	if c.isClosed() {
		return 0, net.ErrClosed
	}
	if c.qstate == querierSendQuery {
		// User requested a query.
		return c.encapsQuery(carrierData[offsetToFrame:])
	}
	return 0, nil
}

// Demux processes an incoming mDNS response packet. Answers are accumulated
// into the internal message. Once sufficient answers are collected or a
// timeout occurs the querier transitions to querierDone.
func (c *Client) Demux(carrierData []byte, frameOffset int) error {
	if c.isClosed() {
		return net.ErrClosed
	}
	frame := carrierData[frameOffset:]
	f, err := dns.NewFrame(frame)
	if err != nil {
		return err
	} else if f.TxID() != 0 {
		return lneto.ErrPacketDrop
	}
	flags := f.Flags()
	if flags.IsResponse() && c.qstate == querierAwaitResponse {
		c.qcode = flags.ResponseCode()
		// Decode response into our message, collecting answers.
		_, _, c.qerr = dns.DecodeMessage(nil, &c.qans, nil, nil, frame)
		if c.qerr != nil {
			c.qstate = querierFailed
			return c.qerr
		}
		c.qstate = querierDone
		return nil // success.
	}
	// Is a request
	// TODO: support requests.
	return nil
}

func (c *Client) encapsQuery(frame []byte) (int, error) {
	msg := dns.Message{
		Questions: c.qqst,
	}
	msglen := msg.Len()
	if int(msglen) > len(frame) {
		c.qerr = lneto.ErrShortBuffer
		c.qstate = querierFailed
		return 0, c.qerr
	}
	// mDNS queries use txid=0 and no flags (RFC 6762 §18.1).
	data, err := msg.AppendTo(frame[:0], mdnsTxID, mdnsFlags)
	if err != nil {
		c.qerr = err
		c.qstate = querierFailed
		return 0, err
	} else if len(data) != int(msglen) {
		panic("bad dns length calculation") // panic since this is a big bug in lneto.
	}
	c.qstate = querierAwaitResponse
	return len(data), nil
}

func (c *Client) isClosed() bool {
	return false
}

// AnswersCopyTo checks if [Client.StartResolve] ended succesfully before
// doing a deep copy of answers received to the argument buffer using [dns.Resource.CopyFrom].
func (c *Client) AnswersCopyTo(dst []dns.Resource) (n int, done bool, err error) {
	if len(dst) == 0 {
		return 0, false, lneto.ErrShortBuffer
	} else if c.qstate == querierFailed {
		return 0, false, c.qerr
	} else if c.qstate != querierDone {
		return 0, false, nil
	}
	for i := range min(len(dst), len(c.qans)) {
		dst[i].CopyFrom(c.qans[i])
		n++
	}
	rcode := c.qcode
	if rcode != 0 {
		return n, true, rcode
	}
	return n, true, nil
}
