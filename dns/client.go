package dns

import (
	"errors"
	"math"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

var _ lneto.StackNode = (*Client)(nil) // Compile-time guarantee of interface implementation.

var errNoCNAME = errors.New("no CNAME in DNS response")

// Client resolves DNS queries over UDP. Several queries may be in flight at once,
// each identified by its transaction ID (txid) as the key to [Client.ResolvePeek],
// [Client.ResolvePop] and [Client.ResolveResponse]. All queries share the client's local port.
type Client struct {
	connID uint64
	// queries holds active queries. Its capacity is fixed by [ClientConfig.MaxQueries];
	// elements past its length keep their Message buffers for reuse.
	queries []query
	vld     lneto.Validator
	lport   uint16
}

// query is one DNS query keyed by its txid. It keeps the sections it sends
// apart from its response so it can be sent again, see [Client.ResolveCanonicalRestart].
type query struct {
	questions       []Question
	additional      []Resource
	resp            Message
	txid            uint16
	respFlags       HeaderFlags
	state           StateClientQuery
	enableRecursion bool
}

type ClientConfig struct {
	LocalPort uint16
	// MaxQueries is the maximum number of queries that may be active at once.
	MaxQueries int
}

type ResolveConfig struct {
	Questions       []Question
	Additional      []Resource
	EnableRecursion bool
	// MaxResponseAnswers limits how many answer records are decoded from the
	// DNS response. If zero it defaults to the number of Questions. Answers
	// are decoded in wire order regardless of type, so a response resolved
	// through CNAMEs needs room for the CNAME records as well as the addresses.
	MaxResponseAnswers uint16
}

// Configure discards all queries and configures the client. It invalidates the
// client's previous registration on a stack, see [Client.ConnectionID].
func (c *Client) Configure(cfg ClientConfig) error {
	if cfg.MaxQueries <= 0 || cfg.MaxQueries > math.MaxUint16 {
		return lneto.ErrInvalidConfig
	}
	c.connID++
	c.lport = cfg.LocalPort
	internal.SliceReuse(&c.queries, cfg.MaxQueries)
	return nil
}

func (c *Client) Protocol() uint64 { return uint64(lneto.IPProtoUDP) }

func (c *Client) LocalPort() uint16 { return c.lport }

func (c *Client) ConnectionID() *uint64 { return &c.connID }

// SetLocalPort changes the port queries are sent from. It invalidates the client's
// previous registration on a stack so it must be registered again.
// Returns [lneto.ErrBadState] while any query is active.
func (c *Client) SetLocalPort(port uint16) error {
	if len(c.queries) > 0 {
		return lneto.ErrBadState
	}
	c.connID++
	c.lport = port
	return nil
}

// NumQueries returns the number of active queries, sent or not, completed or not.
func (c *Client) NumQueries() int { return len(c.queries) }

// CapQueries returns the maximum number of queries that may be active at once.
func (c *Client) CapQueries() int { return cap(c.queries) }

// ResolveStart starts a query identified by txid, which is sent on the next call to [Client.Encapsulate].
// Returns [lneto.ErrExhausted] if [ClientConfig.MaxQueries] are active and
// [lneto.ErrAlreadyRegistered] if a query with the same txid is active.
func (c *Client) ResolveStart(txid uint16, cfg ResolveConfig) error {
	nd := len(cfg.Questions)
	if nd > math.MaxUint16 || nd == 0 || txid == 0 {
		return lneto.ErrInvalidConfig
	} else if c.qidx(txid) >= 0 {
		return lneto.ErrAlreadyRegistered
	} else if len(c.queries) == cap(c.queries) {
		return lneto.ErrExhausted
	}
	validateSections(&c.vld, cfg.Questions, nil, nil, cfg.Additional)
	if err := c.vld.ErrPop(); err != nil {
		return err
	}
	q := internal.SliceReclaim(&c.queries)
	q.reset(txid, cfg)
	return nil
}

// reset sets the query up as a pending query txid with cfg's sections. cfg must be validated.
func (q *query) reset(txid uint16, cfg ResolveConfig) {
	nd := uint16(len(cfg.Questions))
	maxAns := cfg.MaxResponseAnswers
	if maxAns == 0 {
		maxAns = nd
	}
	q.enableRecursion = cfg.EnableRecursion
	// Copy sections: the caller may modify its slices while the query is active.
	internal.SliceCopyFrom(&q.questions, cfg.Questions)
	internal.SliceCopyFrom(&q.additional, cfg.Additional)
	q.restart(txid)
	q.resp.LimitResourceDecoding(nd, maxAns, 0, 0)
}

// restart makes the query pending as txid, discarding its response.
func (q *query) restart(txid uint16) {
	q.resp.Reset()
	q.txid = txid
	q.respFlags = 0
	q.state = CQueryPending
}

// ResolvePeek reports whether the query txid has completed. ok is false if no such query is active.
func (c *Client) ResolvePeek(txid uint16) (completed, ok bool) {
	idx := c.qidx(txid)
	if idx < 0 {
		return false, false
	}
	return c.queries[idx].state == CQueryDone, true
}

// ResolvePop removes the query txid, freeing its slot for another query, and reports whether
// it had completed. ok is false if no such query is active. The response returned by
// [Client.ResolveResponse] for txid must not be used afterwards.
func (c *Client) ResolvePop(txid uint16) (completed, ok bool) {
	idx := c.qidx(txid)
	if idx < 0 {
		return false, false
	}
	completed = c.queries[idx].state == CQueryDone
	c.qidxRemove(idx)
	return completed, true
}

// ResolveResponse returns the decoded response to the completed query txid and its header flags,
// where [HeaderFlags.ResponseCode] reports whether the query succeeded. ok is false if the
// query is not active or has not completed. resp is owned by the client and valid until
// txid is removed with [Client.ResolvePop], [Client.Reset] or [Client.Abort].
func (c *Client) ResolveResponse(txid uint16) (resp *Message, flags HeaderFlags, ok bool) {
	idx := c.qidx(txid)
	if idx < 0 || c.queries[idx].state != CQueryDone {
		return nil, 0, false
	}
	q := &c.queries[idx]
	return &q.resp, q.respFlags, true
}

// ResolveCanonicalRestart restarts the completed query txid as newTxid, querying the canonical name
// its response holds for its question. Use it after a response with CNAME records and no
// address to follow the CNAME chain. The query keeps its slot and memory, its question type
// and additional records; the response to txid must not be used afterwards.
// Returns [lneto.ErrAlreadyRegistered] if newTxid is in use and [lneto.ErrUnsupported] for
// queries with more than one question. A failed call leaves the query unchanged.
func (c *Client) ResolveCanonicalRestart(txid, newTxid uint16) error {
	idx := c.qidx(txid)
	if idx < 0 || c.queries[idx].state != CQueryDone {
		return errNoResponse
	} else if newTxid == 0 {
		return lneto.ErrInvalidConfig
	} else if c.qidx(newTxid) >= 0 {
		return lneto.ErrAlreadyRegistered
	}
	q := &c.queries[idx]
	if rcode := q.respFlags.ResponseCode(); rcode != 0 {
		return rcode
	} else if len(q.questions) != 1 {
		return lneto.ErrUnsupported
	}
	cname := q.resp.CanonicalName(q.questions[0].Name)
	if cname.Len() == 0 {
		return errNoCNAME
	} else if err := cname.validate(); err != nil {
		return err
	}
	q.questions[0].Name.CopyFrom(cname) // cname aliases q.resp, never the question.
	q.restart(newTxid)
	return nil
}

// Reset removes all queries.
func (c *Client) Reset() {
	c.queries = c.queries[:0]
}

// Abort removes all queries and invalidates the client's registration on a stack.
func (c *Client) Abort() {
	c.Reset()
	c.connID++
}

// Encapsulate writes the first query not yet sent. Returns 0 and nil error if there is none.
func (c *Client) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	idx := c.qidxPending()
	if idx < 0 {
		return 0, nil
	}
	q := &c.queries[idx]
	frame := carrierData[offsetToFrame:]
	msglen := uint16(SizeHeader + lenSections(q.questions, nil, nil, q.additional))
	if msglen > uint16(len(frame)) {
		return 0, errCalcLen
	}
	flags := NewClientHeaderFlags(OpCodeQuery, q.enableRecursion)
	n, err := PutMessage(frame, q.txid, flags, q.questions, nil, nil, q.additional)
	if err != nil {
		return 0, err
	}
	q.state = CQueryOutstanding
	// Unset don't frag since DNS requests go through LOTS of nodes.
	// if frameOffset >= 28 {
	// 	version := carrierData[0] >> 4
	// 	if version == 4 {
	// 		carrierData[6], carrierData[7] = 0, 0 // unset IP Flags.
	// 	}
	// }
	return n, nil
}

// Demux decodes a response to a sent query, matched by txid, opcode and question section.
// Frames that answer no query are ignored.
func (c *Client) Demux(carrierData []byte, frameOffset int) error {
	frame := carrierData[frameOffset:]
	f, err := NewFrame(frame)
	if err != nil {
		return err
	}
	idx := c.qidx(f.TxID())
	if idx < 0 || c.queries[idx].state != CQueryOutstanding || !c.queries[idx].isResponse(f) {
		return nil // Not meant for our client.
	}
	q := &c.queries[idx]
	q.respFlags = f.Flags()
	q.state = CQueryDone
	_, incompleteButOK, err := q.resp.Decode(frame)
	if err != nil && !incompleteButOK {
		return err
	}
	return nil
}

// isResponse reports whether frame responds to the query: response flag set,
// same opcode and same question section. txid is checked by the caller.
func (q *query) isResponse(f Frame) bool {
	flags := f.Flags()
	if !flags.IsResponse() || flags.OpCode() != OpCodeQuery || int(f.QDCount()) != len(q.questions) {
		return false
	}
	off := uint16(SizeHeader)
	for i := range q.questions {
		var ok bool
		off, ok = q.questions[i].equalWireFold(f.buf, off)
		if !ok {
			return false
		}
	}
	return true
}

// qidxPending gets query index of next pending query.
func (c *Client) qidxPending() int {
	idx := -1
	for i := range c.queries {
		if c.queries[i].state == CQueryPending {
			idx = i
			break
		}
	}
	return idx
}

// qidx returns query index matching transaction ID.
func (c *Client) qidx(txid uint16) int {
	for i := range c.queries {
		if c.queries[i].txid == txid {
			return i
		}
	}
	return -1
}

// qidxRemove deletes the query at idx by swapping it past the end, keeping its buffers for reuse.
func (c *Client) qidxRemove(idx int) {
	last := len(c.queries) - 1
	c.queries[idx], c.queries[last] = c.queries[last], c.queries[idx]
	c.queries = c.queries[:last]
}
