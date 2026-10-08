package dns

import (
	"math"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

var _ lneto.StackNode = (*Client)(nil) // Compile-time guarantee of interface implementation.

// Client provides parallel query resolution via Lookup* methods. Currently only supports UDP.
type Client struct {
	connID uint64
	// looksies holds query slots. Its length is fixed by [ClientConfig.MaxQueries] and
	// slots never move so the *Message returned by [Client.LookupResponse] stays valid.
	looksies []lookup
	// lidxs is a permutation of queries' indices: lidxs[:len] index active queries
	// and lidxs[len:len(queries)] index free slots, which keep their buffers for reuse.
	lidxs []uint16
	vld   lneto.Validator
	lport uint16
}

// lookup stores a single lookup state with restart ability for canonical name resolution.
type lookup struct {
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

type LookupConfig struct {
	Questions       []Question
	Additional      []Resource
	EnableRecursion bool
	// MaxResponseAnswers hard-limits how many answer records decoded from response.
	MaxResponseAnswers uint16
}

// Configure discards ongoing/pending/active queries and configures client. Also increments connection ID.
func (c *Client) Configure(cfg ClientConfig) error {
	if cfg.MaxQueries <= 0 || cfg.MaxQueries > math.MaxUint16 {
		return lneto.ErrInvalidConfig
	}
	c.connID++
	c.lport = cfg.LocalPort
	n := cfg.MaxQueries
	if cap(c.looksies) < n {
		grown := make([]lookup, n)
		copy(grown, c.looksies[:cap(c.looksies)]) // Keep slot buffers.
		c.looksies = grown
	} else {
		c.looksies = c.looksies[:n]
	}
	internal.SliceReuse(&c.lidxs, n)
	for i := range n {
		c.lidxs = append(c.lidxs, uint16(i))
	}
	c.lidxs = c.lidxs[:0]
	return nil
}

func (c *Client) Protocol() uint64 { return uint64(lneto.IPProtoUDP) }

func (c *Client) LocalPort() uint16 { return c.lport }

func (c *Client) ConnectionID() *uint64 { return &c.connID }

// NumLookups returns the number of active queries, sent or not, completed or not.
func (c *Client) NumLookups() int { return len(c.lidxs) }

// MaxLookups returns the maximum number of queries that may be active at once.
func (c *Client) MaxLookups() int { return len(c.looksies) }

// LookupStart starts a query identified by txid which must be unique.
func (c *Client) LookupStart(txid uint16, cfg LookupConfig) error {
	nd := len(cfg.Questions)
	if nd > math.MaxUint16 || nd == 0 || txid == 0 {
		return lneto.ErrInvalidConfig
	} else if c.qidx(txid) >= 0 {
		return lneto.ErrAlreadyRegistered
	} else if len(c.lidxs) == len(c.looksies) {
		return lneto.ErrExhausted
	}
	validateSections(&c.vld, cfg.Questions, nil, nil, cfg.Additional)
	if err := c.vld.ErrPop(); err != nil {
		return err
	}
	c.lidxs = c.lidxs[:len(c.lidxs)+1] // Claim first free slot.
	c.qat(len(c.lidxs)-1).reset(txid, cfg)
	return nil
}

// reset sets the query up as a pending query txid with cfg's sections. cfg must be validated.
func (q *lookup) reset(txid uint16, cfg LookupConfig) {
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
func (q *lookup) restart(txid uint16) {
	q.resp.Reset()
	q.txid = txid
	q.respFlags = 0
	q.state = CQueryPending
}

// LookupPeek reports whether the query txid has completed. ok is false if no such query is active.
func (c *Client) LookupPeek(txid uint16) (completed, ok bool) {
	idx := c.qidx(txid)
	if idx < 0 {
		return false, false
	}
	return c.qat(idx).state == CQueryDone, true
}

// LookupPop removes the query by txid. completed=true if the query already completed.
func (c *Client) LookupPop(txid uint16) (completed, ok bool) {
	idx := c.qidx(txid)
	if idx < 0 {
		return false, false
	}
	completed = c.qat(idx).state == CQueryDone
	c.qidxRemove(idx)
	return completed, true
}

// LookupResponse returns the decoded response corresponding to the query identied by txid. See [HeaderFlags.ResponseCode] to check if query succesful.
// resp is owned by Client and valid until txid removed with [Client.LookupPop], [Client.Reset], [Client.Abort] or [Client.Configure],
// or restarted with [Client.LookupCanonicalRestart]. Starting, completing or removing other queries does not affect resp.
func (c *Client) LookupResponse(txid uint16) (resp *Message, flags HeaderFlags, ok bool) {
	idx := c.qidx(txid)
	if idx < 0 || c.qat(idx).state != CQueryDone {
		return nil, 0, false
	}
	q := c.qat(idx)
	return &q.resp, q.respFlags, true
}

// LookupCanonicalRestart restarts a completed query txid as newTxid, querying the canonical name its response holds.
// Use when [Message.WriteAnswers] outputs no addresses and [Message.CanonicalName] output is non-zero lengthed.
func (c *Client) LookupCanonicalRestart(txid, newTxid uint16) error {
	idx := c.qidx(txid)
	if idx < 0 || c.qat(idx).state != CQueryDone {
		return errNoResponse
	} else if newTxid == 0 {
		return lneto.ErrInvalidConfig
	} else if c.qidx(newTxid) >= 0 {
		return lneto.ErrAlreadyRegistered
	}
	q := c.qat(idx)
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
	c.lidxs = c.lidxs[:0]
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
	q := c.qat(idx)
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
	if idx < 0 || c.qat(idx).state != CQueryOutstanding || !c.qat(idx).isResponse(f) {
		return nil // Not meant for our client.
	}
	q := c.qat(idx)
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
func (q *lookup) isResponse(f Frame) bool {
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

// qat returns the active query at position idx of qidxs.
func (c *Client) qat(idx int) *lookup {
	return &c.looksies[c.lidxs[idx]]
}

// qidxPending gets qidxs position of next pending query.
func (c *Client) qidxPending() int {
	idx := -1
	for i := range c.lidxs {
		if c.qat(i).state == CQueryPending {
			idx = i
			break
		}
	}
	return idx
}

// qidx returns qidxs position of active query matching transaction ID.
func (c *Client) qidx(txid uint16) int {
	for i := range c.lidxs {
		if c.qat(i).txid == txid {
			return i
		}
	}
	return -1
}

// qidxRemove frees the query at qidxs position idx by swapping its slot index past the end.
// The query itself stays in place, keeping its buffers for reuse.
func (c *Client) qidxRemove(idx int) {
	last := len(c.lidxs) - 1
	c.lidxs[idx], c.lidxs[last] = c.lidxs[last], c.lidxs[idx]
	c.lidxs = c.lidxs[:last]
}
