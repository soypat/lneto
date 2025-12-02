package internet

import (
	"errors"
	"math"
	"net"
	"slices"

	"github.com/soypat/lneto/internal"
)

// StackNode is an abstraction of a packet exchanging protocol controller. This is the building block for all protocols,
// from Ethernet to IP to TCP, practically any protocol can be expressed as a StackNode and function completely.
type StackNode interface {
	CheckEncapsulate(*internal.EncData) bool
	// Encapsulate writes the stack node's frame into carrierData[frameOffset:]
	// along with any other frame or payload the stack node encapsulates.
	// The returned integer is amount of bytes written such that carrierData[frameOffset:frameOffset+n]
	// contains written data. Data inside carrierData[:frameOffset] usually contains data necessary for
	// a StackNode to correctly emit valid frame data: such is the case for TCP packets which require IP
	// frame data for checksum calculation. Thus StackNodes must provide fields in their own frame
	// required by sub-stacknodes for correct encapsulation; in the case of IPv4/6 this means including fields
	// used in pseudo-header checksum like local IP (see [ipv4.CRCWriteUDPPseudo]).
	//
	// When [net.ErrClosed] is returned the StackNode should be discarded and any written data passed up normally.
	// Errors returned by Encapsulate are "extraordinary" and should not be returned unless the StackNode is receiving invalid carrierData/frameOffset.
	DoEncapsulate(carrierData []byte, frameOffset int) (int, error)
	// Demux reads from the argument buffer where frameOffset is the offset of this StackNode's frame first byte.
	// The stack node then dispatches(demuxes) the encapsulated frames to its corresponding sub-stack-node(s).
	Demux(carrierData []byte, frameOffset int) error
	LocalPort() uint16
	Protocol() uint64
	// Connect
	ConnectionID() *uint64
	// SetFlagPending(flagPending func(numPendingEncapsulations int))
}

// node is a concrete StackNode as stored in Stacks. Methods are devirtualized for performance benefits, especially on TinyGo.
type node struct {
	currConnID       uint64
	connID           *uint64
	demux            func([]byte, int) error
	checkEncapsulate func(*internal.EncData) bool
	doEncapsulate    func([]byte, int) (int, error)
	proto            uint16
	port             uint16
}

type handlers struct {
	nodes   []node
	current uint
}

func (h *handlers) Len() int {
	return len(h.nodes)
}

func (h *handlers) GetCurrent() (current *node) {
	if h.current < uint(len(h.nodes)) {
		return &h.nodes[h.current]
	}
	return nil
}

func (h *handlers) GetNext() (next *node) {
	if len(h.nodes) == 0 {
		return nil
	}
	i := h.current + 1
	if i >= uint(len(h.nodes)) {
		i = 0
	}
	h.current = i
	return &h.nodes[i]
}

func (h *handlers) CheckEncapsulate(ed *internal.EncData) bool {
	for range len(h.nodes) {
		if node := h.GetNext(); node != nil && node.checkEncapsulate(ed) {
			return true
		}
	}
	return false
}

func (h *handlers) Reset(maxNodes int) {
	h.current = 0
	h.nodes = slices.Grow(h.nodes[:0], maxNodes)
}

func (h *handlers) GetByProto(protocol uint16) *node {
	for i := range h.nodes {
		node := &h.nodes[i]
		if node.proto == protocol {
			return node
		}
	}

	return nil
}

func (h *handlers) Node(i int) *node {
	return &h.nodes[i]
}

func (h *handlers) Register(n node) error {
	if cap(h.nodes)-len(h.nodes) <= 0 {
		h.nodes = nodesCompact(h.nodes)
	}
	if cap(h.nodes)-len(h.nodes) <= 0 {
		return errNodesFull
	}
	h.nodes = append(h.nodes, n)
	// the last inserted node becomes the next
	h.current = uint(len(h.nodes) - 1)
	return nil
}

var (
	errZeroMaxNodesArg = errors.New("zero max nodes arg")
	errZeroPort        = errors.New("port must be greater than zero")
	errInvalidProto    = errors.New("invalid protocol")
	errProtoRegistered = errors.New("protocol already registered")
	errNodesFull       = errors.New("no more room for new nodes")
	_                  = net.ErrClosed
)

func registerNode(nodesPtr *[]node, h node) error {
	if cap(*nodesPtr)-len(*nodesPtr) <= 0 {
		*nodesPtr = nodesCompact(*nodesPtr)
	}
	if cap(*nodesPtr)-len(*nodesPtr) <= 0 {
		return errNodesFull
	}
	*nodesPtr = append(*nodesPtr, h)
	return nil
}

// func handleNodeError(nodesPtr *[]node, nodeIdx int, err error) (discarded bool) {
// 	if err != nil {
// 		if nodeIdx >= len(*nodesPtr) {
// 			panic("unreachable")
// 		}
// 		nodes := *nodesPtr
// 		if checkNodeErr(&nodes[nodeIdx], err) {
// 			// *nodesPtr = slices.Delete(nodes, nodeIdx, nodeIdx+1)
// 			(*nodesPtr)[nodeIdx] = node{} // 'Delete' node without modifying slice length.
// 			discarded = true
// 		}
// 	}
// 	return discarded
// }

func handleNodeError(nodePtr *node, err error) (discarded bool) {
	if err != nil {
		if checkNodeErr(nodePtr, err) {
			*nodePtr = node{} // 'Delete' node without modifying slice length.
			discarded = true
		}
	}
	return discarded
}

func (node *node) IsInvalid() bool {
	return node.demux == nil || node.doEncapsulate == nil || (node.connID != nil && node.currConnID != *node.connID)
}

func checkNodeErr(node *node, err error) (discard bool) {
	return node.IsInvalid() || (err != nil && err == net.ErrClosed)
}

func nodeFromStackNode(s StackNode, port uint16, protocol uint64) node {
	if protocol > math.MaxUint16 {
		panic(">16bit protocol number unsupported")
	}
	var currConnID uint64
	connIDPtr := s.ConnectionID()
	if connIDPtr != nil {
		currConnID = *connIDPtr
	}
	return node{
		currConnID:       currConnID,
		connID:           connIDPtr,
		demux:            s.Demux,
		checkEncapsulate: s.CheckEncapsulate,
		doEncapsulate:    s.DoEncapsulate,
		proto:            uint16(protocol),
		port:             port,
	}
}

func getNode(nodes []node, port uint16, protocol uint16) (node *node) {
	for i := range nodes {
		node := &nodes[i]
		if node.port == port && node.proto == protocol {
			return node
		}
	}
	return nil
}

// func getEncapsulateNode(nodes *[]node, carrierData []byte, frameOffset int) (nodeIdx int, written int, err error) {
// 	destroyed := false
// 	for i := range *nodes {
// 		node := &(*nodes)[i]
// 		if node.IsInvalid() {
// 			destroyed = true
// 			node.destroy()
// 			continue
// 		}
// 		written, err = node.encapsulate(carrierData, frameOffset)
// 		if written > 0 {
// 			return i, written, err
// 		} else if err != nil {

// 		}
// 	}
// 	if destroyed {
// 		*nodes = nodesCompact(*nodes)
// 	}
// 	return -1, 0, nil
// }

// destroy removes all references to underlying StackNode. Allows garbage collection of node if possible.
func (n *node) destroy() {
	*n = node{}
}

func getNodeByProto(nodes []node, protocol uint16) int {
	for i := range nodes {
		node := &nodes[i]
		if node.proto == protocol {
			return i
		}
	}

	return -1
}

func nodesCompact(nodes []node) []node {
	nilOff := 0
	for i := 0; i < len(nodes); i++ {
		if !nodes[i].IsInvalid() {
			nodes[nilOff] = nodes[i]
			nilOff++
		}
	}
	return nodes[:nilOff]
}
