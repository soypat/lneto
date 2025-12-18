package internet

import (
	"errors"
	"math"
	"net"
	"slices"
)

// StackNode is an abstraction of a packet exchanging protocol controller. This is the building block for all protocols,
// from Ethernet to IP to TCP, practically any protocol can be expressed as a StackNode and function completely.
type StackNode interface {
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
	Encapsulate(carrierData []byte, frameOffset int) (int, error)
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
	currConnID  uint64
	connID      *uint64
	demux       func([]byte, int) error
	encapsulate func([]byte, int) (int, error)
	proto       uint16
	port        uint16
	remoteAddr  []byte
}

type handlers struct {
	nodes []node
}

func (h *handlers) reset(maxNodes int) {
	h.nodes = slices.Grow(h.nodes[:0], maxNodes)
}

func (h *handlers) registerByProto(n node) error {
	err := h.prepAdd()
	if err != nil {
		return err
	}
	if h.nodeByProto(n.proto) != nil {
		return errProtoRegistered
	}
	h.nodes = append(h.nodes, n)
	return nil
}

func (h *handlers) registerByPortProto(n node) error {
	err := h.prepAdd()
	if err != nil {
		return err
	}
	if h.nodeByPortProto(n.port, n.proto) != nil {
		return errProtoRegistered
	}
	h.nodes = append(h.nodes, n)
	return nil
}

func (h *handlers) prepAdd() error {
	if h.full() {
		h.compact()
		if h.full() {
			return errNodesFull
		}
	}
	return nil
}

func (h *handlers) full() bool { return cap(h.nodes) == len(h.nodes) }

func (h *handlers) compact() {
	nilOff := 0
	for i := 0; i < len(h.nodes); i++ {
		if !h.nodes[i].IsInvalid() {
			h.nodes[nilOff] = h.nodes[i]
			nilOff++
		}
	}
	h.nodes = h.nodes[:nilOff]
}

func (h *handlers) tryHandleError(node *node, err error) (discardedGracefully bool) {
	if err != nil && (err == net.ErrClosed || node.IsInvalid()) {
		node.destroy()
		discardedGracefully = true
	}
	return discardedGracefully
}

func (h *handlers) nodeByProto(proto uint16) *node {
	for i := range h.nodes {
		node := &h.nodes[i]
		if node.proto == proto {
			return node
		}
	}
	return nil
}

func (h *handlers) nodeByPort(port uint16) *node {
	for i := range h.nodes {
		node := &h.nodes[i]
		if node.port == port {
			return node
		}
	}
	return nil
}

func (h *handlers) nodeByPortProto(port uint16, protocol uint16) *node {
	for i := range h.nodes {
		node := &h.nodes[i]
		if node.port == port && node.proto == protocol {
			return node
		}
	}
	return nil
}

// encapsulateAny does not add the offset to the amount of bytes written.
func (h *handlers) encapsulateAny(buf []byte, offset int) (*node, int, error) {
	for i := range h.nodes {
		node := &h.nodes[i]
		if node.IsInvalid() {
			continue
		}
		n, err := node.encapsulate(buf, offset)
		if h.tryHandleError(node, err) {
			err = nil // CLOSE error handled gracefully by deleting node.
		}
		if err != nil || n > 0 {
			return node, n, err
		}
	}
	return nil, 0, nil
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

func handleNodeError(nodesPtr *[]node, nodeIdx int, err error) (discarded bool) {
	if err != nil {
		if nodeIdx >= len(*nodesPtr) {
			panic("unreachable")
		}
		nodes := *nodesPtr
		if checkNodeErr(&nodes[nodeIdx], err) {
			// *nodesPtr = slices.Delete(nodes, nodeIdx, nodeIdx+1)
			(*nodesPtr)[nodeIdx] = node{} // 'Delete' node without modifying slice length.
			discarded = true
		}
	}
	return discarded
}

func (node *node) IsInvalid() bool {
	return node.demux == nil || node.encapsulate == nil || (node.connID != nil && node.currConnID != *node.connID)
}

func checkNodeErr(node *node, err error) (discard bool) {
	return node.IsInvalid() || (err != nil && err == net.ErrClosed)
}

func nodeFromStackNode(s StackNode, port uint16, protocol uint64, remoteAddr []byte) node {
	if protocol > math.MaxUint16 {
		panic(">16bit protocol number unsupported")
	}
	var currConnID uint64
	connIDPtr := s.ConnectionID()
	if connIDPtr != nil {
		currConnID = *connIDPtr
	}
	return node{
		currConnID:  currConnID,
		connID:      connIDPtr,
		demux:       s.Demux,
		encapsulate: s.Encapsulate,
		proto:       uint16(protocol),
		port:        port,
		remoteAddr:  append([]byte{}, remoteAddr...),
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
