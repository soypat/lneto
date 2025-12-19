package internet

import (
	"errors"
	"log/slog"
	"math"
	"net"
	"slices"
)

// StackNode is an abstraction of a packet exchanging protocol controller. This is the building block for all protocols,
// from Ethernet to IP to TCP, practically any protocol can be expressed as a StackNode and function completely.
type StackNode interface {
	// Encapsulate writes the stack node's frame into carrierData[offsetToFrame:]
	// along with any other frame or payload the stack node encapsulates.
	// The returned integer is amount of bytes written such that carrierData[offsetToFrame:offsetToFrame+n]
	// contains written data. Data inside carrierData[:offsetToFrame] usually contains data necessary for
	// a StackNode to correctly emit valid frame data: such is the case for TCP packets which require IP
	// frame data for checksum calculation. Thus StackNodes must provide fields in their own frame
	// required by sub-stacknodes for correct encapsulation; in the case of IPv4/6 this means including fields
	// used in pseudo-header checksum like local IP (see [ipv4.CRCWriteUDPPseudo]).
	//
	// offsetToIP is the offset to the IP frame, if present, else its value should be -1.
	// The relation offsetToIP<=offsetToFrame should always hold.
	//
	// When [net.ErrClosed] is returned the StackNode should be discarded and any written data passed up normally.
	// Errors returned by Encapsulate are "extraordinary" and should not be returned unless the StackNode is receiving invalid carrierData/frameOffset.
	Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error)
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
	encapsulate func([]byte, int, int) (int, error)
	proto       uint16
	port        uint16
	// remoteAddr will be set on active(outbound) port connections
	// that require an ARP to set the remoteAddr beforehand.
	remoteAddr []byte
}

type handlers struct {
	context string
	logger
	nodes []node
}

func (h *handlers) reset(context string, maxNodes int) {
	h.nodes = slices.Grow(h.nodes[:0], maxNodes)
	h.context = context
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

func (h *handlers) demuxByProto(buf []byte, offset int, proto uint16) (*node, error) {
	node := h.nodeByProto(proto)
	if node == nil {
		return nil, nil
	}
	err := node.demux(buf, offset)
	if h.tryHandleError(node, err) {
		err = nil
	}
	return node, err
}

func (h *handlers) demuxByPort(buf []byte, offset int, port uint16) (*node, error) {
	node := h.nodeByPort(port)
	if node == nil {
		return nil, nil
	}
	err := node.demux(buf, offset)
	if h.tryHandleError(node, err) {
		err = nil
	}
	return node, err
}

// encapsulateAny finds a node suitable to write and encapsulates the package.
// If no data is sent it returns the last error encountered.
func (h *handlers) encapsulateAny(buf []byte, offsetIP, offsetThisFrame int) (_ *node, n int, err error) {
	for i := range h.nodes {
		node := &h.nodes[i]
		if node.IsInvalid() || (len(node.remoteAddr) > 0 && isAllZeros(node.remoteAddr)) {
			continue
		}
		n, err = node.encapsulate(buf, offsetIP, offsetThisFrame)
		if h.tryHandleError(node, err) {
			err = nil // CLOSE error handled gracefully by deleting node.
		}
		if n > 0 {
			return node, n, err
		} else if err != nil {
			// Make sure not to hang on one handler that keeps returning an error.
			h.error("handlers:encapsulate", slog.String("func", "encapsulateAny"), slog.String("ctx", h.context), slog.String("err", err.Error()))
		}
	}
	return nil, 0, err // Return last written error.
}

func isAllZeros(b []byte) bool {
	for i := range b {
		if b[i] != 0 {
			return false
		}
	}
	return true
}

var (
	errZeroMaxNodesArg = errors.New("zero max nodes arg")
	errZeroPort        = errors.New("port must be greater than zero")
	errInvalidProto    = errors.New("invalid protocol")
	errProtoRegistered = errors.New("protocol already registered")
	errNodesFull       = errors.New("no more room for new nodes")
	_                  = net.ErrClosed
)

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
		remoteAddr:  remoteAddr, // SHARED MEMORY- used to signal.
	}
}

// destroy removes all references to underlying StackNode. Allows garbage collection of node if possible.
func (n *node) destroy() {
	*n = node{}
}
