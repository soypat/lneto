package internet

import (
	"log/slog"
	"math"
	"net"
	"slices"

	"github.com/soypat/lneto"
)

// StackNode is [lneto.StackNode].
//
// Deprecated: Use lneto.StackNode instead.
type StackNode = lneto.StackNode

// node is a concrete StackNode as stored in Stacks. Methods are devirtualized for performance benefits, especially on TinyGo.
type node struct {
	currConnID uint64
	connID     *uint64
	// cbnode has different definitions in tinygo and normal Go compiled programs
	// for performance and heap control reasons.
	callbacks cbnode
	// demux       func([]byte, int) error
	// encapsulate func([]byte, int, int) (int, error)
	proto uint16
	port  uint16
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
		return lneto.ErrAlreadyRegistered
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
		return lneto.ErrAlreadyRegistered
	}
	h.nodes = append(h.nodes, n)
	return nil
}

func (h *handlers) prepAdd() error {
	if h.full() {
		h.compact()
		if h.full() {
			return lneto.ErrBufferFull
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
		if node.proto == proto && !node.IsInvalid() {
			return node
		}
	}
	return nil
}

func (h *handlers) nodeByPort(port uint16) *node {
	for i := range h.nodes {
		node := &h.nodes[i]
		if node.port == port && !node.IsInvalid() {
			return node
		}
	}
	return nil
}

func (h *handlers) nodeByPortProto(port uint16, protocol uint16) *node {
	for i := range h.nodes {
		node := &h.nodes[i]
		if node.port == port && node.proto == protocol && !node.IsInvalid() {
			return node
		}
	}
	return nil
}

func (h *handlers) demuxByProto(buf []byte, offset int, proto uint16) (*node, error) {
	node := h.nodeByProto(proto)
	if node == nil {
		return nil, lneto.ErrPacketDrop
	}
	err := node.callbacks.Demux(buf, offset)
	if h.tryHandleError(node, err) {
		err = nil
	}

	return node, err
}

func (h *handlers) demuxByPort(buf []byte, offset int, port uint16) (*node, error) {
	node := h.nodeByPort(port)
	if node == nil {
		return nil, lneto.ErrPacketDrop
	}
	err := node.callbacks.Demux(buf, offset)
	if h.tryHandleError(node, err) {
		err = nil
		node = nil // Node is destroyed in tryHandleError and invalidated.
	}
	return node, err
}

// encapsulateAny finds a node suitable to write and encapsulates the package.
// If no data is sent it returns the last error encountered.
func (h *handlers) encapsulateAny(buf []byte, offsetIP, offsetThisFrame int) (_ *node, n int, err error) {
	for i := range h.nodes {
		node := &h.nodes[i]
		if node.IsInvalid() {
			continue
		}
		n, err = node.callbacks.Encapsulate(buf, offsetIP, offsetThisFrame)
		if h.tryHandleError(node, err) {
			err = nil  // CLOSE error handled gracefully by deleting node.
			node = nil // Node is destroyed in tryHandleError and invalidated.
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

var (
	_ = net.ErrClosed
)

func (node *node) IsInvalid() bool {
	return node.callbacks.IsZeroed() || (node.connID != nil && node.currConnID != *node.connID)
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
		currConnID: currConnID,
		connID:     connIDPtr,
		callbacks:  makecbnode(s),
		proto:      uint16(protocol),
		port:       port,
		remoteAddr: remoteAddr, // SHARED MEMORY- used to signal.
	}
}

// destroy removes all references to underlying StackNode. Allows garbage collection of node if possible.
func (n *node) destroy() {
	*n = node{}
}
