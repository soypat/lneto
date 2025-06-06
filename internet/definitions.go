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
	//
	Demux(carrierData []byte, frameOffset int) error
	LocalPort() uint16
	Protocol() uint64
	ConnectionID() *uint64
	// SetFlagPending(flagPending func(numPendingEncapsulations int))
}

// node is a concrete StackNode as stored in Stacks. Methods are devirtualized for performance benefits, especially on TinyGo.
type node struct {
	currConnID  uint64
	connID      *uint64
	demux       func([]byte, int) error
	encapsulate func([]byte, int) (int, error)
	lastErrs    [2]error
	proto       uint16
	port        uint16
}

var (
	errZeroPort        = errors.New("port must be greater than zero")
	errInvalidProto    = errors.New("invalid protocol")
	errProtoRegistered = errors.New("protocol already registered")
	_                  = net.ErrClosed
)

func handleNodeError(nodes *[]node, nodeIdx int, err error) {
	if err != nil {
		badConnID := (*nodes)[nodeIdx].connID != nil && *(*nodes)[nodeIdx].connID != (*nodes)[nodeIdx].currConnID
		if err == net.ErrClosed || (*nodes)[nodeIdx].lastErrs[0] == err || (*nodes)[nodeIdx].lastErrs[1] == err || badConnID {
			*nodes = slices.Delete(*nodes, nodeIdx, nodeIdx+1)
		} else {
			// Advance Queue of errors
			(*nodes)[nodeIdx].lastErrs[1] = (*nodes)[nodeIdx].lastErrs[0]
			(*nodes)[nodeIdx].lastErrs[0] = err
		}
	}
}

func addNode(nodes *[]node, h StackNode, port uint16, protocol uint64) {
	if protocol > math.MaxUint16 {
		panic(">16bit protocol number unsupported")
	}
	var currConnID uint64
	connIDPtr := h.ConnectionID()
	if connIDPtr != nil {
		currConnID = *connIDPtr
	}
	*nodes = append(*nodes, node{
		currConnID:  currConnID,
		connID:      connIDPtr,
		demux:       h.Demux,
		encapsulate: h.Encapsulate,
		proto:       uint16(protocol),
		port:        port,
	})
}
