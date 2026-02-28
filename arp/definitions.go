package arp

import (
	"errors"

	"github.com/soypat/lneto"
)

//go:generate stringer -type=Operation -linecomment -output stringers.go .

const (
	sizeHeader   = 8
	sizeHeaderv4 = sizeHeader + 6*2 + 4*2
	sizeHeaderv6 = sizeHeader + 6*2 + 16*2
)

var (
	errQueryPending  = errors.New("arp: query pending")
	errQueryNotFound = errors.New("arp: query not found")

	// errGeneric aliases for common ARP errors.
	errARPBufferFull  = lneto.ErrBufferFull
	errShortARP       = lneto.ErrShortBuffer
	errARPUnsupported = lneto.ErrUnsupported
	errLargeSizes     = lneto.ErrPacketDrop
)

// Operation represents the type of ARP packet, either request or reply/response.
type Operation uint16

const (
	OpRequest Operation = 1 // request
	OpReply   Operation = 2 // reply
)
