package arp

import "errors"

//go:generate stringer -type=Operation -linecomment -output stringers.go .

const (
	sizeHeader   = 8
	sizeHeaderv4 = sizeHeader + 6*2 + 4*2
	sizeHeaderv6 = sizeHeader + 6*2 + 16*2
)

var (
	errARPBufferFull  = errors.New("ARP client need handling:too many ops pending")
	errShortARP       = errors.New("packet too short to be ARP")
	errARPUnsupported = errors.New("ARP not supprortedf")
)

// Operation represents the type of ARP packet, either request or reply/response.
type Operation uint8

const (
	OpRequest Operation = 1 // request
	OpReply   Operation = 2 // reply
)
