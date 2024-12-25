package dns

import (
	"encoding/binary"
	"errors"
)

//go:generate stringer -type=Type,Class,RCode,OpCode -linecomment -output stringers.go .

// common errors. Taken from golang.org/x/net/dns/dnsmessage module.
var (
	errNameTooLong        = errors.New("DNS name exceeds maximum length")
	errNoNullTerm         = errors.New("DNS name missing null terminator")
	errCalcLen            = errors.New("DNS calculated name label length exceeds remaining buffer length")
	errCantAddLabel       = errors.New("long/empty/zterm/escape DNS label or not enough space")
	errBaseLen            = errors.New("insufficient data for base length type")
	errReserved           = errors.New("segment prefix is reserved")
	errTooManyPtr         = errors.New("too many pointers (>10)")
	errInvalidPtr         = errors.New("invalid pointer")
	errInvalidName        = errors.New("invalid dns name")
	errNilResouceBody     = errors.New("nil resource body")
	errResourceLen        = errors.New("insufficient data for resource body length")
	errSegTooLong         = errors.New("segment length too long")
	errZeroSegLen         = errors.New("zero length segment")
	errResTooLong         = errors.New("resource length too long")
	errTooManyQuestions   = errors.New("too many Questions")
	errTooManyAnswers     = errors.New("too many Answers")
	errTooManyAuthorities = errors.New("too many Authorities")
	errTooManyAdditionals = errors.New("too many Additionals")
	errNonCanonicalName   = errors.New("name is not in canonical format (it must end with a .)")
	errStringTooLong      = errors.New("character string exceeds maximum length (255)")
	errCompressedSRV      = errors.New("compressed name in SRV resource data")
)

// Frame encapsulates the raw data of a DNS packet
// and provides methods for manipulating, validating and
// retrieving fields and payload data. See [RFC1035].
//
// [RFC1035]: https://tools.ietf.org/html/rfc1035
type Frame struct {
	buf []byte
}

func NewFrame(buf []byte) Frame {
	return Frame{buf: buf}
}

func (frm Frame) TxID() uint16 {
	return binary.BigEndian.Uint16(frm.buf[0:2])
}

func (frm Frame) SetTxID(txid uint16) {
	binary.BigEndian.PutUint16(frm.buf[0:2], txid)
}

func (frm Frame) Flags() HeaderFlags {
	return HeaderFlags(binary.BigEndian.Uint16(frm.buf[2:4]))
}

func (frm Frame) SetFlags(flags HeaderFlags) {
	binary.BigEndian.PutUint16(frm.buf[2:4], uint16(flags))
}

// QDCount returns number of entries in the question section.
func (frm Frame) QDCount() uint16 {
	return binary.BigEndian.Uint16(frm.buf[4:6])
}

func (frm Frame) SetQDCount(qdCount uint16) {
	binary.BigEndian.PutUint16(frm.buf[4:6], qdCount)
}

// ANCount returns number of resource records in the answer section.
func (frm Frame) ANCount() uint16 {
	return binary.BigEndian.Uint16(frm.buf[6:8])
}

func (frm Frame) SetANCount(anCount uint16) {
	binary.BigEndian.PutUint16(frm.buf[6:8], anCount)
}

// NSCount returns number of name server resource records in the authority records section.
func (frm Frame) NSCount() uint16 {
	return binary.BigEndian.Uint16(frm.buf[8:10])
}

func (frm Frame) SetNSCount(nsCount uint16) {
	binary.BigEndian.PutUint16(frm.buf[8:10], nsCount)
}

// ARCount returns number of resource records in the additional records section.
func (frm Frame) ARCount() uint16 {
	return binary.BigEndian.Uint16(frm.buf[10:12])
}

func (frm Frame) SetARCount(arCount uint16) {
	binary.BigEndian.PutUint16(frm.buf[10:12], arCount)
}

// HeaderFlags gathers the flags in bits 16..31 of the header.
type HeaderFlags uint16

// NewClientHeaderFlags creates the header flags for a client request.
func NewClientHeaderFlags(op OpCode, enableRecursion bool) HeaderFlags {
	return HeaderFlags(op&0b1111)<<11 | HeaderFlags(b2u8(enableRecursion))<<8
}

// IsResponse returns QR bit which specifies whether this message is a query (0), or a response (1).
func (flags HeaderFlags) IsResponse() bool { return flags&(1<<15) != 0 }

// OpCode returns the 4-bit opcode.
func (flags HeaderFlags) OpCode() OpCode { return OpCode(flags>>11) & 0b1111 }

// IsAuthorativeAnswer returns AA bit which specifies that the responding name server is an authority for the domain name in question section.
func (flags HeaderFlags) IsAuthorativeAnswer() bool { return flags&(1<<10) != 0 }

// IsTruncated returns TC bit which specifies that this message was truncated due to length greater than that permitted on the transmission channel.
func (flags HeaderFlags) IsTruncated() bool { return flags&(1<<9) != 0 }

// IsRecursionDesired returns RD bit which specifies whether recursive query support is desired by the client. Is optionally set by client.
func (flags HeaderFlags) IsRecursionDesired() bool { return flags&(1<<8) != 0 }

// IsRecursionAvailable returns RA bit which specifies whether recursive query support is available by the server.
func (flags HeaderFlags) IsRecursionAvailable() bool { return flags&(1<<7) != 0 }

// ResponseCode returns the 4-bit response code set as part of responses.
func (flags HeaderFlags) ResponseCode() RCode { return RCode(flags & 0b1111) }

func (flags HeaderFlags) String() string {
	buf := make([]byte, 0, 16)
	return string(flags.appendF(buf))
}

func (flags HeaderFlags) appendF(buf []byte) []byte {
	writeBit := func(b bool, s string) {
		if b {
			buf = append(buf, s...)
			buf = append(buf, ' ')
		}
	}
	writeBit(flags.IsResponse(), "QR")
	writeBit(flags.IsAuthorativeAnswer(), "AA")
	writeBit(flags.IsTruncated(), "TC")
	writeBit(flags.IsRecursionDesired(), "RD")
	writeBit(flags.IsRecursionAvailable(), "RA")
	buf = append(buf, flags.OpCode().String()...)
	buf = append(buf, ' ')
	buf = append(buf, flags.ResponseCode().String()...)
	return buf
}

const allowCompression = true

// Types taken from golang.org/x/net/dns/dnsmessage package. See https://pkg.go.dev/golang.org/x/net/dns/dnsmessage.

// Type is a type of DNS request and response.
type Type uint16

const (
	// ResourceHeader.Type and Question.Type
	TypeA     Type = 1  // A
	TypeNS    Type = 2  // NS
	TypeCNAME Type = 5  // CNAME
	TypeSOA   Type = 6  // SOA
	TypePTR   Type = 12 // PTR
	TypeMX    Type = 15 // MX
	TypeTXT   Type = 16 // TXT
	TypeAAAA  Type = 28 // AAAA
	TypeSRV   Type = 33 // SRV
	TypeOPT   Type = 41 // OPT

	// Question.Type
	TypeWKS   Type = 11  // WKS
	TypeHINFO Type = 13  // HINFO
	TypeMINFO Type = 14  // MINFO
	TypeAXFR  Type = 252 // AXFR
	TypeALL   Type = 255 // ALL
)

// A Class is a type of network.
type Class uint16

const (
	// ResourceHeader.Class and Question.Class
	ClassINET   Class = 1 // INET
	ClassCSNET  Class = 2 // CSNET
	ClassCHAOS  Class = 3 // CHAOS
	ClassHESIOD Class = 4 // HESIOD

	// Question.Class
	ClassANY Class = 255 // ANY
)

// An OpCode is a DNS operation code which specifies the type of query.
type OpCode uint16

const (
	OpCodeQuery        OpCode = 0 // Standard query
	OpCodeInverseQuery OpCode = 1 // Inverse query
	OpCodeStatus       OpCode = 2 // Server status request
)

// An RCode is a DNS response status code.
type RCode uint16

const (
	// No error condition.
	RCodeSuccess RCode = 0 // success
	// Format error - The name server was unable to interpret the query.
	RCodeFormatError RCode = 1 // format error
	// Server failure - The name server was unable to process this query due to a	problem with the name server.
	RCodeServerFailure RCode = 2 // server failure
	// Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the	domain name referenced in the query does not exist.
	RCodeNameError RCode = 3 // name error
	// Not implemented - The name server does not support the requested kind of query.
	RCodeNotImplemented RCode = 4 // not implemented
	// Refused - The name server refuses to perform the specified operation for policy reasons. For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.
	RCodeRefused RCode = 5 // refused
)

func b2u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
