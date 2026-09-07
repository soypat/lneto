package tcp

import (
	"strings"

	"github.com/soypat/lneto"
)

type OptionKind uint8

const (
	OptEnd                   OptionKind = iota // end of option list
	OptNop                                     // no-operation
	OptMaxSegmentSize                          // maximum segment size
	OptWindowScale                             // window scale
	OptSACKPermitted                           // SACK permitted
	OptSACK                                    // SACK
	OptEcho                                    // echo(obsolete)
	optEchoReply                               // echo reply(obsolete)
	OptTimestamps                              // timestamps
	optPOCP                                    // partial order connection permitted(obsolete)
	optPOSP                                    // partial order service profile(obsolete)
	optCC                                      // CC(obsolete)
	optCCnew                                   // CC.new(obsolete)
	optCCecho                                  // CC.echo(obsolete)
	optACR                                     // alternate checksum request(obsolete)
	optACD                                     // alternate checksum data(obsolete)
	optSkeeter                                 // skeeter
	optBubba                                   // bubba
	OptTrailerChecksum                         // trailer checksum
	optMD5Signature                            // MD5 signature(obsolete)
	OptSCPSCapabilities                        // SCPS capabilities
	OptSNA                                     // selective negative acks
	OptRecordBoundaries                        // record boundaries
	OptCorruptionExperienced                   // corruption experienced
	OptSNAP                                    // SNAP
	OptUnassigned                              // unassigned
	OptCompressionFilter                       // compression filter
	OptQuickStartResponse                      // quick-start response
	OptUserTimeout                             // user timeout or unauthorized use
	OptAuthetication                           // Authentication TCP-AO
	OptMultipath                               // multipath TCP
)

const (
	OptFastOpenCookie        OptionKind = 34  // fast open cookie
	OptEncryptionNegotiation OptionKind = 69  // encryption negotiation
	OptAccurateECN0          OptionKind = 172 // accurate ECN order 0
	OptAccurateECN1          OptionKind = 174 // accurate ECN order 1
)

// IsObsolete returns true if option considered obsolete by newer TCP specifications.
func (kind OptionKind) IsObsolete() bool {
	if kind.IsDefined() {
		return strings.HasSuffix(kind.String(), "(obsolete)")
	}
	return false
}

// IsDefined returns true if the option is a known unreserved option kind.
func (kind OptionKind) IsDefined() bool {
	return kind <= 30 || kind == 34 || kind == 69 || kind == 172 || kind == 174
}

type OptionCodec struct {
	Flags OptionFlags
}

type OptionFlags uint8

const (
	OptFlagSkipSizeValidation OptionFlags = 1 << iota
	OptFlagSkipObsolete
)

func (flags OptionFlags) HasAny(ofTheseFlags OptionFlags) bool {
	return flags&ofTheseFlags != 0
}

func (op OptionCodec) PutOption16(dst []byte, kind OptionKind, v uint16) (int, error) {
	return op.PutOption(dst, kind, byte(v>>8), byte(v))
}

func (op OptionCodec) PutOption32(dst []byte, kind OptionKind, v uint32) (int, error) {
	return op.PutOption(dst, kind, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (op OptionCodec) PutOption(dst []byte, kind OptionKind, data ...byte) (int, error) {
	putSize := 2 + len(data)
	if len(dst) < putSize {
		return -1, lneto.ErrShortBuffer
	} else if putSize > 255 {
		return -1, lneto.ErrInvalidLengthField
	} else if kind == OptNop || kind == OptEnd {
		return -1, lneto.ErrInvalidField
	}
	dst[0] = byte(kind)
	dst[1] = byte(putSize)
	copy(dst[2:], data)
	return putSize, nil
}

// Next parses the next option in opts and returns it along with the remaining buffer.
// Will skip obsolete options and can validate given flags are set.
// Parser must stop calling Next after [OptEnd] returned.
func (op OptionCodec) Next(opts []byte) (kind OptionKind, optData, remainingOpts []byte, err error) {
REDO:
	if len(opts) == 0 || opts[0] == 0 {
		return OptEnd, nil, nil, nil
	}
	var size int
	kind = OptionKind(opts[0])
	if kind == OptNop {
		return kind, nil, opts[1:], nil
	} else if len(opts) == 1 {
		return kind, nil, nil, lneto.ErrTruncatedFrame
	}
	size = int(opts[1])
	if size > len(opts) {
		return kind, nil, nil, lneto.ErrTruncatedFrame
	} else if size < 2 {
		return kind, nil, nil, lneto.ErrInvalidLengthField
	}
	optData = opts[2:size]
	remainingOpts = opts[size:]
	if op.Flags.HasAny(OptFlagSkipObsolete) && kind.IsObsolete() {
		opts = remainingOpts
		goto REDO
	}
	if !op.Flags.HasAny(OptFlagSkipSizeValidation) {
		var expectSize int
		switch kind {
		case OptTimestamps:
			expectSize = 10
		case OptMaxSegmentSize, OptUserTimeout:
			expectSize = 4
		case OptWindowScale:
			expectSize = 3
		case OptSACKPermitted:
			expectSize = 2
		}
		if expectSize != 0 && size != expectSize {
			err = lneto.ErrInvalidLengthField
		}
	}
	return kind, optData, remainingOpts, err
}

// ForEachOption calls fn on all non-End/Nop options in opts. Will skip obsolete options if flag set.
func (op OptionCodec) ForEachOption(opts []byte, fn func(OptionKind, []byte) error) (err error) {
	var kind OptionKind = 1
	var data []byte
	for kind != 0 {
		kind, data, opts, err = op.Next(opts)
		if err != nil {
			break
		} else if kind <= OptNop {
			continue
		} else if err = fn(kind, data); err != nil {
			break
		}
	}
	return err
}
