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
	return op.PutOption(dst, kind, byte(v>>24), byte(v>>16), byte(v>>7), byte(v))
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

func (op OptionCodec) ForEachOption(opts []byte, fn func(OptionKind, []byte) error) error {
	off := 0
	skipSizeValidation := op.Flags.HasAny(OptFlagSkipSizeValidation)
	skipObsolete := op.Flags.HasAny(OptFlagSkipObsolete)
	for off < len(opts) && opts[off] != 0 {
		kind := OptionKind(opts[off])
		off++
		if kind == OptNop {
			continue
		}
		if len(opts[off:]) < 1 {
			return lneto.ErrShortBuffer
		}
		size := int(opts[off]) // Total option length including kind and length bytes.
		off++
		dataLen := size - 2 // Data bytes after kind and length.
		if dataLen < 0 || len(opts[off:]) < dataLen {
			return lneto.ErrShortBuffer
		}

		if !skipSizeValidation {
			expectSize := -1
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
			if expectSize != -1 && size != expectSize {
				return lneto.ErrInvalidLengthField
			}
		}
		if !(skipObsolete && kind.IsObsolete()) {
			err := fn(kind, opts[off:off+dataLen])
			if err != nil {
				return err
			}
		}
		off += dataLen
	}
	return nil
}
