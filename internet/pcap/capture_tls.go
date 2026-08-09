package pcap

import (
	"encoding/binary"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/x/tls"
)

// maxTLSRecordsPerPacket bounds how many record frames a single packet may
// produce. A TCP segment commonly coalesces several small records, but without
// a bound a segment full of 5-byte empty records would produce thousands of
// frames.
const maxTLSRecordsPerPacket = 8

// payloadIsTLS reports whether payload begins with what could be a TLS record
// header. TLS has no magic number, so this is a heuristic: the content type
// must be one of the four TLS 1.3 defines, the legacy record version must be
// 0x03xx and the declared fragment length must be legal.
//
// It is what lets TLS be captured on any port instead of only on 443, and it
// does not collide with HTTP, whose first byte is a method or version letter
// and never a valid content type.
func payloadIsTLS(payload []byte) bool {
	if len(payload) < tls.SizeHeaderRecord {
		return false
	}
	switch tls.ContentType(payload[0]) {
	case tls.ContentTypeChangeCipherSpec, tls.ContentTypeAlert,
		tls.ContentTypeHandshake, tls.ContentTypeApplicationData:
	default:
		return false
	}
	if payload[1] != 0x03 || payload[2] > 0x04 {
		// Every record version in use is 3.x: TLS 1.0 through 1.3 inclusive.
		return false
	}
	n := int(binary.BigEndian.Uint16(payload[3:5]))
	return n > 0 && n <= tls.MaxCiphertext
}

// CaptureTLS breaks down the TLS records starting at bitOffset. A single entry
// point handles every kind of TLS traffic: a record names its own content type,
// so the caller does not need to know whether it is looking at a handshake, an
// alert or application data, which is what makes capturing a whole port 443
// conversation possible without tracking connection state.
//
// One [Frame] is produced per record, plus one more per cleartext handshake
// message carried inside a handshake record. Everything after the ServerHello
// is encrypted and appears on the wire as application_data; its fragment is
// reported as an opaque payload, since decrypting it needs keys a capture does
// not have.
//
// TLS is a byte stream: a record may span TCP segments and a handshake message
// may span records. Whatever arrived is reported and the affected frame carries
// [tls.ErrNeedMore]; reassembly is out of scope for a stateless breakdown.
func (pc *PacketBreakdown) CaptureTLS(dst []Frame, pkt []byte, bitOffset int) ([]Frame, error) {
	debuglog("pcap:tls:start")
	if bitOffset%8 != 0 {
		return dst, errNotByteAligned
	}
	off := bitOffset / 8
	for nrec := 0; off < len(pkt); nrec++ {
		if nrec == maxTLSRecordsPerPacket {
			reclaimRemainingFrame(&dst, "TLS records?", FieldClassPayload, off*octet, octet*len(pkt))
			break
		}
		newdst, consumed, err := pc.captureTLSRecord(dst, pkt, off*octet)
		dst = newdst
		if err != nil {
			if nrec == 0 {
				// Not TLS after all; let the caller frame the payload.
				return dst, err
			}
			// Bytes trailing the last complete record that are too few or too
			// malformed to be a record header of their own.
			reclaimRemainingFrame(&dst, unknownPayloadProto, FieldClassPayload, off*octet, octet*len(pkt))
			break
		}
		off += consumed
	}
	debuglog("pcap:tls:done")
	return dst, nil
}

// captureTLSRecord appends the frames of the single record at bitOffset and
// returns how many bytes of pkt the record occupied.
func (pc *PacketBreakdown) captureTLSRecord(dst []Frame, pkt []byte, bitOffset int) ([]Frame, int, error) {
	rec := pkt[bitOffset/8:]
	rfrm, err := tls.NewRecordFrame(rec)
	if err != nil {
		return dst, 0, err
	}
	rfrm.ValidateSize(pc.validator())
	if pc.validator().HasError() {
		return dst, 0, pc.validator().ErrPop()
	}
	debuglog("pcap:tls:validated")
	const fragOff = tls.SizeHeaderRecord * octet
	ctype := rfrm.ContentType()
	finfo := reclaimFrame(&dst, "TLS", bitOffset, baseTLSRecordFields[:])
	finfo.Fields[0].Name = ctype.StringConst()
	frag := rfrm.Payload()
	if frag == nil {
		// Fragment continues in a later segment. Report what arrived.
		avail := len(rec) - tls.SizeHeaderRecord
		finfo.Errors = append(finfo.Errors, tls.ErrNeedMore)
		if avail > 0 {
			var flags Flags
			if ctype == tls.ContentTypeApplicationData {
				flags = FlagEncrypted
			}
			finfo.Fields = append(finfo.Fields, FrameField{
				Class:          FieldClassPayload,
				FrameBitOffset: fragOff,
				BitLength:      avail * octet,
				Flags:          flags,
			})
		}
		return dst, len(rec), nil
	}

	switch ctype {
	case tls.ContentTypeHandshake:
		// Handshake messages get frames of their own. finfo must not be touched
		// past this point: appending to dst may move the Frame it points at.
		dst = pc.captureTLSHandshake(dst, pkt, bitOffset+fragOff, len(frag))

	case tls.ContentTypeAlert:
		if len(frag) < 2 {
			finfo.Errors = append(finfo.Errors, lneto.ErrTruncatedFrame)
			break
		}
		// The level byte is advisory only: in TLS 1.3 every alert except
		// close_notify and user_canceled is fatal whatever it says.
		finfo.Fields = append(finfo.Fields, FrameField{
			Name:           tls.AlertLevel(frag[0]).StringConst(),
			Class:          FieldClassType,
			FrameBitOffset: fragOff,
			BitLength:      octet,
			Flags:          FlagLegacy,
		}, FrameField{
			Name:           tls.AlertDescription(frag[1]).StringConst(),
			Class:          FieldClassType,
			FrameBitOffset: fragOff + octet,
			BitLength:      octet,
		})

	case tls.ContentTypeApplicationData:
		// Either genuine application data or a protected handshake or alert
		// record; which of the three is only knowable after decryption.
		finfo.Fields = append(finfo.Fields, FrameField{
			Class:          FieldClassPayload,
			FrameBitOffset: fragOff,
			BitLength:      len(frag) * octet,
			Flags:          FlagEncrypted,
		})

	default: // change_cipher_spec and unrecognized content types.
		finfo.Fields = append(finfo.Fields, FrameField{
			Class:          FieldClassPayload,
			FrameBitOffset: fragOff,
			BitLength:      len(frag) * octet,
		})
	}
	return dst, rfrm.RecordLength(), nil
}

// captureTLSHandshake appends one frame per handshake message found in the
// fragLen bytes of handshake record fragment starting at bitOffset.
func (pc *PacketBreakdown) captureTLSHandshake(dst []Frame, pkt []byte, bitOffset, fragLen int) []Frame {
	debuglog("pcap:tls:hs-start")
	const hdr = tls.SizeHeaderHandshake
	frag := pkt[bitOffset/8:][:fragLen]
	fragEnd := bitOffset + fragLen*octet
	for off := 0; off < fragLen; {
		msgBitOff := bitOffset + off*octet
		hfrm, err := tls.NewHandshakeFrame(frag[off:])
		if err != nil {
			// Fewer than 4 bytes left: a message header split across records.
			reclaimRemainingFrame(&dst, "TLS Handshake?", FieldClassPayload, msgBitOff, fragEnd)
			return dst
		}
		mtype := hfrm.MsgType()
		finfo := reclaimFrame(&dst, tlsHandshakeProto(mtype), msgBitOff, baseTLSHandshakeFields[:])
		finfo.Fields[0].Name = mtype.StringConst()
		body := hfrm.Body()
		if body == nil {
			// Message body continues in the next record.
			finfo.Errors = append(finfo.Errors, tls.ErrNeedMore)
			if avail := fragLen - off - hdr; avail > 0 {
				finfo.Fields = append(finfo.Fields, FrameField{
					Class:          FieldClassPayload,
					FrameBitOffset: hdr * octet,
					BitLength:      avail * octet,
				})
			}
			return dst
		}
		switch mtype {
		case tls.HandshakeTypeClientHello:
			pc.captureTLSHello(finfo, body, true)
		case tls.HandshakeTypeServerHello:
			pc.captureTLSHello(finfo, body, false)
		default:
			if len(body) > 0 {
				finfo.Fields = append(finfo.Fields, FrameField{
					Class:          FieldClassPayload,
					FrameBitOffset: hdr * octet,
					BitLength:      len(body) * octet,
				})
			}
		}
		off += hfrm.MessageLength()
	}
	debuglog("pcap:tls:hs-done")
	return dst
}

// captureTLSHello appends the fields of a ClientHello (isClient) or ServerHello
// body to finfo. The two differ only in that the client offers vectors of
// cipher suites and compression methods where the server names exactly one of
// each. Offsets are relative to the start of the handshake message, so the
// handshake header size is added throughout.
//
// The walk is deliberately more permissive than [tls.NewClientHelloFrame]: a
// capture must show what a malformed hello contains, so it reports the fields
// it did decode and stops at the first inconsistent length instead of
// discarding the message.
func (pc *PacketBreakdown) captureTLSHello(finfo *Frame, body []byte, isClient bool) {
	const hdr = tls.SizeHeaderHandshake
	const fixed = 2 + tls.SizeRandom + 1 // legacy_version + random + session id length
	if len(body) < fixed {
		finfo.Errors = append(finfo.Errors, lneto.ErrTruncatedFrame)
		return
	}
	finfo.Fields = append(finfo.Fields, FrameField{
		// Pinned to 0x0303 by TLS 1.3 whatever version is really negotiated;
		// the real version travels in the supported_versions extension.
		Class:          FieldClassVersion,
		FrameBitOffset: hdr * octet,
		BitLength:      2 * octet,
		Flags:          FlagLegacy,
	}, FrameField{
		Name:           "Random",
		Class:          FieldClassID,
		FrameBitOffset: (hdr + 2) * octet,
		BitLength:      tls.SizeRandom * octet,
	})

	off := 2 + tls.SizeRandom
	sidLen := int(body[off])
	off++
	if sidLen > len(body)-off {
		finfo.Errors = append(finfo.Errors, lneto.ErrTruncatedFrame)
		return
	}
	if sidLen > 0 {
		// TLS 1.3 has no session resumption by ID; a non-empty value means
		// middlebox compatibility mode, echoed verbatim by the server.
		finfo.Fields = append(finfo.Fields, FrameField{
			Name:           "Session ID",
			Class:          FieldClassID,
			FrameBitOffset: (hdr + off) * octet,
			BitLength:      sidLen * octet,
		})
	}
	off += sidLen

	if isClient {
		if len(body)-off < 2 {
			finfo.Errors = append(finfo.Errors, lneto.ErrTruncatedFrame)
			return
		}
		suitesLen := int(binary.BigEndian.Uint16(body[off:]))
		off += 2
		if suitesLen > len(body)-off {
			finfo.Errors = append(finfo.Errors, lneto.ErrTruncatedFrame)
			return
		}
		pc.appendTLSCipherSuites(finfo, body[off:off+suitesLen], hdr+off)
		off += suitesLen

		compLen := int(body[off])
		off++
		if compLen > len(body)-off {
			finfo.Errors = append(finfo.Errors, lneto.ErrTruncatedFrame)
			return
		}
		finfo.Fields = append(finfo.Fields, FrameField{
			Name:           "compression methods",
			Class:          FieldClassOptions,
			FrameBitOffset: (hdr + off) * octet,
			BitLength:      compLen * octet,
			Flags:          FlagLegacy,
		})
		off += compLen
	} else {
		if len(body)-off < 3 {
			finfo.Errors = append(finfo.Errors, lneto.ErrTruncatedFrame)
			return
		}
		suite := tls.CipherSuite(binary.BigEndian.Uint16(body[off:]))
		finfo.Fields = append(finfo.Fields, FrameField{
			Name:           suite.StringConst(),
			Class:          FieldClassType,
			FrameBitOffset: (hdr + off) * octet,
			BitLength:      2 * octet,
		}, FrameField{
			Name:           "compression method",
			Class:          FieldClassOptions,
			FrameBitOffset: (hdr + off + 2) * octet,
			BitLength:      octet,
			Flags:          FlagLegacy,
		})
		off += 3
	}

	if len(body)-off < 2 {
		return // No extensions block. Not a legal 1.3 hello, but not a framing error either.
	}
	extsLen := int(binary.BigEndian.Uint16(body[off:]))
	off += 2
	if extsLen > len(body)-off {
		finfo.Errors = append(finfo.Errors, lneto.ErrTruncatedFrame)
		extsLen = len(body) - off
	}
	pc.appendTLSExtensions(finfo, body[off:off+extsLen], hdr+off)
}

// appendTLSCipherSuites appends a cipher_suites container field whose subfields
// name each offered suite. base is the byte offset of suites within the frame.
// GREASE values show up as their numeric type, which is what a capture should
// display: they carry no meaning and are not an error.
func (pc *PacketBreakdown) appendTLSCipherSuites(finfo *Frame, suites []byte, base int) {
	// Reclaim from the Fields backing array to reuse its SubFields backing array.
	sfield := internal.SliceReclaim(&finfo.Fields)
	*sfield = FrameField{
		Name:           "cipher suites",
		Class:          FieldClassOptions,
		SubFields:      sfield.SubFields[:0],
		FrameBitOffset: base * octet,
		BitLength:      len(suites) * octet,
	}
	if pc.SubfieldLimit <= 0 {
		return
	}
	for off := 0; off+2 <= len(suites); off += 2 {
		if len(sfield.SubFields) >= pc.SubfieldLimit {
			finfo.Errors = append(finfo.Errors, ErrLimitExceeded)
			return
		}
		suite := tls.CipherSuite(binary.BigEndian.Uint16(suites[off:]))
		sfield.SubFields = append(sfield.SubFields, FrameField{
			Name:           suite.StringConst(),
			Class:          FieldClassType,
			FrameBitOffset: (base + off) * octet,
			BitLength:      2 * octet,
		})
	}
}

// appendTLSExtensions appends an extensions container field whose subfields are
// the individual extensions. base is the byte offset of exts within the frame.
func (pc *PacketBreakdown) appendTLSExtensions(finfo *Frame, exts []byte, base int) {
	extfield := internal.SliceReclaim(&finfo.Fields)
	*extfield = FrameField{
		Name:           "extensions",
		Class:          FieldClassOptions,
		SubFields:      extfield.SubFields[:0],
		FrameBitOffset: base * octet,
		BitLength:      len(exts) * octet,
	}
	if pc.SubfieldLimit <= 0 {
		return
	}
	for off := 0; off+4 <= len(exts); {
		ext := tls.ExtensionType(binary.BigEndian.Uint16(exts[off:]))
		n := int(binary.BigEndian.Uint16(exts[off+2:]))
		off += 4
		if n > len(exts)-off {
			finfo.Errors = append(finfo.Errors, lneto.ErrTruncatedFrame)
			return
		}
		if len(extfield.SubFields) >= pc.SubfieldLimit {
			finfo.Errors = append(finfo.Errors, ErrLimitExceeded)
			return
		}
		extfield.SubFields = append(extfield.SubFields, tlsExtensionField(ext, exts[off:off+n], base+off))
		off += n
	}
}

// tlsExtensionField describes a single hello extension. Extensions carrying a
// human readable value point at that value instead of at the whole extension
// body, and the bulky opaque ones are classed as payload so that a
// [Formatter.FilterClasses] can drop them without losing the rest of the hello.
func tlsExtensionField(ext tls.ExtensionType, data []byte, base int) FrameField {
	field := FrameField{
		Name:           ext.StringConst(),
		Class:          FieldClassOptions,
		FrameBitOffset: base * octet,
		BitLength:      len(data) * octet,
	}
	switch ext {
	case tls.ExtServerName:
		// server_name_list(2) + name_type(1) + HostName length(2), then the name.
		// Only host_name(0) is defined, and no client has ever sent a second entry.
		const nameOff = 5
		if len(data) >= nameOff && data[2] == 0 {
			n := int(binary.BigEndian.Uint16(data[3:5]))
			if n <= len(data)-nameOff {
				field.Class = FieldClassText
				field.FrameBitOffset = (base + nameOff) * octet
				field.BitLength = n * octet
			}
		}

	case tls.ExtALPN:
		// Each protocol name is length prefixed. Quoting the whole list keeps
		// every name visible, with the length bytes showing up as escapes.
		if len(data) >= 2 {
			field.Class = FieldClassText
			field.FrameBitOffset = (base + 2) * octet
			field.BitLength = (len(data) - 2) * octet
		}

	case tls.ExtKeyShare, tls.ExtPreSharedKey, tls.ExtPadding, tls.ExtSessionTicket,
		tls.ExtCookie, tls.ExtEncryptedClientHello, tls.ExtSignedCertificateTimestamp:
		// Opaque and large: a post-quantum key share alone runs past 1kB.
		field.Class = FieldClassPayload
	}
	return field
}

// tlsHandshakeProto names the frame of a handshake message. Only the messages a
// capture can see in cleartext get a name of their own; the rest travel inside
// a protected record and never reach here undecrypted.
func tlsHandshakeProto(t tls.HandshakeType) string {
	switch t {
	case tls.HandshakeTypeClientHello:
		return "TLS ClientHello"
	case tls.HandshakeTypeServerHello:
		return "TLS ServerHello"
	}
	return "TLS Handshake"
}

var baseTLSRecordFields = [...]FrameField{
	{
		// Name is filled in with the content type's name by captureTLSRecord.
		Class:          FieldClassType,
		FrameBitOffset: 0,
		BitLength:      1 * octet,
	},
	{
		// legacy_record_version, which TLS 1.3 receivers ignore entirely.
		Class:          FieldClassVersion,
		FrameBitOffset: 1 * octet,
		BitLength:      2 * octet,
		Flags:          FlagLegacy,
	},
	{
		Class:          FieldClassSize,
		FrameBitOffset: 3 * octet,
		BitLength:      2 * octet,
	},
}

var baseTLSHandshakeFields = [...]FrameField{
	{
		// Name is filled in with the message type's name by captureTLSHandshake.
		Class:          FieldClassType,
		FrameBitOffset: 0,
		BitLength:      1 * octet,
	},
	{
		Class:          FieldClassSize,
		FrameBitOffset: 1 * octet,
		BitLength:      3 * octet,
	},
}
