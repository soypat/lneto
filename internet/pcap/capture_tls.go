package pcap

import (
	"encoding/binary"

	"github.com/soypat/lneto"
	tls "github.com/soypat/lneto/crypto/tlsraw"
	"github.com/soypat/lneto/internal"
)

// maxTLSRecordsPerPacket bounds how many record frames a single packet may
// produce. A TCP segment commonly coalesces several small records, but without
// a bound a segment full of 5-byte empty records would produce thousands of
// frames.
const maxTLSRecordsPerPacket = 8

// CaptureTLS breaks down the TLS records starting at bitOffset. It is the only
// way TLS gets captured: TCP payloads are never sniffed for TLS, so the caller
// decides which bytes are TLS, e.g. by connection or port. A record names its
// own content type, so the caller need not know whether it is looking at a
// handshake, an alert or application data.
//
// One [Frame] is produced per record, plus one more per cleartext handshake
// message carried inside a handshake record. Everything after the ServerHello
// is encrypted and appears on the wire as application_data; its fragment is
// reported as an opaque payload, since decrypting it needs keys a capture does
// not have.
//
// TLS is a byte stream: a record may span TCP segments and a handshake message
// may span records. Whatever arrived is reported and the affected frame carries
// [lneto.ErrTruncatedFrame]; reassembly is out of scope for a stateless breakdown.
func (pc *PacketBreakdown) CaptureTLS(dst []Frame, pkt []byte, bitOffset int) ([]Frame, error) {
	debuglog("pcap:tls:start")
	if dst == nil {
		dst = pc.initFrames()
	}
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
	if len(rec) < tls.SizeHeaderRecord {
		return dst, 0, lneto.ErrTruncatedFrame
	}
	fragLen := int(binary.BigEndian.Uint16(rec[3:5]))
	if fragLen > tls.MaxCiphertext {
		// Checked before the length is ever used to size a read.
		return dst, 0, lneto.ErrInvalidLengthField
	}
	debuglog("pcap:tls:validated")
	const fragOff = tls.SizeHeaderRecord * octet
	ctype := tls.ContentType(rec[0])
	finfo := reclaimFrame(&dst, "TLS", bitOffset, baseTLSRecordFields[:])
	finfo.Fields[0].Name = ctype.StringConst()
	recLen := tls.SizeHeaderRecord + fragLen
	if len(rec) < recLen {
		// Fragment continues in a later segment. Report what arrived.
		avail := len(rec) - tls.SizeHeaderRecord
		finfo.Errors = append(finfo.Errors, lneto.ErrTruncatedFrame)
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

	frag := rec[tls.SizeHeaderRecord:recLen]
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
			// AlertDescription has no allocation-free name; shown as a number.
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
	return dst, recLen, nil
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
		msg := frag[off:]
		if len(msg) < hdr {
			// A message header split across records.
			reclaimRemainingFrame(&dst, "TLS Handshake?", FieldClassPayload, msgBitOff, fragEnd)
			return dst
		}
		mtype := tls.HandshakeType(msg[0])
		finfo := reclaimFrame(&dst, tlsHandshakeProto(mtype), msgBitOff, baseTLSHandshakeFields[:])
		finfo.Fields[0].Name = mtype.StringConst()
		msgLen := hdr + (int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3]))
		if len(msg) < msgLen {
			// Message body continues in the next record.
			finfo.Errors = append(finfo.Errors, lneto.ErrTruncatedFrame)
			if avail := fragLen - off - hdr; avail > 0 {
				finfo.Fields = append(finfo.Fields, FrameField{
					Class:          FieldClassPayload,
					FrameBitOffset: hdr * octet,
					BitLength:      avail * octet,
				})
			}
			return dst
		}
		body := msg[hdr:msgLen]
		switch mtype {
		case tls.HandshakeTypeClientHello:
			pc.captureTLSClientHello(finfo, body)
		case tls.HandshakeTypeServerHello:
			pc.captureTLSServerHello(finfo, body)
		default:
			if len(body) > 0 {
				finfo.Fields = append(finfo.Fields, FrameField{
					Class:          FieldClassPayload,
					FrameBitOffset: hdr * octet,
					BitLength:      len(body) * octet,
				})
			}
		}
		off += msgLen
	}
	debuglog("pcap:tls:hs-done")
	return dst
}

// captureTLSClientHello appends the fields of a ClientHello body to finfo.
// Field offsets come from the decoded message's views of body.
func (pc *PacketBreakdown) captureTLSClientHello(finfo *Frame, body []byte) {
	var msg tls.HelloClientMsg
	if !pc.decodeTLSHello(finfo, body, msg.Decode) {
		return
	}
	appendTLSHelloHead(finfo, body, msg.SessionID())
	suites := msg.Suites()
	pc.appendTLSCipherSuites(finfo, body, suites)
	comp := msg.Compressions()
	finfo.Fields = append(finfo.Fields, FrameField{
		Name:           "compression methods",
		Class:          FieldClassOptions,
		FrameBitOffset: helloBitOffset(subOffset(body, comp)),
		BitLength:      len(comp) * octet,
		Flags:          FlagLegacy,
	})
	pc.appendTLSExtensions(finfo, body, msg.Extensions(), false)
}

// captureTLSServerHello appends the fields of a ServerHello body to finfo. It
// differs from the client's in naming one suite and one compression method
// where the client offers a list of each.
func (pc *PacketBreakdown) captureTLSServerHello(finfo *Frame, body []byte) {
	var msg tls.HelloServerMsg
	if !pc.decodeTLSHello(finfo, body, msg.Decode) {
		return
	}
	sid := msg.SessionID()
	appendTLSHelloHead(finfo, body, sid)
	suiteOff := subOffset(body, sid) + len(sid)
	finfo.Fields = append(finfo.Fields, FrameField{
		Name:           msg.CipherSuite().StringConst(),
		Class:          FieldClassType,
		FrameBitOffset: helloBitOffset(suiteOff),
		BitLength:      2 * octet,
	}, FrameField{
		Name:           "compression method",
		Class:          FieldClassOptions,
		FrameBitOffset: helloBitOffset(suiteOff + 2),
		BitLength:      octet,
		Flags:          FlagLegacy,
	})
	pc.appendTLSExtensions(finfo, body, msg.Extensions(), true)
}

// decodeTLSHello decodes a hello body and reports whether it can be broken down.
// A hello that did not decode has no field offsets to show: the error and the
// raw bytes are all a capture can say.
func (pc *PacketBreakdown) decodeTLSHello(finfo *Frame, body []byte, decode func([]byte, *lneto.Validator) (int, error)) bool {
	n, err := decode(body, pc.validator())
	if err == nil && n != len(body) {
		err = lneto.ErrInvalidLengthField // Trailing bytes after the extensions.
	}
	if err == nil {
		return true
	}
	finfo.Errors = append(finfo.Errors, err)
	finfo.Fields = append(finfo.Fields, FrameField{
		Class:          FieldClassPayload,
		FrameBitOffset: helloBitOffset(0),
		BitLength:      len(body) * octet,
	})
	return false
}

// subOffset returns where sub starts within buf. sub must be a subslice of buf.
func subOffset(buf, sub []byte) int { return cap(buf) - cap(sub) }

// helloBitOffset converts an offset within a hello body to one within the
// handshake message frame.
func helloBitOffset(bodyOff int) int {
	return (tls.SizeHeaderHandshake + bodyOff) * octet
}

// appendTLSHelloHead appends the fields both hellos begin with.
func appendTLSHelloHead(finfo *Frame, body, sessionID []byte) {
	finfo.Fields = append(finfo.Fields, FrameField{
		// legacy_version. TLS 1.3 pins it to 0x0303 and carries the real version
		// in supported_versions.
		Class:          FieldClassVersion,
		FrameBitOffset: helloBitOffset(0),
		BitLength:      2 * octet,
		Flags:          FlagLegacy,
	}, FrameField{
		Name:           "Random",
		Class:          FieldClassID,
		FrameBitOffset: helloBitOffset(2),
		BitLength:      tls.SizeHelloRandom * octet,
	})
	if len(sessionID) > 0 {
		// TLS 1.3 has no resumption by session ID; a non-empty value means
		// middlebox compatibility mode, echoed verbatim by the server.
		finfo.Fields = append(finfo.Fields, FrameField{
			Name:           "Session ID",
			Class:          FieldClassID,
			FrameBitOffset: helloBitOffset(subOffset(body, sessionID)),
			BitLength:      len(sessionID) * octet,
		})
	}
}

// appendTLSCipherSuites appends a cipher_suites container field whose subfields
// name each offered suite. GREASE values show up as such, which is what a
// capture should display: they carry no meaning and are not an error.
func (pc *PacketBreakdown) appendTLSCipherSuites(finfo *Frame, body, suites []byte) {
	base := subOffset(body, suites)
	// Reclaim from the Fields backing array to reuse its SubFields backing array.
	sfield := internal.SliceReclaim(&finfo.Fields)
	*sfield = FrameField{
		Name:           "cipher suites",
		Class:          FieldClassOptions,
		SubFields:      sfield.SubFields[:0],
		FrameBitOffset: helloBitOffset(base),
		BitLength:      len(suites) * octet,
	}
	if pc.SubfieldLimit <= 0 {
		return
	}
	for off := 0; off+1 < len(suites); off += 2 {
		if len(sfield.SubFields) >= pc.SubfieldLimit {
			finfo.Errors = append(finfo.Errors, ErrLimitExceeded)
			return
		}
		suite := tls.CipherSuite(binary.BigEndian.Uint16(suites[off:]))
		sfield.SubFields = append(sfield.SubFields, FrameField{
			Name:           suite.StringConst(),
			Class:          FieldClassType,
			FrameBitOffset: helloBitOffset(base + off),
			BitLength:      2 * octet,
		})
	}
}

// appendTLSExtensions appends an extensions container field whose subfields are
// the individual extensions. A malformed extension is reported on the frame and
// shown without looking inside it, so the rest of the hello stays visible.
func (pc *PacketBreakdown) appendTLSExtensions(finfo *Frame, body, exts []byte, sentByServer bool) {
	base := subOffset(body, exts)
	extfield := internal.SliceReclaim(&finfo.Fields)
	*extfield = FrameField{
		Name:           "extensions",
		Class:          FieldClassOptions,
		SubFields:      extfield.SubFields[:0],
		FrameBitOffset: helloBitOffset(base),
		BitLength:      len(exts) * octet,
	}
	if pc.SubfieldLimit <= 0 {
		return
	}
	vld := pc.validator()
	for rest := exts; len(rest) > 0; {
		if len(extfield.SubFields) >= pc.SubfieldLimit {
			finfo.Errors = append(finfo.Errors, ErrLimitExceeded)
			return
		}
		ext, err := tls.NewExtensionFrame(rest)
		if err != nil {
			finfo.Errors = append(finfo.Errors, err)
			return
		}
		ext.ValidateType(vld, sentByServer)
		valid := !vld.HasError()
		if !valid {
			finfo.Errors = append(finfo.Errors, vld.ErrPop())
		}
		extfield.SubFields = append(extfield.SubFields, tlsExtensionField(ext, body, valid))
		rest = rest[len(ext.RawData()):]
	}
}

// tlsExtensionField describes a single hello extension. ExtensionType has no
// allocation-free name, so the field spans the whole extension and its type
// shows as the leading 2 bytes. Extensions carrying a human readable value point
// at that value instead, and the bulky opaque ones are classed as payload so
// that a [Formatter.FilterClasses] can drop them without losing the rest of the
// hello. The value is only looked for in a valid extension.
func tlsExtensionField(ext tls.ExtensionFrame, body []byte, valid bool) FrameField {
	data := ext.Data()
	raw := ext.RawData()
	field := FrameField{
		Class:          FieldClassOptions,
		FrameBitOffset: helloBitOffset(subOffset(body, raw)),
		BitLength:      len(raw) * octet,
	}
	if !valid {
		return field
	}
	switch ext.Type() {
	case tls.ExtServerName:
		// ServerNameList of name_type(1) and HostName<1..2^16-1>. A server
		// acknowledges with empty data, which has no name to show.
		for off := 2; off+3 <= len(data); {
			n := int(binary.BigEndian.Uint16(data[off+1:]))
			if data[off] == 0 { // Only host_name is defined.
				field.Class = FieldClassText
				field.FrameBitOffset = helloBitOffset(subOffset(body, data[off+3:]))
				field.BitLength = n * octet
				break
			}
			off += 3 + n
		}

	case tls.ExtALPN:
		// Span the first name through the last so every offered protocol stays
		// visible; the length bytes between them show up as escapes.
		if len(data) > 3 {
			field.Class = FieldClassText
			field.FrameBitOffset = helloBitOffset(subOffset(body, data[3:]))
			field.BitLength = (len(data) - 3) * octet
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
