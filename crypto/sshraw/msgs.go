package sshraw

import "github.com/soypat/lneto"

// Parsers of the small messages of the transport layer, RFC 4253 11 and 12,
// and RFC 5656 4. Each takes a whole payload, message type byte first, and
// returns views into it. Messages after which the connection goes on reject
// trailing bytes; those after which it ends are parsed leniently since there
// is nothing left to protect. On error vld is left without errors.

// ParseDisconnect parses SSH_MSG_DISCONNECT. desc is peer controlled and may
// contain anything; it must be sanitized before it is displayed.
func ParseDisconnect(vld *lneto.Validator, payload []byte) (reason DisconnectReason, desc, lang []byte, err error) {
	var dec decoder
	dec.Reset(payload, vld)
	dec.msgType(MsgDisconnect)
	reason = DisconnectReason(dec.Uint32())
	desc = dec.String()
	lang = dec.String() // language tag.
	if vld.HasError() {
		return 0, nil, nil, vld.ErrPop()
	}
	return reason, desc, lang, nil
}

// ParseServiceName parses SSH_MSG_SERVICE_REQUEST or SSH_MSG_SERVICE_ACCEPT,
// which carry only a service name, and returns the name.
func ParseServiceName(vld *lneto.Validator, payload []byte) (name []byte, err error) {
	var dec decoder
	dec.Reset(payload, vld)
	if typ := MsgType(dec.Uint8()); typ != MsgServiceRequest && typ != MsgServiceAccept {
		dec.Fail(lneto.ErrInvalidField)
	}
	name = dec.String()
	dec.end()
	if vld.HasError() {
		return nil, vld.ErrPop()
	}
	return name, nil
}

// ParseUnimplemented parses SSH_MSG_UNIMPLEMENTED and returns the sequence
// number of the packet the peer did not recognize.
func ParseUnimplemented(vld *lneto.Validator, payload []byte) (seq uint32, err error) {
	var dec decoder
	dec.Reset(payload, vld)
	dec.msgType(MsgUnimplemented)
	seq = dec.Uint32()
	dec.end()
	if vld.HasError() {
		return 0, vld.ErrPop()
	}
	return seq, nil
}

// ParseDebug parses SSH_MSG_DEBUG. msg is peer controlled and may contain
// anything; it must be sanitized before it is displayed.
func ParseDebug(vld *lneto.Validator, payload []byte) (display bool, msg, lang []byte, err error) {
	var dec decoder
	dec.Reset(payload, vld)
	dec.msgType(MsgDebug)
	display = dec.Bool()
	msg = dec.String()
	lang = dec.String() // language tag.
	dec.end()
	if vld.HasError() {
		return false, nil, nil, vld.ErrPop()
	}
	return display, msg, lang, nil
}

// ParseKexECDHInit parses SSH_MSG_KEX_ECDH_INIT, RFC 5656 4, and returns the
// client's ephemeral public key Q_C. Its length is not checked; that is up to
// the negotiated key exchange method.
func ParseKexECDHInit(vld *lneto.Validator, payload []byte) (qc []byte, err error) {
	var dec decoder
	dec.Reset(payload, vld)
	dec.msgType(MsgKexECDHInit)
	qc = dec.String()
	dec.end()
	if vld.HasError() {
		return nil, vld.ErrPop()
	}
	return qc, nil
}
