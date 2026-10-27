package sshraw

import "github.com/soypat/lneto"

// Parsers of the small messages of the transport layer, RFC 4253 11 and 12,
// and RFC 5656 4. Each takes a whole payload, message type byte first, and
// returns views into it. Messages after which the connection goes on reject
// trailing bytes; those after which it ends are parsed leniently since there
// is nothing left to protect. On error vld is left without errors.

// ParseDisconnect parses SSH_MSG_DISCONNECT. desc is peer controlled and may
// contain anything; it must be sanitized before it is displayed.
func ParseDisconnect(payload []byte) (reason DisconnectReason, desc, lang []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgDisconnect)
	reason = DisconnectReason(dec.Uint32())
	desc = dec.String()
	lang = dec.String() // language tag.
	if dec.IsFailed() {
		return 0, nil, nil, dec.Err()
	}
	return reason, desc, lang, nil
}

// ParseServiceName parses SSH_MSG_SERVICE_REQUEST or SSH_MSG_SERVICE_ACCEPT,
// which carry only a service name, and returns the name.
func ParseServiceName(payload []byte) (name []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	if typ := MsgType(dec.Uint8()); typ != MsgServiceRequest && typ != MsgServiceAccept {
		dec.Fail(lneto.ErrInvalidField)
	}
	name = dec.String()
	dec.end()
	if dec.IsFailed() {
		return nil, dec.Err()
	}
	return name, nil
}

// ParseUnimplemented parses SSH_MSG_UNIMPLEMENTED and returns the sequence
// number of the packet the peer did not recognize.
func ParseUnimplemented(payload []byte) (seq uint32, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgUnimplemented)
	seq = dec.Uint32()
	dec.end()
	if dec.IsFailed() {
		return 0, dec.Err()
	}
	return seq, nil
}

// ParseDebug parses SSH_MSG_DEBUG. msg is peer controlled and may contain
// anything; it must be sanitized before it is displayed.
func ParseDebug(payload []byte) (display bool, msg, lang []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgDebug)
	display = dec.Bool()
	msg = dec.String()
	lang = dec.String() // language tag.
	dec.end()
	if dec.IsFailed() {
		return false, nil, nil, dec.Err()
	}
	return display, msg, lang, nil
}

// ParseKexECDHInit parses SSH_MSG_KEX_ECDH_INIT, RFC 5656 4, and returns the
// client's ephemeral public key Q_C. Its length is not checked; that is up to
// the negotiated key exchange method.
func ParseKexECDHInit(payload []byte) (qc []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgKexECDHInit)
	qc = dec.String()
	dec.end()
	if dec.IsFailed() {
		return nil, dec.Err()
	}
	return qc, nil
}

// ParseIgnore parses SSH_MSG_IGNORE, RFC 4253 11.2, and returns its data,
// which carries no meaning and must be ignored.
func ParseIgnore(payload []byte) (data []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgIgnore)
	data = dec.String()
	dec.end()
	if dec.IsFailed() {
		return nil, dec.Err()
	}
	return data, dec.Err()
}

// ParseNewKeys parses SSH_MSG_NEWKEYS, RFC 4253 7.3, which carries only its
// message type. Packets after it in the same direction use the new keys.
func ParseNewKeys(payload []byte) error {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgNewKeys)
	dec.end()
	return dec.Err()
}

// ParseKexECDHReply parses SSH_MSG_KEX_ECDH_REPLY, RFC 5656 4, and returns the
// server's public host key blob K_S, its ephemeral public key Q_S and the
// signature blob over the exchange hash H. None is checked beyond its framing;
// K_S must be verified as the server's host key before the signature is trusted.
func ParseKexECDHReply(payload []byte) (hostKey, qs, sig []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgKexECDHReply)
	hostKey = dec.String()
	qs = dec.String()
	sig = dec.String()
	dec.end()
	if dec.IsFailed() {
		return nil, nil, nil, dec.Err()
	}
	return hostKey, qs, sig, nil
}
