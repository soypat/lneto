package sshraw

import "github.com/soypat/lneto"

// User authentication method names of [ParseUserauthRequest].
const (
	MethodNone                = "none"
	MethodPublicKey           = "publickey"
	MethodPassword            = "password"
	MethodKeyboardInteractive = "keyboard-interactive"
)

// PublicKeyAuthData writes the data signed for publickey user authentication: session ID sid of
// [KeySchedule.SessionID] then the USERAUTH_REQUEST payload up to, not including, the signature.
func (e *Encoder) PublicKeyAuthData(sid, user, service, alg, pubKey []byte) {
	if len(sid) == 0 {
		e.Fail(lneto.ErrBadState) // A signature over no session ID could be replayed in any session.
		return
	} else if err := validateName(alg); err != nil {
		e.Fail(err)
		return
	}
	e.String(sid)
	e.Uint8(uint8(MsgUserauthRequest))
	e.String(user)
	e.String(service)
	e.Str(MethodPublicKey)
	e.Bool(true)
	e.String(alg)
	e.String(pubKey)
}

// ParseUserauthRequest parses SSH_MSG_USERAUTH_REQUEST returning the fields of method in methodData,
// parsed by ParsePublicKeyAuth, ParsePasswordAuth or ParseKeyboardInteractiveAuth. user is peer controlled.
func ParseUserauthRequest(payload []byte) (user, service, method, methodData []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgUserauthRequest)
	user = dec.String()
	service = dec.String()
	method = dec.name()
	if dec.IsFailed() {
		return nil, nil, nil, nil, dec.Err()
	}
	return user, service, method, payload[dec.Off():], nil
}

// ParsePublicKeyAuth parses publickey methodData of ParseUserauthRequest. Unsigned requests ask for
// USERAUTH_PK_OK; a signed one's sig is verified over PublicKeyAuthData, see ParseSignature.
func ParsePublicKeyAuth(methodData []byte) (signed bool, alg, pubKey, sig []byte, err error) {
	var dec decoder
	dec.Reset(methodData)
	signed = dec.Bool()
	alg = dec.name()
	pubKey = dec.String()
	if signed {
		sig = dec.String()
	}
	dec.end()
	if dec.IsFailed() {
		return false, nil, nil, nil, dec.Err()
	}
	return signed, alg, pubKey, sig, nil
}

// ParsePasswordAuth parses password methodData of ParseUserauthRequest. newPassword is set when change is true.
// Passwords are views into methodData, which should be wiped after use.
func ParsePasswordAuth(methodData []byte) (change bool, password, newPassword []byte, err error) {
	var dec decoder
	dec.Reset(methodData)
	change = dec.Bool()
	password = dec.String()
	if change {
		newPassword = dec.String()
	}
	dec.end()
	if dec.IsFailed() {
		return false, nil, nil, dec.Err()
	}
	return change, password, newPassword, nil
}

// ParseKeyboardInteractiveAuth parses keyboard-interactive methodData of ParseUserauthRequest.
// submethods is a hint for the server; lang is deprecated and usually empty.
func ParseKeyboardInteractiveAuth(methodData []byte) (lang, submethods []byte, err error) {
	var dec decoder
	dec.Reset(methodData)
	lang = dec.String()
	submethods = dec.String()
	dec.end()
	if dec.IsFailed() {
		return nil, nil, dec.Err()
	}
	return lang, submethods, nil
}

// ParseUserauthFailure parses SSH_MSG_USERAUTH_FAILURE returning the name-list of methods that can
// continue, see HasName. partial is true when the last request succeeded but more are required.
func ParseUserauthFailure(payload []byte) (methods []byte, partial bool, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgUserauthFailure)
	methods = dec.NameList()
	partial = dec.Bool()
	dec.end()
	if dec.IsFailed() {
		return nil, false, dec.Err()
	}
	return methods, partial, nil
}

// ParseUserauthSuccess parses SSH_MSG_USERAUTH_SUCCESS, which carries only its message type.
func ParseUserauthSuccess(payload []byte) error {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgUserauthSuccess)
	dec.end()
	return dec.Err()
}

// ParseUserauthBanner parses SSH_MSG_USERAUTH_BANNER. msg is peer controlled; sanitize before display.
func ParseUserauthBanner(payload []byte) (msg, lang []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgUserauthBanner)
	msg = dec.String()
	lang = dec.String()
	dec.end()
	if dec.IsFailed() {
		return nil, nil, dec.Err()
	}
	return msg, lang, nil
}

// ParseUserauthPKOK parses SSH_MSG_USERAUTH_PK_OK, the reply to an unsigned publickey request
// echoing its alg and pubKey.
func ParseUserauthPKOK(payload []byte) (alg, pubKey []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgUserauthPKOK)
	alg = dec.String()
	pubKey = dec.String()
	dec.end()
	if dec.IsFailed() {
		return nil, nil, dec.Err()
	}
	return alg, pubKey, nil
}

// ParseUserauthPasswdChangeReq parses SSH_MSG_USERAUTH_PASSWD_CHANGEREQ. prompt is peer controlled;
// sanitize before display.
func ParseUserauthPasswdChangeReq(payload []byte) (prompt, lang []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgUserauthPasswdChangeReq)
	prompt = dec.String()
	lang = dec.String()
	dec.end()
	if dec.IsFailed() {
		return nil, nil, dec.Err()
	}
	return prompt, lang, nil
}

// ValidateUserauthInfoRequest validates SSH_MSG_USERAUTH_INFO_REQUEST returning its prompts to iterate
// with NextUserauthPrompt. name, instruction and prompts are peer controlled; sanitize before display.
func ValidateUserauthInfoRequest(payload []byte) (name, instruction, lang, prompts []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgUserauthInfoRequest)
	name = dec.String()
	instruction = dec.String()
	lang = dec.String()
	count := dec.Uint32()
	if dec.IsFailed() {
		return nil, nil, nil, nil, dec.Err()
	}
	prompts = payload[dec.Off():]
	rest := prompts
	// count is peer controlled: each prompt takes at least 5 bytes, bounding the loop by payload length.
	for ; count > 0; count-- {
		_, _, n, err := NextUserauthPrompt(rest)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		rest = rest[n:]
	}
	if len(rest) != 0 {
		return nil, nil, nil, nil, lneto.ErrInvalidLengthField
	}
	return name, instruction, lang, prompts, nil
}

// NextUserauthPrompt returns the first prompt of prompts, whether the response may be echoed,
// and the bytes it takes.
func NextUserauthPrompt(prompts []byte) (prompt []byte, echo bool, n int, err error) {
	var dec decoder
	dec.Reset(prompts)
	prompt = dec.String()
	echo = dec.Bool()
	if dec.IsFailed() {
		return nil, false, 0, dec.Err()
	}
	return prompt, echo, dec.Off(), nil
}

// ValidateUserauthInfoResponse validates SSH_MSG_USERAUTH_INFO_RESPONSE returning its responses
// to iterate with NextUserauthResponse.
func ValidateUserauthInfoResponse(payload []byte) (responses []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgUserauthInfoResponse)
	count := dec.Uint32()
	if dec.IsFailed() {
		return nil, dec.Err()
	}
	responses = payload[dec.Off():]
	rest := responses
	// count is peer controlled: each response takes at least 4 bytes, bounding the loop by payload length.
	for ; count > 0; count-- {
		_, n, err := NextUserauthResponse(rest)
		if err != nil {
			return nil, err
		}
		rest = rest[n:]
	}
	if len(rest) != 0 {
		return nil, lneto.ErrInvalidLengthField
	}
	return responses, nil
}

// NextUserauthResponse returns the first response of responses and the bytes it takes.
// Responses may hold secrets; wipe the payload after use.
func NextUserauthResponse(responses []byte) (response []byte, n int, err error) {
	var dec decoder
	dec.Reset(responses)
	response = dec.String()
	if dec.IsFailed() {
		return nil, 0, dec.Err()
	}
	return response, dec.Off(), nil
}
