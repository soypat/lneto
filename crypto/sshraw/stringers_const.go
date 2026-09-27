package sshraw

// StringConst methods name values as String does but always return a
// compile-time constant, unlike String which formats an unrecognized value with
// strconv. Wire values are attacker controlled, so decoders and logs on
// embedded targets use StringConst and print the number alongside it.

// nameUnknown names a value this package does not recognize. Other RFCs may
// well define it, notably the method specific message numbers.
const nameUnknown = "unknown"

// StringConst returns the message type's name, or "unknown".
func (v MsgType) StringConst() string {
	switch v {
	case MsgDisconnect, MsgIgnore, MsgUnimplemented, MsgDebug,
		MsgServiceRequest, MsgServiceAccept, MsgExtInfo,
		MsgKexInit, MsgNewKeys, MsgKexECDHInit, MsgKexECDHReply,
		MsgUserauthRequest, MsgUserauthFailure, MsgUserauthSuccess,
		MsgUserauthBanner, MsgUserauthPKOK,
		MsgGlobalRequest, MsgRequestSuccess, MsgRequestFailure,
		MsgChannelOpen, MsgChannelOpenConfirmation, MsgChannelOpenFailure,
		MsgChannelWindowAdjust, MsgChannelData, MsgChannelExtendedData,
		MsgChannelEOF, MsgChannelClose, MsgChannelRequest,
		MsgChannelSuccess, MsgChannelFailure:
		return v.String()
	}
	return nameUnknown
}

// StringConst returns the disconnect reason's name, or "unknown".
func (v DisconnectReason) StringConst() string {
	if v >= DisconnectHostNotAllowedToConnect && v <= DisconnectIllegalUserName {
		return v.String()
	}
	return nameUnknown
}

// StringConst returns the channel open failure reason's name, or "unknown".
func (v ChannelOpenFailureReason) StringConst() string {
	if v >= OpenAdministrativelyProhibited && v <= OpenResourceShortage {
		return v.String()
	}
	return nameUnknown
}
