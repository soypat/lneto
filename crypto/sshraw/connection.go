package sshraw

import "github.com/soypat/lneto"

// Channel types of [ParseChannelOpen].
const (
	ChannelSession        = "session"
	ChannelDirectTCPIP    = "direct-tcpip"
	ChannelForwardedTCPIP = "forwarded-tcpip"
)

// Request names of [ParseGlobalRequest] and [ParseChannelRequest].
const (
	ReqTCPIPForward       = "tcpip-forward"        // Global, data parsed by ParseTCPIPForward.
	ReqCancelTCPIPForward = "cancel-tcpip-forward" // Global, data parsed by ParseTCPIPForward.
	ReqKeepalive          = "keepalive@openssh.com"
	ReqPtyReq             = "pty-req"       // Data parsed by ParsePtyReq.
	ReqEnv                = "env"           // Data parsed by ParseEnvReq.
	ReqShell              = "shell"         // No data.
	ReqExec               = "exec"          // Data parsed by ParseRequestString.
	ReqSubsystem          = "subsystem"     // Data parsed by ParseRequestString.
	ReqWindowChange       = "window-change" // Data parsed by ParseWindowChange.
	ReqSignal             = "signal"        // Data parsed by ParseRequestString.
	ReqExitStatus         = "exit-status"   // Data parsed by ParseExitStatus.
	ReqExitSignal         = "exit-signal"   // Data parsed by ParseExitSignal.
)

const (
	// ExtendedDataStderr is the data type code of stderr in [ParseChannelExtendedData].
	ExtendedDataStderr = 1
	// TTYOpEnd ends encoded terminal modes, see [ValidateTerminalModes].
	TTYOpEnd = 0
	// ttyOpUndefined is the first opcode not yet defined; it stops parsing of terminal modes.
	ttyOpUndefined = 160
)

// ParseGlobalRequest parses SSH_MSG_GLOBAL_REQUEST returning request specific data, see [ReqTCPIPForward].
func ParseGlobalRequest(payload []byte) (name []byte, wantReply bool, data []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgGlobalRequest)
	name = dec.name()
	wantReply = dec.Bool()
	if dec.IsFailed() {
		return nil, false, nil, dec.Err()
	}
	return name, wantReply, payload[dec.Off():], nil
}

// ParseRequestSuccess parses SSH_MSG_REQUEST_SUCCESS returning request specific data,
// the bound uint32 port for a tcpip-forward of port 0.
func ParseRequestSuccess(payload []byte) (data []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgRequestSuccess)
	if dec.IsFailed() {
		return nil, dec.Err()
	}
	return payload[dec.Off():], nil
}

// ParseRequestFailure parses SSH_MSG_REQUEST_FAILURE, which carries only its message type.
func ParseRequestFailure(payload []byte) error {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgRequestFailure)
	dec.end()
	return dec.Err()
}

// ParseTCPIPForward parses data of a tcpip-forward or cancel-tcpip-forward global request.
func ParseTCPIPForward(data []byte) (addr []byte, port uint32, err error) {
	var dec decoder
	dec.Reset(data)
	addr = dec.String()
	port = dec.Uint32()
	dec.end()
	if dec.IsFailed() {
		return nil, 0, dec.Err()
	}
	return addr, port, nil
}

// ParseChannelOpen parses SSH_MSG_CHANNEL_OPEN returning channel type specific data,
// parsed by ParseChannelOpenTCPIP for tcpip channels. Session channels have none.
func ParseChannelOpen(payload []byte) (chanType []byte, sender, window, maxPacket uint32, data []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgChannelOpen)
	chanType = dec.name()
	sender = dec.Uint32()
	window = dec.Uint32()
	maxPacket = dec.Uint32()
	if dec.IsFailed() {
		return nil, 0, 0, 0, nil, dec.Err()
	}
	return chanType, sender, window, maxPacket, payload[dec.Off():], nil
}

// ParseChannelOpenTCPIP parses data of a direct-tcpip or forwarded-tcpip ParseChannelOpen:
// host and port to connect to, or that were connected, and the originator's address and port.
func ParseChannelOpenTCPIP(data []byte) (host []byte, port uint32, origAddr []byte, origPort uint32, err error) {
	var dec decoder
	dec.Reset(data)
	host = dec.String()
	port = dec.Uint32()
	origAddr = dec.String()
	origPort = dec.Uint32()
	dec.end()
	if dec.IsFailed() {
		return nil, 0, nil, 0, dec.Err()
	}
	return host, port, origAddr, origPort, nil
}

// ParseChannelOpenConfirmation parses SSH_MSG_CHANNEL_OPEN_CONFIRMATION returning channel type specific data.
func ParseChannelOpenConfirmation(payload []byte) (recipient, sender, window, maxPacket uint32, data []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgChannelOpenConfirmation)
	recipient = dec.Uint32()
	sender = dec.Uint32()
	window = dec.Uint32()
	maxPacket = dec.Uint32()
	if dec.IsFailed() {
		return 0, 0, 0, 0, nil, dec.Err()
	}
	return recipient, sender, window, maxPacket, payload[dec.Off():], nil
}

// ParseChannelOpenFailure parses SSH_MSG_CHANNEL_OPEN_FAILURE. desc is peer controlled; sanitize before display.
func ParseChannelOpenFailure(payload []byte) (recipient uint32, reason ChannelOpenFailureReason, desc, lang []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgChannelOpenFailure)
	recipient = dec.Uint32()
	reason = ChannelOpenFailureReason(dec.Uint32())
	desc = dec.String()
	lang = dec.String()
	dec.end()
	if dec.IsFailed() {
		return 0, 0, nil, nil, dec.Err()
	}
	return recipient, reason, desc, lang, nil
}

// ParseChannelWindowAdjust parses SSH_MSG_CHANNEL_WINDOW_ADJUST. The window must not exceed 2^32-1 after adding add.
func ParseChannelWindowAdjust(payload []byte) (recipient, add uint32, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgChannelWindowAdjust)
	recipient = dec.Uint32()
	add = dec.Uint32()
	dec.end()
	if dec.IsFailed() {
		return 0, 0, dec.Err()
	}
	return recipient, add, nil
}

// ParseChannelData parses SSH_MSG_CHANNEL_DATA. data counts against the channel window.
func ParseChannelData(payload []byte) (recipient uint32, data []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgChannelData)
	recipient = dec.Uint32()
	data = dec.String()
	dec.end()
	if dec.IsFailed() {
		return 0, nil, dec.Err()
	}
	return recipient, data, nil
}

// ParseChannelExtendedData parses SSH_MSG_CHANNEL_EXTENDED_DATA. code is [ExtendedDataStderr] for stderr.
// data counts against the channel window.
func ParseChannelExtendedData(payload []byte) (recipient, code uint32, data []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgChannelExtendedData)
	recipient = dec.Uint32()
	code = dec.Uint32()
	data = dec.String()
	dec.end()
	if dec.IsFailed() {
		return 0, 0, nil, dec.Err()
	}
	return recipient, code, data, nil
}

// ParseChannelRecipient parses SSH_MSG_CHANNEL_EOF, CHANNEL_CLOSE, CHANNEL_SUCCESS or CHANNEL_FAILURE,
// which carry only the recipient channel.
func ParseChannelRecipient(payload []byte) (recipient uint32, err error) {
	var dec decoder
	dec.Reset(payload)
	switch MsgType(dec.Uint8()) {
	case MsgChannelEOF, MsgChannelClose, MsgChannelSuccess, MsgChannelFailure:
	default:
		dec.Fail(lneto.ErrInvalidField)
	}
	recipient = dec.Uint32()
	dec.end()
	if dec.IsFailed() {
		return 0, dec.Err()
	}
	return recipient, nil
}

// ParseChannelRequest parses SSH_MSG_CHANNEL_REQUEST returning request specific data, see [ReqPtyReq].
func ParseChannelRequest(payload []byte) (recipient uint32, reqType []byte, wantReply bool, data []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgChannelRequest)
	recipient = dec.Uint32()
	reqType = dec.name()
	wantReply = dec.Bool()
	if dec.IsFailed() {
		return 0, nil, false, nil, dec.Err()
	}
	return recipient, reqType, wantReply, payload[dec.Off():], nil
}

// ParsePtyReq parses data of a pty-req ParseChannelRequest. modes are iterated with ValidateTerminalModes.
func ParsePtyReq(data []byte) (term []byte, cols, rows, widthPx, heightPx uint32, modes []byte, err error) {
	var dec decoder
	dec.Reset(data)
	term = dec.String()
	cols = dec.Uint32()
	rows = dec.Uint32()
	widthPx = dec.Uint32()
	heightPx = dec.Uint32()
	modes = dec.String()
	dec.end()
	if dec.IsFailed() {
		return nil, 0, 0, 0, 0, nil, dec.Err()
	}
	return term, cols, rows, widthPx, heightPx, modes, nil
}

// ParseEnvReq parses data of an env ParseChannelRequest.
func ParseEnvReq(data []byte) (name, value []byte, err error) {
	var dec decoder
	dec.Reset(data)
	name = dec.String()
	value = dec.String()
	dec.end()
	if dec.IsFailed() {
		return nil, nil, dec.Err()
	}
	return name, value, nil
}

// ParseRequestString parses data of an exec, subsystem or signal ParseChannelRequest:
// command, subsystem name or signal name without the "SIG" prefix.
func ParseRequestString(data []byte) (s []byte, err error) {
	var dec decoder
	dec.Reset(data)
	s = dec.String()
	dec.end()
	if dec.IsFailed() {
		return nil, dec.Err()
	}
	return s, nil
}

// ParseWindowChange parses data of a window-change ParseChannelRequest.
func ParseWindowChange(data []byte) (cols, rows, widthPx, heightPx uint32, err error) {
	var dec decoder
	dec.Reset(data)
	cols = dec.Uint32()
	rows = dec.Uint32()
	widthPx = dec.Uint32()
	heightPx = dec.Uint32()
	dec.end()
	if dec.IsFailed() {
		return 0, 0, 0, 0, dec.Err()
	}
	return cols, rows, widthPx, heightPx, nil
}

// ParseExitStatus parses data of an exit-status ParseChannelRequest.
func ParseExitStatus(data []byte) (status uint32, err error) {
	var dec decoder
	dec.Reset(data)
	status = dec.Uint32()
	dec.end()
	if dec.IsFailed() {
		return 0, dec.Err()
	}
	return status, nil
}

// ParseExitSignal parses data of an exit-signal ParseChannelRequest. signal lacks the "SIG" prefix;
// msg is peer controlled, sanitize before display.
func ParseExitSignal(data []byte) (signal []byte, coreDumped bool, msg, lang []byte, err error) {
	var dec decoder
	dec.Reset(data)
	signal = dec.String()
	coreDumped = dec.Bool()
	msg = dec.String()
	lang = dec.String()
	dec.end()
	if dec.IsFailed() {
		return nil, false, nil, nil, dec.Err()
	}
	return signal, coreDumped, msg, lang, nil
}

// ValidateTerminalModes validates modes of ParsePtyReq returning the opcodes to iterate with NextTerminalMode.
// Opcodes end at [TTYOpEnd], at the first undefined opcode or at the end of modes; what follows is ignored.
func ValidateTerminalModes(modes []byte) (ops []byte, err error) {
	off := 0
	for off < len(modes) {
		op, _, n, err := NextTerminalMode(modes[off:])
		if err != nil {
			return nil, err
		} else if op == TTYOpEnd || op >= ttyOpUndefined {
			break
		}
		off += n
	}
	return modes[:off], nil
}

// NextTerminalMode returns the first opcode of ops with its argument and the bytes they take.
func NextTerminalMode(ops []byte) (opcode uint8, arg uint32, n int, err error) {
	var dec decoder
	dec.Reset(ops)
	opcode = dec.Uint8()
	if !dec.IsFailed() && opcode != TTYOpEnd && opcode < ttyOpUndefined {
		arg = dec.Uint32()
	}
	if dec.IsFailed() {
		return 0, 0, 0, dec.Err()
	}
	return opcode, arg, dec.Off(), nil
}
