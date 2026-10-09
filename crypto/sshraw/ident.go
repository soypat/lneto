package sshraw

import (
	"bytes"

	"github.com/soypat/lneto"
)

const (
	// IdentPrefix prefixes the start of a server identification.
	// It may be preceded by other lines ending with '\n'.
	IdentPrefix = "SSH-"
)

// NextIdentLine returns the first line of buf without '\n' terminator. Also strips optional '\r' if present.
// Line starting with "SSH-" prefix is the server identification string. See [IdentPrefix].
func NextIdentLine(buf []byte) (line []byte, n int, err error) {
	i := bytes.IndexByte(buf[:min(len(buf), maxIdentLen)], '\n')
	if i < 0 {
		if len(buf) >= maxIdentLen {
			return nil, 0, lneto.ErrInvalidLengthField
		}
		return nil, 0, lneto.ErrTruncatedFrame
	}
	line = buf[:i]
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	return line, i + 1, nil
}

// ParseIdent parses an identification string line as returned by [NextIdentLine] of the format:
//
//	SSH-<protoversion>-<softwareversion> <comments>
//
// proto and software are non-empty printable US-ASCII without spaces; software may contain '-'
// as some implementations send it. comments is returned as is, only checked to not contain null.
// rejectNon2Version rejects with [lneto.ErrUnsupported] protocol versions other than "2.0" and
// "1.99", the latter being a server in "compatibility mode" that also speaks 2.0, RFC 4253 5.1.
func ParseIdent(line []byte, rejectNon2Version bool) (proto, software, comments []byte, err error) {
	if !bytes.HasPrefix(line, []byte(IdentPrefix)) {
		return nil, nil, nil, lneto.ErrInvalidField
	} else if bytes.IndexByte(line, 0) >= 0 {
		return nil, nil, nil, lneto.ErrInvalidField // MUST NOT contain null, unlike preceding lines.
	}
	rest := line[len(IdentPrefix):]
	before, after, ok := bytes.Cut(rest, []byte{'-'})
	if !ok {
		return nil, nil, nil, lneto.ErrInvalidField
	}
	proto, software = before, after
	if sp := bytes.IndexByte(software, ' '); sp >= 0 {
		software, comments = software[:sp], software[sp+1:]
	}
	if !isIdentToken(proto) || !isIdentToken(software) {
		return nil, nil, nil, lneto.ErrInvalidField
	} else if rejectNon2Version && string(proto) != "2.0" && string(proto) != "1.99" {
		return nil, nil, nil, lneto.ErrUnsupported
	}
	return proto, software, comments, nil
}

// isIdentToken reports whether tok is non-empty printable US-ASCII without spaces.
func isIdentToken(tok []byte) bool {
	for _, c := range tok {
		if c <= ' ' || c > '~' {
			return false
		}
	}
	return len(tok) > 0
}

// Ident writes the identification string
//
//	SSH-<proto>-<software> <comments>\r\n
//
// comments omitted when empty. Users should ensure proto, software and comments are valid form,
// see [ValidateIdentFormat].
func (e *Encoder) Ident(proto, software, comments string) {
	n := len(IdentPrefix) + len(proto) + 1 + len(software) + len("\r\n")
	if comments != "" {
		n += 1 + len(comments)
	}
	if n > maxIdentLen {
		e.Fail(lneto.ErrInvalidLengthField)
		return
	} else if software == "" || proto == "" {
		e.Fail(lneto.ErrInvalidField)
		return
	}
	e.str(IdentPrefix)
	e.str(proto)
	e.byte('-')
	e.str(software)
	if comments != "" {
		e.byte(' ')
		e.str(comments)
	}
	e.str("\r\n")
}

// ValidateIdentFormat validates the identification string fields strictly as RFC 4253 4.2 requires
// of a sender, stricter than [ParseIdent] is of a peer: proto and software are non-empty printable
// US-ASCII without spaces or '-' and comments, which may be empty, are printable US-ASCII.
func ValidateIdentFormat(proto, software, comments []byte) error {
	if !isIdentToken(proto) || !isIdentToken(software) ||
		bytes.IndexByte(proto, '-') >= 0 || bytes.IndexByte(software, '-') >= 0 {
		return lneto.ErrInvalidField
	}
	for _, c := range comments {
		if c < ' ' || c > '~' {
			return lneto.ErrInvalidField
		}
	}
	return nil
}
