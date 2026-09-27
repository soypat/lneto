package sshraw

import (
	"bytes"

	"github.com/soypat/lneto"
)

// identV2 starts the identification string this package sends.
const identV2 = IdentPrefix + "2.0-"

// NextIdentLine returns the first line of buf without its line terminator and
// the number of bytes n the line spans, terminator included. The line may be
// an identification string or, when sent by a server, a line preceding it
// which the client must skip: see [IdentPrefix]. A lone LF is accepted as
// terminator since RFC 4253 4.2 only says lines SHOULD end in CR LF.
//
// The line of an identification string is the V_C or V_S of the exchange hash.
func NextIdentLine(buf []byte) (line []byte, n int, err error) {
	i := bytes.IndexByte(buf[:min(len(buf), MaxIdentLen)], '\n')
	if i < 0 {
		if len(buf) >= MaxIdentLen {
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

// ParseIdent parses an identification string line as returned by [NextIdentLine]:
//
//	SSH-protoversion-softwareversion SP comments
//
// protoversion must be 2.0 or 1.99, which a server compatible with both
// protocol versions sends, RFC 4253 5.1. Otherwise ParseIdent returns
// [lneto.ErrUnsupported]. softwareversion may contain '-' though RFC 4253 4.2
// forbids it, since some deployed implementations send it.
func ParseIdent(line []byte) (software, comments []byte, err error) {
	if !bytes.HasPrefix(line, []byte(IdentPrefix)) {
		return nil, nil, lneto.ErrInvalidField
	} else if bytes.IndexByte(line, 0) >= 0 {
		return nil, nil, lneto.ErrInvalidField // MUST NOT contain null, unlike preceding lines.
	}
	rest := line[len(IdentPrefix):]
	dash := bytes.IndexByte(rest, '-')
	if dash < 0 {
		return nil, nil, lneto.ErrInvalidField
	} else if proto := rest[:dash]; string(proto) != "2.0" && string(proto) != "1.99" {
		return nil, nil, lneto.ErrUnsupported
	}
	software = rest[dash+1:]
	if sp := bytes.IndexByte(software, ' '); sp >= 0 {
		software, comments = software[:sp], software[sp+1:]
	}
	if len(software) == 0 {
		return nil, nil, lneto.ErrInvalidField
	}
	for _, c := range software {
		if c <= ' ' || c > '~' {
			return nil, nil, lneto.ErrInvalidField
		}
	}
	return software, comments, nil
}

// Ident writes the identification string SSH-2.0-software SP comments CR LF.
// comments is omitted when empty. Unlike [ParseIdent], Ident follows
// RFC 4253 4.2 strictly: software is printable US-ASCII without spaces or '-'
// and comments are printable US-ASCII.
func (e *Encoder) Ident(software, comments string) {
	n := len(identV2) + len(software) + len("\r\n")
	if comments != "" {
		n += 1 + len(comments)
	}
	if n > MaxIdentLen {
		e.fail(lneto.ErrInvalidLengthField)
		return
	} else if software == "" {
		e.fail(lneto.ErrInvalidField)
		return
	}
	for i := 0; i < len(software); i++ {
		if c := software[i]; c <= ' ' || c > '~' || c == '-' {
			e.fail(lneto.ErrInvalidField)
			return
		}
	}
	for i := 0; i < len(comments); i++ {
		if c := comments[i]; c < ' ' || c > '~' {
			e.fail(lneto.ErrInvalidField)
			return
		}
	}
	e.str(identV2)
	e.str(software)
	if comments != "" {
		e.Uint8(' ')
		e.str(comments)
	}
	e.str("\r\n")
}
