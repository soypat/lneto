package sshraw

import (
	"bytes"
	"errors"
	"testing"

	"github.com/soypat/lneto"
)

func TestParseGlobalRequest(t *testing.T) {
	payload := encode(t, func(e *Encoder) {
		e.Uint8(uint8(MsgGlobalRequest))
		e.Str(ReqTCPIPForward)
		e.Bool(true)
		e.Str("0.0.0.0")
		e.Uint32(2222)
	})
	name, wantReply, data, err := ParseGlobalRequest(payload)
	if err != nil || string(name) != ReqTCPIPForward || !wantReply {
		t.Fatalf("got %q %v err=%v", name, wantReply, err)
	}
	header := payload[:len(payload)-len(data)] // Truncating data is the data parser's concern.
	checkParseErrs(t, header, func(p []byte) error { _, _, _, err := ParseGlobalRequest(p); return err }, false)
	addr, port, err := ParseTCPIPForward(data)
	if err != nil || string(addr) != "0.0.0.0" || port != 2222 {
		t.Fatalf("tcpip-forward: got %q %d err=%v", addr, port, err)
	}
	checkDataErrs(t, data, func(p []byte) error { _, _, err := ParseTCPIPForward(p); return err })
	bad := encode(t, func(e *Encoder) { e.Uint8(uint8(MsgGlobalRequest)); e.Str("tcpip forward"); e.Bool(false) })
	if _, _, _, err = ParseGlobalRequest(bad); !errors.Is(err, lneto.ErrInvalidField) {
		t.Fatalf("bad name err=%v, want %v", err, lneto.ErrInvalidField)
	}

	success := []byte{byte(MsgRequestSuccess), 0, 0, 0x08, 0xae}
	if data, err = ParseRequestSuccess(success); err != nil || !bytes.Equal(data, success[1:]) {
		t.Fatalf("success: data=%x err=%v", data, err)
	} else if _, err = ParseRequestSuccess([]byte{byte(MsgRequestFailure)}); err == nil {
		t.Fatal("success with wrong type: no error")
	}
	failure := []byte{byte(MsgRequestFailure)}
	if err = ParseRequestFailure(failure); err != nil {
		t.Fatal(err)
	} else if err = ParseRequestFailure(append(bytes.Clone(failure), 0)); err == nil {
		t.Fatal("failure with trailing byte: no error")
	}
}

func TestParseChannelOpen(t *testing.T) {
	payload := encode(t, func(e *Encoder) {
		e.Uint8(uint8(MsgChannelOpen))
		e.Str(ChannelDirectTCPIP)
		e.Uint32(7)
		e.Uint32(1 << 20)
		e.Uint32(32768)
		e.Str("example.com")
		e.Uint32(80)
		e.Str("10.0.0.1")
		e.Uint32(5555)
	})
	chanType, sender, window, maxPacket, data, err := ParseChannelOpen(payload)
	if err != nil || string(chanType) != ChannelDirectTCPIP || sender != 7 || window != 1<<20 || maxPacket != 32768 {
		t.Fatalf("got %q %d %d %d err=%v", chanType, sender, window, maxPacket, err)
	}
	header := payload[:len(payload)-len(data)]
	checkParseErrs(t, header, func(p []byte) error { _, _, _, _, _, err := ParseChannelOpen(p); return err }, false)
	host, port, origAddr, origPort, err := ParseChannelOpenTCPIP(data)
	if err != nil || string(host) != "example.com" || port != 80 || string(origAddr) != "10.0.0.1" || origPort != 5555 {
		t.Fatalf("tcpip: got %q %d %q %d err=%v", host, port, origAddr, origPort, err)
	}
	checkDataErrs(t, data, func(p []byte) error { _, _, _, _, err := ParseChannelOpenTCPIP(p); return err })
	bad := encode(t, func(e *Encoder) {
		e.Uint8(uint8(MsgChannelOpen))
		e.Str("bad type")
		e.Uint32(0)
		e.Uint32(0)
		e.Uint32(0)
	})
	if _, _, _, _, _, err = ParseChannelOpen(bad); !errors.Is(err, lneto.ErrInvalidField) {
		t.Fatalf("bad type err=%v, want %v", err, lneto.ErrInvalidField)
	}
}

func TestParseChannelOpenReplies(t *testing.T) {
	confirm := encode(t, func(e *Encoder) {
		e.Uint8(uint8(MsgChannelOpenConfirmation))
		e.Uint32(7)
		e.Uint32(3)
		e.Uint32(1 << 20)
		e.Uint32(32768)
	})
	recipient, sender, window, maxPacket, data, err := ParseChannelOpenConfirmation(confirm)
	if err != nil || recipient != 7 || sender != 3 || window != 1<<20 || maxPacket != 32768 || len(data) != 0 {
		t.Fatalf("confirmation: got %d %d %d %d %x err=%v", recipient, sender, window, maxPacket, data, err)
	}
	checkParseErrs(t, confirm, func(p []byte) error { _, _, _, _, _, err := ParseChannelOpenConfirmation(p); return err }, false)

	failure := encode(t, func(e *Encoder) {
		e.Uint8(uint8(MsgChannelOpenFailure))
		e.Uint32(7)
		e.Uint32(uint32(OpenConnectFailed))
		e.Str("refused")
		e.Str("")
	})
	recipient, reason, desc, lang, err := ParseChannelOpenFailure(failure)
	if err != nil || recipient != 7 || reason != OpenConnectFailed || string(desc) != "refused" || len(lang) != 0 {
		t.Fatalf("failure: got %d %v %q %q err=%v", recipient, reason, desc, lang, err)
	}
	checkParseErrs(t, failure, func(p []byte) error { _, _, _, _, err := ParseChannelOpenFailure(p); return err }, true)
}

func TestParseChannelMessages(t *testing.T) {
	adjust := encode(t, func(e *Encoder) { e.Uint8(uint8(MsgChannelWindowAdjust)); e.Uint32(7); e.Uint32(4096) })
	if recipient, add, err := ParseChannelWindowAdjust(adjust); err != nil || recipient != 7 || add != 4096 {
		t.Fatalf("window adjust: got %d %d err=%v", recipient, add, err)
	}
	checkParseErrs(t, adjust, func(p []byte) error { _, _, err := ParseChannelWindowAdjust(p); return err }, true)

	data := encode(t, func(e *Encoder) { e.Uint8(uint8(MsgChannelData)); e.Uint32(7); e.Str("ls\n") })
	if recipient, d, err := ParseChannelData(data); err != nil || recipient != 7 || string(d) != "ls\n" {
		t.Fatalf("data: got %d %q err=%v", recipient, d, err)
	}
	checkParseErrs(t, data, func(p []byte) error { _, _, err := ParseChannelData(p); return err }, true)

	ext := encode(t, func(e *Encoder) {
		e.Uint8(uint8(MsgChannelExtendedData))
		e.Uint32(7)
		e.Uint32(ExtendedDataStderr)
		e.Str("oops")
	})
	if recipient, code, d, err := ParseChannelExtendedData(ext); err != nil || recipient != 7 || code != ExtendedDataStderr || string(d) != "oops" {
		t.Fatalf("extended data: got %d %d %q err=%v", recipient, code, d, err)
	}
	checkParseErrs(t, ext, func(p []byte) error { _, _, _, err := ParseChannelExtendedData(p); return err }, true)

	for _, typ := range []MsgType{MsgChannelEOF, MsgChannelClose, MsgChannelSuccess, MsgChannelFailure} {
		payload := []byte{byte(typ), 0, 0, 0, 7}
		if recipient, err := ParseChannelRecipient(payload); err != nil || recipient != 7 {
			t.Fatalf("%v: got %d err=%v", typ, recipient, err)
		}
		checkParseErrs(t, payload, func(p []byte) error { _, err := ParseChannelRecipient(p); return err }, true)
	}
	if _, err := ParseChannelRecipient([]byte{byte(MsgChannelData), 0, 0, 0, 7}); err == nil {
		t.Fatal("CHANNEL_DATA as recipient-only message: no error")
	}
}

func TestParseChannelRequest(t *testing.T) {
	payload := encode(t, func(e *Encoder) {
		e.Uint8(uint8(MsgChannelRequest))
		e.Uint32(7)
		e.Str(ReqExec)
		e.Bool(true)
		e.Str("uname -a")
	})
	recipient, reqType, wantReply, data, err := ParseChannelRequest(payload)
	if err != nil || recipient != 7 || string(reqType) != ReqExec || !wantReply {
		t.Fatalf("got %d %q %v err=%v", recipient, reqType, wantReply, err)
	}
	header := payload[:len(payload)-len(data)]
	checkParseErrs(t, header, func(p []byte) error { _, _, _, _, err := ParseChannelRequest(p); return err }, false)
	cmd, err := ParseRequestString(data)
	if err != nil || string(cmd) != "uname -a" {
		t.Fatalf("exec: got %q err=%v", cmd, err)
	}
	checkDataErrs(t, data, func(p []byte) error { _, err := ParseRequestString(p); return err })
	bad := encode(t, func(e *Encoder) { e.Uint8(uint8(MsgChannelRequest)); e.Uint32(7); e.Str("bad req"); e.Bool(false) })
	if _, _, _, _, err = ParseChannelRequest(bad); !errors.Is(err, lneto.ErrInvalidField) {
		t.Fatalf("bad type err=%v, want %v", err, lneto.ErrInvalidField)
	}
}

func TestParseRequestData(t *testing.T) {
	modes := []byte{1, 0, 0, 0, 3, TTYOpEnd}
	pty := encode(t, func(e *Encoder) {
		e.Str("xterm")
		e.Uint32(80)
		e.Uint32(24)
		e.Uint32(640)
		e.Uint32(480)
		e.String(modes)
	})
	term, cols, rows, wpx, hpx, gotModes, err := ParsePtyReq(pty)
	if err != nil || string(term) != "xterm" || cols != 80 || rows != 24 || wpx != 640 || hpx != 480 || !bytes.Equal(gotModes, modes) {
		t.Fatalf("pty-req: got %q %d %d %d %d %x err=%v", term, cols, rows, wpx, hpx, gotModes, err)
	}
	checkDataErrs(t, pty, func(p []byte) error { _, _, _, _, _, _, err := ParsePtyReq(p); return err })

	env := encode(t, func(e *Encoder) { e.Str("LANG"); e.Str("C") })
	if name, value, err := ParseEnvReq(env); err != nil || string(name) != "LANG" || string(value) != "C" {
		t.Fatalf("env: got %q %q err=%v", name, value, err)
	}
	checkDataErrs(t, env, func(p []byte) error { _, _, err := ParseEnvReq(p); return err })

	wc := encode(t, func(e *Encoder) { e.Uint32(120); e.Uint32(40); e.Uint32(0); e.Uint32(0) })
	if cols, rows, wpx, hpx, err := ParseWindowChange(wc); err != nil || cols != 120 || rows != 40 || wpx != 0 || hpx != 0 {
		t.Fatalf("window-change: got %d %d %d %d err=%v", cols, rows, wpx, hpx, err)
	}
	checkDataErrs(t, wc, func(p []byte) error { _, _, _, _, err := ParseWindowChange(p); return err })

	status := []byte{0, 0, 0, 2}
	if code, err := ParseExitStatus(status); err != nil || code != 2 {
		t.Fatalf("exit-status: got %d err=%v", code, err)
	}
	checkDataErrs(t, status, func(p []byte) error { _, err := ParseExitStatus(p); return err })

	sig := encode(t, func(e *Encoder) { e.Str("KILL"); e.Bool(true); e.Str("killed"); e.Str("") })
	if name, core, msg, lang, err := ParseExitSignal(sig); err != nil || string(name) != "KILL" || !core || string(msg) != "killed" || len(lang) != 0 {
		t.Fatalf("exit-signal: got %q %v %q %q err=%v", name, core, msg, lang, err)
	}
	checkDataErrs(t, sig, func(p []byte) error { _, _, _, _, err := ParseExitSignal(p); return err })
}

func TestTerminalModes(t *testing.T) {
	type mode struct {
		op  uint8
		arg uint32
	}
	for _, tc := range []struct {
		name  string
		modes []byte
		want  []mode
	}{
		{"end", []byte{1, 0, 0, 0, 3, 53, 0, 0, 0, 1, TTYOpEnd, 99}, []mode{{1, 3}, {53, 1}}},
		{"undefined opcode stops", []byte{1, 0, 0, 0, 3, 200, 0xff}, []mode{{1, 3}}},
		{"no end", []byte{1, 0, 0, 0, 3}, []mode{{1, 3}}},
		{"empty", nil, nil},
	} {
		ops, err := ValidateTerminalModes(tc.modes)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		var got []mode
		for len(ops) > 0 {
			op, arg, n, err := NextTerminalMode(ops)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			got = append(got, mode{op, arg})
			ops = ops[n:]
		}
		if len(got) != len(tc.want) {
			t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
			}
		}
	}
	if _, err := ValidateTerminalModes([]byte{1, 0, 0, 3}); err == nil {
		t.Fatal("truncated argument: no error")
	}
}
