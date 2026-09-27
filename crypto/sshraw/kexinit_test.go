package sshraw_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/soypat/lneto"
	ssh "github.com/soypat/lneto/crypto/sshraw"
)

// kexInitLists are the 10 name-lists of SSH_MSG_KEXINIT in wire order.
var kexInitLists = [10][]string{
	{ssh.KexCurve25519SHA256, ssh.KexStrictClient},
	{ssh.HostKeyEd25519, ssh.HostKeyECDSAP256},
	{ssh.CipherAES256GCM},
	{ssh.CipherAES128GCM, ssh.CipherAES256GCM},
	{ssh.MACHMACSHA256},
	{ssh.MACHMACSHA256ETM},
	{ssh.CompressionNone},
	{ssh.CompressionNone},
	{},
	{},
}

func appendKexInit(t *testing.T, lists [10][]string, follows bool) []byte {
	t.Helper()
	var e ssh.Encoder
	buf := make([]byte, 512)
	e.Reset(buf, 0)
	e.Uint8(uint8(ssh.MsgKexInit))
	for i := range ssh.SizeCookie {
		e.Uint8(byte(i))
	}
	for _, list := range lists {
		e.NameList(list...)
	}
	e.Bool(follows)
	e.Uint32(0)
	if e.Err() != nil {
		t.Fatal(e.Err())
	}
	return buf[:e.Len()]
}

func TestKexInitDecode(t *testing.T) {
	payload := appendKexInit(t, kexInitLists, true)
	var msg ssh.KexInitMsg
	var vld lneto.Validator
	n, err := msg.Decode(payload, &vld)
	if err != nil {
		t.Fatal(err)
	} else if n != len(payload) {
		t.Fatalf("decoded %d bytes, want %d", n, len(payload))
	}
	for i := range ssh.SizeCookie {
		if msg.Cookie()[i] != byte(i) {
			t.Fatalf("cookie=%x", msg.Cookie())
		}
	}
	got := [10][]byte{
		msg.KexAlgorithms(), msg.HostKeyAlgorithms(),
		msg.CiphersClientToServer(), msg.CiphersServerToClient(),
		msg.MACsClientToServer(), msg.MACsServerToClient(),
		msg.CompressionClientToServer(), msg.CompressionServerToClient(),
		msg.LanguagesClientToServer(), msg.LanguagesServerToClient(),
	}
	for i := range got {
		var e ssh.Encoder
		buf := make([]byte, 256)
		e.Reset(buf, 0)
		e.NameList(kexInitLists[i]...)
		if want := buf[4:e.Len()]; string(got[i]) != string(want) {
			t.Errorf("name-list %d=%q, want %q", i, got[i], want)
		}
	}
	if !msg.FirstKexPacketFollows() {
		t.Error("first_kex_packet_follows=false, want true")
	}
	if !ssh.HasName(msg.KexAlgorithms(), ssh.KexStrictClient) {
		t.Error("strict kex not found")
	}
	allocs := testing.AllocsPerRun(10, func() { msg.Decode(payload, &vld) })
	if allocs != 0 {
		t.Errorf("Decode allocs=%v, want 0", allocs)
	}
}

func TestKexInitDecodeErrors(t *testing.T) {
	valid := appendKexInit(t, kexInitLists, false)
	// The Encoder refuses to write an illegal name so corrupt a valid one.
	withBad := append([]byte{}, valid...)
	withBad[bytes.Index(withBad, []byte(ssh.HostKeyEd25519))+3] = ' '
	for _, tc := range []struct {
		name    string
		payload []byte
		want    error
	}{
		{"empty", nil, lneto.ErrTruncatedFrame},
		{"wrong type", append([]byte{byte(ssh.MsgNewKeys)}, valid[1:]...), lneto.ErrInvalidField},
		{"truncated reserved", valid[:len(valid)-1], lneto.ErrTruncatedFrame},
		{"truncated cookie", valid[:1+ssh.SizeCookie-1], lneto.ErrTruncatedFrame},
		{"truncated list", valid[:1+ssh.SizeCookie+4+2], lneto.ErrTruncatedFrame},
		{"bad name", withBad, lneto.ErrInvalidField},
	} {
		var msg ssh.KexInitMsg
		var vld lneto.Validator
		if _, err := msg.Decode(tc.payload, &vld); !errors.Is(err, tc.want) {
			t.Errorf("%s: err=%v, want %v", tc.name, err, tc.want)
		}
	}
}
