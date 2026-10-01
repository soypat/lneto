package sshraw

import (
	"bytes"
	"errors"
	"testing"

	"github.com/soypat/lneto"
)

// newKexInit encodes a KEXINIT payload whose i'th name-list is lists[i].
func newKexInit(t *testing.T, lists [numKexLists][]string, follows bool) []byte {
	t.Helper()
	var e Encoder
	e.Reset(make([]byte, 512), 0)
	e.Uint8(uint8(MsgKexInit))
	e.Bytes(bytes.Repeat([]byte{0xc0}, SizeCookie))
	for _, l := range lists {
		e.NameList(l...)
	}
	e.Bool(follows)
	e.Uint32(0)
	if e.Err() != nil {
		t.Fatal(e.Err())
	}
	return e.Since(0)
}

func TestKexInitDecode(t *testing.T) {
	var lists [numKexLists][]string
	lists[kexAlgorithms] = []string{"curve25519-sha256", "kex-strict-c-v00@openssh.com"}
	lists[hostKeyAlgorithms] = []string{"ssh-ed25519"}
	lists[ciphersC2S] = []string{"aes128-gcm@openssh.com"}
	lists[ciphersS2C] = []string{"chacha20-poly1305@openssh.com"}
	lists[compressionC2S] = []string{"none"}
	lists[compressionS2C] = []string{"none"}
	payload := newKexInit(t, lists, true)

	var m KexInitMsg
	var vld lneto.Validator
	n, err := m.Decode(payload, &vld)
	if err != nil {
		t.Fatal(err)
	} else if n != len(payload) {
		t.Fatalf("Decode n=%d, want %d", n, len(payload))
	}
	got := [numKexLists][]byte{
		m.KexAlgorithms(), m.HostKeyAlgorithms(),
		m.CiphersClientToServer(), m.CiphersServerToClient(),
		m.MACsClientToServer(), m.MACsServerToClient(),
		m.CompressionClientToServer(), m.CompressionServerToClient(),
		m.LanguagesClientToServer(), m.LanguagesServerToClient(),
	}
	for i := range got {
		want := []byte{}
		for j, name := range lists[i] {
			if j > 0 {
				want = append(want, ',')
			}
			want = append(want, name...)
		}
		if !bytes.Equal(got[i], want) {
			t.Errorf("list %d=%q, want %q", i, got[i], want)
		}
	}
	if !m.FirstKexPacketFollows() {
		t.Error("first_kex_packet_follows not set")
	} else if m.Cookie()[0] != 0xc0 {
		t.Error("bad cookie")
	}

	for _, tc := range []struct {
		name    string
		payload []byte
		want    error
	}{
		{"truncated", payload[:len(payload)-1], lneto.ErrTruncatedFrame},
		{"wrong type", append([]byte{byte(MsgNewKeys)}, payload[1:]...), lneto.ErrInvalidField},
		{"empty", nil, lneto.ErrTruncatedFrame},
	} {
		if _, err := m.Decode(tc.payload, &vld); !errors.Is(err, tc.want) {
			t.Errorf("%s: err=%v, want %v", tc.name, err, tc.want)
		}
	}
	bad := bytes.Clone(payload)
	bad[1+SizeCookie+4] = ' ' // First name of kex_algorithms gets a space.
	if _, err := m.Decode(bad, &vld); !errors.Is(err, lneto.ErrInvalidField) {
		t.Errorf("bad name err=%v, want %v", err, lneto.ErrInvalidField)
	}
}
