package sshraw

import (
	"bytes"
	"testing"
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
	if e.IsFailed() {
		t.Fatal("encode failed")
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
	n, err := m.Decode(payload)
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
	}{
		{"truncated", payload[:len(payload)-1]},
		{"wrong type", append([]byte{byte(MsgNewKeys)}, payload[1:]...)},
		{"empty", nil},
	} {
		if _, err := m.Decode(tc.payload); err == nil {
			t.Errorf("%s: no error", tc.name)
		}
	}
	bad := bytes.Clone(payload)
	bad[1+SizeCookie+4] = ' ' // First name of kex_algorithms gets a space.
	if _, err := m.Decode(bad); err == nil {
		t.Error("bad name: no error")
	}
}

func TestPseudoAlgorithms(t *testing.T) {
	pseudo := []string{KexStrictClient, KexStrictServer, ExtInfoClient, ExtInfoServer}
	var lists [numKexLists][]string
	lists[kexAlgorithms] = append([]string{"curve25519-sha256"}, pseudo...)
	var m KexInitMsg
	if _, err := m.Decode(newKexInit(t, lists, false)); err != nil {
		t.Fatal(err)
	}
	for _, name := range pseudo {
		if err := ValidateNameList([]byte(name)); err != nil {
			t.Errorf("%q: %v", name, err)
		} else if !HasName(m.KexAlgorithms(), []byte(name)) {
			t.Errorf("%q not found in kex_algorithms", name)
		}
	}
	// Each side advertises its own name, so pseudo algorithms are never negotiated.
	if name, ok := Negotiate([]byte(KexStrictClient+","+ExtInfoClient), []byte(KexStrictServer+","+ExtInfoServer)); ok {
		t.Errorf("negotiated pseudo algorithm %q", name)
	}
}

func TestKexInitWrongGuess(t *testing.T) {
	decode := func(kex, hostKey []string, follows bool) *KexInitMsg {
		var lists [numKexLists][]string
		lists[kexAlgorithms] = kex
		lists[hostKeyAlgorithms] = hostKey
		var m KexInitMsg
		if _, err := m.Decode(newKexInit(t, lists, follows)); err != nil {
			t.Fatal(err)
		}
		return &m
	}
	kex := []string{"curve25519-sha256", "ecdh-sha2-nistp256"}
	hostKey := []string{"ssh-ed25519", "ecdsa-sha2-nistp256"}
	own := decode(kex, hostKey, false)
	for _, tc := range []struct {
		name          string
		kex, hostKey  []string
		follows, want bool
	}{
		{"no guess", []string{"ecdh-sha2-nistp256"}, hostKey, false, false},
		{"right", kex, hostKey, true, false},
		{"right, other lists differ", []string{kex[0], "x"}, []string{hostKey[0]}, true, false},
		{"kex wrong", []string{kex[1], kex[0]}, hostKey, true, true},
		{"host key wrong", kex, []string{hostKey[1], hostKey[0]}, true, true},
		{"prefix", []string{"curve25519-sha256x"}, hostKey, true, true},
	} {
		peer := decode(tc.kex, tc.hostKey, tc.follows)
		if got := peer.WrongGuess(own); got != tc.want {
			t.Errorf("%s: WrongGuess=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestHasName(t *testing.T) {
	for _, tc := range []struct {
		list, name string
		want       bool
	}{
		{"", "a", false},
		{"a", "a", true},
		{"a,b,c", "a", true},
		{"a,b,c", "b", true},
		{"a,b,c", "c", true},
		{"a,b,c", "d", false},
		{"ab,c", "a", false},  // Prefix of a name.
		{"a,bc", "c", false},  // Suffix of a name.
		{"a,b", "a,b", false}, // Not a single name.
		{"a,b", "", false},
	} {
		if got := HasName([]byte(tc.list), []byte(tc.name)); got != tc.want {
			t.Errorf("HasName(%q, %q)=%v, want %v", tc.list, tc.name, got, tc.want)
		}
	}
}

func TestNegotiate(t *testing.T) {
	for _, tc := range []struct {
		client, server string
		want           string
		ok             bool
	}{
		{"a,b,c", "c,b,a", "a", true}, // Client preference wins.
		{"a,b,c", "c,b", "b", true},
		{"a,b,c", "c", "c", true},
		{"a,b", "c,d", "", false},
		{"", "a", "", false},
		{"a", "", "", false},
		{"ab,b", "a,b", "b", true}, // Prefixes do not match.
		{"curve25519-sha256,kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com,curve25519-sha256", "curve25519-sha256", true},
	} {
		got, ok := Negotiate([]byte(tc.client), []byte(tc.server))
		if ok != tc.ok || string(got) != tc.want {
			t.Errorf("Negotiate(%q, %q)=(%q, %v), want (%q, %v)", tc.client, tc.server, got, ok, tc.want, tc.ok)
		}
	}
}
