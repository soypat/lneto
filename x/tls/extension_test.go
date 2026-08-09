package tls_test

import (
	"errors"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/x/tls"
)

func TestExtensionListWalksAndToleratesGREASE(t *testing.T) {
	// Two extensions: a GREASE type with empty data, then supported_versions.
	exts := []byte{
		0x0a, 0x0a, 0x00, 0x00, // GREASE, len 0
		0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, // supported_versions
	}
	list, err := tls.ParseClientExtensions(exts, 0)
	if err != nil {
		t.Fatal(err)
	}
	var types []tls.ExtensionType
	for off, ext := range list.All {
		if want := 4*len(types) + 4; off != want {
			t.Errorf("%v at offset %d want %d", ext.Type(), off, want)
		}
		types = append(types, ext.Type())
	}
	if len(types) != 2 || types[1] != tls.ExtSupportedVersions {
		t.Fatalf("got %v", types)
	}
	if !tls.IsGREASE(uint16(types[0])) {
		t.Errorf("first extension %#x not recognized as GREASE", types[0])
	}
}

func TestParseExtensionsTruncated(t *testing.T) {
	for _, tc := range [][]byte{
		{0x00},                               // partial type
		{0x00, 0x2b, 0x00},                   // partial length
		{0x00, 0x2b, 0x00, 0x05, 0x02, 0x03}, // length overruns
	} {
		_, err := tls.ParseClientExtensions(tc, 0)
		if !errors.Is(err, lneto.ErrTruncatedFrame) {
			t.Errorf("% x: got %v want ErrTruncatedFrame", tc, err)
		}
	}
}

func TestParseExtensionsRejectsMalformedInnerList(t *testing.T) {
	// Framing inside a recognized extension is checked at parse, which is what
	// lets the iterators be error-free.
	for _, tc := range [][]byte{
		{0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x1d},             // supported_groups, odd list
		{0x00, 0x2b, 0x00, 0x03, 0x04, 0x03, 0x04},             // supported_versions, prefix overruns
		{0x00, 0x10, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00},       // alpn, zero-length name
		{0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x09}, // server_name, name overruns
	} {
		if _, err := tls.ParseClientExtensions(tc, 0); err == nil {
			t.Errorf("% x accepted", tc)
		}
	}
}

func TestExtensionIterationStopsOnBreak(t *testing.T) {
	// Two extensions with no inner structure of their own.
	exts := []byte{0x00, 0x15, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00}
	list, err := tls.ParseClientExtensions(exts, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for range list.All {
		n++
		break
	}
	if n != 1 {
		t.Errorf("walk continued after break: %d iterations", n)
	}
}

func TestKeySharesAcceptGREASEEntry(t *testing.T) {
	// Chrome sends a GREASE key share whose key_exchange is a single byte.
	// Rejecting it as malformed breaks Chrome outright.
	exts := []byte{
		0x00, 0x33, 0x00, 0x0d, // key_share, 13 bytes
		0x00, 0x0b, // client_shares length 11
		0x1a, 0x1a, 0x00, 0x01, 0x00, // GREASE group, 1 byte body
		0x00, 0x1d, 0x00, 0x02, 0xab, 0xcd, // x25519, 2 byte body
	}
	list, err := tls.ParseClientExtensions(exts, 0)
	if err != nil {
		t.Fatal(err)
	}
	type share struct {
		g tls.NamedGroup
		n int
	}
	var got []share
	for _, ext := range list.All {
		for _, ks := range ext.KeyShares {
			got = append(got, share{ks.Group, len(ks.Key)})
		}
	}
	if len(got) != 2 {
		t.Fatalf("got %d shares want 2", len(got))
	}
	if !tls.IsGREASE(uint16(got[0].g)) || got[0].n != 1 {
		t.Errorf("GREASE share mishandled: %+v", got[0])
	}
	if got[1].g != tls.GroupX25519 || got[1].n != 2 {
		t.Errorf("x25519 share mishandled: %+v", got[1])
	}
}

func TestServerKeyShareHelloRetryRequestForm(t *testing.T) {
	// A HelloRetryRequest names a group with no key.
	exts := []byte{0x00, 0x33, 0x00, 0x02, 0x00, 0x1d}
	list, err := tls.ParseServerExtensions(exts, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, ext := range list.All {
		for _, ks := range ext.KeyShares {
			n++
			if ks.Group != tls.GroupX25519 || len(ks.Key) != 0 {
				t.Errorf("got %v with %d key bytes", ks.Group, len(ks.Key))
			}
		}
	}
	if n != 1 {
		t.Errorf("walked %d shares want 1", n)
	}
}

func TestALPNProtos(t *testing.T) {
	exts := []byte{
		0x00, 0x10, 0x00, 0x0e,
		0x00, 0x0c,
		0x02, 'h', '2',
		0x08, 'h', 't', 't', 'p', '/', '1', '.', '1',
	}
	list, err := tls.ParseClientExtensions(exts, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, ext := range list.All {
		for _, p := range ext.ALPNProtos {
			names = append(names, string(p))
		}
	}
	if len(names) != 2 || names[0] != "h2" || names[1] != "http/1.1" {
		t.Errorf("got %q", names)
	}
}

func TestSupportedVersionsClientAndServerForms(t *testing.T) {
	// The ClientHello form is a list behind a one-byte prefix; the ServerHello
	// form is a bare uint16.
	client := []byte{0x00, 0x2b, 0x00, 0x05, 0x04, 0x1a, 0x1a, 0x03, 0x04}
	list, err := tls.ParseClientExtensions(client, 0)
	if err != nil {
		t.Fatal(err)
	}
	var vers []uint16
	for _, ext := range list.All {
		for _, v := range ext.SupportedVersions {
			vers = append(vers, v)
		}
	}
	if len(vers) != 2 || vers[1] != tls.VersionTLS13 {
		t.Errorf("client form got %#x", vers)
	}

	server := []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	list, err = tls.ParseServerExtensions(server, 0)
	if err != nil {
		t.Fatal(err)
	}
	vers = vers[:0]
	for _, ext := range list.All {
		for _, v := range ext.SupportedVersions {
			vers = append(vers, v)
		}
	}
	if len(vers) != 1 || vers[0] != tls.VersionTLS13 {
		t.Errorf("server form got %#x", vers)
	}
}

func TestVectorRejectsTrailingBytes(t *testing.T) {
	// A prefix that under-describes its buffer leaves bytes whose meaning this
	// parser and a middlebox could disagree about.
	exts := []byte{0x00, 0x0a, 0x00, 0x05, 0x00, 0x02, 0x00, 0x1d, 0xff}
	if _, err := tls.ParseClientExtensions(exts, 0); err == nil {
		t.Error("trailing bytes after vector accepted")
	}
}

func TestSubIteratorOffsetsAreBodyRelative(t *testing.T) {
	// base threads through every nesting level so a decoder adds no arithmetic.
	const base = 100
	exts := []byte{
		0x00, 0x00, 0x00, 0x0b, // server_name, 11 bytes
		0x00, 0x09, // list length
		0x00, 0x00, 0x06, // host_name, 6 bytes
		'a', '.', 'c', 'o', 'm', '!',
	}
	list, err := tls.ParseClientExtensions(exts, base)
	if err != nil {
		t.Fatal(err)
	}
	for off, ext := range list.All {
		if off != base+4 {
			t.Errorf("extension data at %d want %d", off, base+4)
		}
		for noff, name := range ext.ServerNames {
			// 4 extension header + 2 list length + 3 entry header
			if want := base + 9; noff != want {
				t.Errorf("name at %d want %d", noff, want)
			}
			if string(name.Name) != "a.com!" {
				t.Errorf("name %q", name.Name)
			}
		}
	}
}

func FuzzParseClientExtensions(f *testing.F) {
	f.Add([]byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04})
	f.Add([]byte{0x0a, 0x0a, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		list, err := tls.ParseClientExtensions(b, 0)
		if err != nil {
			return
		}
		total := 0
		for off, ext := range list.All {
			total += 4 + len(ext.Data())
			if total > len(b) {
				t.Fatalf("walked %d bytes past input length %d", total, len(b))
			}
			if off+len(ext.Data()) > len(b) {
				t.Fatalf("extension data at %d overruns %d byte input", off, len(b))
			}
			// No sub-iterator may escape its slice, whatever the type says.
			for o, ks := range ext.KeyShares {
				if o+len(ks.Key) > len(b) {
					t.Fatalf("key share at %d overruns input", o)
				}
			}
			for o, name := range ext.ServerNames {
				if o+len(name.Name) > len(b) {
					t.Fatalf("server name at %d overruns input", o)
				}
			}
			for o, p := range ext.ALPNProtos {
				if o+len(p) > len(b) {
					t.Fatalf("alpn name at %d overruns input", o)
				}
			}
			for o := range ext.SupportedVersions {
				if o+2 > len(b) {
					t.Fatalf("version at %d overruns input", o)
				}
			}
			for o := range ext.SupportedGroups {
				if o+2 > len(b) {
					t.Fatalf("group at %d overruns input", o)
				}
			}
			for o := range ext.SignatureSchemes {
				if o+2 > len(b) {
					t.Fatalf("scheme at %d overruns input", o)
				}
			}
		}
		if total != len(b) {
			t.Fatalf("clean walk consumed %d of %d bytes", total, len(b))
		}
	})
}
