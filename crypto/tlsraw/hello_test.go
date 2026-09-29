package tlsraw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/rfc8448"
)

// extCase is one extension_data blob with the outcome expected of it in each
// direction. Both directions live in the same row because most of what
// ValidateType enforces is the asymmetry between them: a client offers a list
// where a server names the single thing it picked.
type extCase struct {
	name   string
	exts   []ExtensionType // types sharing one ValidateType branch.
	data   []byte          // extension_data; the 4-byte header is synthesized.
	client error           // wanted error when sent by a client, nil when valid.
	server error           // wanted error when sent by a server.
}

var key32 = make([]byte, 32) // A key share of the x25519 size; contents unread.

var extCases = []extCase{
	// application_layer_protocol_negotiation, RFC 7301 3.1.
	{
		name:   "alpn one name",
		exts:   []ExtensionType{ExtALPN},
		data:   vec16(name("h2")),
		client: nil,
		server: nil, // The single name fills the list.
	}, {
		name:   "alpn two names",
		exts:   []ExtensionType{ExtALPN},
		data:   vec16(name("h2"), name("http")),
		client: nil,                         // A client offers a list.
		server: lneto.ErrInvalidLengthField, // A server selects one, RFC 7301 3.2.
	}, {
		name:   "alpn zero length name",
		exts:   []ExtensionType{ExtALPN},
		data:   vec16(name("")),
		client: lneto.ErrTruncatedFrame, // Too short to hold any valid list.
		server: lneto.ErrTruncatedFrame,
	}, {
		name:   "alpn zero length name then name",
		exts:   []ExtensionType{ExtALPN},
		data:   vec16(name(""), name("h2")),
		client: lneto.ErrInvalidLengthField, // A walk could not advance past it.
		server: lneto.ErrInvalidLengthField,
	}, {
		name:   "alpn list length too long",
		exts:   []ExtensionType{ExtALPN},
		data:   setLen16(vec16(name("h2")), +1),
		client: lneto.ErrTruncatedFrame,
		server: lneto.ErrTruncatedFrame,
	}, {
		name:   "alpn list length too short",
		exts:   []ExtensionType{ExtALPN},
		data:   setLen16(vec16(name("h2")), -1),
		client: lneto.ErrInvalidLengthField,
		server: lneto.ErrInvalidLengthField,
	}, {
		name:   "alpn empty list",
		exts:   []ExtensionType{ExtALPN},
		data:   vec16(),
		client: lneto.ErrTruncatedFrame,
		server: lneto.ErrTruncatedFrame,
	}, {
		name:   "alpn name overruns list",
		exts:   []ExtensionType{ExtALPN},
		data:   vec16(name("h2"), b(0x05)), // Last name claims 5 bytes, none follow.
		client: lneto.ErrTruncatedFrame,
		server: lneto.ErrInvalidLengthField,
	},

	// server_name, RFC 6066 3. A server acknowledges with empty extension_data.
	{
		name:   "sni one host",
		exts:   []ExtensionType{ExtServerName},
		data:   sni("example.com"),
		client: nil,
		server: lneto.ErrInvalidLengthField,
	}, {
		name:   "sni empty",
		exts:   []ExtensionType{ExtServerName},
		data:   nil,
		client: lneto.ErrTruncatedFrame,
		server: nil, // The server's acknowledgement.
	}, {
		name:   "sni not host_name",
		exts:   []ExtensionType{ExtServerName},
		data:   vec16(b(1), u16(3), b('a', 'b', 'c')),
		client: lneto.ErrInvalidField,
		server: lneto.ErrInvalidLengthField,
	}, {
		name:   "sni two hosts",
		exts:   []ExtensionType{ExtServerName},
		data:   vec16(b(0), u16(1), b('a'), b(0), u16(1), b('b')),
		client: lneto.ErrInvalidLengthField,
		server: lneto.ErrInvalidLengthField,
	}, {
		name:   "sni zero length host",
		exts:   []ExtensionType{ExtServerName},
		data:   vec16(b(0), u16(0)),
		client: lneto.ErrTruncatedFrame, // Shorter than the shortest valid list.
		server: lneto.ErrInvalidLengthField,
	}, {
		name:   "sni host length too long",
		exts:   []ExtensionType{ExtServerName},
		data:   vec16(b(0), u16(4), b('a', 'b', 'c')),
		client: lneto.ErrTruncatedFrame,
		server: lneto.ErrInvalidLengthField,
	},

	// supported_groups, signature_algorithms and signature_algorithms_cert are
	// all lists of 16-bit codes and share one branch.
	{
		name:   "code list two entries",
		exts:   []ExtensionType{ExtSupportedGroups, ExtSignatureAlgorithms, ExtSignatureAlgorithmsCert},
		data:   vec16(u16(uint16(GroupX25519)), u16(uint16(GroupSECP256R1))),
		client: nil,
		server: nil,
	}, {
		name:   "code list one entry",
		exts:   []ExtensionType{ExtSupportedGroups, ExtSignatureAlgorithms, ExtSignatureAlgorithmsCert},
		data:   vec16(u16(uint16(GroupX25519))),
		client: nil,
		server: nil,
	}, {
		name:   "code list odd length",
		exts:   []ExtensionType{ExtSupportedGroups, ExtSignatureAlgorithms, ExtSignatureAlgorithmsCert},
		data:   vec16(u16(uint16(GroupX25519)), b(0x00)),
		client: lneto.ErrInvalidLengthField,
		server: lneto.ErrInvalidLengthField,
	}, {
		name:   "code list empty",
		exts:   []ExtensionType{ExtSupportedGroups, ExtSignatureAlgorithms, ExtSignatureAlgorithmsCert},
		data:   vec16(),
		client: lneto.ErrInvalidLengthField,
		server: lneto.ErrInvalidLengthField,
	}, {
		name:   "code list length too long",
		exts:   []ExtensionType{ExtSupportedGroups, ExtSignatureAlgorithms, ExtSignatureAlgorithmsCert},
		data:   setLen16(vec16(u16(uint16(GroupX25519))), +2),
		client: lneto.ErrTruncatedFrame,
		server: lneto.ErrTruncatedFrame,
	},

	// supported_versions, RFC 8446 4.2.1. A client lists, a server names one.
	{
		name:   "versions client list",
		exts:   []ExtensionType{ExtSupportedVersions},
		data:   vec8(u16(VersionTLS13)),
		client: nil,
		server: lneto.ErrInvalidLengthField,
	}, {
		name:   "versions server selection",
		exts:   []ExtensionType{ExtSupportedVersions},
		data:   u16(VersionTLS13),
		client: lneto.ErrTruncatedFrame,
		server: nil,
	}, {
		name:   "versions list odd length",
		exts:   []ExtensionType{ExtSupportedVersions},
		data:   vec8(u16(VersionTLS13), b(0x00)),
		client: lneto.ErrInvalidLengthField,
		server: lneto.ErrInvalidLengthField,
	}, {
		name:   "versions list empty",
		exts:   []ExtensionType{ExtSupportedVersions},
		data:   vec8(),
		client: lneto.ErrInvalidLengthField,
		server: lneto.ErrInvalidLengthField,
	},

	// key_share, RFC 8446 4.2.8.
	{
		name:   "key share client one entry",
		exts:   []ExtensionType{ExtKeyShare},
		data:   vec16(share(GroupX25519, key32)),
		client: nil,
		server: lneto.ErrInvalidLengthField,
	}, {
		name:   "key share client two entries",
		exts:   []ExtensionType{ExtKeyShare},
		data:   vec16(share(GroupX25519, key32), share(GroupSECP256R1, key32)),
		client: nil,
		server: lneto.ErrInvalidLengthField,
	}, {
		name:   "key share server entry",
		exts:   []ExtensionType{ExtKeyShare},
		data:   share(GroupX25519, key32),
		client: lneto.ErrInvalidLengthField,
		server: nil,
	}, {
		name:   "key share hello retry request group",
		exts:   []ExtensionType{ExtKeyShare},
		data:   u16(uint16(GroupX25519)),
		client: lneto.ErrTruncatedFrame,
		server: nil, // A HelloRetryRequest carries the group alone.
	}, {
		name:   "key share empty client shares",
		exts:   []ExtensionType{ExtKeyShare},
		data:   vec16(),
		client: nil, // A client soliciting a HelloRetryRequest.
		server: nil, // Shape of a group-only entry; the group itself is unchecked.
	}, {
		name:   "key share client zero length key",
		exts:   []ExtensionType{ExtKeyShare},
		data:   vec16(share(GroupX25519, nil)),
		client: lneto.ErrInvalidLengthField,
		// A server reads the list length as its group and the group as a key
		// length, which then overruns.
		server: lneto.ErrTruncatedFrame,
	}, {
		name:   "key share server zero length key",
		exts:   []ExtensionType{ExtKeyShare},
		data:   share(GroupX25519, nil),
		client: lneto.ErrTruncatedFrame,
		server: lneto.ErrInvalidLengthField,
	}, {
		name:   "key share key length too long",
		exts:   []ExtensionType{ExtKeyShare},
		data:   setLen16(vec16(share(GroupX25519, key32)), +2),
		client: lneto.ErrTruncatedFrame,
		server: lneto.ErrInvalidLengthField,
	},
}

// TestValidateTypeTable checks the shape each extension is allowed to take in
// each direction.
func TestValidateTypeTable(t *testing.T) {
	for _, tc := range extCases {
		for _, ext := range tc.exts {
			for _, sentByServer := range [2]bool{false, true} {
				want := tc.client
				dir := "client"
				if sentByServer {
					want, dir = tc.server, "server"
				}
				t.Run(fmt.Sprintf("%s/ext%d/%s", tc.name, ext, dir), func(t *testing.T) {
					ef, err := NewExtensionFrame(frame(ext, tc.data))
					if err != nil {
						t.Fatalf("frame: %s", err)
					}
					var vld lneto.Validator
					if checked := ef.ValidateType(&vld, sentByServer); !checked {
						t.Fatalf("extension %d not checked by ValidateType", ext)
					}
					got := vld.ErrPop()
					if !errors.Is(got, want) {
						t.Errorf("data=%x err=%v, want %v", tc.data, got, want)
					}
				})
			}
		}
	}
}

// TestValidateTypeTruncation feeds every truncation of every table case to
// ValidateType. Any error is fine, a panic is not: a validator must decide on
// the bytes it was handed and never index past them.
func TestValidateTypeTruncation(t *testing.T) {
	for _, tc := range extCases {
		for _, ext := range tc.exts {
			// The header declares the truncated length so the bytes reach the
			// validator; NewExtensionFrame would reject a frame cut short of it.
			for n := 0; n <= len(tc.data); n++ {
				ef, err := NewExtensionFrame(frame(ext, tc.data[:n]))
				if err != nil {
					t.Fatalf("%s: frame of %d bytes: %s", tc.name, n, err)
				}
				var vld lneto.Validator
				ef.ValidateType(&vld, false)
				vld.ResetErr()
				ef.ValidateType(&vld, true)
			}
		}
	}
}

// TestValidateTypeRFC8448 walks the extensions of a real handshake to catch a
// validator tightened past traffic that must be accepted.
func TestValidateTypeRFC8448(t *testing.T) {
	var vld lneto.Validator
	var ch HelloClientMsg
	if _, err := ch.Decode(rfc8448.ClientHello[SizeHeaderHandshake:], &vld); err != nil {
		t.Fatal(err)
	}
	walkExtensions(t, ch.Extensions(), false, func(ExtensionFrame) {})
	var sh HelloServerMsg
	if _, err := sh.Decode(rfc8448.ServerHello[SizeHeaderHandshake:], &vld); err != nil {
		t.Fatal(err)
	}
	walkExtensions(t, sh.Extensions(), true, func(ExtensionFrame) {})
}

// frame prepends the extension header to data, so no case can accidentally
// exercise NewExtensionFrame's length check in place of a validator.
func frame(ext ExtensionType, data []byte) []byte {
	return append(append(u16(uint16(ext)), u16(uint16(len(data)))...), data...)
}

func b(v ...byte) []byte { return v }

func u16(v uint16) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return buf[:]
}

// vec8 concatenates body behind the 1-byte length prefix of a TLS vector.
func vec8(body ...[]byte) []byte {
	v := concat(body)
	return append([]byte{byte(len(v))}, v...)
}

// vec16 concatenates body behind the 2-byte length prefix of a TLS vector.
func vec16(body ...[]byte) []byte {
	v := concat(body)
	return append(u16(uint16(len(v))), v...)
}

// name builds an ALPN ProtocolName.
func name(s string) []byte { return vec8([]byte(s)) }

// sni builds a ServerNameList holding one host_name.
func sni(host string) []byte {
	return vec16(b(0), u16(uint16(len(host))), []byte(host))
}

// share builds a KeyShareEntry.
func share(g NamedGroup, key []byte) []byte {
	return append(u16(uint16(g)), vec16(key)...)
}

// setLen16 adds delta to the 2-byte length prefix at the start of v, making it
// lie about the bytes that follow.
func setLen16(v []byte, delta int) []byte {
	v = append([]byte{}, v...)
	binary.BigEndian.PutUint16(v, uint16(int(binary.BigEndian.Uint16(v))+delta))
	return v
}

func concat(parts [][]byte) []byte {
	var v []byte
	for _, p := range parts {
		v = append(v, p...)
	}
	return v
}
