package sshraw

import (
	"encoding/binary"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/wire"
	"github.com/soypat/lneto/internal"
)

// Indices of the name-lists of SSH_MSG_KEXINIT in wire order.
const (
	kexAlgorithms = iota
	hostKeyAlgorithms
	ciphersC2S
	ciphersS2C
	macsC2S
	macsS2C
	compressionC2S
	compressionS2C
	languagesC2S
	languagesS2C
	numKexLists
)

// Pseudo algorithms appended to kex_algorithms to signal support of an
// extension. They are not key exchange methods: each side sends only its own
// and looks for the peer's with [HasName], so [Negotiate] never selects them.
const (
	// KexStrictClient and KexStrictServer enable strict key exchange, OpenSSH
	// PROTOCOL 1.10, mitigating Terrapin (CVE-2023-48795). It is in use when the
	// client sends KexStrictClient and the server KexStrictServer in their first
	// KEXINIT; later KEXINITs are not looked at. Sequence numbers are then reset
	// on every NEWKEYS and any message besides those of the key exchange during
	// the first exchange must end the connection.
	KexStrictClient = "kex-strict-c-v00@openssh.com"
	KexStrictServer = "kex-strict-s-v00@openssh.com"
	// ExtInfoClient and ExtInfoServer announce willingness to receive
	// SSH_MSG_EXT_INFO, RFC 8308 2.1. Only the first KEXINIT is looked at. A
	// server may send EXT_INFO only to a client that sent ExtInfoClient.
	ExtInfoClient = "ext-info-c"
	ExtInfoServer = "ext-info-s"
)

// KexInitMsg is an SSH_MSG_KEXINIT payload, RFC 4253 7.1:
//
//	byte         SSH_MSG_KEXINIT
//	byte[16]     cookie (random bytes)
//	name-list    kex_algorithms
//	name-list    server_host_key_algorithms
//	name-list    encryption_algorithms_client_to_server
//	name-list    encryption_algorithms_server_to_client
//	name-list    mac_algorithms_client_to_server
//	name-list    mac_algorithms_server_to_client
//	name-list    compression_algorithms_client_to_server
//	name-list    compression_algorithms_server_to_client
//	name-list    languages_client_to_server
//	name-list    languages_server_to_client
//	boolean      first_kex_packet_follows
//	uint32       0 (reserved for future extension)
//
// The payload, message type byte included, is the I_C or I_S of the exchange hash.
type KexInitMsg struct {
	buf   []byte
	lists [numKexLists]uint32 // Offset of each name-list's contents.
}

func (m *KexInitMsg) reset() { *m = KexInitMsg{} }

// Decode parses a KEXINIT payload starting at its message type byte and
// validates every name-list. The reserved field is not checked to be zero.
// Decode fails if the message is not complete.
func (m *KexInitMsg) Decode(payload []byte) (int, error) {
	m.reset()
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgKexInit)
	dec.Advance(SizeCookie)
	var lists [numKexLists]uint32
	for i := range lists {
		list := dec.NameList()
		lists[i] = uint32(dec.Off() - len(list))
	}
	dec.Bool()   // first_kex_packet_follows.
	dec.Uint32() // reserved.
	if dec.IsFailed() {
		return dec.Off(), dec.Err()
	}
	m.buf = payload
	m.lists = lists
	return dec.Off(), nil
}

// list returns the contents of the i'th name-list.
func (m *KexInitMsg) list(i int) []byte {
	off := m.lists[i]
	n := binary.BigEndian.Uint32(m.buf[off-4:])
	return m.buf[off : off+n]
}

// Cookie returns the 16 random bytes of the sender.
func (m *KexInitMsg) Cookie() *[SizeCookie]byte { return (*[SizeCookie]byte)(m.buf[1 : 1+SizeCookie]) }

// KexAlgorithms returns kex_algorithms. It also carries pseudo algorithms such
// as [KexStrictClient] and [ExtInfoClient], looked for with [HasName].
func (m *KexInitMsg) KexAlgorithms() []byte { return m.list(kexAlgorithms) }

// HostKeyAlgorithms returns server_host_key_algorithms.
func (m *KexInitMsg) HostKeyAlgorithms() []byte { return m.list(hostKeyAlgorithms) }

// CiphersClientToServer returns encryption_algorithms_client_to_server.
func (m *KexInitMsg) CiphersClientToServer() []byte { return m.list(ciphersC2S) }

// CiphersServerToClient returns encryption_algorithms_server_to_client.
func (m *KexInitMsg) CiphersServerToClient() []byte { return m.list(ciphersS2C) }

// MACsClientToServer returns mac_algorithms_client_to_server. It is not
// negotiated when the cipher is an AEAD, whose tag is the MAC.
func (m *KexInitMsg) MACsClientToServer() []byte { return m.list(macsC2S) }

// MACsServerToClient returns mac_algorithms_server_to_client. It is not
// negotiated when the cipher is an AEAD, whose tag is the MAC.
func (m *KexInitMsg) MACsServerToClient() []byte { return m.list(macsS2C) }

// CompressionClientToServer returns compression_algorithms_client_to_server.
func (m *KexInitMsg) CompressionClientToServer() []byte { return m.list(compressionC2S) }

// CompressionServerToClient returns compression_algorithms_server_to_client.
func (m *KexInitMsg) CompressionServerToClient() []byte { return m.list(compressionS2C) }

// LanguagesClientToServer returns languages_client_to_server, usually empty.
func (m *KexInitMsg) LanguagesClientToServer() []byte { return m.list(languagesC2S) }

// LanguagesServerToClient returns languages_server_to_client, usually empty.
func (m *KexInitMsg) LanguagesServerToClient() []byte { return m.list(languagesS2C) }

// FirstKexPacketFollows reports whether the sender guessed the key exchange
// method and sent its first packet already. If the guess is wrong the packet
// must be ignored, RFC 4253 7.
func (m *KexInitMsg) FirstKexPacketFollows() bool {
	last := m.list(languagesS2C)
	off := int(m.lists[languagesS2C]) + len(last)
	return m.buf[off] != 0
}

// WrongGuess reports whether the peer that sent m guessed the key exchange and
// guessed wrong, in which case its next packet must be silently ignored,
// RFC 4253 7. own is the KEXINIT sent to the peer. The guess is right when both
// sides prefer the same key exchange and host key algorithms, those listed first.
func (m *KexInitMsg) WrongGuess(own *KexInitMsg) bool {
	if !m.FirstKexPacketFollows() {
		return false
	}
	peerKex, _ := nextName(m.KexAlgorithms())
	ownKex, _ := nextName(own.KexAlgorithms())
	peerHostKey, _ := nextName(m.HostKeyAlgorithms())
	ownHostKey, _ := nextName(own.HostKeyAlgorithms())
	return !internal.BytesEqual(peerKex, ownKex) || !internal.BytesEqual(peerHostKey, ownHostKey)
}

// decoder provides an API to readably decode SSH messages, RFC 4251 5, see [wire.Decoder].
type decoder struct {
	wire.Decoder
	_err error
}

func (dec *decoder) Fail(err error) {
	dec._err = err
	dec.Decoder.Fail()
}

func (dec *decoder) Err() (err error) {
	if dec._err != nil {
		err = dec._err
	} else if dec.Decoder.IsFailed() {
		err = lneto.ErrTruncatedFrame
	}
	return err
}

func (dec *decoder) IsFailed() bool {
	return dec.Decoder.IsFailed() || dec._err != nil
}

// Bool decodes a boolean. Any non-zero value is true, RFC 4251 5.
func (dec *decoder) Bool() bool { return dec.Uint8() != 0 }

// String decodes a length prefixed string and returns its contents.
func (dec *decoder) String() []byte { return dec.Take(dec.Uint32()) }

// NameList decodes a string and validates it as a name-list.
func (dec *decoder) NameList() []byte {
	list := dec.String()
	if list == nil {
		return nil
	} else if err := ValidateNameList(list); err != nil {
		dec.Fail(err)
		return nil
	}
	return list
}

// MPInt decodes a non-negative mpint, RFC 4251 5, and returns its unsigned big
// endian magnitude without the leading zero byte. Negative values and needless
// leading bytes are rejected. Zero is returned as an empty slice.
func (dec *decoder) MPInt() []byte {
	v := dec.String()
	switch {
	case len(v) == 0:
		return v
	case v[0]&0x80 != 0:
		dec.Fail(lneto.ErrInvalidField) // Negative.
		return nil
	case v[0] == 0:
		if len(v) == 1 || v[1]&0x80 == 0 {
			dec.Fail(lneto.ErrInvalidField) // Needless leading zero.
			return nil
		}
		return v[1:]
	}
	return v
}

// msgType decodes the message type byte and requires it to be want.
func (dec *decoder) msgType(want MsgType) {
	if MsgType(dec.Uint8()) != want {
		dec.Fail(lneto.ErrInvalidField)
	}
}

// end requires the message to have been decoded whole.
func (dec *decoder) end() {
	if dec.Remaining() != 0 {
		dec.Fail(lneto.ErrInvalidLengthField)
	}
}

// ValidateNameList validates the contents of a name-list, RFC 4251 5: comma
// separated names of printable US-ASCII without whitespace, each at most
// [maxNameLen] long. The empty list is valid.
func ValidateNameList(list []byte) error {
	if len(list) == 0 {
		return nil
	}
	start := 0
	for i := 0; i <= len(list); i++ {
		if i == len(list) || list[i] == ',' {
			if err := validateName(list[start:i]); err != nil {
				return err
			}
			start = i + 1
		}
	}
	return nil
}

// HasName reports whether name is one of the names of list.
func HasName(list, name []byte) bool {
	for len(list) > 0 {
		var next []byte
		next, list = nextName(list)
		if internal.BytesEqual(next, name) {
			return true
		}
	}
	return false
}

// Negotiate returns the first name of the client's list that is also in the
// server's list, RFC 4253 7.1. The result is a view into client. ok is false
// when no name is shared and the connection must be closed.
func Negotiate(client, server []byte) (name []byte, ok bool) {
	for len(client) > 0 {
		name, client = nextName(client)
		if HasName(server, name) {
			return name, true
		}
	}
	return nil, false
}

// nextName splits off the first name of a non-empty list.
func nextName(list []byte) (name, rest []byte) {
	for i := range list {
		if list[i] == ',' {
			return list[:i], list[i+1:]
		}
	}
	return list, nil
}
