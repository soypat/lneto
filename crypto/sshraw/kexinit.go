package sshraw

import (
	"encoding/binary"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/wire"
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
func (m *KexInitMsg) Decode(payload []byte, vld *lneto.Validator) (int, error) {
	m.reset()
	var dec decoder
	dec.Reset(payload, vld)
	dec.msgType(MsgKexInit)
	dec.Advance(SizeCookie)
	var lists [numKexLists]uint32
	for i := range lists {
		list := dec.NameList()
		lists[i] = uint32(dec.Off() - len(list))
	}
	dec.Bool()   // first_kex_packet_follows.
	dec.Uint32() // reserved.
	if vld.HasError() {
		return dec.Off(), vld.ErrPop()
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

// decoder provides an API to readably decode SSH messages, RFC 4251 5, see [wire.Decoder].
type decoder struct{ wire.Decoder }

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
