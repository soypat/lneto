package sshraw

import (
	"encoding/binary"

	"github.com/soypat/lneto"
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
	dec := decoder{buf: payload, vld: vld}
	dec.msgType(MsgKexInit)
	dec.Advance(SizeCookie)
	var lists [numKexLists]uint32
	for i := range lists {
		list := dec.NameList()
		lists[i] = uint32(dec.off - len(list))
	}
	dec.Bool()   // first_kex_packet_follows.
	dec.Uint32() // reserved.
	if vld.HasError() {
		return dec.off, vld.ErrPop()
	}
	m.buf = payload
	m.lists = lists
	return dec.off, nil
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
