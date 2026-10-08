//go:build !(386 || arm || mips || mipsle)

package lneto

// ConnID is the connection context number returned by
// [StackNode.ConnectionID]. Stacks read it atomically while the node's owner
// may change it, so its width follows the platform: 64-bit atomics panic on
// 386, arm, mips and mipsle unless the word is 8-byte aligned, which a field
// in an arbitrary struct is not. ConnID is uint32 there and uint64 elsewhere.
// It is a defined type so that implementations name it on every platform
// rather than a width that only builds on some.
type ConnID uint64
