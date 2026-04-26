//go:build tinygo

package netdev

// UseNetdev is the dynamic linker function
// for inserting a networking stack into the
// standard library implementation in the TinyGo compiler.
//
//go:linkname UseNetdev net.useNetdev
func UseNetdev(dev GoNet)
