//go:build !tinygo

package rawsock

import "syscall"

const sysBPF = syscall.SYS_BPF
