//go:build !tinygo && darwin

package rawsock

import "syscall"

const sysaccept = syscall.SYS_ACCEPT
