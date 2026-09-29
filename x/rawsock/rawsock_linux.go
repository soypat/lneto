//go:build !tinygo && linux

package rawsock

import "syscall"

const sysaccept = syscall.SYS_ACCEPT4
