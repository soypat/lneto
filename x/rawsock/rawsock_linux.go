//go:build !tinygo && linux && !386

package rawsock

import "syscall"

const sysaccept = syscall.SYS_ACCEPT4
