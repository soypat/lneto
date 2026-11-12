//go:build !tinygo

package rawsock

// sysBPF is the bpf(2) syscall number, missing from the syscall package on amd64.
const sysBPF = 321
