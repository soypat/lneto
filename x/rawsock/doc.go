// Package rawsock listens and reads over Linux sockets through syscalls
// directly, without the net package. It exists so a server can be measured
// without net.TCPConn, its netFD and its poller on the path.
//
// [Conn] and [Listener] implement [net.Conn] and [net.Listener] the way
// TinyGo's net package does: a connection is its file descriptor plus its
// addresses, deadlines live on the struct and are handed to the socket, and
// nothing sits between a Read and the syscall. A server written against these
// interfaces runs unchanged over the net package, over this package and over
// TinyGo's netdev.
package rawsock
