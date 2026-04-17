package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	gnet "github.com/usbarmory/go-net"
)

const pollTime = 5 * time.Millisecond

var networkDevice NetworkDevice

// NetworkDevice implements gnet.NetworkDevice for bridging with raw Ethernet I/O.
type NetworkDevice struct {
	send func([]byte) error
	recv func([]byte) (int, error)
}

func (d *NetworkDevice) Transmit(buf []byte) error        { return d.send(buf) }
func (d *NetworkDevice) Receive(buf []byte) (int, error)   { return d.recv(buf) }

func main() {
	ctx := context.Background()
	if err := run(ctx); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	// Create gVisor-based networking stack.
	stack := gnet.NewGVisorStack(1)

	// Configure stack with MAC, IP prefix, and gateway.
	err := stack.Configure(
		"aa:bb:cc:dd:ee:ff",
		netip.MustParsePrefix("192.168.1.10/24"),
		netip.MustParseAddr("192.168.1.1"),
	)
	if err != nil {
		return fmt.Errorf("configuring stack: %w", err)
	}

	err = stack.EnableICMP()
	if err != nil {
		return fmt.Errorf("enabling ICMP: %w", err)
	}

	// Bridge the stack with a network device for packet I/O.
	iface := &gnet.Interface{
		Stack:         stack,
		NetworkDevice: &networkDevice,
		HandleStackErr: func(err error, tx bool) {
			dir := "rx"
			if tx {
				dir = "tx"
			}
			fmt.Printf("stack %s err: %v\n", dir, err)
		},
	}
	// Start the packet processing loop in a goroutine.
	go iface.Start()

	// Create a TCP listener on port 80 using the gVisor stack.
	const sockStream = 0x1
	laddr := net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("192.168.1.10"), 80))
	c, err := stack.Socket(ctx, "tcp", syscall.AF_INET, sockStream, laddr, nil)
	if err != nil {
		return fmt.Errorf("creating AF_INET stream socket: %w", err)
	}
	listener := c.(net.Listener)
	for ctx.Err() == nil {
		time.Sleep(pollTime)
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("conn failed:", err)
			continue
		}
		go handleConn(conn)
	}
	return nil
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	conn.Write([]byte("Hello from gVisor stack!"))
}
