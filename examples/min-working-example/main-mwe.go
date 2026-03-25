package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/x/xnet"
)

const pollTime = 5 * time.Millisecond
const protoTimeout = 5 * time.Second
const protoRetries = 3

const (
	tcpBufsize         = 2048
	tcpPacketQueueSize = 4
	// Number of connections in TCP pool.
	tcpConnPoolSize = 20
	// EstablishedTimeout sets the timeout for a TCP connection since it is acquired until it is established.
	// If the connection does not establish in this time it will be closed by the pool.
	tcpEstablishedTimeout = 4 * time.Second
	tcpCloseTimeout       = protoTimeout
)

var nanotime = func() int64 {
	return time.Now().UnixNano()
}

var network Interface

type Interface interface {
	SendEth(frame []byte) error
	RecvEth(dst []byte) (int, error)
	HardwareAddress6() ([6]byte, error)
	MaxFrameLength() (int, error)
}

func main() {
	var stack xnet.StackAsync
	ctx := context.Background()
	if err := run(ctx, &stack); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(ctx context.Context, stack *xnet.StackAsync) error {
	hwaddr, err := network.HardwareAddress6()
	if err != nil {
		return err
	}
	framelen, err := network.MaxFrameLength()
	if err != nil {
		return err
	}
	err = stack.Reset(xnet.StackConfig{
		Hostname: "lneto-mwe",
		RandSeed: time.Now().UnixNano(),
		// A passive TCP listener to many remote ports takes up one spot, active TCP clients to one remote port take up a spot.
		MaxTCPConns: 1,
		// MaxUDPConns: 1 , // For MDNS support.
		// AcceptMulticast: true, // For MDNS.
		MTU:             uint16(framelen - ethernet.MaxOverheadSize),
		HardwareAddress: hwaddr,
	})
	if err != nil {
		return fmt.Errorf("configuring stack: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Start stack routine to leverage easy to use blocking+retrying APIs.
	// Other option is to instead use async API which leads to more verbose
	// and more stateful code.
	go stackLoop(ctx, stack)
	rstack := stack.StackRetrying(pollTime)
	results, err := rstack.DoDHCPv4([4]byte{}, protoTimeout, protoRetries)
	if err != nil {
		return fmt.Errorf("doing DHCP: %w", err)
	}
	err = stack.AssimilateDHCPResults(results)
	if err != nil {
		return fmt.Errorf("assimilating DHCP: %w", err)
	}
	gateway, err := rstack.DoResolveHardwareAddress6(results.Router, protoTimeout, protoRetries)
	if err != nil {
		return fmt.Errorf("resolving router MAC: %w", err)
	}
	stack.SetGateway6(gateway)
	berkstack := stack.StackBlocking(pollTime).StackBerkeley(xnet.BerkeleyConfig{
		ListenerPoolConfig: xnet.TCPPoolConfig{
			PoolSize:           tcpConnPoolSize,
			QueueSize:          tcpPacketQueueSize,
			TxBufSize:          tcpBufsize,
			RxBufSize:          tcpBufsize,
			NanoTime:           nanotime,
			EstablishedTimeout: tcpEstablishedTimeout,
			ClosingTimeout:     tcpCloseTimeout,
		},
	})

	laddr := net.TCPAddrFromAddrPort(netip.AddrPortFrom(results.AssignedAddr, 80))
	// raddr := net.TCPAddr{} // If active (client) connection then set raddr in which case a net.Conn type is returned.
	const sockstream = 0x1
	c, err := berkstack.Socket(ctx, "tcp", syscall.AF_INET, sockstream, laddr, nil)
	if err != nil {
		return fmt.Errorf("creating AF_INET stream socket: %w", err)
	}
	listener := c.(net.Listener)
	for ctx.Err() == nil {
		time.Sleep(pollTime)
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("conn failed:", err)
		}
		go handleConn(conn)
	}
	return nil
}

func handleConn(conn net.Conn) {
	// Always close conn on finishing work so connection is reused.
	defer conn.Close()

	// Do something with conn.
	conn.Write([]byte("Hello!"))
}

func stackLoop(ctx context.Context, stack *xnet.StackAsync) {
	// Enables logging of packets.
	var cap xnet.CapturePrinter
	must(cap.Configure(os.Stdout, xnet.CapturePrinterConfig{
		Now:           time.Now,
		TimePrecision: 3,
	}))
	frameLength, _ := network.MaxFrameLength()
	buf := make([]byte, frameLength)
	for ctx.Err() == nil {
		nwrite, err := stack.Encapsulate(buf[:], -1, 0)
		if err != nil {
			fmt.Println("encaps err:", err)
		} else if nwrite > 0 {
			network.SendEth(buf[:nwrite])
			cap.PrintPacket("OUT", buf[:nwrite])
		}
		nread, err := network.RecvEth(buf[:])
		if err != nil {
			fmt.Println("network read err:", err)
		} else if nread > 0 {
			err = stack.Demux(buf[:nread], 0)
			if err != nil && err != lneto.ErrPacketDrop {
				fmt.Println("demux err:", err)
			} else {
				cap.PrintPacket("IN ", buf[:nread])
			}
		}
		if nwrite == 0 && nread == 0 {
			time.Sleep(pollTime)
		}
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
