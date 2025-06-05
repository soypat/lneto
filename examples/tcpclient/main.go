package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/soypat/lneto/http/httpraw"
)

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("DONE")
}

func run() error {
	var port int
	flag.IntVar(&port, "lport", 13337, "Local port over which to hit server")
	flag.Parse()
	// Prepare GET request.
	var hdr httpraw.Header
	hdr.SetMethod("GET")
	hdr.SetRequestURI("/")
	hdr.SetProtocol("HTTP/1.1")
	req, err := hdr.AppendRequest(nil)
	if err != nil {
		return err
	}

	fmt.Println(time.Now().Format("15:04:05.000"), "dialing...")
	conn, err := net.DialTCP("tcp4", &net.TCPAddr{IP: []byte{192, 168, 10, 1}, Port: port}, &net.TCPAddr{IP: []byte{192, 168, 10, 2}, Port: 80})
	if err != nil {
		return err
	}
	defer conn.Close()
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		s := <-c
		fmt.Println("terminating connection on signal", s.String())
		conn.Close()
		os.Exit(0)
	}()
	fmt.Println(time.Now().Format("15:04:05.000"), "writing...")
	conn.Write(req)
	hdr.Reset(nil)
	var needMore bool = true
	for needMore {
		_, err = hdr.ReadFromLimited(conn, 1024)
		if err != nil {
			break
		}
		const asResponse = true
		needMore, err = hdr.TryParse(asResponse)
	}
	if err != nil {
		return err
	}
	fmt.Println(time.Now().Format("15:04:05.000"), "got HTTP:\n", hdr.String())
	return nil
}
