package main

import (
	"fmt"
	"net"
	"os"

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
	fmt.Println("dialing...")
	conn, err := net.DialTCP("tcp4", &net.TCPAddr{IP: []byte{192, 168, 10, 1}, Port: 1337}, &net.TCPAddr{IP: []byte{192, 168, 10, 2}, Port: 80})
	if err != nil {
		return err
	}
	fmt.Println("reading...")
	var hdr httpraw.Header
	for {
		_, err = hdr.ReadFromLimited(conn, 1024)
		if err != nil {
			return err
		}
		const asRequest = false
		var ok bool
		ok, err = hdr.TryParse(asRequest)
		if ok {
			break
		} else if err != nil {
			return err
		}
	}
	fmt.Println("got HTTP:\n", hdr.String())
	return nil
}
