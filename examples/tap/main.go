package main

import (
	"fmt"
	"log"
	"net/netip"
	"os"
	"time"

	"github.com/soypat/lneto/internal"
)

func main() {
	err := run()
	if err != nil {
		log.Fatalln("failed:", err)
	}
	fmt.Println("finished")

}

func run() error {
	ip := netip.MustParsePrefix("192.168.10.1/24")
	tap, err := internal.NewTap("tap0", ip)
	if err != nil {
		return err
	}
	defer tap.Close()
	var buf [2048]byte
	pkt := 0
	for {
		n, err := tap.Read(buf[:])
		if err != nil {
			return err
		} else if n == 0 {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		pkt++
		fmt.Fprintf(os.Stdout, "rx%d (%d): %q\n\n", pkt, n, buf[:n])
	}
}
