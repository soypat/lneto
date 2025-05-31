package main

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/soypat/lneto/internal/ltesto"
)

func main() {
	err := run()
	if err != nil {
		log.Fatalln("failed:", err)
	}
	fmt.Println("finished")

}

func run() error {
	var (
		flagNet             = "192.168.10.1/24"
		flagiface           = "tap0"
		flagMTU             = 1500
		flagPacketQueueSize = 2048
	)
	ip, err := netip.ParsePrefix(flagNet)
	if err != nil {
		return err
	}
	sv, err := ltesto.NewHTTPTapServer(flagiface, ip, flagMTU, flagPacketQueueSize, flagPacketQueueSize)
	if err != nil {
		return err
	}
	defer sv.Close()
	hwaddr, err := sv.HardwareAddress6()
	if err != nil {
		return err
	}
	fmt.Println("listening on http://127.0.0.1:7070/recv  and  http://127.0.0.1:7070/send on hwaddr:", net.HardwareAddr(hwaddr[:]).String())
	go http.ListenAndServe(":7070", sv)
	misses := 0
	for {
		result, err := sv.HandleTap()
		if err != nil {
			slog.Error("handletap:error", slog.String("err", err.Error()), slog.Any("result", result))
		}
		if result.Failed {
			return errors.New("tap failed, exit program")
		} else if result.ReceivedSize == 0 && result.SentSize == 0 {
			misses++
			if misses > 1000 {
				time.Sleep(200 * time.Millisecond) // No data exchanged, sleep a bit to not hog CPU.
			} else {
				time.Sleep(50 * time.Millisecond) // No data exchanged, sleep a bit to not hog CPU.
			}
		} else {
			misses = 0
		}
	}
}
