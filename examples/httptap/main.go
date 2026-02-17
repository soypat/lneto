package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/internet/pcap"
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
		flagInterface = "tap0"
		flagMinMTU    = math.MaxUint16
	)
	flag.StringVar(&flagInterface, "i", flagInterface, "Interface to select. tap* creates a tap interface. Any other name will create a bridge to the name of the interface i.e: 'enp7s0', 'wlp8s0', 'lo'")
	flag.IntVar(&flagMinMTU, "mtu", flagMinMTU, "Set the interface minimum MTU to use for buffer.")
	flag.Parse()
	if flagMinMTU < 1500 {
		return errors.New("minimum MTU too small")
	}
	var (
		flagNet             = "192.168.10.1/24"
		flagiface           = "tap0"
		flagPacketQueueSize = 2048
	)
	var iface ltesto.Interface
	if strings.HasPrefix(flagInterface, "tap") {
		pfx, err := netip.ParsePrefix(flagNet)
		if err != nil {
			return err
		}
		tap, err := internal.NewTap(flagiface, pfx)
		if err != nil {
			return err
		}
		iface = tap
	} else {
		br, err := internal.NewBridge(flagInterface)
		if err != nil {
			return err
		}
		iface = br
	}

	sv, err := ltesto.NewHTTPTapServer(iface, flagMinMTU, flagPacketQueueSize, flagPacketQueueSize)
	if err != nil {
		return err
	}
	defer sv.Close()
	var cap pcap.PacketBreakdown
	pf := pcap.Formatter{
		FilterClasses: []pcap.FieldClass{pcap.FieldClassDst, pcap.FieldClassSrc, pcap.FieldClassSize, pcap.FieldClassFlags},
	}
	var pfbuf []byte
	sv.OnTransfer(func(channel int, pkt []byte) {
		channelstr := "OS"
		if channel != 0 {
			channelstr = strconv.Itoa(channel) // Will not allocate for values 99 and under (stdlib).
		}
		captime := time.Now()
		frames, err := cap.CaptureEthernet(nil, pkt, 0)
		if err == nil {
			pfbuf = append(pfbuf[:0], '[')
			pfbuf, err = pf.FormatFrames(pfbuf, frames, pkt)
			pfbuf = append(pfbuf, ']')
			if err != nil {
				fmt.Printf("%-2s %s !err:%s\n", channelstr, captime.Format("15:04:05.000"), err)
			} else {
				fmt.Printf("%-2s %s %s\n", channelstr, captime.Format("15:04:05.000"), pfbuf)
			}
		} else {
			fmt.Printf("%-2s %s %s %v %s\n", channelstr, captime.Format("15:04:05.000"), "cap ERR", frames, err.Error())
		}
	})
	hwaddr, err := sv.HardwareAddress6()
	if err != nil {
		return err
	}
	fmt.Println("listening on http://127.0.0.1:7070/recv  and  http://127.0.0.1:7070/send on hwaddr:", net.HardwareAddr(hwaddr[:]).String())
	http.ListenAndServe(":7070", sv)
	return errors.New("finished")
}
