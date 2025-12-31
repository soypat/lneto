package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/internet/pcap"
	"github.com/soypat/lneto/tcp"
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
	)
	flag.StringVar(&flagInterface, "i", flagInterface, "Interface to select. tap* creates a tap interface. Any other name will create a bridge to the name of the interface i.e: 'enp7s0', 'wlp8s0', 'lo'")
	flag.Parse()
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

	sv, err := ltesto.NewHTTPTapServer(iface, flagPacketQueueSize, flagPacketQueueSize)
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
		captime := time.Now()
		frames, err := cap.CaptureEthernet(nil, pkt, 0)
		if err == nil {
			pfbuf = append(pfbuf[:0], '[')
			pfbuf, err = pf.FormatFrames(pfbuf, frames, pkt)
			pfbuf = append(pfbuf, ']')
			if err != nil {
				fmt.Printf("%d %s !err:%s\n", channel, captime.Format("15:04:05.000"), err)
			} else {
				fmt.Printf("%d %s %s\n", channel, captime.Format("15:04:05.000"), pfbuf)
			}
		} else {
			fmt.Println(channel, captime.Format("15:04:05.000"), "cap ERR", frames, err.Error())
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

func getTCPData(frames []pcap.Frame, pkt []byte) (flags tcp.Flags, src, dst uint16) {
	for i := range frames {
		proto := frames[i].Protocol
		if proto == lneto.IPProtoTCP {
			return tcp.Flags(getFrameClassUint(frames[i], pkt, pcap.FieldClassFlags)),
				uint16(getFrameClassUint(frames[i], pkt, pcap.FieldClassSrc)),
				uint16(getFrameClassUint(frames[i], pkt, pcap.FieldClassDst))
		} else if proto == lneto.IPProtoUDP {
			return 0,
				uint16(getFrameClassUint(frames[i], pkt, pcap.FieldClassSrc)),
				uint16(getFrameClassUint(frames[i], pkt, pcap.FieldClassDst))
		}
	}
	return 0, 0, 0
}

func getFrameClassUint(frame pcap.Frame, pkt []byte, class pcap.FieldClass) uint64 {
	iflags, err := frame.FieldByClass(class)
	if err != nil {
		return 0
	}
	v, err := frame.FieldAsUint(iflags, pkt)
	if err != nil {
		return 0
	}
	return v
}
