package main

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"time"

	"github.com/soypat/lneto"
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
	var cap pcap.PacketBreakdown
	sv.OnTransfer(func(channel int, pkt []byte) {
		captime := time.Now()
		frames, err := cap.CaptureEthernet(nil, pkt, 0)
		if err == nil {
			flags, src, dst := getTCPData(frames, pkt)
			if flags != 0 {
				fmt.Println(channel, captime.Format("15:04:05.000"), frames, flags.String(), src, "->", dst)
			} else {
				fmt.Println(channel, captime.Format("15:04:05.000"), frames)
			}
		} else {
			fmt.Println(channel, captime.Format("15:04:05.000"), "ERR", frames, err.Error())
		}
	})
	hwaddr, err := sv.HardwareAddress6()
	if err != nil {
		return err
	}
	fmt.Println("listening on http://127.0.0.1:7070/recv  and  http://127.0.0.1:7070/send on hwaddr:", net.HardwareAddr(hwaddr[:]).String())
	go http.ListenAndServe(":7070", sv)
	const standbyDuration = 5 * time.Second
	lastHit := time.Now().Add(-standbyDuration)
	for {
		result, err := sv.HandleTap()
		if err != nil {
			slog.Error("handletap:error", slog.String("err", err.Error()), slog.Any("result", result))
		}
		if result.Failed {
			return errors.New("tap failed, exit program")
		} else if result.ReceivedSize == 0 && result.SentSize == 0 {
			if time.Since(lastHit) > standbyDuration {
				time.Sleep(5 * time.Millisecond) // Enter standby.
			} else {
				runtime.Gosched()
			}
		} else {
			lastHit = time.Now()
		}
	}
}

func getTCPData(frames []pcap.Frame, pkt []byte) (flags tcp.Flags, src, dst uint16) {
	for i := range frames {
		if frames[i].Protocol != lneto.IPProtoTCP {
			continue
		}
		return tcp.Flags(getFrameClassUint(frames[i], pkt, pcap.FieldClassFlags)),
			uint16(getFrameClassUint(frames[i], pkt, pcap.FieldClassSrc)),
			uint16(getFrameClassUint(frames[i], pkt, pcap.FieldClassDst))
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
