package xnet

import (
	"io"
	"strconv"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internet/pcap"
)

type CapturePrinterConfig struct {
	NamespaceWidth int
	// TimePrecision if non-zero is used to print timestamp
	// at which the packet was received. By default the amount of
	// seconds since configuration is printed.
	TimePrecision int
	// Now returns the current time.
	Now func() time.Time
}

// CapturePrinter prints internet packets using the [pcap.PacketBreakdown] and [pcap.Formatter] types.
type CapturePrinter struct {
	write      func(b []byte) (int, error)
	frms       []pcap.Frame
	cap        pcap.PacketBreakdown
	pfmt       pcap.Formatter
	fmtPcapBuf []byte
	// minimum length of namespace on print.
	namespaceminwidth int

	timeprec int
	origin   time.Time
	now      func() time.Time
}

func (stack *CapturePrinter) Configure(writer io.Writer, cfg CapturePrinterConfig) error {
	stack.timeprec = cfg.TimePrecision
	stack.now = cfg.Now
	if stack.printTimestamps() {
		stack.origin = cfg.Now()
	}
	stack.namespaceminwidth = cfg.NamespaceWidth
	stack.write = writer.Write
	return nil
}

// Formatter returns a pointer to the underlying pcap.Formatter type.
// One can then configure the formatter's fields to affect printing.
func (stack *CapturePrinter) Formatter() *pcap.Formatter {
	return &stack.pfmt
}

// PrintIP formats and writes a breakdown of the IPv4 or IPv6 packet, prefixed by prefix.
func (stack *CapturePrinter) PrintIP(prefix string, ipPkt []byte) {
	stack.printPacket(prefix, true, ipPkt)
}

// PrintEthernet formats and writes a breakdown of the Ethernet frame, prefixed by prefix.
func (stack *CapturePrinter) PrintEthernet(prefix string, ethPkt []byte) {
	stack.printPacket(prefix, false, ethPkt)
}

func (stack *CapturePrinter) printPacket(prefix string, ip bool, pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	fmtbuf := stack.fmtPcapBuf[:0]
	useTimestamps := stack.printTimestamps()
	var captime time.Time
	if useTimestamps {
		captime = stack.now()
	}
	var err error
	if ip {
		switch pkt[0] >> 4 {
		case 4:
			stack.frms, err = stack.cap.CaptureIPv4(stack.frms[:0], pkt, 0)
		case 6:
			stack.frms, err = stack.cap.CaptureIPv6(stack.frms[:0], pkt, 0)
		default:
			err = lneto.ErrUnsupported
		}
	} else {
		stack.frms, err = stack.cap.CaptureEthernet(stack.frms[:0], pkt, 0)
	}
	if err == nil {
		if useTimestamps {
			diff := captime.Sub(stack.origin)
			ms := diff.Milliseconds()
			fmtbuf = strconv.AppendInt(fmtbuf, ms/1000, 10)
			fmtbuf = append(fmtbuf, '.')
			frac := ms % 1000
			if frac < 0 {
				frac = -frac
			}
			// Pad fractional part to timeprec digits (up to 3).
			switch {
			case stack.timeprec >= 3:
				if frac < 100 {
					fmtbuf = append(fmtbuf, '0')
				}
				if frac < 10 {
					fmtbuf = append(fmtbuf, '0')
				}
				fmtbuf = strconv.AppendInt(fmtbuf, frac, 10)
			case stack.timeprec == 2:
				frac /= 10 // truncate to centiseconds
				if frac < 10 {
					fmtbuf = append(fmtbuf, '0')
				}
				fmtbuf = strconv.AppendInt(fmtbuf, frac, 10)
			case stack.timeprec == 1:
				frac /= 100 // truncate to deciseconds
				fmtbuf = strconv.AppendInt(fmtbuf, frac, 10)
			}
			fmtbuf = append(fmtbuf, ' ')
		}

		fmtbuf = append(fmtbuf, prefix...)
		appendSpaces := max(0, stack.namespaceminwidth-len(prefix)) + 1 // add single space to separate actual format from packet length.
		for range appendSpaces {
			fmtbuf = append(fmtbuf, ' ')
		}
		fmtbuf = strconv.AppendInt(fmtbuf, int64(len(pkt)), 10)
		fmtbuf = append(fmtbuf, ' ')
		fmtbuf, err = stack.pfmt.FormatFrames(fmtbuf, stack.frms, pkt)
	}
	fmtbuf = append(fmtbuf, '\n')
	if err != nil {
		fmtbuf = append(fmtbuf, "ERROR "...)
		fmtbuf = append(fmtbuf, prefix...)
		fmtbuf = append(fmtbuf, ": "...)
		fmtbuf = append(fmtbuf, err.Error()...)
	}
	stack.write(fmtbuf)
	stack.fmtPcapBuf = fmtbuf[:0] // Reuse buffer if allocated at larger size.
}

func (stack *CapturePrinter) printTimestamps() bool {
	return stack.timeprec > 0 && stack.now != nil
}
