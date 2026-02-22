package xnet

import (
	"io"
	"strconv"

	"github.com/soypat/lneto/internet/pcap"
)

type CapturePrinterConfig struct {
	NamespaceWidth int
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
}

func (stack *CapturePrinter) Configure(writer io.Writer, cfg CapturePrinterConfig) error {
	stack.namespaceminwidth = cfg.NamespaceWidth
	stack.write = writer.Write
	return nil
}

// Formatter returns a pointer to the underlying pcap.Formatter type.
// One can then configure the formatter's fields to affect printing.
func (stack *CapturePrinter) Formatter() *pcap.Formatter {
	return &stack.pfmt
}

func (stack *CapturePrinter) PrintPacket(prefix string, pkt []byte) {
	fmtbuf := stack.fmtPcapBuf[:0]
	var err error
	stack.frms, err = stack.cap.CaptureEthernet(stack.frms[:0], pkt, 0)
	if err == nil {
		fmtbuf = append(fmtbuf, prefix...)
		// Ensure minimum width of packet length display for less jitter in log viewline.
		prevlen := len(prefix)
		fmtbuf = strconv.AppendInt(fmtbuf, int64(len(pkt)), 10)
		numLength := len(fmtbuf) - prevlen
		appendSpaces := max(0, stack.namespaceminwidth-numLength) + 1 // add single space to separate actual format from packet length.
		for range appendSpaces {
			fmtbuf = append(fmtbuf, ' ')
		}
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
