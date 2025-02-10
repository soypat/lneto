package tcp

import (
	"log/slog"

	"github.com/soypat/lneto/internal"
)

// logger provides methods that can be easily attached by struct embedding
// to types in this package.
type logger struct {
	log *slog.Logger
}

func (l logger) logerr(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.log, slog.LevelError, msg, attrs...)
}
func (l logger) info(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.log, slog.LevelInfo, msg, attrs...)
}
func (l logger) warn(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.log, slog.LevelWarn, msg, attrs...)
}
func (l logger) debug(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.log, slog.LevelDebug, msg, attrs...)
}
func (l logger) trace(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.log, internal.LevelTrace, msg, attrs...)
}
func (l logger) logenabled(lvl slog.Level) bool {
	return internal.LogEnabled(l.log, lvl)
}

func (tcb *ControlBlock) traceSnd(msg string) {
	tcb.trace(msg,
		slog.String("state", tcb._state.String()),
		slog.Uint64("pend", uint64(tcb.pending[0])),
		slog.Uint64("snd.nxt", uint64(tcb.snd.NXT)),
		slog.Uint64("snd.una", uint64(tcb.snd.UNA)),
		slog.Uint64("snd.wnd", uint64(tcb.snd.WND)),
	)
}

func (tcb *ControlBlock) traceRcv(msg string) {
	tcb.trace(msg,
		slog.String("state", tcb._state.String()),
		slog.Uint64("rcv.nxt", uint64(tcb.rcv.NXT)),
		slog.Uint64("rcv.wnd", uint64(tcb.rcv.WND)),
		slog.Bool("challenge", tcb.challengeAck),
	)
}

func (tcb *ControlBlock) traceSeg(msg string, seg Segment) {
	if tcb.logenabled(internal.LevelTrace) {
		tcb.trace(msg,
			slog.Uint64("seg.seq", uint64(seg.SEQ)),
			slog.Uint64("seg.ack", uint64(seg.ACK)),
			slog.Uint64("seg.wnd", uint64(seg.WND)),
			slog.String("seg.flags", seg.Flags.String()),
			slog.Uint64("seg.data", uint64(seg.DATALEN)),
		)
	}
}
