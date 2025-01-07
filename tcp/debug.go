package tcp

import (
	"context"
	"log/slog"

	"github.com/soypat/lneto/internal"
)

func (tcb *ControlBlock) logenabled(lvl slog.Level) bool {
	return internal.HeapAllocDebugging || (tcb.log != nil && tcb.log.Handler().Enabled(context.Background(), lvl))
}

func (tcb *ControlBlock) logattrs(lvl slog.Level, msg string, attrs ...slog.Attr) {
	internal.LogAttrs(tcb.log, lvl, msg, attrs...)
}

func (tcb *ControlBlock) debug(msg string, attrs ...slog.Attr) {
	tcb.logattrs(slog.LevelDebug, msg, attrs...)
}

func (tcb *ControlBlock) trace(msg string, attrs ...slog.Attr) {
	tcb.logattrs(internal.LevelTrace, msg, attrs...)
}

func (tcb *ControlBlock) logerr(msg string, attrs ...slog.Attr) {
	tcb.logattrs(slog.LevelError, msg, attrs...)
}

func (tcb *ControlBlock) traceSnd(msg string) {
	tcb.trace(msg,
		slog.String("state", tcb.state.String()),
		slog.Uint64("pend", uint64(tcb.pending[0])),
		slog.Uint64("snd.nxt", uint64(tcb.snd.NXT)),
		slog.Uint64("snd.una", uint64(tcb.snd.UNA)),
		slog.Uint64("snd.wnd", uint64(tcb.snd.WND)),
	)
}

func (tcb *ControlBlock) traceRcv(msg string) {
	tcb.trace(msg,
		slog.String("state", tcb.state.String()),
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
