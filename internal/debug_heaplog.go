//go:build debugheaplog

package internal

import (
	"log/slog"
	"time"
	"unsafe"
)

const (
	HeapAllocDebugging = true
	timefmt            = "[01-02 15:04:05.000]"
)

var (
	timebuf [len(timefmt) * 2]byte
)

func LogEnabled(l *slog.Logger, lvl slog.Level) bool {
	return logEnabled
}

func logAttrsAndAllocs(allocmsg string, l *slog.Logger, level slog.Level, msg string, attrs ...slog.Attr) {
	LogAttrs(nil, level, msg, attrs...) // already logs attributes
}

func LogAttrs(_ *slog.Logger, level slog.Level, msg string, attrs ...slog.Attr) {
	now := time.Now()
	n := len(now.AppendFormat(timebuf[:0], timefmt))
	print("time=", unsafe.String(&timebuf[0], n), " ")
	if level == LevelTrace {
		print("TRACE ")
	} else if level < slog.LevelDebug {
		print("SEQS ")
	} else {
		print(level.String(), " ")
	}
	print(msg)
	for _, a := range attrs {
		switch a.Value.Kind() {
		case slog.KindString:
			print(" ", a.Key, "=", a.Value.String())
		case slog.KindInt64:
			print(" ", a.Key, "=", a.Value.Int64())
		case slog.KindUint64:
			print(" ", a.Key, "=", a.Value.Uint64())
		case slog.KindBool:
			print(" ", a.Key, "=", a.Value.Bool())
		}
	}
	println()
	LogAllocs(msg)
}
