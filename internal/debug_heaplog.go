//go:build debugheaplog

package internal

import (
	"log/slog"
	"runtime"
	"time"
	"unsafe"
)

const (
	HeapAllocDebugging = true
	timefmt            = "[01-02 15:04:05.000]"
)

var (
	memstats   runtime.MemStats
	lastAllocs uint64

	timebuf [len(timefmt) * 2]byte
)

func LogAttrs(_ *slog.Logger, level slog.Level, msg string, attrs ...slog.Attr) {
	now := time.Now()
	n := len(now.AppendFormat(timebuf[:0], timefmt))
	runtime.ReadMemStats(&memstats)
	if memstats.TotalAlloc != lastAllocs {
		print("[ALLOC] inc=", int64(memstats.TotalAlloc)-int64(lastAllocs))
		print(" tot=", memstats.TotalAlloc, " seqs")
		println()
	}
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
	runtime.ReadMemStats(&memstats)
	if memstats.TotalAlloc != lastAllocs {
		lastAllocs = memstats.TotalAlloc
	}
}
