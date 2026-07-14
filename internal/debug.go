package internal

import (
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"sync"
)

const (
	LevelTrace slog.Level = slog.LevelDebug - 2

	usePrintLogAllocs = HeapAllocDebugging
)

var (
	memstats    runtime.MemStats
	lastAllocs  uint64
	lastMallocs uint64
	allocmu     sync.Mutex
	allocbuf    [128]byte
)

func LogAttrsAndAllocs(allocmsg string, l *slog.Logger, level slog.Level, msg string, attrs ...slog.Attr) {
	logAttrsAndAllocs(allocmsg, l, level, msg, attrs...)
}

func LogAllocs(msg string) {
	allocmu.Lock()
	runtime.ReadMemStats(&memstats)
	if memstats.TotalAlloc == lastAllocs {
		allocmu.Unlock()
		return
	}
	inc := int64(memstats.TotalAlloc) - int64(lastAllocs)
	numAlloc := int64(memstats.TotalAlloc) - int64(lastAllocs)
	free := memstats.HeapSys - memstats.HeapInuse
	if usePrintLogAllocs {
		// Branch used when debugheaplog enabled
		print("[ALLOC] ", msg)
		print(" inc=", inc)
		print(" n=", numAlloc)
		print(" heap=", memstats.HeapAlloc)
		print(" free=", free)
		print(" tot=", memstats.TotalAlloc)
		println()
	} else {
		n := copy(allocbuf[:], "[ALLOC] ")
		n += copy(allocbuf[n:], msg)
		n += copyValueInt(allocbuf[n:], "inc", inc)
		n += copyValueInt(allocbuf[n:], "n", numAlloc)
		n += copyValueUint(allocbuf[n:], "heap", memstats.HeapAlloc)
		n += copyValueUint(allocbuf[n:], "free", free)
		n += copyValueUint(allocbuf[n:], "tot", memstats.TotalAlloc)
		allocbuf[n] = '\n'
		os.Stdout.Write(allocbuf[:n+1])
		if n > len(allocbuf) {
			n2 := copy(allocbuf[:], "[WARN] ALLOC BUF OVERRUN")
			n2 += copyValueUint(allocbuf[n2:], "n", uint64(n))
			allocbuf[n2] = '\n'
			os.Stdout.Write(allocbuf[:n2+1])
		}
	}
	lastAllocs = memstats.TotalAlloc
	lastMallocs = memstats.Mallocs
	allocmu.Unlock()
}

func copyValueInt(buf []byte, key string, v int64) int {
	// ' ' + key + '=' + up to 20 chars for int64
	if len(buf) < 2+len(key)+20 {
		return 0
	}
	buf[0] = ' '
	n := 1 + copy(buf[1:], key)
	buf[n] = '='
	n++
	return n + copyInt(buf[n:], v)
}

func copyValueUint(buf []byte, key string, v uint64) int {
	if len(buf) < 2+len(key)+20 {
		return 0
	}
	buf[0] = ' '
	n := 1 + copy(buf[1:], key)
	buf[n] = '='
	n++
	return n + copyUint(buf[n:], v)
}

// copyInt formats v into buf and returns the number of bytes written.
// Caller must ensure cap(buf) >= 20.
func copyInt(buf []byte, v int64) int {
	return len(strconv.AppendInt(buf[:0], v, 10))
}

// copyUint formats v into buf and returns the number of bytes written.
// Caller must ensure cap(buf) >= 20.
func copyUint(buf []byte, v uint64) int {
	return len(strconv.AppendUint(buf[:0], v, 10))
}
