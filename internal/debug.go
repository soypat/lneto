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
	numAlloc := int64(memstats.Mallocs) - int64(lastMallocs)
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
		buf := allocbuf[:len(allocbuf)-1] // keep one character for newline.
		n := copy(buf[:], "[ALLOC] ")
		n += copy(buf[n:], msg)
		n += copyValueInt(buf[n:], "inc", inc)
		n += copyValueInt(buf[n:], "n", numAlloc)
		n += copyValueUint(buf[n:], "heap", memstats.HeapAlloc)
		n += copyValueUint(buf[n:], "free", free)
		lastN := copyValueUint(buf[n:], "tot", memstats.TotalAlloc)
		n += lastN
		allocbuf[n] = '\n' // n will never be larger than len(allocbuf)-1
		os.Stdout.Write(allocbuf[:n+1])
		if lastN == 0 {
			n2 := copy(allocbuf[:], "[WARN] ALLOC BUF OVERRUN\n")
			os.Stdout.Write(allocbuf[:n2])
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
