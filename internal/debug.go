package internal

import (
	"log/slog"
	"runtime"
	"strconv"
	"sync"
	"unsafe"
)

const (
	LevelTrace slog.Level = slog.LevelDebug - 2

	usePrintLogAllocs = true
)

var (
	memstats    runtime.MemStats
	lastAllocs  uint64
	lastMallocs uint64
	allocmu     sync.Mutex
	allocbuf    [256]byte
)

func LogAllocs(msg string) {
	allocmu.Lock()
	runtime.ReadMemStats(&memstats)
	if memstats.TotalAlloc == lastAllocs {
		allocmu.Unlock()
		return
	}
	if usePrintLogAllocs {
		print("[ALLOC] ", msg)
		print(" inc=", int64(memstats.TotalAlloc)-int64(lastAllocs))
		print(" n=", int64(memstats.Mallocs)-int64(lastMallocs))
		print(" heap=", memstats.HeapAlloc)
		print(" free=", memstats.HeapSys-memstats.HeapInuse)
		print(" tot=", memstats.TotalAlloc)
		println()
	} else {
		n := copy(allocbuf[:], "[ALLOC] ")
		n += copy(allocbuf[n:], msg)
		n += copyValueInt(allocbuf[n:], "inc", int64(memstats.TotalAlloc)-int64(lastAllocs))
		n += copyValueInt(allocbuf[n:], "n", int64(memstats.Mallocs)-int64(lastMallocs))
		n += copyValueUint(allocbuf[n:], "heap", memstats.HeapAlloc)
		n += copyValueUint(allocbuf[n:], "free", memstats.HeapSys-memstats.HeapInuse)
		n += copyValueUint(allocbuf[n:], "tot", memstats.TotalAlloc)
		println(unsafe.String(&allocbuf[0], n))
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
