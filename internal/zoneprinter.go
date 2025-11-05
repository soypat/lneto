package internal

import (
	"errors"
	"fmt"
	"strconv"
)

type ZonePrinter struct {
	zbuf []BufferZone
	aux  []byte
}

type BufferZone struct {
	Name       string
	Start, End int
}

func (bp *ZonePrinter) AppendPrintZones(dst []byte, bufSize int, zones ...BufferZone) ([]byte, error) {
	n := bufSize
	if n == 0 {
		return dst, errors.New("empty buffer")
	}
	if len(bp.zbuf) != 0 {
		panic("race condition detected: zbuf not zero lengthed- ZonePrinter not to be used concurrently")
	}
	// Zeroed zone buffer. Will be used to detect collisions.
	// TODO(soypat): Really wasteful, there's an obvious way to just have len(zones)+1 zbuf, but I've already spent too much time here. This also makes collision detection really easy so whatever.
	bp.zbuf = append(bp.zbuf[:0], make([]BufferZone, n)...)
	labels := bp.zbuf

	// helper to paint an interval on the ring
	paint := func(z BufferZone) error {
		if z.End == 0 { // 0 == empty
			return nil
		}
		if z.Start < z.End {
			for i := z.Start; i < z.End; i++ {
				if labels[i].Name != "" {
					return fmt.Errorf("paint collision: %q/%q @%d size=%d", labels[i].Name, z.Name, i, bufSize)
				}
				labels[i].Name = z.Name
			}
		} else { // wrap
			for i := z.Start; i < n; i++ {
				if labels[i].Name != "" {
					return fmt.Errorf("wrap(start) paint collision: %q/%q @%d size=%d", labels[i].Name, z.Name, i, bufSize)
				}
				labels[i].Name = z.Name
			}
			for i := 0; i < z.End; i++ {
				if labels[i].Name != "" {
					return fmt.Errorf("wrap(end) paint collision: %q/%q @%d size=%d", labels[i].Name, z.Name, i, bufSize)
				}
				labels[i].Name = z.Name
			}
		}
		return nil
	}

	// paint
	for _, zone := range zones {
		err := paint(zone)
		if err != nil {
			return dst, err
		}
	}

	// unpainted sections are free.
	for i := range labels {
		if labels[i].Name == "" {
			labels[i].Name = "free"
		}
	}
	// Compress to segments.
	icurrent := 0
	for i := 1; i < n; i++ {
		current := labels[icurrent]
		next := labels[i]
		if current.Name != next.Name {
			labels[icurrent].End = i
			icurrent++
			labels[icurrent].Start = i
			labels[icurrent].Name = next.Name
		}
	}
	segs := labels[:icurrent+1]
	segs[icurrent].End = n

	var l1 []byte = dst
	var l2 []byte = bp.aux[:0]
	for _, s := range segs {
		l2start := len(l2)
		if s.Name == "free" {
			l2 = append(l2, "|  "...)
		} else {
			l2 = append(l2, "|--"...)
		}
		l2 = append(l2, s.Name...)
		l2 = append(l2, '(')
		l2 = strconv.AppendInt(l2, int64(s.End-s.Start), 10)
		if s.Name == "free" {
			l2 = append(l2, ")  "...)
		} else {
			l2 = append(l2, ")--"...)
		}
		fraglen := len(l2) - l2start

		l1start := len(l1)
		l1 = strconv.AppendInt(l1, int64(s.Start), 10)

		paddingNeeded := fraglen - (len(l1) - l1start)
		for range paddingNeeded {
			l1 = append(l1, ' ')
		}
	}
	l1 = strconv.AppendInt(l1, int64(bufSize), 10)
	l1 = append(l1, '\n')
	l2 = append(l2, '|')
	l1 = append(l1, l2...)
	bp.zbuf = bp.zbuf[:0] // zero out, used to detect concurrent usage of ZonePrinter.
	return l1, nil
}
