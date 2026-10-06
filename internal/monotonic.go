package internal

import "time"

// Monotonic is a monotonic time source. Must be configured before use.
type Monotonic struct {
	src func() int64
	alt time.Time
}

// Config configures the clock with src. If src is nil will use [time.Since] in its stead.
func (m *Monotonic) Config(src func() int64) {
	m.src = src
	if src == nil {
		m.alt = time.Now()
	}
}

// Nanotime returns the monotonic nanoseconds of configured src. If src=nil will return time since configuration with [time.Since].
func (m *Monotonic) Nanotime() (nanos int64) {
	if m.src != nil {
		nanos = m.src()
	} else {
		nanos = time.Since(m.alt).Nanoseconds()
	}
	return nanos
}
