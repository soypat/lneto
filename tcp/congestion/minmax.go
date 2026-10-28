package congestion

// maxFilter is a windowed maximum in constant space, as Linux's
// lib/win_minmax.c: it keeps the best, second best and third best sample, each
// covering a more recent part of the window. BBR uses it for max_bw
// ([draft-ietf-ccwg-bbr] §2.10).
type maxFilter struct {
	s    [3]maxSample
	seed bool // A sample was taken.
}

type maxSample struct {
	t uint32 // Time, in the caller's unit.
	v uint64
}

// get returns the maximum in the window.
func (m *maxFilter) get() uint64 { return m.s[0].v }

func (m *maxFilter) reset(t uint32, v uint64) uint64 {
	m.seed = true
	m.s[0] = maxSample{t: t, v: v}
	m.s[1], m.s[2] = m.s[0], m.s[0]
	return v
}

// update takes sample v at time t into a window of win and returns the
// maximum.
func (m *maxFilter) update(win, t uint32, v uint64) uint64 {
	val := maxSample{t: t, v: v}
	if !m.seed || m.s[0].v <= v || t-m.s[2].t > win {
		return m.reset(t, v) // A new maximum, or nothing left in the window.
	}
	if m.s[1].v <= v {
		m.s[1], m.s[2] = val, val
	} else if m.s[2].v <= v {
		m.s[2] = val
	}
	// Age out the best samples and keep the second covering the most recent
	// 3/4 of the window and the third the most recent 1/2.
	if dt := t - m.s[0].t; dt > win {
		m.s[0], m.s[1], m.s[2] = m.s[1], m.s[2], val
		if t-m.s[0].t > win {
			m.s[0], m.s[1], m.s[2] = m.s[1], m.s[2], val
		}
	} else if m.s[1].t == m.s[0].t && dt > win/4 {
		m.s[1], m.s[2] = val, val
	} else if m.s[2].t == m.s[1].t && dt > win/2 {
		m.s[2] = val
	}
	return m.s[0].v
}
