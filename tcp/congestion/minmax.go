package congestion

// A windowed max filter, ported unchanged from the pre-rework branch: it is pure
// arithmetic over a caller-supplied time base, so the move to a monotonic clock at
// the policy hooks does not touch it.

// minmaxSample is one entry of the windowed [minmax] filter.
type minmaxSample struct {
	t uint32 // monotonic time stamp (round count or millisecond clock).
	v uint64 // measured value.
}

// minmax is a windowed running maximum/minimum estimator that tracks the best
// value over a sliding window in O(1) space using three staggered samples
// (best, second-best and third-best, each covering progressively more recent
// fractions of the window) instead of storing every sample. BBR uses such a
// windowed max filter for its bandwidth estimate ([draft-ietf-ccwg-bbr]
// §2.10). Use [minmax.runningMax] for a windowed maximum and
// [minmax.runningMin] for a windowed minimum.
type minmax struct {
	s    [3]minmaxSample
	seed bool // false until the first measurement has been recorded.
}

// get returns the current best (max or min) value in the window.
func (m *minmax) get() uint64 { return m.s[0].v }

func (m *minmax) reset(t uint32, meas uint64) uint64 {
	m.seed = true
	val := minmaxSample{t: t, v: meas}
	m.s[0], m.s[1], m.s[2] = val, val, val
	return m.s[0].v
}

// runningMax updates the windowed maximum with measurement meas at time t over
// a window of win, returning the current maximum.
func (m *minmax) runningMax(win, t uint32, meas uint64) uint64 {
	val := minmaxSample{t: t, v: meas}
	if !m.seed || m.s[0].v <= val.v || // first sample or found new max?
		val.t-m.s[2].t > win { // nothing left in window?
		return m.reset(t, meas)
	}
	if m.s[1].v <= val.v {
		m.s[1] = val
		m.s[2] = val
	} else if m.s[2].v <= val.v {
		m.s[2] = val
	}
	return m.subwinUpdate(win, t, val)
}

// runningMin updates the windowed minimum with measurement meas at time t over
// a window of win, returning the current minimum.
func (m *minmax) runningMin(win, t uint32, meas uint64) uint64 {
	val := minmaxSample{t: t, v: meas}
	if !m.seed || val.v <= m.s[0].v || // first sample or found new min?
		val.t-m.s[2].t > win { // nothing left in window?
		return m.reset(t, meas)
	}
	if val.v <= m.s[1].v {
		m.s[1] = val
		m.s[2] = val
	} else if val.v <= m.s[2].v {
		m.s[2] = val
	}
	return m.subwinUpdate(win, t, val)
}

// subwinUpdate ages out samples that fall outside the window and re-partitions
// the remaining estimates so the second estimate covers the most recent 3/4 of
// the window and the third the most recent 1/2.
func (m *minmax) subwinUpdate(win, t uint32, val minmaxSample) uint64 {
	dt := t - m.s[0].t
	if dt > win {
		// Best value has aged out; second/third estimates take over.
		m.s[0] = m.s[1]
		m.s[1] = m.s[2]
		m.s[2] = val
		if t-m.s[0].t > win {
			m.s[0] = m.s[1]
			m.s[1] = m.s[2]
			m.s[2] = val
		}
	} else if m.s[1].t == m.s[0].t && dt > win/4 {
		// Second estimate covers the most recent 3/4 of the window.
		m.s[2] = val
		m.s[1] = val
	} else if m.s[2].t == m.s[1].t && t-m.s[1].t > win/2 {
		// Third estimate covers the most recent 1/2 of the window.
		m.s[2] = val
	}
	return m.s[0].v
}
