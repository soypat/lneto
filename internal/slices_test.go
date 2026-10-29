package internal

import "testing"

func TestByteSetIndexAny(t *testing.T) {
	var bs ByteSet
	for _, test := range []struct {
		s, set string
		want   int
	}{
		{s: "", set: "ab", want: -1},
		{s: "abc", set: "", want: -1},
		{s: "abc", set: "xyz", want: -1},
		{s: "\x00", set: "\x00", want: 0},
		{s: "abc", set: "c", want: 2},
		{s: "abc", set: "xb", want: 1},
		{s: "a\r\nb\x00", set: "\r\x00", want: 1},
		{s: "ab\x00", set: "\r\x00", want: 2},
		// Bytes match as bytes, not as UTF-8 runes like strings.IndexAny.
		{s: "\xff\x80", set: "\x80", want: 1},
		{s: "\xc3\xa9", set: "\xa9", want: 1},
	} {
		bs.Clear()
		bs.Add(test.set)
		if got := bs.IndexAny(test.s); got != test.want {
			t.Errorf("IndexAnyBytes(%q, %q): want %d, got %d", test.s, test.set, test.want, got)
		}
	}
}

func TestByteSetAddRangeInvert(t *testing.T) {
	for _, test := range []struct {
		lo, hi byte
		invert bool
		s      string
		want   int
	}{
		{lo: '0', hi: '9', s: "ab7c", want: 2},
		{lo: '0', hi: '9', s: "abc", want: -1},
		{lo: 0, hi: 0x1f, s: "ab\tc", want: 2},
		{lo: 0xf0, hi: 0xff, s: "a\xff", want: 1},
		{lo: 0, hi: 0xff, s: "x", want: 0},
		{lo: 'b', hi: 'a', s: "ab", want: -1}, // lo > hi is empty.
		{lo: 'a', hi: 'z', invert: true, s: "abC", want: 2},
		{lo: 'b', hi: 'a', invert: true, s: "\x00", want: 0},
		{lo: 0, hi: 0xff, invert: true, s: "abc", want: -1},
	} {
		var bs ByteSet
		bs.AddRange(test.lo, test.hi)
		if test.invert {
			bs.Invert()
		}
		if got := bs.IndexAny(test.s); got != test.want {
			t.Errorf("AddRange(%#x, %#x) invert=%v IndexAny(%q): want %d, got %d", test.lo, test.hi, test.invert, test.s, test.want, got)
		}
	}
}
