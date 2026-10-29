package internal

import "testing"

func TestIndexAnyBytes(t *testing.T) {
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
		if got := IndexAnyBytes(test.s, test.set); got != test.want {
			t.Errorf("IndexAnyBytes(%q, %q): want %d, got %d", test.s, test.set, test.want, got)
		}
	}
}
