package ntp

import (
	"encoding/binary"
	"testing"
	"time"
)

// testNow is a fixed clock, so results do not depend on when the tests run.
func testNow() time.Time { return time.Date(2026, 10, 2, 13, 14, 15, 123456789, time.UTC) }

func TestTimestamp(t *testing.T) {
	now := testNow()
	nowp1 := now.Add(time.Second)
	t1, err := TimestampFromTime(now)
	if err != nil {
		t.Fatal(err)
	}
	t2, _ := TimestampFromTime(nowp1)
	gotnow := t1.Time()
	if gotnow.Sub(now) > time.Microsecond {
		t.Fatalf("got %v, want %v", gotnow, now)
	}

	d := t2.Sub(t1)
	if d != time.Second {
		t.Fatalf("expected 1s, got %s", d)
	}
	d = t1.Sub(t2)
	if d != -time.Second {
		t.Fatalf("expected -1s, got %s", d)
	}

	var b [8]byte
	t1.Put(b[:])
	readback := binary.BigEndian.Uint64(b[:])
	t1got := TimestampFromUint64(readback)
	if t1got != t1 {
		t.Fatalf("got %v, want %v", t1got, t1)
	}
}

func TestTimestampOverflow(t *testing.T) {
	const tol = time.Microsecond
	var now = time.Date(2035, 2, 7, 6, 28, 16, 0, time.UTC)
	told, err := TimestampFromTime(baseTime)
	if err != nil {
		t.Fatal(err)
	}
	tmodern, err := TimestampFromTime(now)
	if err != nil {
		t.Fatal(err)
	}
	diff := tmodern.Sub(told)
	if diff < 0 {
		t.Fatalf("got %v, want positive", diff)
	}
	diffwant := now.Sub(baseTime)
	differr := (diff - diffwant).Abs()
	if differr > tol {
		t.Fatalf("got diff %v", differr)
	}
}
