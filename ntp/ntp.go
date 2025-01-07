// package ntp implements the NTP protocol as described in RFC 5905.
package ntp

import (
	"encoding/binary"
	"errors"
	"math"
	"math/bits"
	"sync"
	"time"
)

// NTP Global Parameters.
const (
	SizeHeader = 48
	ClientPort = 1023 // Typical Client port number.
	ServerPort = 123  // NTP server port number
	Version4   = 4    // Current NTP Version Number
	MinPoll    = 4    // Minimum poll exponent (16s)
	MaxPoll    = 17   // Maximum poll exponent (~36h)
	MaxDisp    = 16   // Maximum dispersion (16s)
	MaxDist    = 1    // Distance threshold (1s)
	MaxStratum = 16   // Maximum stratum
	MinDispDiv = 200  // Minimum dispersion divisor 1/(200) == 0.005
)

func NewFrame(buf []byte) (Frame, error) {
	if len(buf) < SizeHeader {
		return Frame{buf: nil}, errors.New("NTP frame too short")
	}
	return Frame{buf: buf}, nil
}

// Frame encapsulates the raw data of an NTP packet
// and provides methods for manipulating, validating and
// retrieving fields and payload data. See [RFC5905].
//
// [RFC5905]: https://tools.ietf.org/html/rfc5905
type Frame struct {
	buf []byte
}

func (frm Frame) Flags() (mode Mode, version uint8, lp LeapIndicator) {
	b := frm.buf[0]
	mode = Mode(b & 0b111)
	version = (b << 3) & 0b11
	lp = LeapIndicator(b >> 5)
	return mode, version, lp
}

func (frm Frame) SetFlags(mode Mode, version uint8, lp LeapIndicator) {
	b := uint8(mode)&0b111 | (Version4&0b11)<<3 | uint8(lp&0b111)<<5
	frm.buf[0] = b
}

func (frm Frame) Stratum() Stratum           { return Stratum(frm.buf[1]) }
func (frm Frame) SetStratum(stratum Stratum) { frm.buf[1] = byte(stratum) }

// Poll is 8-bit signed integer representing the maximum interval between
// successive messages, in log2 seconds.  Suggested default limits for
// minimum and maximum poll intervals are 6 and 10, respectively.
func (frm Frame) Poll() int8        { return int8(frm.buf[2]) }
func (frm Frame) SetPoll(Poll int8) { frm.buf[2] = uint8(Poll) }

// Precision is 8-bit signed integer representing the precision of the
// system clock, in log2 seconds.  For instance, a value of -18
// corresponds to a precision of about one microsecond.  The precision
// can be determined when the service first starts up as the minimum
// time of several iterations to read the system clock.
func (frm Frame) Precision() int8             { return int8(frm.buf[3]) }
func (frm Frame) SetPrecision(Precision int8) { frm.buf[3] = uint8(Precision) }

// Total round-trip delay to the reference clock, in NTP short format.
func (frm Frame) RootDelay() Short {
	return Short(binary.BigEndian.Uint32(frm.buf[4:8]))
}
func (frm Frame) SetRootDelay(rd Short) {
	binary.BigEndian.PutUint32(frm.buf[4:8], uint32(rd))
}

// Total dispersion to the reference clock, in NTP short format.
func (frm Frame) RootDispersion() Short {
	return Short(binary.BigEndian.Uint32(frm.buf[8:12]))
}
func (frm Frame) SetRootDispersion(rd Short) {
	binary.BigEndian.PutUint32(frm.buf[8:12], uint32(rd))
}

// 32-bit code identifying the particular server or reference clock.
// The interpretation depends on the value in the stratum field.
// For packet stratum 0 (unspecified or invalid), this is a four-character
// ASCII [RFC1345] string, called the "kiss code", used for debugging and monitoring purposes.
// For stratum 1 (reference clock), this is a four-octet, left-justified,
// zero-padded ASCII string assigned to the reference clock.
// The authoritative list of Reference Identifiers is maintained by IANA; however, any string
// beginning with the ASCII character "X" is reserved for unregistered
// experimentation and development.
func (frm Frame) ReferenceID() *[4]byte {
	return (*[4]byte)(frm.buf[12:16])
}

// ReferenceTime is when the system clock was last set or corrected, in NTP timestamp format.
func (frm Frame) ReferenceTime() Timestamp {
	return TimestampFromUint64(binary.BigEndian.Uint64(frm.buf[16:24]))
}
func (frm Frame) SetReferenceTime(rt Timestamp) {
	rt.Put(frm.buf[16:24])
}

// OriginTime is time at the client when the request departed for the server, in NTP timestamp format.
func (frm Frame) OriginTime() Timestamp {
	return TimestampFromUint64(binary.BigEndian.Uint64(frm.buf[24:32]))
}
func (frm Frame) SetOriginTime(ot Timestamp) {
	ot.Put(frm.buf[24:32])
}

// ReceiveTime time at the server when the request arrived from the client, in NTP timestamp format.
func (frm Frame) ReceiveTime() Timestamp {
	return TimestampFromUint64(binary.BigEndian.Uint64(frm.buf[32:40]))
}
func (frm Frame) SetReceiveTime(rt Timestamp) {
	rt.Put(frm.buf[32:40])
}

// TransmitTime at the server when the response left for the client, in NTP timestamp format.
func (frm Frame) TransmitTime() Timestamp {
	return TimestampFromUint64(binary.BigEndian.Uint64(frm.buf[40:48]))
}
func (frm Frame) SetTransmitTime(rt Timestamp) {
	rt.Put(frm.buf[40:48])
}

// ClearHeader zeros out the header contents.
func (frm Frame) ClearHeader() {
	for i := range frm.buf[:SizeHeader] {
		frm.buf[i] = 0
	}
}

type Short uint32

var baseTime = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)

// BaseTime returnsS the time that corresponds to the NTP base time.
// The zero value for [Timestamp] and [Date] types corresponds to this time.
func BaseTime() time.Time {
	return baseTime
}

// In the date and timestamp formats, the prime epoch, or base date of
// era 0, is 0 h 1 January 1900 UTC, when all bits are zero.  It should
// be noted that strictly speaking, UTC did not exist prior to 1 January
// 1972, but it is convenient to assume it has existed for all eternity,
// even if all knowledge of historic leap seconds has been lost.  Dates
// are relative to the prime epoch; values greater than zero represent
// times after that date; values less than zero represent times before
// it.  Note that the Era Offset field of the date format and the
// Seconds field of the timestamp format have the same interpretation.

// Timestamp format is used in packet headers and other
// places with limited word size.  It includes a 32-bit unsigned seconds
// field spanning 136 years and a 32-bit fraction field resolving 232
// picoseconds.  The 32-bit short format is used in delay and dispersion
// header fields where the full resolution and range of the other
// formats are not justified.  It includes a 16-bit unsigned seconds
// field and a 16-bit fraction field.
type Timestamp struct {
	sec uint32
	fra uint32
}

func (t Timestamp) Put(b []byte) {
	_ = b[7] // bounds check hint to compiler; see golang.org/issue/14808
	binary.BigEndian.PutUint32(b[:4], t.sec)
	binary.BigEndian.PutUint32(b[4:], t.fra)
}

// IsZero reports whether t represents the zero time instant.
func (t Timestamp) IsZero() bool { return t.sec == 0 && t.fra == 0 }

func TimestampFromUint64(ts uint64) Timestamp {
	return Timestamp{
		sec: uint32(ts >> 32),
		fra: uint32(ts),
	}
}

func TimestampFromTime(t time.Time) (Timestamp, error) {
	t = t.UTC()
	if t.Before(baseTime) {
		return Timestamp{}, errors.New("ntp.TimestampFromTime: time is before baseTime")
	}
	off := t.Sub(baseTime)
	sec := uint64(off / time.Second)
	if sec > math.MaxUint32 {
		return Timestamp{}, errors.New("ntp.TimestampFromTime: time is too large")
	}
	fra := uint64(off%time.Second) * math.MaxUint32 / uint64(time.Second)
	return Timestamp{
		sec: uint32(sec),
		fra: uint32(fra),
	}, nil
}

// The 128-bit date format is used where sufficient storage and word
// size are available.  It includes a 64-bit signed seconds field
// spanning 584 billion years and a 64-bit fraction field resolving .05
// attosecond (i.e., 0.5e-18).
type Date struct {
	sec  int64
	frac uint64
}

func (t Timestamp) Seconds() uint32 { return t.sec }

func (t Timestamp) Fractions() uint32 { return t.fra }

func (t Short) Seconds() uint16   { return uint16(t >> 16) }
func (t Short) Fractions() uint16 { return uint16(t) }

func (t Timestamp) Time() time.Time {
	off := time.Second*time.Duration(t.Seconds()) + time.Second*time.Duration(t.Fractions())/math.MaxUint32
	return baseTime.Add(off)
}

func (t Timestamp) Sub(v Timestamp) time.Duration {
	dsec := time.Duration(t.sec) - time.Duration(v.sec)
	dfra := time.Duration(t.fra) - time.Duration(v.fra)
	// Work in uint64 to avoid overflow since fra is possibly MaxUint32-1
	// which means the result of dfra*MaxUint32 would be MaxUint64-MaxUint32, overflowing time.Duration's
	// underlying int64 representation by *a lot*.
	dfraneg := dfra < 0
	dfra = time.Duration(uint64(dfra.Abs()) * uint64(time.Second) / math.MaxUint32)
	if dfraneg {
		dfra = -dfra
	}
	return dsec*time.Second + dfra
}

func (t Timestamp) Add(d time.Duration) Timestamp {
	add := uint32(uint64(d%time.Second) * math.MaxUint32 / uint64(time.Second))
	add, carry := bits.Add32(t.fra, add, 0)
	t.sec += uint32(d/time.Second) + carry
	t.fra = add
	return t
}

func (d Date) Time() (time.Time, error) {
	sec := d.sec
	neg := sec < 0
	if neg {
		sec = -sec
	}
	hi, seclo := bits.Mul64(uint64(sec), uint64(time.Second))
	if hi != 0 || seclo > math.MaxInt64-uint64(time.Second)-1 {
		return time.Time{}, errors.New("ntp.Date.Time overflow")
	}
	off := time.Duration(seclo)
	off += time.Second * time.Duration(d.frac>>32) / math.MaxUint32
	if neg {
		off = -off
	}
	return baseTime.Add(off), nil
}

var (
	ntpOnceSystemClock sync.Once
	sysPrec            int8
)

// SystemPrecision calculates the Precision field value for the NTP header once
// and reuses it for all future calls.
func SystemPrecision() int8 {
	ntpOnceSystemClock.Do(recalculateSystemPrecision)
	return sysPrec
}

func recalculateSystemPrecision() {
	sysPrec = CalculateSystemPrecision(nil)
}

// CalculateSystemPrecision calculates the NTP system precision for a time source.
// If the time source is nil the default static call to [time.Now] is used.
func CalculateSystemPrecision(now func() time.Time) int8 {
	const maxIter = 16
	var times [maxIter]time.Time
	if now == nil {
		for i := 0; i < maxIter; i++ {
			times[i] = time.Now()
		}
	} else {
		for i := 0; i < maxIter; i++ {
			times[i] = now()
		}
	}
	avg := times[maxIter-1].Sub(times[0]) / maxIter
	return int8(math.Log2(avg.Seconds()))
}
