package ntp

import (
	"log/slog"
	"time"

	"github.com/soypat/lneto"
)

type state uint8

const (
	stateClosed state = iota
	stateSend1
	stateAwait1
	stateSend2
	stateAwait2
	stateDone
)

const sysprecRecalcNeeded int8 = 127

type Client struct {
	connID uint64
	start  time.Time
	_now   func() time.Time
	_log   *slog.Logger
	// t stores the four NTP timestamps per RFC 5905:
	//  - t[0] (T1): Client timestamp of request packet transmission.
	//  - t[1] (T2): Server timestamp of request packet reception.
	//  - t[2] (T3): Server timestamp of response packet transmission.
	//  - t[3] (T4): Client timestamp of response packet reception.
	t             [4]Timestamp
	offset1       time.Duration // clock offset from first exchange, averaged with second in OffsetUnsynced.
	rtt1          time.Duration // round-trip delay from first exchange, averaged with second in RoundTripDelay.
	state         state
	serverStratum Stratum
	sysprec       int8
}

func (c *Client) Reset(sysprec int8, now func() time.Time) {
	*c = Client{
		connID:  c.connID + 1,
		_now:    now,
		_log:    c._log,
		sysprec: sysprec,
		state:   stateSend1,
	}
}

// SetLogger configures a structured logger for debug output.
// Pass nil to disable logging (the default).
func (c *Client) SetLogger(l *slog.Logger) { c._log = l }

func (c *Client) Protocol() uint64  { return 0 }
func (c *Client) LocalPort() uint16 { return ClientPort }
func (c *Client) ConnectionID() *uint64 {
	return &c.connID
}

func (c *Client) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	if c.IsDone() {
		return 0, nil
	}
	payload := carrierData[offsetToFrame:]
	frm, err := NewFrame(payload)
	if err != nil {
		return 0, err
	}

	var exchange int
	switch c.state {
	case stateSend1:
		now := c.now()
		c.start = now
		var err error
		if c.t[0], err = TimestampFromTime(now); err != nil {
			return 0, err
		}
		c.state = stateAwait1
		exchange = 1
	case stateSend2:
		now := c.now()
		c.start = now
		var err error
		if c.t[0], err = TimestampFromTime(now); err != nil {
			return 0, err
		}
		c.state = stateAwait2
		exchange = 2
	default:
		return 0, nil // Nothing to handle.
	}

	frm.ClearHeader()
	frm.SetStratum(StratumUnsync)
	frm.SetPoll(6)
	frm.SetPrecision(c.sysprec)
	frm.SetTransmitTime(c.t[0])
	frm.SetFlags(ModeClient, Version4, LeapNoWarning)
	if c._log != nil {
		c._log.Debug("ntp.Client:encapsulate", slog.Int("exchange", exchange),
			slog.Uint64("T1.sec", uint64(c.t[0].Seconds())))
	}
	return SizeHeader, nil
}

func (c *Client) Demux(carrierData []byte, frameOffset int) error {
	if c.IsDone() {
		return nil
	}
	payload := carrierData[frameOffset:]
	frm, err := NewFrame(payload)
	if err != nil {
		return err
	}

	switch c.state {
	case stateAwait1:
		xmt := frm.TransmitTime()
		orig := frm.OriginTime()
		if xmt == orig || orig != c.t[0] {
			if c._log != nil {
				c._log.Debug("ntp.Client:demux:drop", slog.String("reason", "origin mismatch"),
					slog.Uint64("orig.sec", uint64(orig.Seconds())), slog.Uint64("T1.sec", uint64(c.t[0].Seconds())))
			}
			return lneto.ErrPacketDrop
		}
		txelapsed := c.now().Sub(c.start)
		c.t[1] = frm.ReceiveTime()
		c.t[2] = xmt
		c.t[3] = c.t[0].Add(txelapsed)
		c.serverStratum = frm.Stratum()
		c.offset1 = (c.t[1].Sub(c.t[0]) + c.t[2].Sub(c.t[3])) / 2
		c.rtt1 = c.t[3].Sub(c.t[0]) - c.t[2].Sub(c.t[1])
		c.state = stateSend2
		if c._log != nil {
			c._log.Debug("ntp.Client:demux:exchange1",
				slog.Duration("offset", c.offset1), slog.Duration("rtt", c.rtt1),
				slog.String("stratum", c.serverStratum.String()))
		}
	case stateAwait2:
		xmt := frm.TransmitTime()
		orig := frm.OriginTime()
		if xmt == orig || orig != c.t[0] {
			if c._log != nil {
				c._log.Debug("ntp.Client:demux:drop", slog.String("reason", "origin mismatch"),
					slog.Uint64("orig.sec", uint64(orig.Seconds())), slog.Uint64("T1.sec", uint64(c.t[0].Seconds())))
			}
			return lneto.ErrPacketDrop
		}
		txelapsed := c.now().Sub(c.start)
		c.t[1] = frm.ReceiveTime()
		c.t[2] = xmt
		c.t[3] = c.t[0].Add(txelapsed)
		c.serverStratum = frm.Stratum()
		offset2 := (c.t[1].Sub(c.t[0]) + c.t[2].Sub(c.t[3])) / 2
		rtt2 := c.t[3].Sub(c.t[0]) - c.t[2].Sub(c.t[1])
		c.state = stateDone
		if c._log != nil {
			c._log.Debug("ntp.Client:demux:exchange2",
				slog.Duration("offset", offset2), slog.Duration("rtt", rtt2),
				slog.Duration("avg_offset", (c.offset1+offset2)/2),
				slog.Duration("avg_rtt", (c.rtt1+rtt2)/2))
		}
	}
	return nil
}

func (c *Client) IsDone() bool {
	return c.state == stateDone
}

func (c *Client) now() time.Time {
	if c._now == nil {
		return time.Now()
	}
	return c._now()
}

// Now returns the current time as corrected by NTP protocol.
func (c *Client) Now() time.Time {
	now, off := c.offsetAndNow()
	return now.Add(off)
}

// ServerStratum returns the stratum of the server client synchronized with.
func (c *Client) ServerStratum() Stratum { return c.serverStratum }

// Offset is a helper method to determine the difference between the Client's clock and the server's clock.
// Use [Client.Now] to calculate the server's time.
func (c *Client) Offset() time.Duration {
	if c.IsDone() {
		_, off := c.offsetAndNow()
		return off
	}
	return 0
}

func (c *Client) offsetAndNow() (clientNow time.Time, offset time.Duration) {
	// OffsetUnsynced returns θ (server ahead of client) computed from real T1/T4
	// timestamps, so the corrected server time is simply clientNow + θ.
	return c.now(), c.OffsetUnsynced()
}

// OffsetUnsynced returns the absolute time offset difference between client and server clock
// as calculated by the clock synchronization algorithm. It is unsynced — the result will not
// change with time. When both exchanges are complete the result is the average of both exchanges.
func (c *Client) OffsetUnsynced() time.Duration {
	if c.IsDone() {
		t := &c.t
		offset2 := (t[1].Sub(t[0]) + t[2].Sub(t[3])) / 2
		return (c.offset1 + offset2) / 2
	}
	return 0
}

// RoundTripDelay returns the average round-trip delay across both NTP exchanges.
func (c *Client) RoundTripDelay() time.Duration {
	if c.IsDone() {
		rtt2 := c.t[3].Sub(c.t[0]) - c.t[2].Sub(c.t[1])
		return (c.rtt1 + rtt2) / 2
	}
	return -1
}
