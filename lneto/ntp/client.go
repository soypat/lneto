package ntp

import (
	"errors"
	"io"
	"time"
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

func NewClient(now func() time.Time) *Client {
	return &Client{
		_now:     now,
		_sysprec: sysprecRecalcNeeded,
	}
}

type Client struct {
	start time.Time
	_now  func() time.Time
	t     [4]Timestamp
	// org      Timestamp
	// rec      Timestamp
	xmt           Timestamp
	state         state
	serverStratum Stratum
	_sysprec      int8
}

func (c *Client) Send(payload []byte) (int, error) {
	if c.isDone() {
		return 0, io.EOF
	}
	frm, err := NewFrame(payload)
	if err != nil {
		return 0, err
	}

	switch c.state {
	case stateSend1:
		c.start = c.now()
		c.xmt = TimestampFromUint64(0)
		c.state = stateAwait1
	case stateSend2:
		c.xmt = c.unsyncTimestamp(c.now())
		c.state = stateDone
	default:
		return 0, nil // Nothing to handle.
	}

	for i := range payload[:SizeHeader] {
		payload[i] = 0
	}
	sysprec := c.sysprec()
	frm.ClearHeader()
	frm.SetStratum(StratumUnsync)
	frm.SetPoll(6)
	frm.SetPrecision(sysprec)
	frm.SetOriginTime(c.xmt)
	frm.SetFlags(ModeClient, Version4, LeapNoWarning)
	return SizeHeader, nil
}

func (c *Client) Read(payload []byte) error {
	if c.isDone() {
		return io.EOF
	}
	frm, err := NewFrame(payload)
	if err != nil {
		return err
	}
	t := &c.t
	switch c.state {
	case stateAwait1:
		tstx := frm.TransmitTime()
		tsorig := frm.OriginTime()
		if tstx == tsorig || tsorig == c.xmt {
			return errors.New("bogus NTP packet")
		}
		t[0] = tsorig
		t[1] = frm.ReceiveTime()
		t[2] = tstx
		t[3] = c.unsyncTimestamp(c.now())
		c.serverStratum = frm.Stratum()
		c.state = stateDone
	case stateAwait2:
		c.state = stateAwait2
	}
	return nil
}

func (c *Client) isDone() bool {
	return c.state == stateDone
}

func (c *Client) now() time.Time {
	if c._now == nil {
		return time.Now()
	}
	return c._now()
}

func (c *Client) unsyncTimestamp(now time.Time) Timestamp {
	return TimestampFromUint64(0).Add(now.Sub(c.start))
}

func (c *Client) sysprec() int8 {
	if c._sysprec == sysprecRecalcNeeded {
		c._sysprec = CalculateSystemPrecision(c._now)
	}
	return c._sysprec
}

// Now returns the current time as corrected by NTP protocol.
func (c *Client) Now() time.Time {
	return c.now().Add(c.Offset())
}

// ServerStratum returns the stratum of the server client synchronized with.
func (c *Client) ServerStratum() Stratum { return c.serverStratum }

// Offset returns the
func (c *Client) Offset() time.Duration {
	if c.isDone() {
		t := &c.t
		return t[1].Sub(t[0])/2 + t[2].Sub(t[3])/2
	}
	return 0
}
