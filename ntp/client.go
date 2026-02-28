package ntp

import (
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
	// t stores the time offsets needed to compute the time at client
	// taking into consideration the round-trip delay.
	//  - t[0] (orig): Client timestamp of request packet transmission.
	//  - t[1] (rec): Server timestamp of request packet reception.
	//  - t[2] (xmt): Server timestamp of response packet transmission.
	//  - t[3]: Client timestamp of response packet reception.
	t [4]Timestamp
	// org      Timestamp
	state         state
	serverStratum Stratum
	sysprec       int8
}

func (c *Client) Reset(sysprec int8, now func() time.Time) {
	*c = Client{
		connID:  c.connID + 1,
		_now:    now,
		sysprec: sysprec,
		state:   stateSend1,
	}
}

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

	switch c.state {
	case stateSend1:
		c.start = c.now()
		c.t[0] = TimestampFromUint64(0)
		c.state = stateAwait1
	case stateSend2:
		// c.xmt = c.unsyncTimestamp(c.now())
		c.state = stateDone
	default:
		return 0, nil // Nothing to handle.
	}

	for i := range payload[:SizeHeader] {
		payload[i] = 0
	}

	frm.ClearHeader()
	frm.SetStratum(StratumUnsync)
	frm.SetPoll(6)
	frm.SetPrecision(c.sysprec)
	frm.SetOriginTime(c.t[0])
	frm.SetFlags(ModeClient, Version4, LeapNoWarning)
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
			return lneto.ErrPacketDrop
		}

		txelapsed := c.now().Sub(c.start)
		c.t[1] = frm.ReceiveTime()
		c.t[2] = xmt
		c.t[3] = c.t[0].Add(txelapsed)
		c.serverStratum = frm.Stratum()
		c.state = stateDone // TODO: add second exchange part.
	case stateAwait2:
		c.state = stateDone
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
	now := c.now()
	serverToBase := c.OffsetUnsynced()
	clientToBase := now.Sub(BaseTime())
	serverToClient := serverToBase - clientToBase
	return now, serverToClient
}

// OffsetUnsynced returns the absolute time offset difference between client and server clock
// as calculated by the clock synchonization algorithm. It is unsynchonized- the result of OffsetUnsynced will not change with time.
func (c *Client) OffsetUnsynced() time.Duration {
	if c.IsDone() {
		t := &c.t
		return (t[1].Sub(t[0]) + t[2].Sub(t[3])) / 2
	}
	return 0
}

func (c *Client) RoundTripDelay() time.Duration {
	if c.IsDone() {
		d0 := c.t[3].Sub(c.t[0])
		d1 := c.t[2].Sub(c.t[1])
		return d0 - d1
	}
	return -1
}
