package dhcp

import (
	"io"
)

type ClientV4 struct {
	reqHostname []byte
	hostname    []byte
	offer       [4]byte
	svip        [4]byte
	reqIP       [4]byte
	dns         [4]byte
	router      [4]byte
	subnet      [4]byte
	broadcast   [4]byte
	gateway     [4]byte
	optbuf      [10]Option
	currentXID  uint32
	tRenew      uint32
	tRebind     uint32
	tIPLease    uint32
	state       ClientState
}

type RequestConfig struct {
	RequestedAddr [4]byte
	// Optional hostname to request.
	Hostname string
}

func (c *ClientV4) BeginRequest(xid uint32, cfg RequestConfig) error {
	c.currentXID = xid
	c.reqHostname = append(c.reqHostname[:0], cfg.Hostname...)
	c.reqIP = cfg.RequestedAddr
	return nil
}

func (c *ClientV4) Write(dst []byte) (int, error) {
	if c.isClosed() {
		return 0, io.EOF
	}
	frm, err := NewFrameV4(dst)
	if err != nil {
		return 0, err
	}
	// var options []Option
	// var nextState ClientState
	switch c.state {
	case StateInit:
		frm.MagicCookie()
	}
	return 0, nil
}

func (c *ClientV4) isClosed() bool { return c.state == 0 }
