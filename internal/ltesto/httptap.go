package ltesto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
)

const minMTU = 256

type Interface interface {
	Read(b []byte) (int, error)
	Write(b []byte) (int, error)
	Close() error
	HardwareAddress6() ([6]byte, error)
	MTU() (int, error)
	IPMask() (netip.Prefix, error)
}

// NewHTTPTapClient returns a HTTPTapClient ready for use.
func NewHTTPTapClient(baseURL string) *HTTPTapClient {
	var h HTTPTapClient
	h.sendurl = baseURL + "/send"
	h.recvurl = baseURL + "/recv"
	h.infoURL = baseURL + "/info"
	_, err := url.Parse(h.sendurl)
	if err != nil {
		panic(err)
	}
	return &h
}

func (h *HTTPTapClient) IPPrefix() netip.Prefix {
	h.ensureMTU()
	return h.ip
}

func (h *HTTPTapClient) MTU() int {
	h.ensureMTU()
	return len(h.buf)
}

func (h *HTTPTapClient) HardwareAddr6() [6]byte {
	return h.hwaddr
}

func (h *HTTPTapClient) ensureMTU() (err error) {
	if len(h.buf) != 0 {
		return nil // MTU processed correctly.
	}
	defer func() {
		if err != nil {
			err = fmt.Errorf("unable to get MTU from server: %w", err)
		}
	}()
	resp, err := h.c.Get(h.infoURL)
	if err != nil {
		return err
	}
	var info tapInfo
	err = json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		return err
	} else if info.MTU <= minMTU {
		return errors.New("small MTU")
	}
	h.ip, err = netip.ParsePrefix(info.IPPrefix)
	if err != nil {
		return err
	}
	h.buf = make([]byte, info.MTU)
	hw, err := net.ParseMAC(info.HardwareAddr)
	if err == nil {
		copy(h.hwaddr[:], hw)
	}
	return nil
}

type HTTPTapClient struct {
	c       http.Client
	infoURL string
	recvurl string
	sendurl string
	ip      netip.Prefix
	hwaddr  [6]byte
	buf     []byte
}

func (h *HTTPTapClient) ReadDiscard() error {
	for {
		d, _ := h.ReadBytes() // Empty remote data.
		if len(d) == 0 {
			break
		}
	}
	return nil
}

func (h *HTTPTapClient) ReadBytes() (data []byte, err error) {
	err = h.ensureMTU()
	if err != nil {
		return nil, err
	}
	resp, err := h.c.Get(h.recvurl)
	if err != nil {
		return nil, err
	} else if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status + " for " + h.recvurl)
	}
	buf := h.buf
	err = json.NewDecoder(resp.Body).Decode(&buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (h *HTTPTapClient) Read(b []byte) (int, error) {
	err := h.ensureMTU()
	if err != nil {
		return 0, err
	} else if len(b) < h.MTU() {
		return 0, errors.New("buffer must have at least MTU size")
	}
	data, err := h.ReadBytes()
	if err != nil {
		return 0, err
	}
	n := copy(b, data)
	return n, nil
}

func (h *HTTPTapClient) Write(b []byte) (int, error) {
	err := h.ensureMTU()
	if err != nil {
		return 0, err
	} else if len(b) > h.MTU() {
		return 0, errors.New("buffer larger than MTU")
	}
	data, _ := json.Marshal(b)
	resp, err := h.c.Post(h.sendurl, "application/json", bytes.NewReader(data))
	if err != nil {
		return 0, err
	} else if resp.StatusCode != 200 {
		return 0, errors.New(resp.Status + " for " + h.sendurl)
	}
	return len(b), nil
}

func (h *HTTPTapClient) Close() error { return nil }

type HTTPTapServer struct {
	router    *http.ServeMux
	stack     stack
	tap       Interface
	buf       []byte
	onTx      func(channel int, pkt []byte)
	tapfailed bool
}

type tapInfo struct {
	MTU          int
	IPPrefix     string
	HardwareAddr string
}

func (sv *HTTPTapServer) OnTransfer(cb func(channel int, pkt []byte)) {
	sv.onTx = cb
}

func NewHTTPTapServer(iface Interface, queueOut, queueIn int) (*HTTPTapServer, error) {
	if iface == nil {
		return nil, errors.New("nil interface argument to HTTP interface server")
	}
	mtu, err := iface.MTU()
	if err != nil {
		return nil, err
	} else if mtu < minMTU {
		return nil, errors.New("too small MTU")
	}
	netmask, err := iface.IPMask()
	if err != nil {
		return nil, err
	}

	s := stack{
		out: make(chan []byte, queueOut),
		in:  make(chan []byte, queueIn),
	}
	sv := http.NewServeMux()
	taps := &HTTPTapServer{
		router: sv,
		stack:  s,
		tap:    iface,
		buf:    make([]byte, mtu),
	}
	sv.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		var data []byte
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			if taps.onTx != nil {
				taps.onTx(1, data)
			}
			select {
			case s.out <- data:
			default:
				http.Error(w, "outgoing packet queue full", http.StatusInternalServerError)
			}
		}
	})
	sv.HandleFunc("/recv", func(w http.ResponseWriter, r *http.Request) {
		select {
		case data := <-s.in:
			json.NewEncoder(w).Encode(data)
		default:
			json.NewEncoder(w).Encode("") // send empty string.
		}
	})

	ipstr := netmask.String()
	sv.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		info := tapInfo{
			MTU:      mtu,
			IPPrefix: ipstr,
		}
		hw, err := iface.HardwareAddress6()
		if err == nil {
			info.HardwareAddr = net.HardwareAddr(hw[:]).String()
		}
		json.NewEncoder(w).Encode(info)
	})

	return taps, nil
}

func (sv *HTTPTapServer) HardwareAddress6() (hwaddr [6]byte, err error) {
	return sv.tap.HardwareAddress6()
}

func (sv *HTTPTapServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sv.router.ServeHTTP(w, r)
}

func (sv *HTTPTapServer) Close() error {
	return sv.tap.Close()
}

type HandleTapResult struct {
	Failed       bool
	SentSize     int
	ReceivedSize int
}

func (sv *HTTPTapServer) HandleTap() (result HandleTapResult, err error) {
	result.ReceivedSize, err = sv.readTap()
	result.Failed = sv.tapfailed
	if result.Failed && err != nil {
		return result, err
	}
	var err2 error
	result.ReceivedSize, err2 = sv.writeTap()
	result.Failed = result.Failed || sv.tapfailed
	if err2 != nil && err == nil {
		err = err2
	} else if err2 != nil {
		err = errors.Join(err, err2)
	}
	return result, err
}

func (sv *HTTPTapServer) readTap() (int, error) {
	buf := sv.buf
	n, err := sv.tap.Read(buf[:])
	if err != nil {
		sv.tapfailed = true
		return n, err
	} else if n > 0 {
		if sv.onTx != nil {
			sv.onTx(0, buf[:n])
		}
		err = sv.stack.recv(buf[:n])
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (sv *HTTPTapServer) writeTap() (int, error) {
	buf := sv.buf
	n, err := sv.stack.handle(buf[:])
	if err != nil {
		return n, err
	} else if n > 0 {
		n, err = sv.tap.Write(buf[:n])
		if err != nil {
			sv.tapfailed = true
			return n, err
		}
	}
	return n, err
}

type stack struct {
	out chan []byte
	in  chan []byte
}

func (s *stack) recv(b []byte) (err error) {
	bcopy := append([]byte{}, b...)
RETRY:
	select {
	case s.in <- bcopy:
	default:
		err = errors.New("receive queue packet full, dropping packet")
		<-s.in
		goto RETRY
	}
	return err
}

func (s *stack) handle(b []byte) (n int, _ error) {
	select {
	case incoming := <-s.out:
		n = copy(b, incoming)
	default:
		// pass if no data available.
	}
	return n, nil
}
