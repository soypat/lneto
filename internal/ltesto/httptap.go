package ltesto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"
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

var _ Interface = (*HTTPTapClient)(nil)

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

func (h *HTTPTapClient) IPMask() (netip.Prefix, error) {
	err := h.ensureMTU()
	return h.ip, err
}

func (h *HTTPTapClient) MTU() (int, error) {
	err := h.ensureMTU()
	return len(h.buf), err
}

func (h *HTTPTapClient) HardwareAddress6() ([6]byte, error) {
	err := h.ensureMTU()
	return h.hwaddr, err
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

func (h *HTTPTapClient) ReadDiscard() (err error) {
	for {
		d, err2 := h.ReadBytes() // Empty remote data.
		if len(d) == 0 {
			err = err2
			break
		}
	}
	return err
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
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("bad server response %s %s: %s", h.sendurl, resp.Status, b)
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
	} else if len(b) < len(h.buf) {
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
	} else if len(b) > len(h.buf) {
		return 0, errors.New("buffer larger than MTU")
	}
	data, _ := json.Marshal(b)
	resp, err := h.c.Post(h.sendurl, "application/json", bytes.NewReader(data))
	if err != nil {
		return 0, err
	} else if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("bad server response for plen %d @ %s %s: %s", len(b), h.sendurl, resp.Status, b)
	}
	return len(b), nil
}

func (h *HTTPTapClient) Close() error { return nil }

type HTTPTapServer struct {
	sendmu sync.Mutex
	recvmu sync.Mutex
	router *http.ServeMux
	tap    Interface
	buf    []byte
	onTx   func(channel int, pkt []byte)
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

	sv := http.NewServeMux()
	taps := &HTTPTapServer{
		router: sv,
		tap:    iface,
		buf:    make([]byte, mtu),
	}
	sv.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		retries := 10
		for {
			if taps.sendmu.TryLock() {
				defer taps.sendmu.Unlock()
				break
			} else if retries == 0 {
				slog.Error("send-overload")
				http.Error(w, "resource in use", http.StatusInternalServerError)
				return
			}
			retries--
			time.Sleep(100 * time.Microsecond) // approx duration of what one request processing takes on my machine.
		}
		var data []byte
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, err = taps.tap.Write(data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if taps.onTx != nil {
			taps.onTx(1, data)
		}
	})
	sv.HandleFunc("/recv", func(w http.ResponseWriter, r *http.Request) {
		if !taps.recvmu.TryLock() {
			http.Error(w, "resource in use: recv may take a while, are you using concurrent access or have you restarted your client? please wait!", http.StatusInternalServerError)
			return
		}
		defer taps.recvmu.Unlock()
		n, err := taps.tap.Read(taps.buf)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if taps.onTx != nil {
			taps.onTx(0, taps.buf[:n])
		}
		json.NewEncoder(w).Encode(taps.buf[:n])
	})
	hw6, err := iface.HardwareAddress6()
	if err != nil {
		return nil, fmt.Errorf("acquiring hardware address: %w", err)
	}
	hwstr := net.HardwareAddr(hw6[:]).String()
	ipstr := netmask.String()
	sv.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		info := tapInfo{
			MTU:          mtu,
			IPPrefix:     ipstr,
			HardwareAddr: hwstr,
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
