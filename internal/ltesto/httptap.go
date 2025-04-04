package ltesto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/soypat/lneto/internal"
)

// NewHTTPTapClient returns a HTTPTapClient ready for use.
func NewHTTPTapClient(baseURL string) *HTTPTapClient {
	var h HTTPTapClient
	h.sendurl = baseURL + "/send"
	h.recvurl = baseURL + "/recv"
	_, err := url.Parse(h.sendurl)
	if err != nil {
		panic(err)
	}
	return &h
}

type HTTPTapClient struct {
	c       http.Client
	recvurl string
	sendurl string
}

func (h *HTTPTapClient) ReadDiscard() {
	var data [2048]byte
	var n int = -1
	for n != 0 {
		n, _ = h.Read(data[:]) // Empty remote data.
	}
}

func (h *HTTPTapClient) Read(b []byte) (int, error) {
	resp, err := h.c.Get(h.recvurl)
	if err != nil {
		return 0, err
	} else if resp.StatusCode != 200 {
		return 0, errors.New(resp.Status + " for " + h.recvurl)
	}
	var data []byte
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return 0, err
	} else if len(b) < len(data) {
		return 0, fmt.Errorf("got too large packet %d for buffer %d", len(data), len(b))
	}
	copy(b, data)
	return len(data), nil
}

func (h *HTTPTapClient) Write(b []byte) (int, error) {
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
	tap       *internal.Tap
	buf       []byte
	tapfailed bool
}

func NewHTTPTapServer(iface string, ip netip.Prefix, mtu, queueOut, queueIn int) (*HTTPTapServer, error) {
	tap, err := internal.NewTap(iface, ip)
	if err != nil {
		return nil, err
	}

	s := stack{
		out: make(chan []byte, queueOut),
		in:  make(chan []byte, queueIn),
	}
	sv := http.NewServeMux()
	sv.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		var data []byte
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			select {
			case s.out <- data:
				slog.Info("http-send", slog.Int("plen", len(data)))
			default:
				http.Error(w, "outgoing packet queue full", http.StatusInternalServerError)
			}
		}
	})
	sv.HandleFunc("/recv", func(w http.ResponseWriter, r *http.Request) {
		select {
		case data := <-s.in:
			json.NewEncoder(w).Encode(data)
			slog.Info("http-recv", slog.Int("plen", len(data)))
		default:
			json.NewEncoder(w).Encode("") // send empty string.
		}
	})
	taps := HTTPTapServer{
		router: sv,
		stack:  s,
		tap:    tap,
		buf:    make([]byte, mtu),
	}
	return &taps, nil
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
