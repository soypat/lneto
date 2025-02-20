package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/soypat/lneto/internal"
)

func main() {
	err := run()
	if err != nil {
		log.Fatalln("failed:", err)
	}
	fmt.Println("finished")

}

func run() error {
	var (
		flagNet   = "192.168.10.1/24"
		flagiface = "tap0"
		flagMTU   = 1500
	)
	slogger := slog.Default()
	ip, err := netip.ParsePrefix(flagNet)
	if err != nil {
		return err
	}
	tap, err := internal.NewTap(flagiface, ip)
	if err != nil {
		return err
	}
	defer tap.Close()
	s := stack{
		out: make(chan []byte, 256),
		in:  make(chan []byte, 2048),
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
	fmt.Println("listening on http://127.0.0.1:7070/recv  and  http://127.0.0.1:7070/send")
	go http.ListenAndServe(":7070", sv)

	buf := make([]byte, flagMTU)
	for {
		n, err := tap.Read(buf[:])
		if err != nil {
			log.Fatal(err)
		} else if n > 0 {
			err = s.recv(buf[:n])
			if err != nil {
				slogger.Error("recv", slog.String("err", err.Error()), slog.Int("plen", n))
			} else {
				slogger.Info("recv", slog.Int("plen", n))
			}
		}
		n, err = s.handle(buf[:])
		if err != nil {
			slogger.Error("handle", slog.String("err", err.Error()))
		} else if n > 0 {
			_, err = tap.Write(buf[:n])
			if err != nil {
				log.Fatal(err)
			} else {
				slogger.Info("write", slog.Int("plen", n))
			}
		}
	}
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
