package httphi_test

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"

	"github.com/soypat/lneto/http/httphi"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/x/rawsock"
)

// ExampleRouter_linux goes over how to setup a linux server using raw linux connections.
// See [ExampleMuxSlice_query_forms_multipart] on how to define handlers for common HTTP processing.
func ExampleRouter_linux() {
	// Chrome tends to send ~700 bytes on a typical landing page request.
	const requestBuffer = 1024
	const numHeaderKV = requestBuffer / 32 //
	var mux httphi.MuxSlice
	mux.Handle("GET /", func(ex *httphi.Exchange) {
		ex.WriteBody([]byte("hello world"))
	})
	var router httphi.Router
	err := router.Configure(httphi.RouterConfig{
		FixedNumGoroutines:          -1, // Unbounded goroutines and allocations.
		RequestHeaderBufferSize:     requestBuffer,
		ResponseHeaderMinBufferSize: 32, // Shared buffer with Request, not strictly necessary, especially if not sending headers.
		RequestNumHeaderKVCap:       numHeaderKV,
		NormalizeOutgoingKeys:       true,
		Mux:                         &mux,
		Logger:                      slog.Default(),
	})
	if err != nil {
		log.Fatal(err)
	}
	// Raw linux sockets.
	var listener rawsock.Listener
	err = listener.Listen(8080)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("server up at http://localhost:%d", listener.Port())
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		err = router.Handle(conn)
		if err != nil {
			log.Println("httphi.Router failed to handle connection:", err)
		}
	}
}

// ExampleMuxSlice_query_forms_multipart goes over how to define Handlers (HandleFunc).
// See [ExampleRouter_linux] for how to setup the server.
func ExampleMuxSlice_query_forms_multipart() {

	var mux httphi.MuxSlice

	mux.Handle("/users/{id}", func(ex *httphi.Exchange) {
		userID := ex.PathValue("id")
		fmt.Printf("someone requested data for user %s", userID)
	})

	mux.Handle("/query", func(ex *httphi.Exchange) {
		// query parameter in URL.
		const decodeQuery = true
		const queryKey = "search"
		queryValue, present := ex.AppendQuery(nil, queryKey, decodeQuery)
		fmt.Printf("got query=%v %s=%s", present, queryKey, queryValue)
	})

	mux.Handle("GET /form", func(ex *httphi.Exchange) {
		// Request Body Form.
		formbuf := make([]byte, 1024)
		var form httpraw.Form
		err := ex.RequestParseForm(&form, formbuf)
		if err != nil {
			ex.WriteHeader(httphi.StatusInternalServerError)
			return
		}
		for i := range form.Len() {
			k, v := form.Pair(i)
			fmt.Printf("received form value %d: %s=%s\n", i, k, v)
		}
	})

	mux.Handle("GET /file-upload", func(ex *httphi.Exchange) {
		// File upload directly onto server using multipart.
		formbuf := make([]byte, 1024)
		_, err := ex.ReadMultiparts(nil, formbuf, func(hdr *httpraw.MultipartHeader) io.WriteCloser {
			fp, err := os.Create(string(hdr.Filename))
			if err != nil {
				return nil
			}
			return fp // Will write full file contents to fp.
		})
		if err != nil {
			ex.WriteHeader(httphi.StatusInternalServerError)
			return
		}
	})

}
