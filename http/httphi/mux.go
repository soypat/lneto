package httphi

import (
	"strings"

	"github.com/soypat/lneto/internal"
)

type Mux interface {
	LookupHandler(get Method, uri []byte) HandlerFunc
}

type MuxSlice struct {
	// TODO: binary search worth it?
	_handlers []struct {
		method  Method
		uri     string
		handler HandlerFunc
	}
}

func (sm *MuxSlice) Reset(capacity int) {
	internal.SliceReuse(&sm._handlers, capacity)
}

func (sm *MuxSlice) LookupHandler(method Method, uri []byte) HandlerFunc {
	for _, endpoint := range sm._handlers {
		if endpoint.method != MethUndefined && endpoint.method != method {
			continue
		}
		// Method matches.
		if b2s(uri) == endpoint.uri {
			return endpoint.handler
		}
	}
	return nil
}

func (sm *MuxSlice) Handle(reg string, handler HandlerFunc) {
	v := internal.SliceReclaim(&sm._handlers)
	method := MethUndefined
	methodOrURL, url, methodFound := strings.Cut(reg, " ")
	if methodFound {
		method = MethodFromBytes([]byte(methodOrURL))
	} else {
		url = methodOrURL
	}
	v.method = method
	v.uri = url
	v.handler = handler
}
