//go:build 386 || arm || mips || mipsle

package internal

import (
	"sync/atomic"

	"github.com/soypat/lneto"
)

// LoadConnID atomically loads *id.
func LoadConnID(id *lneto.ConnID) lneto.ConnID {
	return lneto.ConnID(atomic.LoadUint32((*uint32)(id)))
}

// IncConnID atomically increments *id.
func IncConnID(id *lneto.ConnID) { atomic.AddUint32((*uint32)(id), 1) }
