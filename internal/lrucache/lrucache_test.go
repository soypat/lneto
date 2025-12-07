package lrucache

import (
	"testing"
)

type dummyCache[K, V comparable] struct {
	s   []node[K, V]
	max int
}

func (c *dummyCache[K, V]) Get(k K) (v V, ok bool) {
	for i := len(c.s) - 1; i >= 0; i-- {
		if c.s[i].k == k {
			return c.s[i].v, true
		}
	}
	return
}

func (c *dummyCache[K, V]) Push(k K, v V) {
	c.s = append(c.s, node[K, V]{k, v})
	for len(c.s) > c.max {
		c.s = c.s[1:]
	}
}

func FuzzMain(f *testing.F) {
	type operation uint8
	const (
		opGet operation = iota
		opPush
		opDone
	)

	for size := uint8(1); size <= 4; size++ {
		f.Add(size-1, []byte{0x81, 0x01, 0x01})                         // push(1,1) get(1)
		f.Add(size-1, []byte{0x81, 0x01, 0x82, 0x03, 0x02, 0x01, 0x00}) // push(1,1) push(2,3) get(2) get(1) get(0)
	}

	f.Fuzz(func(t *testing.T, sizeM1 uint8, ops []byte) {
		nextOpB := func() (byte, bool) {
			if len(ops) == 0 {
				return 0, false
			}
			opB := ops[0]
			ops = ops[1:]
			return opB, true
		}
		totalOps := 0
		nextOp := func() (operation, int8, uint8) {
			if opB, ok := nextOpB(); ok {
				op := operation(opB >> 7)
				key := int8(opB & 0x7F)
				switch op {
				case opGet:
					totalOps++
					return op, key, 0
				case opPush:
					if value, ok := nextOpB(); ok {
						totalOps++
						return op, key, value
					}
				}
			}
			return opDone, 0, 0
		}

		doneOps := 0
		size := int(sizeM1) + 1
		c := New[int8, uint8](size)
		r := dummyCache[int8, uint8]{max: size}
		for {
			op, key, value := nextOp()
			switch op {
			case opGet:
				valA, okA := c.Get(key)
				valE, okE := r.Get(key)
				doneOps++
				if okE != okA || valE != valA {
					t.Errorf("expected %v,%v got %v,%v", valE, okE, valA, okA)
				}
			case opPush:
				c.Push(key, value)
				r.Push(key, value)
				doneOps++
			case opDone:
				if totalOps != doneOps {
					t.Fatalf("processed ops mismatch: total %d done %d", totalOps, doneOps)
				}
				return
			}
		}
	})
}
