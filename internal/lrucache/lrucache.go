package lrucache

type node[K, V comparable] struct {
	k K
	v V
}

type Cache[K, V comparable] struct {
	nodes []node[K, V]
	index uint // points to the last written entry
}

func New[K, V comparable](maxSize int) Cache[K, V] {
	if maxSize <= 0 {
		panic("lrucache max size must be > 0")
	}
	return Cache[K, V]{
		nodes: make([]node[K, V], 0, maxSize),
	}
}

func (c *Cache[K, V]) Get(k K) (v V, ok bool) {
	// lookup starting from index and then backwards
	i := c.index
	for range len(c.nodes) {
		n := &c.nodes[i]
		if n.k == k {
			return n.v, true
		}
		if i == 0 {
			i = uint(len(c.nodes))
		}
		i--
	}
	return v, ok
}

func (c *Cache[K, V]) Push(k K, v V) {
	// write the entry immediately after the one pointed by index (with wrapping)
	if len(c.nodes) < cap(c.nodes) {
		c.nodes = append(c.nodes, node[K, V]{k, v})
		c.index = uint(len(c.nodes) - 1)
	} else {
		c.index++
		if c.index >= uint(len(c.nodes)) {
			c.index = 0
		}
		c.nodes[c.index] = node[K, V]{k, v}
	}
}
