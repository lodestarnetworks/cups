// Package responsecache provides a concurrency-safe bounded cache for encoded
// control-plane responses. It keeps duplicate-request handling constant-time
// even after the cache reaches capacity.
package responsecache

import (
	"container/list"
	"sync"
	"time"
)

type entry[K comparable] struct {
	key       K
	wire      []byte
	expiresAt time.Time
}

// Cache is a least-recently-used response cache. Values are copied on both
// insertion and retrieval so callers cannot mutate cached wire data.
type Cache[K comparable] struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	entries  map[K]*list.Element
	order    *list.List
}

func New[K comparable](capacity int, ttl time.Duration) *Cache[K] {
	return &Cache[K]{
		capacity: capacity,
		ttl:      ttl,
		entries:  make(map[K]*list.Element, max(capacity, 0)),
		order:    list.New(),
	}
}

func (c *Cache[K]) Get(key K) ([]byte, bool) {
	if c.capacity <= 0 || c.ttl <= 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	element, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	value := element.Value.(*entry[K])
	if !value.expiresAt.After(time.Now()) {
		c.remove(element)
		return nil, false
	}
	c.order.MoveToBack(element)
	return append([]byte(nil), value.wire...), true
}

func (c *Cache[K]) Put(key K, wire []byte) {
	if c.capacity <= 0 || c.ttl <= 0 {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if element, ok := c.entries[key]; ok {
		value := element.Value.(*entry[K])
		value.wire = append(value.wire[:0], wire...)
		value.expiresAt = now.Add(c.ttl)
		c.order.MoveToBack(element)
		return
	}
	if c.order.Len() >= c.capacity {
		c.remove(c.order.Front())
	}
	value := &entry[K]{key: key, wire: append([]byte(nil), wire...), expiresAt: now.Add(c.ttl)}
	c.entries[key] = c.order.PushBack(value)
}

func (c *Cache[K]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *Cache[K]) remove(element *list.Element) {
	if element == nil {
		return
	}
	value := element.Value.(*entry[K])
	delete(c.entries, value.key)
	c.order.Remove(element)
}
