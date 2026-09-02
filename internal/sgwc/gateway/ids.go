package gateway

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sort"
	"sync"
)

var errIDSpaceExhausted = errors.New("sgwc: tunnel identifier space exhausted")

type idAllocator struct {
	mu    sync.Mutex
	teids map[uint32]struct{}
	seids map[uint64]struct{}
}

func newIDAllocator() *idAllocator {
	return &idAllocator{teids: make(map[uint32]struct{}), seids: make(map[uint64]struct{})}
}

func (a *idAllocator) allocateTEID() (uint32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for attempt := 0; attempt < 512; attempt++ {
		var raw [4]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return 0, err
		}
		id := binary.BigEndian.Uint32(raw[:])
		if id == 0 {
			continue
		}
		if _, exists := a.teids[id]; exists {
			continue
		}
		a.teids[id] = struct{}{}
		return id, nil
	}
	return 0, errIDSpaceExhausted
}

func (a *idAllocator) allocateSEID() (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for attempt := 0; attempt < 512; attempt++ {
		var raw [8]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return 0, err
		}
		id := binary.BigEndian.Uint64(raw[:])
		if id == 0 {
			continue
		}
		if _, exists := a.seids[id]; exists {
			continue
		}
		a.seids[id] = struct{}{}
		return id, nil
	}
	return 0, errIDSpaceExhausted
}

func (a *idAllocator) releaseTEIDs(ids ...uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, id := range ids {
		delete(a.teids, id)
	}
}

func (a *idAllocator) releaseSEID(id uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.seids, id)
}

func (a *idAllocator) reserveTEID(id uint32) bool {
	if id == 0 {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.teids[id]; exists {
		return false
	}
	a.teids[id] = struct{}{}
	return true
}

func (a *idAllocator) reserveSEID(id uint64) bool {
	if id == 0 {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.seids[id]; exists {
		return false
	}
	a.seids[id] = struct{}{}
	return true
}

type lockSet struct {
	locks [256]sync.Mutex
}

func (s *lockSet) lock(value uint64) func() {
	lock := &s.locks[lockIndex(value)]
	lock.Lock()
	return lock.Unlock
}

// lockMany acquires every lock bucket touched by values in a stable order.
// Multiple session IDs can hash to the same bucket, so buckets are de-duplicated
// before locking. This lets one S11 procedure update several PDN contexts
// atomically without introducing self-deadlocks or lock-order inversions.
func (s *lockSet) lockMany(values []uint64) func() {
	seen := make(map[uint8]struct{}, len(values))
	indices := make([]int, 0, len(values))
	for _, value := range values {
		index := lockIndex(value)
		if _, exists := seen[index]; exists {
			continue
		}
		seen[index] = struct{}{}
		indices = append(indices, int(index))
	}
	sort.Ints(indices)
	for _, index := range indices {
		s.locks[index].Lock()
	}
	return func() {
		for index := len(indices) - 1; index >= 0; index-- {
			s.locks[indices[index]].Unlock()
		}
	}
}

func lockIndex(value uint64) uint8 {
	return byte(value ^ (value >> 16) ^ (value >> 32) ^ (value >> 48))
}
