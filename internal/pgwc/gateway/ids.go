package gateway

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
)

var errIDSpaceExhausted = errors.New("pgwc: identifier space exhausted")

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

func (a *idAllocator) release(teids []uint32, seid uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, teid := range teids {
		delete(a.teids, teid)
	}
	delete(a.seids, seid)
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
	lock := &s.locks[byte(value^(value>>16)^(value>>32)^(value>>48))]
	lock.Lock()
	return lock.Unlock
}
