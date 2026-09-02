package dataplane

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

type BufferClassConfig struct {
	QCI                 uint8
	MaxPackets          int
	MaxBytes            int64
	MaxPacketsPerBearer int
	HoldTime            time.Duration
}

type BufferClassCounters struct {
	QCI            uint8
	CurrentPackets uint64
	CurrentBytes   uint64
	Enqueued       uint64
	Flushed        uint64
	Expired        uint64
	OverflowDrops  uint64
	Purged         uint64
}

type BufferCounters struct {
	CurrentPackets uint64
	CurrentBytes   uint64
	Enqueued       uint64
	Flushed        uint64
	Expired        uint64
	OverflowDrops  uint64
	Purged         uint64
	Classes        []BufferClassCounters
}

type bufferKey struct {
	upSEID uint64
	pdrID  uint16
}

type bufferedFrame struct {
	wire         []byte
	payloadBytes int
	enqueued     time.Time
}

type drainedBuffer struct {
	pool   uint8
	frames []bufferedFrame
}

type bearerBuffer struct {
	pool   uint8
	frames []bufferedFrame
	bytes  int64
}

type bufferClassState struct {
	config         BufferClassConfig
	currentPackets uint64
	currentBytes   uint64
	enqueued       uint64
	flushed        uint64
	expired        uint64
	overflowDrops  uint64
	purged         uint64
}

// packetBuffer owns bounded, independent memory pools for each configured
// QCI. Unconfigured QCIs use pool 0, so a saturated bulk pool cannot consume
// the QCI 5 reservation used for IMS signalling.
type packetBuffer struct {
	mu      sync.Mutex
	classes map[uint8]*bufferClassState
	queues  map[bufferKey]*bearerBuffer
}

func newPacketBuffer(classes []BufferClassConfig) (*packetBuffer, error) {
	if len(classes) == 0 {
		return nil, errors.New("sgwu dataplane: at least one downlink buffer class is required")
	}
	buffer := &packetBuffer{
		classes: make(map[uint8]*bufferClassState, len(classes)),
		queues:  make(map[bufferKey]*bearerBuffer),
	}
	for index, class := range classes {
		if _, exists := buffer.classes[class.QCI]; exists {
			return nil, fmt.Errorf("sgwu dataplane: duplicate downlink buffer QCI %d", class.QCI)
		}
		if class.MaxPackets <= 0 || class.MaxBytes <= 0 || class.MaxPacketsPerBearer <= 0 || class.MaxPacketsPerBearer > class.MaxPackets || class.HoldTime <= 0 {
			return nil, fmt.Errorf("sgwu dataplane: invalid downlink buffer class at index %d", index)
		}
		copy := class
		buffer.classes[class.QCI] = &bufferClassState{config: copy}
	}
	if _, exists := buffer.classes[0]; !exists {
		return nil, errors.New("sgwu dataplane: downlink buffer class QCI 0 is required")
	}
	return buffer, nil
}

func (b *packetBuffer) enqueue(key bufferKey, qci uint8, packet []byte, payloadBytes int, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	poolID := qci
	pool, exists := b.classes[poolID]
	if !exists {
		poolID = 0
		pool = b.classes[0]
	}
	queue := b.queues[key]
	if queue != nil && queue.pool != poolID {
		b.purgeQueueLocked(key, queue, false)
		queue = nil
	}
	if queue == nil {
		queue = &bearerBuffer{pool: poolID}
		b.queues[key] = queue
	}
	packetBytes := int64(len(packet))
	if len(queue.frames) >= pool.config.MaxPacketsPerBearer || pool.currentPackets >= uint64(pool.config.MaxPackets) || packetBytes > pool.config.MaxBytes-int64(pool.currentBytes) {
		pool.overflowDrops++
		return false
	}
	wire := append([]byte(nil), packet...)
	queue.frames = append(queue.frames, bufferedFrame{wire: wire, payloadBytes: payloadBytes, enqueued: now})
	queue.bytes += packetBytes
	pool.currentPackets++
	pool.currentBytes += uint64(packetBytes)
	pool.enqueued++
	return true
}

func (b *packetBuffer) drain(key bufferKey) drainedBuffer {
	b.mu.Lock()
	defer b.mu.Unlock()
	queue := b.queues[key]
	if queue == nil {
		return drainedBuffer{}
	}
	delete(b.queues, key)
	pool := b.classes[queue.pool]
	count := uint64(len(queue.frames))
	pool.currentPackets -= count
	pool.currentBytes -= uint64(queue.bytes)
	pool.flushed += count
	return drainedBuffer{pool: queue.pool, frames: queue.frames}
}

// restore closes the PFCP transition race where a bearer returns to BUFF
// while a previous activation is being flushed. Older drained frames are put
// in front of packets that arrived during the flush, with the same hard pool
// limits applied. Restored packets are not double-counted as new enqueues or
// successful flushes.
func (b *packetBuffer) restore(key bufferKey, drainedPool, qci uint8, frames []bufferedFrame) {
	if len(frames) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if source := b.classes[drainedPool]; source != nil {
		count := uint64(len(frames))
		if source.flushed >= count {
			source.flushed -= count
		} else {
			source.flushed = 0
		}
	}
	poolID := qci
	pool, exists := b.classes[poolID]
	if !exists {
		poolID = 0
		pool = b.classes[0]
	}
	existing := b.queues[key]
	candidates := make([]bufferedFrame, 0, len(frames)+bufferLength(existing))
	candidates = append(candidates, frames...)
	if existing != nil {
		existingPool := b.classes[existing.pool]
		existingPool.currentPackets -= uint64(len(existing.frames))
		existingPool.currentBytes -= uint64(existing.bytes)
		candidates = append(candidates, existing.frames...)
		delete(b.queues, key)
	}
	availablePackets := pool.config.MaxPackets - int(pool.currentPackets)
	if availablePackets > pool.config.MaxPacketsPerBearer {
		availablePackets = pool.config.MaxPacketsPerBearer
	}
	availableBytes := pool.config.MaxBytes - int64(pool.currentBytes)
	accepted := 0
	var acceptedBytes int64
	for accepted < len(candidates) && accepted < availablePackets {
		frameBytes := int64(len(candidates[accepted].wire))
		if frameBytes > availableBytes-acceptedBytes {
			break
		}
		acceptedBytes += frameBytes
		accepted++
	}
	if accepted > 0 {
		retained := append([]bufferedFrame(nil), candidates[:accepted]...)
		b.queues[key] = &bearerBuffer{pool: poolID, frames: retained, bytes: acceptedBytes}
		pool.currentPackets += uint64(accepted)
		pool.currentBytes += uint64(acceptedBytes)
	}
	pool.overflowDrops += uint64(len(candidates) - accepted)
}

func bufferLength(queue *bearerBuffer) int {
	if queue == nil {
		return 0
	}
	return len(queue.frames)
}

func (b *packetBuffer) keys(upSEID uint64) []bufferKey {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]bufferKey, 0, 2)
	for key := range b.queues {
		if key.upSEID == upSEID {
			out = append(out, key)
		}
	}
	return out
}

func (b *packetBuffer) expire(now time.Time) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	var expired uint64
	for key, queue := range b.queues {
		pool := b.classes[queue.pool]
		cut := 0
		var bytes int64
		for cut < len(queue.frames) && !queue.frames[cut].enqueued.Add(pool.config.HoldTime).After(now) {
			bytes += int64(len(queue.frames[cut].wire))
			cut++
		}
		if cut == 0 {
			continue
		}
		count := uint64(cut)
		expired += count
		pool.currentPackets -= count
		pool.currentBytes -= uint64(bytes)
		pool.expired += count
		remaining := copy(queue.frames, queue.frames[cut:])
		for index := remaining; index < len(queue.frames); index++ {
			queue.frames[index] = bufferedFrame{}
		}
		queue.frames = queue.frames[:remaining]
		queue.bytes -= bytes
		if len(queue.frames) == 0 {
			delete(b.queues, key)
		}
	}
	return expired
}

func (b *packetBuffer) purgeSession(upSEID uint64) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	var purged uint64
	for key, queue := range b.queues {
		if key.upSEID != upSEID {
			continue
		}
		purged += uint64(len(queue.frames))
		b.purgeQueueLocked(key, queue, true)
	}
	return purged
}

func (b *packetBuffer) purgeQueueLocked(key bufferKey, queue *bearerBuffer, explicit bool) {
	delete(b.queues, key)
	pool := b.classes[queue.pool]
	count := uint64(len(queue.frames))
	pool.currentPackets -= count
	pool.currentBytes -= uint64(queue.bytes)
	if explicit {
		pool.purged += count
	} else {
		pool.overflowDrops += count
	}
}

func (b *packetBuffer) counters() BufferCounters {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := BufferCounters{Classes: make([]BufferClassCounters, 0, len(b.classes))}
	for _, state := range b.classes {
		class := BufferClassCounters{
			QCI: state.config.QCI, CurrentPackets: state.currentPackets, CurrentBytes: state.currentBytes,
			Enqueued: state.enqueued, Flushed: state.flushed, Expired: state.expired,
			OverflowDrops: state.overflowDrops, Purged: state.purged,
		}
		out.Classes = append(out.Classes, class)
		out.CurrentPackets += class.CurrentPackets
		out.CurrentBytes += class.CurrentBytes
		out.Enqueued += class.Enqueued
		out.Flushed += class.Flushed
		out.Expired += class.Expired
		out.OverflowDrops += class.OverflowDrops
		out.Purged += class.Purged
	}
	sort.Slice(out.Classes, func(i, j int) bool { return out.Classes[i].QCI < out.Classes[j].QCI })
	return out
}
