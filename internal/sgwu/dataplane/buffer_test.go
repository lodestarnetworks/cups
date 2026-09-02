package dataplane

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestPacketBufferReservesQCI5Pool(t *testing.T) {
	buffer, err := newPacketBuffer([]BufferClassConfig{
		{QCI: 0, MaxPackets: 1, MaxBytes: 128, MaxPacketsPerBearer: 1, HoldTime: time.Second},
		{QCI: 5, MaxPackets: 1, MaxBytes: 128, MaxPacketsPerBearer: 1, HoldTime: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if !buffer.enqueue(bufferKey{upSEID: 1, pdrID: 2}, 9, []byte{1, 2, 3}, 3, now) {
		t.Fatal("default pool rejected its first packet")
	}
	if buffer.enqueue(bufferKey{upSEID: 2, pdrID: 2}, 9, []byte{4}, 1, now) {
		t.Fatal("default pool exceeded its configured limit")
	}
	if !buffer.enqueue(bufferKey{upSEID: 3, pdrID: 2}, 5, []byte{5}, 1, now) {
		t.Fatal("QCI 5 pool was starved by the full default pool")
	}
	counters := buffer.counters()
	if counters.CurrentPackets != 2 || counters.OverflowDrops != 1 || counters.Classes[1].QCI != 5 || counters.Classes[1].CurrentPackets != 1 {
		t.Fatalf("unexpected counters: %#v", counters)
	}
}

func TestPacketBufferDrainExpiryAndPurge(t *testing.T) {
	buffer, err := newPacketBuffer([]BufferClassConfig{
		{QCI: 0, MaxPackets: 8, MaxBytes: 1024, MaxPacketsPerBearer: 4, HoldTime: 100 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	first := bufferKey{upSEID: 10, pdrID: 2}
	second := bufferKey{upSEID: 11, pdrID: 2}
	if !buffer.enqueue(first, 9, []byte{1, 2}, 2, started) || !buffer.enqueue(first, 9, []byte{3}, 1, started.Add(80*time.Millisecond)) || !buffer.enqueue(second, 9, []byte{4}, 1, started) {
		t.Fatal("enqueue failed")
	}
	if expired := buffer.expire(started.Add(110 * time.Millisecond)); expired != 2 {
		t.Fatalf("expired %d packets, want 2", expired)
	}
	drained := buffer.drain(first)
	if len(drained.frames) != 1 || drained.frames[0].payloadBytes != 1 {
		t.Fatalf("drained frames = %#v", drained.frames)
	}
	if !buffer.enqueue(second, 9, []byte{5}, 1, started.Add(120*time.Millisecond)) {
		t.Fatal("enqueue after expiry failed")
	}
	if purged := buffer.purgeSession(second.upSEID); purged != 1 {
		t.Fatalf("purged %d packets, want 1", purged)
	}
	counters := buffer.counters()
	if counters.CurrentPackets != 0 || counters.Enqueued != 4 || counters.Flushed != 1 || counters.Expired != 2 || counters.Purged != 1 {
		t.Fatalf("unexpected counters: %#v", counters)
	}
}

func TestPacketBufferRestorePreservesOrderAndFlushAccounting(t *testing.T) {
	buffer, err := newPacketBuffer([]BufferClassConfig{
		{QCI: 0, MaxPackets: 4, MaxBytes: 128, MaxPacketsPerBearer: 4, HoldTime: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bufferKey{upSEID: 21, pdrID: 2}
	now := time.Now()
	buffer.enqueue(key, 9, []byte{1}, 1, now)
	buffer.enqueue(key, 9, []byte{2}, 1, now)
	drained := buffer.drain(key)
	buffer.enqueue(key, 9, []byte{3}, 1, now)
	buffer.restore(key, drained.pool, 9, drained.frames)

	restored := buffer.drain(key)
	if len(restored.frames) != 3 || restored.frames[0].wire[0] != 1 || restored.frames[1].wire[0] != 2 || restored.frames[2].wire[0] != 3 {
		t.Fatalf("restore changed packet order: %#v", restored.frames)
	}
	counters := buffer.counters()
	if counters.Enqueued != 3 || counters.Flushed != 3 || counters.CurrentPackets != 0 || counters.OverflowDrops != 0 {
		t.Fatalf("restore double-counted packets: %#v", counters)
	}
}

func BenchmarkPacketBufferIdlePagingBurst(b *testing.B) {
	const (
		burstPackets = 32
		packetBytes  = 1208
	)
	buffer, err := newPacketBuffer([]BufferClassConfig{
		{QCI: 0, MaxPackets: 65_536, MaxBytes: 64 * 1024 * 1024, MaxPacketsPerBearer: burstPackets, HoldTime: 5 * time.Second},
		{QCI: 5, MaxPackets: 16_384, MaxBytes: 16 * 1024 * 1024, MaxPacketsPerBearer: 64, HoldTime: 10 * time.Second},
	})
	if err != nil {
		b.Fatal(err)
	}
	packet := make([]byte, packetBytes)
	now := time.Now()
	var next atomic.Uint64
	b.SetBytes(burstPackets * packetBytes)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		key := bufferKey{upSEID: next.Add(1), pdrID: 2}
		for pb.Next() {
			for index := 0; index < burstPackets; index++ {
				if !buffer.enqueue(key, 9, packet, packetBytes-8, now) {
					b.Error("benchmark buffer unexpectedly overflowed")
					return
				}
			}
			if drained := buffer.drain(key); len(drained.frames) != burstPackets {
				b.Errorf("benchmark drained %d packets", len(drained.frames))
				return
			}
		}
	})
}
