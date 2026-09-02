package main

import (
	"math"
	"testing"
	"time"
)

func TestMobileIMIXProfileIsDeterministic(t *testing.T) {
	profile, err := newPacketProfile("mobile-imix", 1_200)
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[int]int)
	for sequence := uint64(1); sequence <= 100; sequence++ {
		counts[profile.size(sequence)]++
	}
	want := map[int]int{64: 40, 256: 20, 512: 10, 1_200: 30}
	for size, expected := range want {
		if counts[size] != expected {
			t.Fatalf("size %d count=%d, want %d", size, counts[size], expected)
		}
	}
	if profile.average != 488 || profile.maxSize() != 1_200 {
		t.Fatalf("average/max=%f/%d, want 488/1200", profile.average, profile.maxSize())
	}
}

func TestMillionSessionIdentitiesStayInRange(t *testing.T) {
	first := ueAddress(0)
	last := ueAddress(999_999)
	if first.String() != "10.0.0.2" || first == last || !uePrefix.Contains(last) {
		t.Fatalf("unexpected UE range: first=%s last=%s prefix=%s", first, last, uePrefix)
	}
	seen := make(map[int]struct{})
	for sequence := uint64(1); sequence <= 100_000; sequence++ {
		index := sessionIndex(sequence, 1_000_000)
		if index < 0 || index >= 1_000_000 {
			t.Fatalf("session index out of range: %d", index)
		}
		seen[index] = struct{}{}
	}
	if len(seen) < 90_000 {
		t.Fatalf("session selector covered only %d/100000 samples", len(seen))
	}
}

func TestCapacitySizing(t *testing.T) {
	if got := fastPathRuleCapacity(1); got != 4 {
		t.Fatalf("one-session fast-path rules=%d, want 4", got)
	}
	if got := fastPathRuleCapacity(1_000_000); got != 2_000_000 {
		t.Fatalf("million-session fast-path rules=%d", got)
	}
	if got := kernelHashSize(1); got != 1_024 {
		t.Fatalf("one-session kernel hash=%d, want 1024", got)
	}
	if got := kernelHashSize(100_000); got != 16_384 {
		t.Fatalf("100k kernel hash=%d, want 16384", got)
	}
	if got := kernelHashSize(1_000_000); got != 131_072 {
		t.Fatalf("million-session kernel hash=%d, want 131072", got)
	}
}

func TestBenchmarkDurationBounds(t *testing.T) {
	for _, duration := range []time.Duration{100 * time.Millisecond, time.Minute, maximumDuration} {
		if err := validateDuration(duration); err != nil {
			t.Fatalf("duration %s rejected: %v", duration, err)
		}
	}
	for _, duration := range []time.Duration{100*time.Millisecond - 1, maximumDuration + 1} {
		if err := validateDuration(duration); err == nil {
			t.Fatalf("duration %s accepted", duration)
		}
	}
}

func TestSummarizeUsesMeasuredMixedPacketBytes(t *testing.T) {
	profile, err := newPacketProfile("mobile-imix", 1_200)
	if err != nil {
		t.Fatal(err)
	}
	value := &measurement{direction: "uplink", started: time.Unix(1, 0), ended: time.Unix(2, 0)}
	value.sent.Store(2)
	value.received.Store(2)
	value.sentBytes.Store(1_264)
	value.receivedBytes.Store(1_264)
	got := summarize(value, config{profile: profile, sessions: 100_000, activeSessions: 100_000, workers: 2})
	if got.InnerPacketBytes != 0 || got.PacketProfile != "mobile-imix" || got.InstalledSessions != 100_000 {
		t.Fatalf("unexpected mixed-profile metadata: %+v", got)
	}
	if math.Abs(got.ReceivedMbps-0.010112) > 0.000001 || got.LossPercent != 0 {
		t.Fatalf("received Mbps/loss=%f/%f", got.ReceivedMbps, got.LossPercent)
	}
}
