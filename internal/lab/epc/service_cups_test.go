package epc

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

type serviceTestTimeoutError struct{}

func (serviceTestTimeoutError) Error() string   { return "test timeout" }
func (serviceTestTimeoutError) Timeout() bool   { return true }
func (serviceTestTimeoutError) Temporary() bool { return true }

func TestServiceCUPSIPv4UDPRoundTrip(t *testing.T) {
	source := netip.MustParseAddr("10.47.0.2")
	destination := netip.MustParseAddr("10.253.80.2")
	payload := []byte("lodestar")
	packet, err := buildIPv4UDP(source, destination, 40_000, 40_001, payload)
	if err != nil {
		t.Fatal(err)
	}
	if ipv4HeaderChecksum(packet[:20]) != 0 {
		t.Fatal("generated IPv4 header checksum is invalid")
	}
	gotSource, gotDestination, gotSourcePort, gotDestinationPort, gotPayload, err := parseIPv4UDP(packet)
	if err != nil {
		t.Fatal(err)
	}
	if gotSource != source || gotDestination != destination || gotSourcePort != 40_000 || gotDestinationPort != 40_001 || string(gotPayload) != string(payload) {
		t.Fatalf("parsed packet %s:%d -> %s:%d payload=%q", gotSource, gotSourcePort, gotDestination, gotDestinationPort, gotPayload)
	}
}

func TestServiceCUPSHoldBounds(t *testing.T) {
	valid := ServiceCUPSConfig{
		MMEControl:   netip.MustParseAddrPort("10.253.10.2:2123"),
		SGWS11:       netip.MustParseAddrPort("10.253.10.1:2123"),
		ENBUser:      netip.MustParseAddrPort("10.253.40.2:2152"),
		ExternalUser: netip.MustParseAddrPort("10.253.80.2:40001"),
		IMSI:         "001010123456789", APN: "lodestartest", EBI: 5,
		Timeout: time.Second, SocketBufferBytes: 64 << 10,
		ThroughputDirection: "both", PayloadSize: 1200, PacketBatchSize: 128,
		MMEControlTEID: 1, ENodeBTEID: 2,
	}
	for name, mutate := range map[string]func(*ServiceCUPSConfig){
		"negative post-modify": func(config *ServiceCUPSConfig) { config.HoldAfterModify = -time.Nanosecond },
		"long post-modify":     func(config *ServiceCUPSConfig) { config.HoldAfterModify = time.Minute + time.Nanosecond },
		"negative post-data":   func(config *ServiceCUPSConfig) { config.HoldAfterData = -time.Nanosecond },
		"long post-data":       func(config *ServiceCUPSConfig) { config.HoldAfterData = time.Minute + time.Nanosecond },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := validateServiceCUPS(candidate); err == nil {
				t.Fatal("invalid hold duration was accepted")
			}
		})
	}
	if err := validateServiceCUPS(valid); err != nil {
		t.Fatalf("valid service config rejected: %v", err)
	}
}

func TestServiceCUPSThroughputBounds(t *testing.T) {
	valid := ServiceCUPSConfig{
		MMEControl:   netip.MustParseAddrPort("10.253.10.2:2123"),
		SGWS11:       netip.MustParseAddrPort("10.253.10.1:2123"),
		ENBUser:      netip.MustParseAddrPort("10.253.40.2:2152"),
		ExternalUser: netip.MustParseAddrPort("10.253.80.2:40001"),
		IMSI:         "001010123456789", APN: "lodestartest", EBI: 5,
		Timeout: time.Second, SocketBufferBytes: 64 << 10,
		ThroughputDuration: time.Second, ThroughputDirection: "both",
		PayloadSize: 1200, TargetPacketsPerSecond: 95_000, PacketBatchSize: 128,
		MMEControlTEID: 1, ENodeBTEID: 2,
	}
	for name, mutate := range map[string]func(*ServiceCUPSConfig){
		"short duration": func(config *ServiceCUPSConfig) { config.ThroughputDuration = 99 * time.Millisecond },
		"long duration": func(config *ServiceCUPSConfig) {
			config.ThroughputDuration = maximumServiceThroughputDuration + time.Nanosecond
		},
		"bad direction":  func(config *ServiceCUPSConfig) { config.ThroughputDirection = "sideways" },
		"small packet":   func(config *ServiceCUPSConfig) { config.PayloadSize = 63 },
		"large packet":   func(config *ServiceCUPSConfig) { config.PayloadSize = 1401 },
		"negative rate":  func(config *ServiceCUPSConfig) { config.TargetPacketsPerSecond = -1 },
		"excessive rate": func(config *ServiceCUPSConfig) { config.TargetPacketsPerSecond = 1_000_001 },
		"zero batch":     func(config *ServiceCUPSConfig) { config.PacketBatchSize = 0 },
		"large batch":    func(config *ServiceCUPSConfig) { config.PacketBatchSize = 1025 },
		"zero MME TEID":  func(config *ServiceCUPSConfig) { config.MMEControlTEID = 0 },
		"zero eNB TEID":  func(config *ServiceCUPSConfig) { config.ENodeBTEID = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := validateServiceCUPS(candidate); err == nil {
				t.Fatal("invalid throughput configuration was accepted")
			}
		})
	}
	if err := validateServiceCUPS(valid); err != nil {
		t.Fatalf("valid throughput configuration rejected: %v", err)
	}
}

func TestServiceCUPSThroughputPayload(t *testing.T) {
	payload := serviceThroughputPayload(64, 42)
	if !validServiceThroughputPayload(payload, 64) {
		t.Fatal("generated service throughput payload was rejected")
	}
	if binary.BigEndian.Uint64(payload[8:16]) != 42 {
		t.Fatal("service throughput payload lost its sequence")
	}
	payload[0] ^= 0xff
	if validServiceThroughputPayload(payload, 64) {
		t.Fatal("corrupt service throughput payload was accepted")
	}
}

func TestServiceSequenceTrackerCountsUniqueDuplicateAndReorderedPackets(t *testing.T) {
	tracker := newServiceSequenceTracker(16)
	for _, sequence := range []uint64{0, 1, 3, 2, 3, 5, 4} {
		tracker.observe(sequence)
	}
	stats := tracker.stats()
	if stats.unique != 6 || stats.duplicates != 1 || stats.outOfOrder != 2 || stats.tooOld != 0 ||
		!stats.initialized || stats.highest != 5 {
		t.Fatalf("unexpected sequence stats: %+v", stats)
	}
}

func TestServiceSequenceTrackerBoundsOldReordering(t *testing.T) {
	tracker := newServiceSequenceTracker(4)
	for _, sequence := range []uint64{0, 1, 2, 3, 4, 0, 4} {
		tracker.observe(sequence)
	}
	stats := tracker.stats()
	if stats.unique != 5 || stats.duplicates != 1 || stats.outOfOrder != 0 || stats.tooOld != 1 ||
		stats.highest != 4 {
		t.Fatalf("unexpected bounded sequence stats: %+v", stats)
	}
}

func TestMeasureServiceStreamReportsUniqueSequenceDelivery(t *testing.T) {
	const batchSize = 8
	packets := make(chan uint64, 1<<16)
	sequences := newServiceSequenceTracker(64)
	injectedDuplicate := false
	send := func(firstSequence uint64, count int) (int, error) {
		for index := 0; index < count; index++ {
			sequence := firstSequence + uint64(index)
			if !injectedDuplicate && index == 0 && count > 1 {
				packets <- sequence + 1
				packets <- sequence
				packets <- sequence + 1
				index++
				injectedDuplicate = true
				continue
			}
			packets <- sequence
		}
		return count, nil
	}
	receive := func(deadline time.Time) (int, uint64, error) {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		for received := 0; received < batchSize; {
			select {
			case sequence := <-packets:
				sequences.observe(sequence)
				received++
				if len(packets) == 0 {
					return received, 0, nil
				}
			case <-timer.C:
				return received, 0, serviceTestTimeoutError{}
			}
		}
		return batchSize, 0, nil
	}
	result, err := measureServiceStream(
		context.Background(), 20*time.Millisecond, 1200, 10_000, batchSize, send, receive, sequences,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.ReceivedPackets != result.SentPackets || result.ReceivedDatagrams != result.SentPackets+1 ||
		result.DuplicatePackets != 1 || result.OutOfOrderPackets != 1 || result.LostPackets != 0 {
		t.Fatalf("unexpected measured sequence result: %+v", result)
	}
}

func TestServiceCUPSIPv4UDPRejectsMalformedPackets(t *testing.T) {
	if _, _, _, _, _, err := parseIPv4UDP([]byte{0x45}); err == nil {
		t.Fatal("accepted a truncated IPv4 packet")
	}
	if _, err := buildIPv4UDP(netip.IPv6Loopback(), netip.MustParseAddr("10.0.0.1"), 1, 2, nil); err == nil {
		t.Fatal("accepted an IPv6 source")
	}
}
