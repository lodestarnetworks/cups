package dataplane

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
)

func TestQERPolicerUsesBitsPerSecondAndIndependentDirections(t *testing.T) {
	engine := newPolicyEngine(100 * time.Millisecond)
	now := time.Unix(1, 0)
	matched := rules.PacketRule{
		UPSEID: 10,
		QERs: []rules.QER{{
			ID: 1, UplinkGateOpen: true, DownlinkGateOpen: true,
			MaxUplinkBitsPerSecond: 80_000, MaxDownlinkBitsPerSecond: 160_000,
		}},
	}
	// A 100 ms bucket at 80,000 bits/s holds exactly 1,000 bytes.
	if got := engine.authorize(matched, rules.SourceAccess, 1_000, now); got != policyAllow {
		t.Fatalf("first uplink decision = %v", got)
	}
	if got := engine.authorize(matched, rules.SourceAccess, 1, now); got != policyRateExceeded {
		t.Fatalf("over-limit uplink decision = %v", got)
	}
	// Downlink owns a separate 160,000 bit/s bucket and remains unaffected.
	if got := engine.authorize(matched, rules.SourceCore, 2_000, now); got != policyAllow {
		t.Fatalf("independent downlink decision = %v", got)
	}
	if got := engine.authorize(matched, rules.SourceAccess, 500, now.Add(50*time.Millisecond)); got != policyAllow {
		t.Fatalf("refilled uplink decision = %v", got)
	}
	if counters := engine.counters(); counters.QERRateDrops != 1 || counters.QERGateDrops != 0 {
		t.Fatalf("policy counters = %+v", counters)
	}
}

func TestQCI1BearerKeepsIndependentCreditDuringBulkOverload(t *testing.T) {
	engine := newPolicyEngine(100 * time.Millisecond)
	now := time.Unix(2, 0)
	bulk := rules.PacketRule{UPSEID: 20, QERs: []rules.QER{{
		ID: 1, QCI: 9, ARP: 8, UplinkGateOpen: true, DownlinkGateOpen: true,
		MaxDownlinkBitsPerSecond: 80_000,
	}}}
	voice := rules.PacketRule{UPSEID: 20, QERs: []rules.QER{{
		ID: 2, QCI: 1, ARP: 2, UplinkGateOpen: true, DownlinkGateOpen: true,
		MaxDownlinkBitsPerSecond: 64_000,
	}}}
	if engine.authorize(bulk, rules.SourceCore, 1_000, now) != policyAllow ||
		engine.authorize(bulk, rules.SourceCore, 1, now) != policyRateExceeded {
		t.Fatal("bulk bearer did not reach its independent limit")
	}
	for packet := 0; packet < 3; packet++ {
		if got := engine.authorize(voice, rules.SourceCore, 220, now); got != policyAllow {
			t.Fatalf("QCI 1 packet %d was affected by bulk overload: %v", packet, got)
		}
	}
}

func TestURRMeasuresPostPolicyTrafficWithoutGating(t *testing.T) {
	engine := newPolicyEngine(100 * time.Millisecond)
	now := time.Unix(3, 0)
	matched := rules.PacketRule{UPSEID: 30, URRs: []rules.URR{{
		ID: 7, MeasureVolume: true, MeasureDuration: true, ReportingThreshold: 1_000,
	}}}
	engine.recordUsage(matched, rules.SourceAccess, 600, now)
	engine.recordUsage(matched, rules.SourceCore, 500, now.Add(time.Second))
	usage := engine.usageSnapshot()
	if len(usage) != 1 || usage[0].UplinkBytes != 600 || usage[0].DownlinkBytes != 500 ||
		usage[0].UplinkPackets != 1 || usage[0].DownlinkPackets != 1 || usage[0].ThresholdEvents != 1 ||
		!usage[0].FirstPacket.Equal(now) || !usage[0].LastPacket.Equal(now.Add(time.Second)) {
		t.Fatalf("usage snapshot = %+v", usage)
	}
	if counters := engine.counters(); counters.URRMeteredBytes != 1_100 || counters.URRMeteredPackets != 2 || counters.URRThresholdEvents != 1 || counters.URRActiveMeters != 1 {
		t.Fatalf("URR counters = %+v", counters)
	}
	// Thresholds are observability events only: no usage state is consulted by
	// QER authorization, even after crossing one.
	if got := engine.authorize(matched, rules.SourceAccess, 65_535, now); got != policyAllow {
		t.Fatalf("URR unexpectedly gated unmetered traffic: %v", got)
	}
	engine.deleteSession(matched.UPSEID)
	if counters := engine.counters(); counters.URRActiveMeters != 0 {
		t.Fatalf("deleted session retained usage meters: %+v", counters)
	}
}

func TestClosedQERDropsBeforeRateAccounting(t *testing.T) {
	engine := newPolicyEngine(100 * time.Millisecond)
	matched := rules.PacketRule{UPSEID: 40, QERs: []rules.QER{{
		ID: 1, UplinkGateOpen: false, DownlinkGateOpen: true,
		MaxUplinkBitsPerSecond: 1_000_000,
	}}}
	if got := engine.authorize(matched, rules.SourceAccess, 100, time.Now()); got != policyGateClosed {
		t.Fatalf("closed gate decision = %v", got)
	}
	if counters := engine.counters(); counters.QERGateDrops != 1 || counters.QERRateDrops != 0 {
		t.Fatalf("policy counters = %+v", counters)
	}
}

func TestStalePacketRuleCannotRecreatePolicyStateAfterDelete(t *testing.T) {
	store := rules.NewStore()
	outer := rules.FTEID{TEID: 200, IP: netip.MustParseAddr("10.200.0.20")}
	created, err := store.Create(rules.Session{
		CPSEID: 10, UPSEID: 20,
		PDRs: map[uint16]rules.PDR{
			1: {
				ID: 1, SourceInterface: rules.SourceAccess,
				LocalFTEID: rules.FTEID{TEID: 100, IP: netip.MustParseAddr("10.200.0.10")},
				FARID:      1, QERIDs: []uint32{1}, URRIDs: []uint32{1},
			},
		},
		FARs: map[uint32]rules.FAR{
			1: {ID: 1, ApplyAction: rules.ActionForward, DestinationInterface: rules.DestinationCore, OuterHeader: &outer},
		},
		QERs: map[uint32]rules.QER{
			1: {ID: 1, UplinkGateOpen: true, DownlinkGateOpen: true, MaxUplinkBitsPerSecond: 80_000},
		},
		URRs: map[uint32]rules.URR{
			1: {ID: 1, MeasureVolume: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	stale, ok := store.LookupPacket(rules.SourceAccess, 100)
	if !ok || !stale.Active() {
		t.Fatal("committed packet rule was not active")
	}
	engine := newPolicyEngine(100 * time.Millisecond)
	if decision := engine.authorize(stale, rules.SourceAccess, 100, time.Now()); decision != policyAllow {
		t.Fatalf("active rule authorization = %v", decision)
	}
	engine.recordUsage(stale, rules.SourceAccess, 100, time.Now())
	if counters := engine.counters(); counters.URRActiveMeters != 1 {
		t.Fatalf("active rule did not create its usage meter: %+v", counters)
	}

	if err := store.Delete(created.UPSEID, created.Revision); err != nil {
		t.Fatal(err)
	}
	engine.deleteSession(created.UPSEID)
	if stale.Active() {
		t.Fatal("deleted session left its packet generation active")
	}
	if decision := engine.authorize(stale, rules.SourceAccess, 100, time.Now()); decision != policyRuleInactive {
		t.Fatalf("stale rule authorization = %v, want inactive", decision)
	}
	engine.recordUsage(stale, rules.SourceAccess, 100, time.Now())
	if counters := engine.counters(); counters.URRActiveMeters != 0 || counters.URRMeteredPackets != 2 || counters.URRMeteredBytes != 200 {
		t.Fatalf("stale rule did not preserve totals without recreating a meter: %+v", counters)
	}
	if usage := engine.usageSnapshot(); len(usage) != 0 {
		t.Fatalf("stale rule recreated usage state: %+v", usage)
	}
	shard := engine.shard(created.UPSEID)
	shard.mu.Lock()
	rateBuckets := len(shard.rates)
	shard.mu.Unlock()
	if rateBuckets != 0 {
		t.Fatalf("stale rule recreated %d rate buckets", rateBuckets)
	}
}
