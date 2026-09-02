package dataplane

import (
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
)

func TestPGWPolicyBitrateDirectionsAndTelemetryThreshold(t *testing.T) {
	engine := newPolicyEngine(100 * time.Millisecond)
	session := rules.Session{
		UPSEID: 42, Revision: 1, UplinkGateOpen: true, DownlinkGateOpen: true,
		MaxUplinkBitsPerSecond: 80_000, MaxDownlinkBitsPerSecond: 160_000,
		QERID: 1, URRID: 7, MeasureVolume: true, MeasureDuration: true,
		UsageReportingThreshold: 1_500,
	}
	engine.reconcileSession(session)
	matched := defaultPacketRule(session)
	now := time.Unix(100, 0)
	if got := engine.authorize(matched, true, 1_000, now); got != policyAllow {
		t.Fatalf("first uplink decision = %d", got)
	}
	engine.recordUsage(matched, true, 1_000, now)
	if got := engine.authorize(matched, false, 1_000, now); got != policyAllow {
		t.Fatalf("independent downlink decision = %d", got)
	}
	engine.recordUsage(matched, false, 1_000, now)
	if got := engine.authorize(matched, true, 1_000, now); got != policyRateExceeded {
		t.Fatalf("immediate second uplink decision = %d", got)
	}
	if got := engine.authorize(matched, true, 1_000, now.Add(110*time.Millisecond)); got != policyAllow {
		t.Fatalf("refilled uplink decision = %d", got)
	}
	counters := engine.counters()
	if counters.QERRateDrops != 1 || counters.QERGateDrops != 0 || counters.URRMeteredPackets != 2 ||
		counters.URRMeteredBytes != 2_000 || counters.URRThresholdEvents != 1 || counters.URRActiveMeters != 1 {
		t.Fatalf("policy counters = %#v", counters)
	}
	usage := engine.usageSnapshot()
	if len(usage) != 1 || usage[0].UPSEID != 42 || usage[0].URRID != 7 || usage[0].UplinkBytes != 1_000 ||
		usage[0].DownlinkBytes != 1_000 || usage[0].ThresholdEvents != 1 {
		t.Fatalf("usage = %#v", usage)
	}
	engine.deleteSession(session.UPSEID)
	if engine.counters().URRActiveMeters != 0 || len(engine.usageSnapshot()) != 0 {
		t.Fatal("deleted session retained policy state")
	}
}

func TestPGWPolicyGateAndThresholdNeverActsAsQuota(t *testing.T) {
	engine := newPolicyEngine(100 * time.Millisecond)
	session := rules.Session{
		UPSEID: 9, Revision: 1, UplinkGateOpen: false, DownlinkGateOpen: true,
		URRID: 1, MeasureVolume: true, UsageReportingThreshold: 100,
	}
	engine.reconcileSession(session)
	matched := defaultPacketRule(session)
	now := time.Unix(200, 0)
	if got := engine.authorize(matched, true, 200, now); got != policyGateClosed {
		t.Fatalf("closed gate decision = %d", got)
	}
	for index := 0; index < 3; index++ {
		if got := engine.authorize(matched, false, 200, now); got != policyAllow {
			t.Fatalf("threshold incorrectly gated packet %d: %d", index, got)
		}
		engine.recordUsage(matched, false, 200, now)
	}
	counters := engine.counters()
	if counters.QERGateDrops != 1 || counters.URRThresholdEvents != 6 || counters.URRMeteredPackets != 3 {
		t.Fatalf("policy counters = %#v", counters)
	}
}

func TestPGWPolicySeparatesBearerQERsAndReconcilesMeters(t *testing.T) {
	engine := newPolicyEngine(100 * time.Millisecond)
	session := rules.Session{
		UPSEID: 77, Revision: 1, UplinkGateOpen: true, DownlinkGateOpen: true,
		MaxUplinkBitsPerSecond: 80_000, QERID: 10, URRID: 20, MeasureVolume: true,
		DedicatedBearers: []rules.Bearer{{
			UplinkGateOpen: true, DownlinkGateOpen: true, MaxUplinkBitsPerSecond: 80_000,
			QERID: 11, URRID: 21, MeasureVolume: true, QCI: 1, ARP: 2,
		}},
	}
	engine.reconcileSession(session)
	defaultRule := defaultPacketRule(session)
	dedicatedRule := rules.PacketRule{
		UPSEID: session.UPSEID, Revision: session.Revision,
		UplinkGateOpen: true, DownlinkGateOpen: true, MaxUplinkBitsPerSecond: 80_000,
		QERID: 11, URRID: 21, MeasureVolume: true, QCI: 1, ARP: 2,
	}
	now := time.Unix(300, 0)
	if got := engine.authorize(defaultRule, true, 1_000, now); got != policyAllow {
		t.Fatalf("default bearer decision = %d", got)
	}
	if got := engine.authorize(dedicatedRule, true, 1_000, now); got != policyAllow {
		t.Fatalf("dedicated bearer shared the default QER bucket: %d", got)
	}
	engine.recordUsage(defaultRule, true, 1_000, now)
	engine.recordUsage(dedicatedRule, true, 500, now)
	usage := engine.usageSnapshot()
	if len(usage) != 2 || usage[1].QERID != 11 || usage[1].URRID != 21 || usage[1].QCI != 1 || usage[1].UplinkBytes != 500 {
		t.Fatalf("per-bearer usage = %#v", usage)
	}

	session.Revision = 2
	session.DedicatedBearers = nil
	engine.reconcileSession(session)
	engine.recordUsage(dedicatedRule, true, 500, now)
	if counters := engine.counters(); counters.URRActiveMeters != 1 {
		t.Fatalf("active meters after bearer removal = %d", counters.URRActiveMeters)
	}
	if usage := engine.usageSnapshot(); len(usage) != 1 || !usage[0].DefaultBearer {
		t.Fatalf("removed bearer usage remained: %#v", usage)
	}
}

func defaultPacketRule(session rules.Session) rules.PacketRule {
	return rules.PacketRule{
		UPSEID: session.UPSEID, Revision: session.Revision,
		UplinkGateOpen: session.UplinkGateOpen, DownlinkGateOpen: session.DownlinkGateOpen,
		MaxUplinkBitsPerSecond:   session.MaxUplinkBitsPerSecond,
		MaxDownlinkBitsPerSecond: session.MaxDownlinkBitsPerSecond,
		QERID:                    session.QERID, URRID: session.URRID, MeasureVolume: session.MeasureVolume,
		MeasureDuration: session.MeasureDuration, UsageReportingThreshold: session.UsageReportingThreshold,
		Default: true,
	}
}
