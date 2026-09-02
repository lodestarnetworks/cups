package pfcpclient_test

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	"github.com/lodestarnetworks/cups/internal/pfcp/usagereport"
	"github.com/lodestarnetworks/cups/internal/sgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/sgwu/pfcpserver"
	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
)

func TestAssociationSessionLifecycleOverUDP(t *testing.T) {
	const testEnterpriseID uint16 = 65000
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := rules.NewStore()
	server, err := pfcpserver.New(pfcpserver.Config{
		Listen:       netip.MustParseAddrPort("127.0.0.1:0"),
		Advertise:    netip.MustParseAddr("127.0.0.1"),
		AccessUserIP: netip.MustParseAddr("127.10.0.1"),
		CoreUserIP:   netip.MustParseAddr("127.20.0.1"),
		AllowedCP:    []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		StartedAt:    time.Unix(1_700_000_000, 0),
		EnterpriseID: testEnterpriseID,
		Transport:    testTransportConfig(),
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	var usageMu sync.RWMutex
	var usage []usagereport.Measurement
	if err := server.SetUsageSource(func() []usagereport.Measurement {
		usageMu.RLock()
		defer usageMu.RUnlock()
		return append([]usagereport.Measurement(nil), usage...)
	}); err != nil {
		t.Fatalf("set usage source: %v", err)
	}
	serve(t, ctx, server.Serve)

	client, err := pfcpclient.New(pfcpclient.Config{
		Listen:       netip.MustParseAddrPort("127.0.0.1:0"),
		Advertise:    netip.MustParseAddr("127.0.0.1"),
		Remote:       server.LocalAddr(),
		StartedAt:    time.Unix(1_700_000_100, 0),
		EnterpriseID: testEnterpriseID,
		Transport:    testTransportConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	serve(t, ctx, client.Serve)

	opCtx, opCancel := context.WithTimeout(ctx, 3*time.Second)
	defer opCancel()
	if err := client.Associate(opCtx); err != nil {
		t.Fatalf("associate: %v", err)
	}
	if _, ok := client.Association(); !ok {
		t.Fatal("association was not recorded")
	}
	if err := client.Heartbeat(opCtx); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	client.MarkUnavailable()
	if err := client.Heartbeat(opCtx); !errors.Is(err, pfcpclient.ErrNotAssociated) {
		t.Fatalf("heartbeat without an association error = %v, want ErrNotAssociated", err)
	}
	if _, associated := client.Association(); associated {
		t.Fatal("heartbeat silently recreated a missing association")
	}
	if err := client.Associate(opCtx); err != nil {
		t.Fatalf("reassociate after local unavailable state: %v", err)
	}

	pfcpSession, err := client.Establish(opCtx, pfcpclient.Establishment{
		CPSEID:          0x1001,
		AccessLocal:     pfcpclient.Tunnel{TEID: 0x1101, IP: netip.MustParseAddr("127.10.0.1")},
		CoreLocal:       pfcpclient.Tunnel{TEID: 0x1201, IP: netip.MustParseAddr("127.20.0.1")},
		CoreRemote:      pfcpclient.Tunnel{TEID: 0x2201, IP: netip.MustParseAddr("127.20.0.2")},
		UplinkBitrate:   10_000_000,
		DownlinkBitrate: 20_000_000,
		QCI:             9, ARP: 8,
	})
	if err != nil {
		t.Fatalf("establish: %v", err)
	}
	if pfcpSession.UPSEID == 0 {
		t.Fatal("UP-SEID was not allocated")
	}

	_, uplinkFAR, ok := store.Lookup(rules.SourceAccess, 0x1101)
	if !ok || uplinkFAR.OuterHeader == nil || uplinkFAR.OuterHeader.TEID != 0x2201 || uplinkFAR.DestinationInterface != rules.DestinationCore {
		t.Fatalf("unexpected uplink FAR: %#v, found=%v", uplinkFAR, ok)
	}
	_, downlinkFAR, ok := store.Lookup(rules.SourceCore, 0x1201)
	if !ok || downlinkFAR.ApplyAction != rules.ActionBuffer|rules.ActionNotifyControlPlane || downlinkFAR.BARID != 9 || downlinkFAR.OuterHeader != nil {
		t.Fatalf("downlink should be gated pending Modify Bearer: %#v, found=%v", downlinkFAR, ok)
	}

	enodeb := pfcpclient.Tunnel{TEID: 0x3301, IP: netip.MustParseAddr("127.10.0.2")}
	if err := client.ActivateDownlink(opCtx, &pfcpSession, enodeb); err != nil {
		t.Fatalf("activate downlink: %v", err)
	}
	_, downlinkFAR, ok = store.Lookup(rules.SourceCore, 0x1201)
	if !ok || downlinkFAR.ApplyAction != rules.ActionForward || downlinkFAR.OuterHeader == nil || downlinkFAR.OuterHeader.TEID != enodeb.TEID || downlinkFAR.DestinationInterface != rules.DestinationAccess {
		t.Fatalf("unexpected active downlink FAR: %#v, found=%v", downlinkFAR, ok)
	}
	if err := client.DeactivateDownlink(opCtx, &pfcpSession); err != nil {
		t.Fatalf("deactivate downlink: %v", err)
	}
	_, downlinkFAR, ok = store.Lookup(rules.SourceCore, 0x1201)
	if !ok || downlinkFAR.ApplyAction != rules.ActionBuffer|rules.ActionNotifyControlPlane || downlinkFAR.OuterHeader == nil || downlinkFAR.OuterHeader.TEID != enodeb.TEID {
		t.Fatalf("unexpected inactive downlink FAR: %#v, found=%v", downlinkFAR, ok)
	}
	if !server.QueueDownlinkReport(pfcpSession.UPSEID, 2, 9, 8, 0) {
		t.Fatal("downlink report was not queued")
	}
	if server.QueueDownlinkReport(pfcpSession.UPSEID, 2, 9, 8, 0) {
		t.Fatal("duplicate downlink report was not suppressed")
	}
	select {
	case report := <-client.Reports():
		if report.CPSEID != pfcpSession.CPSEID || report.PDRID != 2 {
			t.Fatalf("unexpected downlink report: %#v", report)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for downlink report")
	}
	if err := client.ActivateDownlink(opCtx, &pfcpSession, enodeb); err != nil {
		t.Fatalf("reactivate downlink: %v", err)
	}

	dedicatedRules := pfcpclient.RuleIDs{
		UplinkPDR: 3, DownlinkPDR: 4, UplinkFAR: 3, DownlinkFAR: 4, QER: 2, URR: 2,
	}
	dedicatedPlan := pfcpclient.BearerPlan{
		Rules:           dedicatedRules,
		AccessLocal:     pfcpclient.Tunnel{TEID: 0x1102, IP: netip.MustParseAddr("127.10.0.1")},
		CoreLocal:       pfcpclient.Tunnel{TEID: 0x1202, IP: netip.MustParseAddr("127.20.0.1")},
		CoreRemote:      pfcpclient.Tunnel{TEID: 0x2202, IP: netip.MustParseAddr("127.20.0.2")},
		UplinkBitrate:   2_000_000,
		DownlinkBitrate: 3_000_000,
		QCI:             1, ARP: 2,
	}
	if err := client.AddBearer(opCtx, &pfcpSession, dedicatedPlan); err != nil {
		t.Fatalf("add dedicated bearer: %v", err)
	}
	_, dedicatedUplinkFAR, ok := store.Lookup(rules.SourceAccess, dedicatedPlan.AccessLocal.TEID)
	if !ok || dedicatedUplinkFAR.OuterHeader == nil || dedicatedUplinkFAR.OuterHeader.TEID != dedicatedPlan.CoreRemote.TEID {
		t.Fatalf("unexpected dedicated uplink FAR: %#v, found=%v", dedicatedUplinkFAR, ok)
	}
	_, dedicatedDownlinkFAR, ok := store.Lookup(rules.SourceCore, dedicatedPlan.CoreLocal.TEID)
	if !ok || dedicatedDownlinkFAR.ApplyAction != rules.ActionDrop {
		t.Fatalf("dedicated downlink should be closed before MME acceptance: %#v, found=%v", dedicatedDownlinkFAR, ok)
	}
	dedicatedENodeB := pfcpclient.Tunnel{TEID: 0x3302, IP: netip.MustParseAddr("127.10.0.2")}
	if err := client.ActivateBearer(opCtx, &pfcpSession, dedicatedRules, dedicatedENodeB); err != nil {
		t.Fatalf("activate dedicated bearer: %v", err)
	}
	_, dedicatedDownlinkFAR, ok = store.Lookup(rules.SourceCore, dedicatedPlan.CoreLocal.TEID)
	if !ok || dedicatedDownlinkFAR.ApplyAction != rules.ActionForward || dedicatedDownlinkFAR.OuterHeader == nil || dedicatedDownlinkFAR.OuterHeader.TEID != dedicatedENodeB.TEID {
		t.Fatalf("unexpected active dedicated downlink FAR: %#v, found=%v", dedicatedDownlinkFAR, ok)
	}
	if err := client.UpdateBearerQoS(opCtx, &pfcpSession, dedicatedRules, 1, 2, true, false, 4_000_000, 5_000_000); err != nil {
		t.Fatalf("update dedicated QER: %v", err)
	}
	snapshot := store.Snapshot()
	if len(snapshot) != 1 || len(snapshot[0].URRs) != 2 || !snapshot[0].URRs[1].MeasureVolume || !snapshot[0].URRs[2].MeasureDuration || snapshot[0].URRs[1].ReportingThreshold != 1<<30 || len(snapshot[0].PDRs[1].URRIDs) != 1 {
		t.Fatalf("telemetry URRs were not installed: %#v", snapshot)
	}
	if len(snapshot) != 1 || snapshot[0].QERs[dedicatedRules.QER].MaxUplinkBitsPerSecond != 4_000_000 || snapshot[0].QERs[dedicatedRules.QER].MaxDownlinkBitsPerSecond != 5_000_000 || snapshot[0].QERs[dedicatedRules.QER].QCI != 1 || snapshot[0].QERs[dedicatedRules.QER].ARP != 2 || !snapshot[0].QERs[dedicatedRules.QER].PreemptionCapable {
		t.Fatalf("dedicated QER was not updated: %#v", snapshot)
	}
	measurementAt := time.Now().UTC()
	usageMu.Lock()
	usage = []usagereport.Measurement{{
		UPSEID: pfcpSession.UPSEID, URRID: 1,
		UplinkPackets: 11, DownlinkPackets: 7,
		UplinkBytes: 11_000, DownlinkBytes: 7_000,
		ThresholdEvents: 1, FirstPacket: measurementAt.Add(-time.Second), LastPacket: measurementAt,
	}}
	usageMu.Unlock()
	usageDeadline := time.Now().Add(3 * time.Second)
	for client.UsageLedgerStats().ReportsAccepted != 1 && time.Now().Before(usageDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	usageStats := client.UsageLedgerStats()
	if usageStats.ReportsAccepted != 1 || usageStats.UplinkPackets != 11 || usageStats.DownlinkPackets != 7 || usageStats.UplinkBytes != 11_000 || usageStats.DownlinkBytes != 7_000 || usageStats.ActiveCheckpoints != 1 {
		t.Fatalf("unexpected accepted usage telemetry: %#v", usageStats)
	}
	deliveryDeadline := time.Now().Add(3 * time.Second)
	usageCounters := server.Counters()
	for (usageCounters.UsageReportsSent != 1 || usageCounters.UsageReportsPending != 0) && time.Now().Before(deliveryDeadline) {
		time.Sleep(10 * time.Millisecond)
		usageCounters = server.Counters()
	}
	if usageCounters.UsageReportsGenerated != 1 || usageCounters.UsageReportsSent != 1 || usageCounters.UsageReportsPending != 0 {
		t.Fatalf("unexpected usage-report delivery counters: %#v", usageCounters)
	}
	if err := client.RemoveBearer(opCtx, &pfcpSession, dedicatedRules); err != nil {
		t.Fatalf("remove dedicated bearer: %v", err)
	}
	if _, _, ok := store.Lookup(rules.SourceAccess, dedicatedPlan.AccessLocal.TEID); ok {
		t.Fatal("dedicated uplink PDR survived removal")
	}
	if _, _, ok := store.Lookup(rules.SourceCore, dedicatedPlan.CoreLocal.TEID); ok {
		t.Fatal("dedicated downlink PDR survived removal")
	}

	if err := client.Delete(opCtx, pfcpSession); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := client.Delete(opCtx, pfcpSession); err != nil {
		t.Fatalf("idempotent delete after Session Not Found: %v", err)
	}
	if _, ok := store.FindByUPSEID(pfcpSession.UPSEID); ok {
		t.Fatal("PFCP session survived deletion")
	}
	if client.UsageLedgerStats().ActiveCheckpoints != 0 {
		t.Fatal("usage-report checkpoint survived PFCP session deletion")
	}

	counters := server.Counters()
	if counters.AssociationsEstablished != 2 || counters.SessionsEstablished != 1 || counters.SessionsModified != 7 || counters.SessionsDeleted != 1 || counters.RejectedRequests != 1 {
		t.Fatalf("unexpected server counters: %#v", counters)
	}
	deadline := time.Now().Add(time.Second)
	for counters.DownlinkReportsSent != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		counters = server.Counters()
	}
	if counters.DownlinkReportsQueued != 1 || counters.DownlinkReportsSent != 1 || counters.DownlinkReportsSuppressed != 1 || counters.DownlinkReportsFailed != 0 {
		t.Fatalf("unexpected downlink report counters: %#v", counters)
	}
}

func testTransportConfig() pfcptransport.Config {
	config := pfcptransport.DefaultConfig()
	config.RetransmitTimeout = 100 * time.Millisecond
	config.MaxRetransmits = 1
	return config
}

func serve(t *testing.T, ctx context.Context, fn func(context.Context) error) {
	t.Helper()
	go func() {
		if err := fn(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("serve: %v", err)
		}
	}()
}
