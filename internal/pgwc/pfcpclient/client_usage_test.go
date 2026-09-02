package pfcpclient_test

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	"github.com/lodestarnetworks/cups/internal/pfcp/usagereport"
	"github.com/lodestarnetworks/cups/internal/pgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/pgwu/pfcpserver"
	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
)

func TestPGWUUsageReportDeliveredAndDurablyReconciled(t *testing.T) {
	const enterpriseID uint16 = 65000
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := pfcptransport.DefaultConfig()
	transport.RetransmitTimeout = 100 * time.Millisecond
	transport.MaxRetransmits = 1
	pgwcAddress := netip.MustParseAddr("127.126.0.1")
	pgwuAddress := netip.MustParseAddr("127.126.0.2")
	store := rules.NewStoreWithLimit(100)
	server, err := pfcpserver.New(pfcpserver.Config{
		Listen: netip.AddrPortFrom(pgwuAddress, 0), Advertise: pgwuAddress,
		UserIP: netip.MustParseAddr("10.200.0.21"), AllowedCP: []netip.Addr{pgwcAddress},
		StartedAt: time.Unix(1_700_001_000, 0), EnterpriseID: enterpriseID, Transport: transport,
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
	go func() {
		if err := server.Serve(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("serve PGW-U: %v", err)
		}
	}()

	client, err := pfcpclient.New(pfcpclient.Config{
		Listen: netip.AddrPortFrom(pgwcAddress, 0), Advertise: pgwcAddress,
		Remote: server.LocalAddr(), StartedAt: time.Unix(1_700_001_100, 0),
		EnterpriseID: enterpriseID, Transport: transport,
		UsageLedger: usagereport.LedgerConfig{
			Path: filepath.Join(t.TempDir(), "pgwc-usage.wal"), Identity: []byte("pgwc-usage-e2e-v1"), MaxBytes: 1 << 20,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	go func() {
		if err := client.Serve(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("serve PGW-C: %v", err)
		}
	}()

	operation, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	if err := client.Associate(operation); err != nil {
		t.Fatalf("associate: %v", err)
	}
	current, err := client.Establish(operation, pfcpclient.Establishment{
		CPSEID: 0x1001, UEIPv4: netip.MustParseAddr("10.90.0.2"),
		Local:         pfcpclient.Tunnel{TEID: 0x2101, IP: netip.MustParseAddr("10.200.0.21")},
		Remote:        pfcpclient.Tunnel{TEID: 0x3101, IP: netip.MustParseAddr("10.200.0.11")},
		UplinkBitrate: 100_000_000, DownlinkBitrate: 200_000_000, QCI: 9, ARP: 8,
	})
	if err != nil {
		t.Fatalf("establish: %v", err)
	}
	if current.UPSEID == 0 || current.DefaultRules.URR == 0 || store.Count() != 1 {
		t.Fatalf("invalid established PFCP session: %#v", current)
	}

	measurementAt := time.Now().UTC()
	usageMu.Lock()
	usage = []usagereport.Measurement{{
		UPSEID: current.UPSEID, URRID: current.DefaultRules.URR,
		UplinkPackets: 31, DownlinkPackets: 29,
		UplinkBytes: 31_000, DownlinkBytes: 29_000,
		ThresholdEvents: 1, FirstPacket: measurementAt.Add(-2 * time.Second), LastPacket: measurementAt,
	}}
	usageMu.Unlock()

	deadline := time.Now().Add(3 * time.Second)
	for client.UsageLedgerStats().ReportsAccepted != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	stats := client.UsageLedgerStats()
	if !stats.Durable || stats.ReportsAccepted != 1 || stats.ActiveCheckpoints != 1 ||
		stats.UplinkPackets != 31 || stats.DownlinkPackets != 29 || stats.UplinkBytes != 31_000 || stats.DownlinkBytes != 29_000 || stats.WALRecords == 0 {
		t.Fatalf("unexpected PGW-C usage ledger: %#v", stats)
	}
	deliveryDeadline := time.Now().Add(3 * time.Second)
	counters := server.Counters()
	for (counters.UsageReportsSent != 1 || counters.UsageReportsPending != 0) && time.Now().Before(deliveryDeadline) {
		time.Sleep(10 * time.Millisecond)
		counters = server.Counters()
	}
	if counters.UsageReportsGenerated != 1 || counters.UsageReportsSent != 1 || counters.UsageReportsPending != 0 {
		t.Fatalf("unexpected PGW-U report counters: %#v", counters)
	}

	if err := client.Delete(operation, current); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := client.Delete(operation, current); err != nil {
		t.Fatalf("idempotent delete after Session Not Found: %v", err)
	}
	if store.Count() != 0 || client.UsageLedgerStats().ActiveCheckpoints != 0 || client.UsageLedgerRemoveFailures() != 0 {
		t.Fatalf("session deletion leaked state: store=%d ledger=%#v remove_failures=%d", store.Count(), client.UsageLedgerStats(), client.UsageLedgerRemoveFailures())
	}
}
