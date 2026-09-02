package pfcpserver

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	pfcpassociation "github.com/lodestarnetworks/cups/internal/pfcp/association"
	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	sgwclient "github.com/lodestarnetworks/cups/internal/sgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
)

func TestGracePreservesSGWRulesBlocksNewBearersAndReconcilesAtomically(t *testing.T) {
	transport := pfcptransport.DefaultConfig()
	transport.RetransmitTimeout = 50 * time.Millisecond
	transport.MaxRetransmits = 1
	store := rules.NewStoreWithLimit(10)
	server, err := New(Config{
		Listen: netip.MustParseAddrPort("127.0.0.1:0"), Advertise: netip.MustParseAddr("127.0.0.1"),
		AccessUserIP: netip.MustParseAddr("127.10.0.1"), CoreUserIP: netip.MustParseAddr("127.20.0.1"),
		AllowedCP: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, StartedAt: time.Now().UTC(),
		AssociationTimeout: 20 * time.Millisecond, GraceWindow: 60 * time.Millisecond, Transport: transport,
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	client, err := sgwclient.New(sgwclient.Config{
		Listen: netip.MustParseAddrPort("127.0.0.1:0"), Advertise: netip.MustParseAddr("127.0.0.1"),
		Remote: server.LocalAddr(), StartedAt: time.Now().UTC(), Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = client.Close(); _ = server.Close() })
	go func() { _ = server.Serve(ctx) }()
	go func() { _ = client.Serve(ctx) }()
	operation, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	if err := client.Associate(operation); err != nil {
		t.Fatal(err)
	}
	plan := graceTestPlan(1000)
	first, err := client.Establish(operation, plan)
	if err != nil {
		t.Fatal(err)
	}
	stalePlan := graceTestPlan(2000)
	if _, err := client.Establish(operation, stalePlan); err != nil {
		t.Fatal(err)
	}

	time.Sleep(30 * time.Millisecond)
	server.sweepAssociations()
	peer := netip.MustParseAddr("127.0.0.1")
	if state := server.AssociationState(peer); state != pfcpassociation.StateGrace || len(store.Snapshot()) != 2 {
		t.Fatalf("grace state=%s sessions=%d", state, len(store.Snapshot()))
	}
	if _, _, ok := store.Lookup(rules.SourceAccess, plan.AccessLocal.TEID); !ok {
		t.Fatal("default bearer stopped forwarding during grace")
	}
	if _, _, ok := store.Lookup(rules.SourceAccess, plan.AdditionalBearers[0].AccessLocal.TEID); !ok {
		t.Fatal("dedicated bearer stopped forwarding during grace")
	}
	blocked := graceTestPlan(3000)
	if _, err := client.Establish(operation, blocked); !errors.Is(err, sgwclient.ErrRejected) {
		t.Fatalf("new session during grace error = %v", err)
	}

	if err := client.Associate(operation); err != nil {
		t.Fatal(err)
	}
	if state := server.AssociationState(peer); state != pfcpassociation.StateReconciling {
		t.Fatalf("state after reconnect = %s", state)
	}
	plan.CoreRemote.TEID++
	plan.AdditionalBearers[0].CoreRemote.TEID++
	replayed, err := client.Establish(operation, plan)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.UPSEID != first.UPSEID {
		t.Fatalf("UP-SEID changed during in-place replay: %d -> %d", first.UPSEID, replayed.UPSEID)
	}
	if err := client.CompleteReconciliation(operation); err != nil {
		t.Fatal(err)
	}
	if len(store.Snapshot()) != 1 || server.AssociationState(peer) != pfcpassociation.StateAssociated {
		t.Fatalf("post-reconcile state=%s sessions=%d", server.AssociationState(peer), len(store.Snapshot()))
	}
	_, defaultFAR, ok := store.Lookup(rules.SourceAccess, plan.AccessLocal.TEID)
	if !ok || defaultFAR.OuterHeader == nil || defaultFAR.OuterHeader.TEID != plan.CoreRemote.TEID {
		t.Fatalf("default replay was not committed atomically: %#v", defaultFAR)
	}
	_, dedicatedFAR, ok := store.Lookup(rules.SourceAccess, plan.AdditionalBearers[0].AccessLocal.TEID)
	if !ok || dedicatedFAR.OuterHeader == nil || dedicatedFAR.OuterHeader.TEID != plan.AdditionalBearers[0].CoreRemote.TEID {
		t.Fatalf("dedicated replay was not committed atomically: %#v", dedicatedFAR)
	}

	time.Sleep(30 * time.Millisecond)
	server.sweepAssociations()
	if len(store.Snapshot()) != 1 {
		t.Fatal("session was removed at grace entry")
	}
	time.Sleep(70 * time.Millisecond)
	server.sweepAssociations()
	if state := server.AssociationState(peer); state != pfcpassociation.StateUnavailable || len(store.Snapshot()) != 0 {
		t.Fatalf("expiry state=%s sessions=%d", state, len(store.Snapshot()))
	}
	counters := server.Counters()
	if counters.GraceEntries != 2 || counters.GraceExpirations != 1 || counters.Reconciliations != 1 || counters.StaleSessionsPurged != 2 {
		t.Fatalf("grace counters = %#v", counters)
	}
}

func graceTestPlan(seed uint32) sgwclient.Establishment {
	accessRemote := sgwclient.Tunnel{TEID: seed + 5, IP: netip.MustParseAddr("127.10.0.2")}
	dedicatedRemote := sgwclient.Tunnel{TEID: seed + 15, IP: netip.MustParseAddr("127.10.0.2")}
	return sgwclient.Establishment{
		CPSEID:       uint64(seed) + 1,
		AccessLocal:  sgwclient.Tunnel{TEID: seed + 2, IP: netip.MustParseAddr("127.10.0.1")},
		CoreLocal:    sgwclient.Tunnel{TEID: seed + 3, IP: netip.MustParseAddr("127.20.0.1")},
		CoreRemote:   sgwclient.Tunnel{TEID: seed + 4, IP: netip.MustParseAddr("127.20.0.2")},
		AccessRemote: &accessRemote, UplinkBitrate: 10_000_000, DownlinkBitrate: 20_000_000,
		QCI: 9, ARP: 8,
		AdditionalBearers: []sgwclient.BearerPlan{{
			Rules:        sgwclient.RuleIDs{UplinkPDR: 3, DownlinkPDR: 4, UplinkFAR: 3, DownlinkFAR: 4, QER: 2, URR: 2},
			AccessLocal:  sgwclient.Tunnel{TEID: seed + 12, IP: netip.MustParseAddr("127.10.0.1")},
			CoreLocal:    sgwclient.Tunnel{TEID: seed + 13, IP: netip.MustParseAddr("127.20.0.1")},
			CoreRemote:   sgwclient.Tunnel{TEID: seed + 14, IP: netip.MustParseAddr("127.20.0.2")},
			AccessRemote: &dedicatedRemote, UplinkBitrate: 2_000_000, DownlinkBitrate: 3_000_000,
			QCI: 1, ARP: 2,
		}},
	}
}
