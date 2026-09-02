package pfcpserver

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pfcpassociation "github.com/lodestarnetworks/cups/internal/pfcp/association"
	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	pgwclient "github.com/lodestarnetworks/cups/internal/pgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
	"github.com/lodestarnetworks/cups/pkg/pfcp"
)

func TestClientServerSessionLifecycle(t *testing.T) {
	transport := pfcptransport.DefaultConfig()
	transport.RetransmitTimeout = 50 * time.Millisecond
	transport.MaxRetransmits = 1
	store := rules.NewStoreWithLimit(10)
	server, err := New(Config{
		Listen: netip.MustParseAddrPort("127.0.0.1:0"), Advertise: netip.MustParseAddr("127.0.0.1"),
		UserIP: netip.MustParseAddr("10.200.0.20"), AllowedCP: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		StartedAt: time.Now().UTC(), Transport: transport,
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	client, err := pgwclient.New(pgwclient.Config{
		Listen: netip.MustParseAddrPort("127.0.0.1:0"), Advertise: netip.MustParseAddr("127.0.0.1"),
		Remote: server.LocalAddr(), StartedAt: time.Now().UTC(), Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer server.Close()
	defer client.Close()
	go func() { _ = server.Serve(ctx) }()
	go func() { _ = client.Serve(ctx) }()

	operation, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	if err := client.Associate(operation); err != nil {
		t.Fatal(err)
	}
	if err := client.Heartbeat(operation); err != nil {
		t.Fatal(err)
	}
	client.MarkUnavailable()
	if err := client.Heartbeat(operation); !errors.Is(err, pgwclient.ErrNotAssociated) {
		t.Fatalf("heartbeat without an association error = %v, want ErrNotAssociated", err)
	}
	if _, associated := client.Association(); associated {
		t.Fatal("heartbeat silently recreated a missing association")
	}
	if err := client.Associate(operation); err != nil {
		t.Fatalf("reassociate after local unavailable state: %v", err)
	}
	session, err := client.Establish(operation, pgwclient.Establishment{
		CPSEID: 1001, UEIPv4: netip.MustParseAddr("10.90.0.2"),
		Local:         pgwclient.Tunnel{TEID: 2001, IP: netip.MustParseAddr("10.200.0.20")},
		Remote:        pgwclient.Tunnel{TEID: 3001, IP: netip.MustParseAddr("10.200.0.10")},
		UplinkBitrate: 1_000_000_000, DownlinkBitrate: 2_000_000_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	stored, ok := store.FindByCPSEID(session.CPSEID)
	if !ok || stored.UEIPv4.String() != "10.90.0.2" || stored.Remote.TEID != 3001 || stored.MaxDownlinkBitsPerSecond != 2_000_000_000 ||
		stored.QERID != 1 || stored.URRID != 1 || !stored.MeasureVolume || !stored.MeasureDuration || stored.UsageReportingThreshold != 1<<30 {
		t.Fatalf("unexpected stored rules: %#v", stored)
	}
	if err := client.UpdateRemote(operation, &session, pgwclient.Tunnel{TEID: 3002, IP: netip.MustParseAddr("10.200.0.11")}); err != nil {
		t.Fatal(err)
	}
	stored, _ = store.FindByCPSEID(session.CPSEID)
	if stored.Remote.TEID != 3002 || stored.Remote.IP.String() != "10.200.0.11" {
		t.Fatalf("remote tunnel was not updated: %#v", stored.Remote)
	}
	if err := client.Delete(operation, session); err != nil {
		t.Fatal(err)
	}
	if store.Count() != 0 {
		t.Fatalf("rules remain after delete: %d", store.Count())
	}
	counters := server.Counters()
	if counters.SessionsEstablished != 1 || counters.SessionsModified != 1 || counters.SessionsDeleted != 1 {
		t.Fatalf("unexpected counters: %#v", counters)
	}
}

func TestErrorCallbackPanicIsIsolated(t *testing.T) {
	server := &Server{config: Config{OnError: func(ErrorEvent) { panic("observer failure") }}}
	server.emitError(ErrorEvent{Procedure: "test", Err: errors.New("rejected")})
}

func TestClientServerDedicatedBearerLifecycle(t *testing.T) {
	const enterpriseID uint16 = 65000
	var reported []ErrorEvent
	transport := pfcptransport.DefaultConfig()
	transport.RetransmitTimeout = 50 * time.Millisecond
	transport.MaxRetransmits = 1
	store := rules.NewStoreWithLimit(10)
	server, err := New(Config{
		Listen: netip.MustParseAddrPort("127.0.0.1:0"), Advertise: netip.MustParseAddr("127.0.0.1"),
		UserIP: netip.MustParseAddr("10.200.0.20"), AllowedCP: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		StartedAt: time.Now().UTC(), EnterpriseID: enterpriseID, Transport: transport,
		OnError: func(event ErrorEvent) { reported = append(reported, event) },
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	client, err := pgwclient.New(pgwclient.Config{
		Listen: netip.MustParseAddrPort("127.0.0.1:0"), Advertise: netip.MustParseAddr("127.0.0.1"),
		Remote: server.LocalAddr(), StartedAt: time.Now().UTC(), EnterpriseID: enterpriseID, Transport: transport,
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
	ue := netip.MustParseAddr("10.90.0.22")
	session, err := client.Establish(operation, pgwclient.Establishment{
		CPSEID: 2201, UEIPv4: ue,
		Local:         pgwclient.Tunnel{TEID: 2202, IP: netip.MustParseAddr("10.200.0.20")},
		Remote:        pgwclient.Tunnel{TEID: 2203, IP: netip.MustParseAddr("10.200.0.10")},
		UplinkBitrate: 1_000_000_000, DownlinkBitrate: 1_000_000_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := pgwclient.RuleIDs{
		UplinkPDRs: []uint16{21}, DownlinkPDRs: []uint16{22},
		UplinkFAR: 11, DownlinkFAR: 12, QER: 2, URR: 2,
	}
	plan := pgwclient.BearerPlan{
		Rules:         ids,
		Local:         pgwclient.Tunnel{TEID: 2212, IP: netip.MustParseAddr("10.200.0.20")},
		Remote:        pgwclient.Tunnel{TEID: 2213, IP: netip.MustParseAddr("10.200.0.10")},
		UplinkBitrate: 128_000, DownlinkBitrate: 256_000, QCI: 1, ARP: 2,
		TFT: gtpv2.TrafficFlowTemplate{
			Operation: gtpv2.TFTOperationCreate,
			Filters: []gtpv2.PacketFilter{{
				ID: 1, Direction: gtpv2.TFTDirectionBidirectional, Precedence: 10,
				Components: []gtpv2.PacketFilterComponent{
					{Type: gtpv2.TFTComponentProtocol, Value: []byte{17}},
					{Type: gtpv2.TFTComponentSingleLocalPort, Value: []byte{0x13, 0xc4}},
					{Type: gtpv2.TFTComponentSingleRemotePort, Value: []byte{0x13, 0xc5}},
				},
			}},
		},
	}
	if err := client.AddBearer(operation, &session, plan); err != nil {
		t.Fatal(err)
	}
	stored, ok := store.FindByCPSEID(session.CPSEID)
	if !ok || len(stored.DedicatedBearers) != 1 {
		t.Fatalf("dedicated bearer was not installed: %#v", stored)
	}
	bearer := stored.DedicatedBearers[0]
	if bearer.Local.TEID != 2212 || bearer.Remote.TEID != 2213 || bearer.QERID != 2 || bearer.URRID != 2 ||
		bearer.QCI != 1 || bearer.ARP != 2 || bearer.MaxUplinkBitsPerSecond != 128_000 || bearer.MaxDownlinkBitsPerSecond != 256_000 || len(bearer.Filters) != 2 {
		t.Fatalf("unexpected dedicated bearer: %#v", bearer)
	}
	uplinkVoice := testTransportPacket(ue, true, 5060, 5061)
	if rule, ok := store.LookupUplinkPacket(2212, uplinkVoice); !ok || rule.Default || rule.QERID != 2 {
		t.Fatalf("uplink voice rule = %#v, %v", rule, ok)
	}
	downlinkVoice := testTransportPacket(ue, false, 5060, 5061)
	if rule, ok := store.LookupDownlinkPacket(ue, downlinkVoice); !ok || rule.Default || rule.Remote.TEID != 2213 {
		t.Fatalf("downlink voice rule = %#v, %v", rule, ok)
	}
	downlinkBulk := testTransportPacket(ue, false, 443, 443)
	if rule, ok := store.LookupDownlinkPacket(ue, downlinkBulk); !ok || !rule.Default || rule.Remote.TEID != 2203 {
		t.Fatalf("downlink default rule = %#v, %v", rule, ok)
	}

	// A malformed partial removal must reject without changing the committed
	// generation or leaving a half-installed bearer.
	beforeRevision := stored.Revision
	pdrID, _ := pfcp.NewPDRIDIE(ids.UplinkPDRs[0])
	removePDR, _ := pfcp.NewGroupedIE(pfcp.IERemovePDR, pdrID)
	rejected := server.sessionModification(client.LocalAddr(), pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, HasSEID: true, MessageType: pfcp.MessageSessionModificationRequest, SEID: session.UPSEID},
		IEs:    []pfcp.IE{removePDR},
	})
	causeIE, ok := rejected.Find(pfcp.IECause)
	if !ok {
		t.Fatal("partial-removal response has no Cause IE")
	}
	cause, err := causeIE.Cause()
	if err != nil || cause != pfcp.CauseRuleCreationFailure {
		t.Fatalf("partial-removal cause = %d, %v", cause, err)
	}
	if len(reported) != 1 || reported[0].Procedure != "session_modification" || reported[0].Peer != client.LocalAddr() || reported[0].Err == nil ||
		!strings.Contains(reported[0].Err.Error(), "removal is incomplete") {
		t.Fatalf("unexpected internal rejection event: %#v", reported)
	}
	stored, _ = store.FindByCPSEID(session.CPSEID)
	if stored.Revision != beforeRevision || len(stored.DedicatedBearers) != 1 || len(stored.DedicatedBearers[0].Filters) != 2 {
		t.Fatalf("partial removal mutated committed state: %#v", stored)
	}

	if err := client.UpdateBearerQoS(operation, &session, ids, 2, 3, 512_000, 768_000); err != nil {
		t.Fatal(err)
	}
	updatedRemote := pgwclient.Tunnel{TEID: 2223, IP: netip.MustParseAddr("10.200.0.11")}
	if err := client.UpdateBearerRemote(operation, &session, ids, updatedRemote); err != nil {
		t.Fatal(err)
	}
	stored, _ = store.FindByCPSEID(session.CPSEID)
	bearer = stored.DedicatedBearers[0]
	if bearer.QCI != 2 || bearer.ARP != 3 || bearer.MaxUplinkBitsPerSecond != 512_000 || bearer.MaxDownlinkBitsPerSecond != 768_000 ||
		bearer.Remote.TEID != 2223 || bearer.Remote.IP.String() != "10.200.0.11" {
		t.Fatalf("dedicated bearer update did not commit: %#v", bearer)
	}
	if err := client.RemoveBearer(operation, &session, ids); err != nil {
		t.Fatal(err)
	}
	stored, _ = store.FindByCPSEID(session.CPSEID)
	if len(stored.DedicatedBearers) != 0 || len(session.Bearers) != 0 {
		t.Fatalf("dedicated bearer remains after removal: %#v / %#v", stored.DedicatedBearers, session.Bearers)
	}
	if _, ok := store.LookupUplinkPacket(2212, uplinkVoice); ok {
		t.Fatal("removed dedicated-bearer TEID remains indexed")
	}
	if rule, ok := store.LookupDownlinkPacket(ue, downlinkVoice); !ok || !rule.Default || rule.Remote.TEID != 2203 {
		t.Fatalf("voice did not fall back to default bearer after removal: %#v, %v", rule, ok)
	}
	if err := client.Delete(operation, session); err != nil {
		t.Fatal(err)
	}
	counters := server.Counters()
	if counters.SessionsEstablished != 1 || counters.SessionsModified != 4 || counters.SessionsDeleted != 1 || counters.RejectedRequests != 1 {
		t.Fatalf("unexpected dedicated-bearer lifecycle counters: %#v", counters)
	}
}

func TestDurableRestartReconcilesDedicatedBearer(t *testing.T) {
	const enterpriseID uint16 = 65000
	transport := pfcptransport.DefaultConfig()
	transport.RetransmitTimeout = 50 * time.Millisecond
	transport.MaxRetransmits = 2
	walPath := filepath.Join(t.TempDir(), "pgwu-restart.wal")
	wal, recovered, err := rules.OpenWAL(walPath, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	store := rules.NewStoreWithParticipants(10, nil, wal)
	if err := store.Restore(recovered); err != nil {
		t.Fatal(err)
	}
	cpAddress := netip.MustParseAddr("127.120.0.1")
	upAddress := netip.MustParseAddr("127.120.0.2")
	userAddress := netip.MustParseAddr("10.200.0.20")
	started := time.Now().UTC().Add(-10 * time.Second)
	server, err := New(Config{
		Listen: netip.AddrPortFrom(upAddress, 0), Advertise: upAddress, UserIP: userAddress,
		AllowedCP: []netip.Addr{cpAddress}, StartedAt: started, EnterpriseID: enterpriseID, Transport: transport,
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	serverAddress := server.LocalAddr()
	client, err := pgwclient.New(pgwclient.Config{
		Listen: netip.AddrPortFrom(cpAddress, 0), Advertise: cpAddress, Remote: serverAddress,
		StartedAt: started, EnterpriseID: enterpriseID, Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = client.Close()
		_ = server.Close()
		_ = wal.Close()
	})
	go func() { _ = server.Serve(ctx) }()
	go func() { _ = client.Serve(ctx) }()
	operation, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	if err := client.Associate(operation); err != nil {
		t.Fatal(err)
	}
	ue := netip.MustParseAddr("10.90.0.44")
	plan := pgwclient.Establishment{
		CPSEID: 4401, UEIPv4: ue,
		Local:         pgwclient.Tunnel{TEID: 4402, IP: userAddress},
		Remote:        pgwclient.Tunnel{TEID: 4403, IP: netip.MustParseAddr("10.200.0.10")},
		UplinkBitrate: 1_000_000_000, DownlinkBitrate: 1_000_000_000,
		AdditionalBearers: []pgwclient.BearerPlan{{
			Rules: pgwclient.RuleIDs{
				UplinkPDRs: []uint16{21}, DownlinkPDRs: []uint16{22},
				UplinkFAR: 11, DownlinkFAR: 12, QER: 2, URR: 2,
			},
			Local:         pgwclient.Tunnel{TEID: 4412, IP: userAddress},
			Remote:        pgwclient.Tunnel{TEID: 4413, IP: netip.MustParseAddr("10.200.0.10")},
			UplinkBitrate: 8_000_000, DownlinkBitrate: 12_000_000, QCI: 1, ARP: 2,
			TFT: gtpv2.TrafficFlowTemplate{
				Operation: gtpv2.TFTOperationCreate,
				Filters: []gtpv2.PacketFilter{{
					ID: 1, Direction: gtpv2.TFTDirectionBidirectional, Precedence: 10,
					Components: []gtpv2.PacketFilterComponent{
						{Type: gtpv2.TFTComponentProtocol, Value: []byte{17}},
						{Type: gtpv2.TFTComponentSingleLocalPort, Value: []byte{0x13, 0xc4}},
						{Type: gtpv2.TFTComponentSingleRemotePort, Value: []byte{0x13, 0xc5}},
					},
				}},
			},
		}},
	}
	first, err := client.Establish(operation, plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Bearers) != 1 || len(store.Snapshot()[0].DedicatedBearers) != 1 {
		t.Fatal("initial dedicated bearer was not committed before restart")
	}

	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := wal.Close(); err != nil {
		t.Fatal(err)
	}
	wal, recovered, err = rules.OpenWAL(walPath, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 1 || len(recovered[0].DedicatedBearers) != 1 {
		t.Fatalf("durable restart recovered %#v", recovered)
	}
	store = rules.NewStoreWithParticipants(10, nil, wal)
	if err := store.Restore(recovered); err != nil {
		t.Fatal(err)
	}
	server, err = New(Config{
		Listen: serverAddress, Advertise: upAddress, UserIP: userAddress,
		AllowedCP: []netip.Addr{cpAddress}, StartedAt: started.Add(5 * time.Second),
		EnterpriseID: enterpriseID, Transport: transport,
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(ctx) }()
	if err := client.Heartbeat(operation); !errors.Is(err, pgwclient.ErrPeerRestarted) {
		t.Fatalf("heartbeat after PGW-U restart error = %v", err)
	}
	if err := client.Associate(operation); err != nil {
		t.Fatal(err)
	}
	if state := server.AssociationState(cpAddress); state != pfcpassociation.StateReconciling {
		t.Fatalf("restart association state = %s", state)
	}
	replayed, err := client.Establish(operation, plan)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.UPSEID != first.UPSEID {
		t.Fatalf("restart changed UP-SEID: %d -> %d", first.UPSEID, replayed.UPSEID)
	}
	if err := client.CompleteReconciliation(operation); err != nil {
		t.Fatal(err)
	}
	voice := testTransportPacket(ue, false, 5060, 5061)
	rule, ok := store.LookupDownlinkPacket(ue, voice)
	if !ok || rule.Default || rule.QERID != 2 || rule.Remote.TEID != 4413 {
		t.Fatalf("reconciled dedicated classifier = %#v, %v", rule, ok)
	}
	if server.AssociationState(cpAddress) != pfcpassociation.StateAssociated || store.Count() != 1 {
		t.Fatal("PGW-U restart reconciliation did not complete cleanly")
	}
}

func TestGraceBlocksNewSessionsPreservesForwardingAndReconciles(t *testing.T) {
	transport := pfcptransport.DefaultConfig()
	transport.RetransmitTimeout = 50 * time.Millisecond
	transport.MaxRetransmits = 1
	store := rules.NewStoreWithLimit(10)
	server, err := New(Config{
		Listen: netip.MustParseAddrPort("127.0.0.1:0"), Advertise: netip.MustParseAddr("127.0.0.1"),
		UserIP: netip.MustParseAddr("10.200.0.20"), AllowedCP: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		StartedAt: time.Now().UTC(), AssociationTimeout: 20 * time.Millisecond, GraceWindow: 60 * time.Millisecond,
		Transport: transport,
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	client, err := pgwclient.New(pgwclient.Config{
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
	plan := pgwclient.Establishment{
		CPSEID: 7001, UEIPv4: netip.MustParseAddr("10.90.0.7"),
		Local:  pgwclient.Tunnel{TEID: 8001, IP: netip.MustParseAddr("10.200.0.20")},
		Remote: pgwclient.Tunnel{TEID: 9001, IP: netip.MustParseAddr("10.200.0.10")},
	}
	first, err := client.Establish(operation, plan)
	if err != nil {
		t.Fatal(err)
	}
	stalePlan := plan
	stalePlan.CPSEID++
	stalePlan.UEIPv4 = netip.MustParseAddr("10.90.0.8")
	stalePlan.Local.TEID++
	stalePlan.Remote.TEID++
	if _, err := client.Establish(operation, stalePlan); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	server.sweepAssociations()
	peer := netip.MustParseAddr("127.0.0.1")
	if state := server.AssociationState(peer); state != pfcpassociation.StateGrace || store.Count() != 2 {
		t.Fatalf("grace state=%s sessions=%d", state, store.Count())
	}
	newPlan := stalePlan
	newPlan.CPSEID++
	newPlan.UEIPv4 = netip.MustParseAddr("10.90.0.9")
	newPlan.Local.TEID++
	newPlan.Remote.TEID++
	if _, err := client.Establish(operation, newPlan); !errors.Is(err, pgwclient.ErrRejected) {
		t.Fatalf("new session during grace error = %v", err)
	}
	if store.Count() != 2 {
		t.Fatal("grace changed the forwarding rule set")
	}
	if err := client.Associate(operation); err != nil {
		t.Fatal(err)
	}
	if state := server.AssociationState(peer); state != pfcpassociation.StateReconciling {
		t.Fatalf("state after reconnect = %s", state)
	}
	plan.Remote = pgwclient.Tunnel{TEID: 9011, IP: netip.MustParseAddr("10.200.0.11")}
	replayed, err := client.Establish(operation, plan)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.UPSEID != first.UPSEID {
		t.Fatalf("UP-SEID changed during in-place reconciliation: %d -> %d", first.UPSEID, replayed.UPSEID)
	}
	if err := client.CompleteReconciliation(operation); err != nil {
		t.Fatal(err)
	}
	if store.Count() != 1 {
		t.Fatalf("unreaffirmed sessions after reconciliation = %d", store.Count()-1)
	}
	stored, ok := store.FindByCPSEID(plan.CPSEID)
	if !ok || stored.Remote.TEID != 9011 || server.AssociationState(peer) != pfcpassociation.StateAssociated {
		t.Fatalf("reconciled state=%s rules=%#v", server.AssociationState(peer), stored)
	}

	time.Sleep(30 * time.Millisecond)
	server.sweepAssociations()
	if store.Count() != 1 {
		t.Fatal("session was removed on grace entry")
	}
	time.Sleep(70 * time.Millisecond)
	server.sweepAssociations()
	if state := server.AssociationState(peer); state != pfcpassociation.StateUnavailable || store.Count() != 0 {
		t.Fatalf("expiry state=%s sessions=%d", state, store.Count())
	}
	counters := server.Counters()
	if counters.GraceEntries != 2 || counters.GraceExpirations != 1 || counters.Reconciliations != 1 || counters.StaleSessionsPurged != 2 {
		t.Fatalf("grace counters = %#v", counters)
	}
}
