//go:build linux

package pfcpserver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/internal/kernelgtp"
	pfcpassociation "github.com/lodestarnetworks/cups/internal/pfcp/association"
	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	pgwclient "github.com/lodestarnetworks/cups/internal/pgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/pgwu/dataplane"
	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
)

func TestPFCPKernelDurableRestartReconciliation(t *testing.T) {
	if testing.Short() {
		t.Skip("durable kernel restart integration test")
	}
	if !kernelTestEnabled() {
		t.Skip("kernel GTP PFCP test requires a disposable network namespace")
	}

	pgwuOuter := netip.MustParseAddr("10.254.77.1")
	sgwuOuter := netip.MustParseAddr("10.254.77.2")
	pgwcPFCP := netip.MustParseAddr("10.254.78.1")
	pgwuPFCP := netip.MustParseAddr("10.254.78.2")
	ue := netip.MustParseAddr("10.254.200.8")
	linkName := fmt.Sprintf("lodrst%d", testPID()%100_000)
	stateDirectory := t.TempDir()
	statePath := filepath.Join(stateDirectory, "pgwu.wal")
	ownerPath := filepath.Join(stateDirectory, "kernel.owner")
	transport := pfcptransport.DefaultConfig()
	transport.RetransmitTimeout = 50 * time.Millisecond
	transport.MaxRetransmits = 1

	type phase struct {
		log       *rules.WAL
		forwarder *dataplane.KernelForwarder
		store     *rules.Store
		server    *Server
		cancel    context.CancelFunc
	}
	openPhase := func(started time.Time) (*phase, error) {
		log, recovered, err := rules.OpenWAL(statePath, 1<<20)
		if err != nil {
			return nil, err
		}
		forwarder, err := dataplane.OpenKernel(dataplane.KernelConfig{
			S5: netip.AddrPortFrom(pgwuOuter, kernelgtp.GTPUPort), AllowedSGWPeers: []netip.Addr{sgwuOuter},
			TunnelName: linkName, OwnershipFile: ownerPath, UEPoolPrefix: netip.MustParsePrefix("10.254.200.0/24"),
			UEGateway: netip.MustParseAddr("10.254.200.1"), HashSize: 4_096, MTU: 1_400,
			SocketBufferBytes: 4 * 1024 * 1024, AllowUnsupportedPolicy: true,
		})
		if err != nil {
			_ = log.Close()
			return nil, err
		}
		store := rules.NewStoreWithParticipants(10, forwarder, log)
		if err := store.Restore(recovered); err != nil {
			_ = forwarder.Close()
			_ = log.Close()
			return nil, err
		}
		server, err := New(Config{
			Listen: netip.AddrPortFrom(pgwuPFCP, 8_805), Advertise: pgwuPFCP, UserIP: pgwuOuter,
			AllowedCP: []netip.Addr{pgwcPFCP}, StartedAt: started,
			AssociationTimeout: time.Second, GraceWindow: 10 * time.Second, Transport: transport,
		}, store)
		if err != nil {
			_ = forwarder.Close()
			_ = log.Close()
			return nil, err
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = server.Serve(ctx) }()
		return &phase{log: log, forwarder: forwarder, store: store, server: server, cancel: cancel}, nil
	}
	closePhase := func(current *phase) error {
		if current == nil {
			return nil
		}
		current.cancel()
		return errors.Join(current.server.Close(), current.forwarder.Close(), current.log.Close())
	}

	started := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	first, err := openPhase(started)
	if err != nil {
		t.Fatal(err)
	}
	client, err := pgwclient.New(pgwclient.Config{
		Listen: netip.AddrPortFrom(pgwcPFCP, 0), Advertise: pgwcPFCP,
		Remote: first.server.LocalAddr(), StartedAt: started.Add(-time.Hour), Transport: transport,
	})
	if err != nil {
		_ = closePhase(first)
		t.Fatal(err)
	}
	defer client.Close()
	clientContext, stopClient := context.WithCancel(context.Background())
	defer stopClient()
	go func() { _ = client.Serve(clientContext) }()

	operation, stop := context.WithTimeout(context.Background(), 3*time.Second)
	if err := client.Associate(operation); err != nil {
		stop()
		_ = closePhase(first)
		t.Fatal(err)
	}
	plan := pgwclient.Establishment{
		CPSEID: 21_001, UEIPv4: ue,
		Local: pgwclient.Tunnel{TEID: 22_001, IP: pgwuOuter}, Remote: pgwclient.Tunnel{TEID: 23_001, IP: sgwuOuter},
		UplinkBitrate: 1_000_000_000, DownlinkBitrate: 1_000_000_000,
	}
	created, err := client.Establish(operation, plan)
	stop()
	if err != nil {
		_ = closePhase(first)
		t.Fatal(err)
	}
	if first.log.Stats().Records != 1 || first.store.Count() != 1 {
		_ = closePhase(first)
		t.Fatalf("first phase durable state: WAL=%+v sessions=%d", first.log.Stats(), first.store.Count())
	}
	if err := closePhase(first); err != nil {
		t.Fatal(err)
	}

	second, err := openPhase(started.Add(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer closePhase(second)
	if second.store.Count() != 1 || second.server.AssociationState(pgwcPFCP) != pfcpassociation.StateUnavailable {
		t.Fatalf("recovered state count=%d association=%s", second.store.Count(), second.server.AssociationState(pgwcPFCP))
	}
	probe, err := kernelgtp.Open()
	if err != nil {
		t.Fatal(err)
	}
	link, err := probe.InspectLink(linkName)
	if err != nil {
		_ = probe.Close()
		t.Fatal(err)
	}
	contexts, err := probe.ListContexts(link.Index)
	_ = probe.Close()
	if err != nil || len(contexts) != 1 || contexts[0].IncomingTEID != plan.Local.TEID {
		t.Fatalf("kernel state before PFCP replay = %+v, %v", contexts, err)
	}

	operation, stop = context.WithTimeout(context.Background(), 3*time.Second)
	err = client.Associate(operation)
	if !errors.Is(err, pgwclient.ErrPeerRestarted) {
		stop()
		t.Fatalf("PGW-U restart detection error = %v", err)
	}
	if second.server.AssociationState(pgwcPFCP) != pfcpassociation.StateReconciling {
		stop()
		t.Fatalf("association after restart = %s", second.server.AssociationState(pgwcPFCP))
	}
	reconciled, err := client.Establish(operation, plan)
	if err != nil {
		stop()
		t.Fatal(err)
	}
	if reconciled.UPSEID != created.UPSEID || second.store.Count() != 1 {
		stop()
		t.Fatalf("reconciled session=%+v original=%+v count=%d", reconciled, created, second.store.Count())
	}
	if records := second.log.Stats().Records; records != 1 {
		stop()
		t.Fatalf("exact PFCP replay appended a duplicate durable transition: records=%d, want 1", records)
	}
	if err := client.CompleteReconciliation(operation); err != nil {
		stop()
		t.Fatal(err)
	}
	if second.server.AssociationState(pgwcPFCP) != pfcpassociation.StateAssociated {
		stop()
		t.Fatalf("association after reconciliation = %s", second.server.AssociationState(pgwcPFCP))
	}
	if err := client.Delete(operation, reconciled); err != nil {
		stop()
		t.Fatal(err)
	}
	stop()
	if second.store.Count() != 0 || second.log.Stats().Records != 2 {
		t.Fatalf("post-delete durable state: count=%d WAL=%+v", second.store.Count(), second.log.Stats())
	}
	if err := closePhase(second); err != nil {
		t.Fatal(err)
	}
	second = nil

	finalLog, recovered, err := rules.OpenWAL(statePath, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer finalLog.Close()
	if len(recovered) != 0 {
		t.Fatalf("deleted session recovered after second restart: %+v", recovered)
	}
}

func kernelTestEnabled() bool {
	return os.Getenv("SGW_NEXT_KERNEL_GTP_TEST") == "1" && os.Geteuid() == 0
}
func testPID() int { return os.Getpid() }
