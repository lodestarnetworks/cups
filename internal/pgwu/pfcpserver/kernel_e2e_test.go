//go:build linux

package pfcpserver

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/internal/kernelgtp"
	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	pgwclient "github.com/lodestarnetworks/cups/internal/pgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/pgwu/dataplane"
	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
)

func TestPFCPProgramsKernelGTP(t *testing.T) {
	if os.Getenv("SGW_NEXT_KERNEL_GTP_TEST") != "1" {
		t.Skip("kernel GTP PFCP test requires a disposable network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel GTP PFCP test requires root")
	}

	pgwuOuter := netip.MustParseAddr("10.254.77.1")
	sgwuOuter := netip.MustParseAddr("10.254.77.2")
	pgwcPFCP := netip.MustParseAddr("10.254.78.1")
	pgwuPFCP := netip.MustParseAddr("10.254.78.2")
	ue := netip.MustParseAddr("10.254.200.7")
	linkName := fmt.Sprintf("lodpgw%d", os.Getpid()%100_000)

	forwarder, err := dataplane.OpenKernel(dataplane.KernelConfig{
		S5: netip.AddrPortFrom(pgwuOuter, kernelgtp.GTPUPort), AllowedSGWPeers: []netip.Addr{sgwuOuter},
		TunnelName: linkName, OwnershipFile: filepath.Join(t.TempDir(), "kernel.owner"),
		UEPoolPrefix: netip.MustParsePrefix("10.254.200.0/24"),
		UEGateway:    netip.MustParseAddr("10.254.200.1"), HashSize: 4_096, MTU: 1_400,
		SocketBufferBytes: 4 * 1024 * 1024, AllowUnsupportedPolicy: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	store := rules.NewStoreWithApplier(10, forwarder)

	transport := pfcptransport.DefaultConfig()
	transport.RetransmitTimeout = 50 * time.Millisecond
	transport.MaxRetransmits = 1
	server, err := New(Config{
		Listen: netip.AddrPortFrom(pgwuPFCP, 8_805), Advertise: pgwuPFCP, UserIP: pgwuOuter,
		AllowedCP: []netip.Addr{pgwcPFCP}, StartedAt: time.Now().UTC(), Transport: transport,
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := pgwclient.New(pgwclient.Config{
		Listen: netip.AddrPortFrom(pgwcPFCP, 0), Advertise: pgwcPFCP,
		Remote: server.LocalAddr(), StartedAt: time.Now().UTC(), Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()
	go func() { _ = client.Serve(ctx) }()

	operation, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	if err := client.Associate(operation); err != nil {
		t.Fatal(err)
	}
	session, err := client.Establish(operation, pgwclient.Establishment{
		CPSEID: 11_001, UEIPv4: ue,
		Local:         pgwclient.Tunnel{TEID: 12_001, IP: pgwuOuter},
		Remote:        pgwclient.Tunnel{TEID: 13_001, IP: sgwuOuter},
		UplinkBitrate: 1_000_000_000, DownlinkBitrate: 1_000_000_000,
	})
	if err != nil {
		t.Fatal(err)
	}

	probe, err := kernelgtp.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	link, err := probe.InspectLink(linkName)
	if err != nil {
		t.Fatal(err)
	}
	contexts, err := probe.ListContexts(link.Index)
	if err != nil {
		t.Fatal(err)
	}
	if len(contexts) != 1 || contexts[0].UEIPv4 != ue || contexts[0].IncomingTEID != 12_001 || contexts[0].OutgoingTEID != 13_001 {
		t.Fatalf("PFCP establishment kernel state = %+v", contexts)
	}

	if err := client.UpdateRemote(operation, &session, pgwclient.Tunnel{TEID: 13_002, IP: sgwuOuter}); err != nil {
		t.Fatal(err)
	}
	updated, err := probe.GetContext(link.Index, 12_001)
	if err != nil {
		t.Fatal(err)
	}
	if updated.OutgoingTEID != 13_002 {
		t.Fatalf("PFCP modification kernel state = %+v", updated)
	}

	if err := client.Delete(operation, session); err != nil {
		t.Fatal(err)
	}
	contexts, err = probe.ListContexts(link.Index)
	if err != nil {
		t.Fatal(err)
	}
	if len(contexts) != 0 || store.Count() != 0 {
		t.Fatalf("PFCP deletion leaked kernel=%+v desired=%d", contexts, store.Count())
	}
}
