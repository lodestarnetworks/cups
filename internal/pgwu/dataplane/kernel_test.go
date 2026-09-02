package dataplane

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/lodestarnetworks/cups/internal/kernelgtp"
	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
)

type fakeKernelController struct {
	ensured    []kernelgtp.Context
	deleted    [][2]uint32
	reconciled []kernelgtp.Context
	err        error
}

func (f *fakeKernelController) EnsureContext(context kernelgtp.Context) (bool, error) {
	f.ensured = append(f.ensured, context)
	return true, f.err
}

func (f *fakeKernelController) DeleteContext(link, teid uint32) error {
	f.deleted = append(f.deleted, [2]uint32{link, teid})
	return f.err
}

func (f *fakeKernelController) PeerFilterCounters(kernelgtp.Link) (kernelgtp.PeerFilterCounters, error) {
	return kernelgtp.PeerFilterCounters{DroppedPackets: 7}, f.err
}

func (f *fakeKernelController) Reconcile(_ uint32, contexts []kernelgtp.Context) (kernelgtp.ReconcileReport, error) {
	f.reconciled = append([]kernelgtp.Context(nil), contexts...)
	return kernelgtp.ReconcileReport{Created: len(contexts)}, f.err
}

func (f *fakeKernelController) Close() error { return f.err }

func TestKernelForwarderAppliesSessionTransitions(t *testing.T) {
	controller := &fakeKernelController{}
	forwarder := &KernelForwarder{
		controller: controller, link: kernelgtp.Link{Name: "lspgwu0", Index: 9},
		s5:      netip.MustParseAddrPort("10.250.40.2:2152"),
		allowed: map[netip.Addr]struct{}{netip.MustParseAddr("10.250.40.1"): {}},
		uePools: []netip.Prefix{netip.MustParsePrefix("10.251.0.0/16")},
		closed:  make(chan struct{}),
	}
	session := rules.Session{
		UEIPv4:         netip.MustParseAddr("10.251.0.7"),
		Local:          rules.Tunnel{TEID: 101, IP: netip.MustParseAddr("10.250.40.2")},
		Remote:         rules.Tunnel{TEID: 201, IP: netip.MustParseAddr("10.250.40.1")},
		UplinkGateOpen: true, DownlinkGateOpen: true,
	}
	if err := forwarder.Apply(nil, &session); err != nil {
		t.Fatal(err)
	}
	if len(controller.ensured) != 1 || controller.ensured[0].IncomingTEID != 101 || controller.ensured[0].OutgoingTEID != 201 {
		t.Fatalf("create transition = %+v", controller.ensured)
	}
	blocked := session
	blocked.DownlinkGateOpen = false
	if err := forwarder.Apply(&session, &blocked); err != nil {
		t.Fatal(err)
	}
	if len(controller.deleted) != 1 || controller.deleted[0] != [2]uint32{9, 101} {
		t.Fatalf("gate transition = %+v", controller.deleted)
	}
	if err := forwarder.Apply(&blocked, &session); err != nil {
		t.Fatal(err)
	}
	if len(controller.ensured) != 2 {
		t.Fatalf("reopen transition did not restore context: %+v", controller.ensured)
	}
}

func TestKernelForwarderRejectsUnallowlistedPeer(t *testing.T) {
	forwarder := &KernelForwarder{
		controller: &fakeKernelController{}, link: kernelgtp.Link{Name: "lspgwu0", Index: 9},
		s5: netip.MustParseAddrPort("10.250.40.2:2152"), allowed: map[netip.Addr]struct{}{},
		uePools: []netip.Prefix{netip.MustParsePrefix("10.251.0.0/16")}, closed: make(chan struct{}),
	}
	session := rules.Session{
		UEIPv4:         netip.MustParseAddr("10.251.0.7"),
		Local:          rules.Tunnel{TEID: 101, IP: netip.MustParseAddr("10.250.40.2")},
		Remote:         rules.Tunnel{TEID: 201, IP: netip.MustParseAddr("10.250.40.1")},
		UplinkGateOpen: true, DownlinkGateOpen: true,
	}
	if err := forwarder.Apply(nil, &session); !errors.Is(err, ErrKernelPolicyUnsupported) {
		t.Fatalf("peer validation error = %v", err)
	}
}

func TestKernelForwarderReportsStartupRecovery(t *testing.T) {
	forwarder := &KernelForwarder{
		controller: &fakeKernelController{},
		link: kernelgtp.Link{
			Name: "missing-test-link", Index: 9,
			Recovery: kernelgtp.RecoveryReport{LinkRemoved: true, PeerFilterRemoved: true},
		},
		closed: make(chan struct{}),
	}
	counters := forwarder.Counters()
	if counters.RecoveredGTPLinks != 1 || counters.RecoveredFirewalls != 1 {
		t.Fatalf("startup recovery counters = %+v", counters)
	}
}

func TestKernelForwarderReconcilesRecoveredSessions(t *testing.T) {
	controller := &fakeKernelController{}
	forwarder := &KernelForwarder{
		controller: controller, link: kernelgtp.Link{Name: "lspgwu0", Index: 9},
		s5:      netip.MustParseAddrPort("10.250.40.2:2152"),
		allowed: map[netip.Addr]struct{}{netip.MustParseAddr("10.250.40.1"): {}},
		uePools: []netip.Prefix{netip.MustParsePrefix("10.251.0.0/16")}, closed: make(chan struct{}),
	}
	open := rules.Session{
		CPSEID: 1, UPSEID: 2, Revision: 1, UEIPv4: netip.MustParseAddr("10.251.0.7"),
		Local:          rules.Tunnel{TEID: 101, IP: netip.MustParseAddr("10.250.40.2")},
		Remote:         rules.Tunnel{TEID: 201, IP: netip.MustParseAddr("10.250.40.1")},
		UplinkGateOpen: true, DownlinkGateOpen: true,
	}
	closed := open
	closed.UPSEID++
	closed.CPSEID++
	closed.UEIPv4 = netip.MustParseAddr("10.251.0.8")
	closed.Local.TEID++
	closed.Remote.TEID++
	closed.DownlinkGateOpen = false
	if err := forwarder.ReconcileSessions([]rules.Session{open, closed}); err != nil {
		t.Fatal(err)
	}
	if len(controller.reconciled) != 1 || controller.reconciled[0].IncomingTEID != open.Local.TEID {
		t.Fatalf("reconciled contexts = %+v", controller.reconciled)
	}
}

func TestNormalizeKernelUEPoolsSupportsDisjointAPNRanges(t *testing.T) {
	pools, err := normalizeKernelUEPools(KernelConfig{UEPools: []UEPool{
		{Prefix: netip.MustParsePrefix("10.46.0.0/16"), Gateway: netip.MustParseAddr("10.46.0.1")},
		{Prefix: netip.MustParsePrefix("10.45.0.0/16"), Gateway: netip.MustParseAddr("10.45.0.1")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(pools) != 2 || pools[0].Prefix != netip.MustParsePrefix("10.45.0.0/16") || pools[1].Prefix != netip.MustParsePrefix("10.46.0.0/16") {
		t.Fatalf("normalized UE pools = %#v", pools)
	}
	overlap := KernelConfig{UEPools: []UEPool{
		{Prefix: netip.MustParsePrefix("10.45.0.0/16"), Gateway: netip.MustParseAddr("10.45.0.1")},
		{Prefix: netip.MustParsePrefix("10.45.1.0/24"), Gateway: netip.MustParseAddr("10.45.1.1")},
	}}
	if _, err := normalizeKernelUEPools(overlap); err == nil {
		t.Fatal("overlapping UE pools were accepted")
	}
}

func TestKernelForwarderRejectsUEOutsideServedPools(t *testing.T) {
	local := netip.MustParseAddr("10.250.40.2")
	remote := netip.MustParseAddr("10.250.40.1")
	forwarder := &KernelForwarder{
		s5: netip.AddrPortFrom(local, 2152), allowed: map[netip.Addr]struct{}{remote: {}},
		uePools: []netip.Prefix{netip.MustParsePrefix("10.45.0.0/16")},
	}
	current := rules.Session{
		UEIPv4: netip.MustParseAddr("10.48.0.2"),
		Local:  rules.Tunnel{TEID: 1, IP: local}, Remote: rules.Tunnel{TEID: 2, IP: remote},
	}
	if err := forwarder.validateSession(&current); !errors.Is(err, ErrKernelPolicyUnsupported) {
		t.Fatalf("outside-pool validation error = %v", err)
	}
}
