package main

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/lodestarnetworks/cups/internal/config"
	"github.com/lodestarnetworks/cups/internal/pgwc/gateway"
	"github.com/lodestarnetworks/cups/internal/pgwc/ipam"
	"github.com/lodestarnetworks/cups/internal/pgwc/session"
)

func TestPGWCStateIdentityIncludesPFCPEnterpriseID(t *testing.T) {
	base := config.PGWC{
		S5Listen: "10.200.10.1:2123", S5Advertise: "10.200.10.1", AllowedSGW: []string{"10.200.10.2"},
		PFCPListen: "10.200.20.1:8805", PFCPAdvertise: "10.200.20.1", PFCPRemote: "10.200.20.2:8805",
		PGWUUserIP: "10.200.30.1", APN: "lodestartest", UEPoolPrefix: "10.90.0.0/24", UEGateway: "10.90.0.1",
		DNSIPv4: []string{"10.200.40.1", "10.200.40.2"}, SubscriberSalt: "test-secret",
	}
	first, err := pgwcStateIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	base.PFCPEnterpriseID = 65000
	second, err := pgwcStateIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("PFCP enterprise ID did not change durable-state identity")
	}
}

func TestPGWCStateIdentityIncludesQCI1UserPlaneAddress(t *testing.T) {
	base := config.PGWC{
		S5Listen: "10.200.10.1:2123", S5Advertise: "10.200.10.1", AllowedSGW: []string{"10.200.10.2"},
		PFCPListen: "10.200.20.1:8805", PFCPAdvertise: "10.200.20.1", PFCPRemote: "10.200.20.2:8805",
		PGWUUserIP: "10.200.30.1", APN: "lodestartest", UEPoolPrefix: "10.90.0.0/24", UEGateway: "10.90.0.1",
		DNSIPv4: []string{"10.200.40.1", "10.200.40.2"}, SubscriberSalt: "test-secret",
	}
	first, err := pgwcStateIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	base.PGWUQCI1UserIP = "10.200.30.2"
	second, err := pgwcStateIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("QCI 1 user-plane address did not change durable-state identity")
	}
}

func TestBuildAPNProfilesCreatesIndependentPoolsAndPolicy(t *testing.T) {
	value := config.PGWC{
		MaxSessions: 100,
		APNProfiles: []config.PGWCAPNProfile{
			{
				APN: "internet", UEPoolPrefix: "10.45.0.0/24", UEGateway: "10.45.0.1",
				DNSIPv4: []string{"10.200.40.1", "10.200.40.2"}, IPv4LinkMTU: 1400,
				APNAMBRUplinkBPS: 1_000_000_000, APNAMBRDownlinkBPS: 2_000_000_000,
			},
			{
				APN: "ims", UEPoolPrefix: "10.46.0.0/24", UEGateway: "10.46.0.1",
				DNSIPv4: []string{"10.200.40.1", "10.200.40.2"}, PCSCFIPv4: []string{"10.250.70.3"},
				IPv4LinkMTU: 1400, APNAMBRUplinkBPS: 100_000_000, APNAMBRDownlinkBPS: 100_000_000,
			},
		},
	}
	profiles, err := buildAPNProfiles(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 || profiles[0].Pool == profiles[1].Pool {
		t.Fatalf("APN profiles did not receive independent pools: %#v", profiles)
	}
	if got := profiles[0].Pool.Prefix(); got != netip.MustParsePrefix("10.45.0.0/24") {
		t.Fatalf("internet prefix = %s", got)
	}
	if got := profiles[1].Pool.Prefix(); got != netip.MustParsePrefix("10.46.0.0/24") {
		t.Fatalf("IMS prefix = %s", got)
	}
	if profiles[0].Pool.Capacity() != 100 || profiles[1].Pool.Capacity() != 100 {
		t.Fatalf("profile capacities = %d, %d", profiles[0].Pool.Capacity(), profiles[1].Pool.Capacity())
	}
	if len(profiles[1].PCSCFIPv4) != 1 || profiles[1].PCSCFIPv4[0] != netip.MustParseAddr("10.250.70.3") {
		t.Fatalf("IMS P-CSCF policy = %v", profiles[1].PCSCFIPv4)
	}
}

func TestRestoreAPNLeasesRestoresInternetAndIMSPools(t *testing.T) {
	internet, err := ipam.New(netip.MustParsePrefix("10.45.0.0/24"), netip.MustParseAddr("10.45.0.1"), 100)
	if err != nil {
		t.Fatal(err)
	}
	ims, err := ipam.New(netip.MustParsePrefix("10.46.0.0/24"), netip.MustParseAddr("10.46.0.1"), 100)
	if err != nil {
		t.Fatal(err)
	}
	profiles := []gateway.APNProfile{{APN: "internet", Pool: internet}, {APN: "ims", Pool: ims}}
	recovered := []session.Session{
		{ID: 1, SubscriberKey: "subscriber", APN: "internet", UEIPv4: netip.MustParseAddr("10.45.0.20")},
		{ID: 2, SubscriberKey: "subscriber", APN: "ims", UEIPv4: netip.MustParseAddr("10.46.0.30")},
	}
	if err := restoreAPNLeases(profiles, recovered); err != nil {
		t.Fatal(err)
	}
	if internet.Used() != 1 || ims.Used() != 1 {
		t.Fatalf("restored lease counts internet=%d IMS=%d", internet.Used(), ims.Used())
	}
	if lease, err := internet.Acquire("subscriber\x00internet"); err != nil || lease.Addr != recovered[0].UEIPv4 {
		t.Fatalf("restored internet lease = %#v, %v", lease, err)
	}
	if lease, err := ims.Acquire("subscriber\x00ims"); err != nil || lease.Addr != recovered[1].UEIPv4 {
		t.Fatalf("restored IMS lease = %#v, %v", lease, err)
	}
}

func TestRestoreAPNLeasesRejectsCrossPoolSession(t *testing.T) {
	internet, _ := ipam.New(netip.MustParsePrefix("10.45.0.0/24"), netip.MustParseAddr("10.45.0.1"), 100)
	profiles := []gateway.APNProfile{{APN: "internet", Pool: internet}}
	if err := restoreAPNLeases(profiles, []session.Session{{
		ID: 1, SubscriberKey: "subscriber", APN: "internet", UEIPv4: netip.MustParseAddr("10.46.0.30"),
	}}); err == nil {
		t.Fatal("cross-pool recovered session was accepted")
	}
	if internet.Used() != 0 {
		t.Fatal("invalid recovery consumed an internet lease")
	}
}

func TestPGWCStateIdentityCoversMultiAPNProfilesDeterministically(t *testing.T) {
	base := config.PGWC{
		S5Listen: "10.200.10.1:2123", S5Advertise: "10.200.10.1", AllowedSGW: []string{"10.200.10.2"},
		PFCPListen: "10.200.20.1:8805", PFCPAdvertise: "10.200.20.1", PFCPRemote: "10.200.20.2:8805",
		PGWUUserIP: "10.200.30.1", SubscriberSalt: "test-secret",
		APNProfiles: []config.PGWCAPNProfile{
			{APN: "internet", UEPoolPrefix: "10.45.0.0/24", UEGateway: "10.45.0.1", DNSIPv4: []string{"10.200.40.1", "10.200.40.2"}},
			{APN: "ims", UEPoolPrefix: "10.46.0.0/24", UEGateway: "10.46.0.1", DNSIPv4: []string{"10.200.40.1", "10.200.40.2"}, PCSCFIPv4: []string{"10.250.70.3"}},
		},
	}
	first, err := pgwcStateIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	base.APNProfiles[0], base.APNProfiles[1] = base.APNProfiles[1], base.APNProfiles[0]
	reordered, err := pgwcStateIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, reordered) {
		t.Fatal("profile ordering changed durable-state identity")
	}
	base.APNProfiles[0].PCSCFIPv4 = []string{"10.250.70.4"}
	changed, err := pgwcStateIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, changed) {
		t.Fatal("P-CSCF policy did not change durable-state identity")
	}
}
