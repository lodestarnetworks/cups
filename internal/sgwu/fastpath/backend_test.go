//go:build linux

package fastpath

import (
	"net/netip"
	"testing"

	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
)

func TestBuildEntriesUsesOnlyEligibleForwardingRules(t *testing.T) {
	backend := &Backend{
		access: resolvedSide{neighbours: map[netip.Addr]endpoint{
			netip.MustParseAddr("10.1.0.2"): {ifindex: 1},
		}},
		core: resolvedSide{neighbours: map[netip.Addr]endpoint{
			netip.MustParseAddr("10.2.0.2"): {ifindex: 2},
		}},
	}
	accessOuter := rules.FTEID{TEID: 400, IP: netip.MustParseAddr("10.1.0.2")}
	coreOuter := rules.FTEID{TEID: 200, IP: netip.MustParseAddr("10.2.0.2")}
	session := rules.Session{
		CPSEID: 1, UPSEID: 2, Revision: 7,
		PDRs: map[uint16]rules.PDR{
			1: {ID: 1, SourceInterface: rules.SourceAccess, LocalFTEID: rules.FTEID{TEID: 100, IP: netip.MustParseAddr("10.1.0.1")}, FARID: 1},
			2: {ID: 2, SourceInterface: rules.SourceCore, LocalFTEID: rules.FTEID{TEID: 300, IP: netip.MustParseAddr("10.2.0.1")}, FARID: 2},
		},
		FARs: map[uint32]rules.FAR{
			1: {ID: 1, ApplyAction: rules.ActionForward, DestinationInterface: rules.DestinationCore, OuterHeader: &coreOuter},
			2: {ID: 2, ApplyAction: rules.ActionBuffer | rules.ActionNotifyControlPlane, DestinationInterface: rules.DestinationAccess, OuterHeader: &accessOuter},
		},
		QERs: map[uint32]rules.QER{}, URRs: map[uint32]rules.URR{},
	}
	entries, err := backend.buildEntries(session)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].tunnelKey.Source != sideAccess || entries[0].tunnelKey.Teid != 100 || entries[0].value.Teid != 200 {
		t.Fatalf("unexpected fast-path entries %#v", entries)
	}
}

func TestBuildEntriesAccountsURRAndFallsBackForUnsupportedPolicy(t *testing.T) {
	backend := &Backend{
		access: resolvedSide{neighbours: map[netip.Addr]endpoint{}},
		core: resolvedSide{neighbours: map[netip.Addr]endpoint{
			netip.MustParseAddr("10.2.0.2"): {ifindex: 2},
		}},
	}
	outer := rules.FTEID{TEID: 200, IP: netip.MustParseAddr("10.2.0.2")}
	base := rules.Session{
		CPSEID: 1, UPSEID: 2, Revision: 1,
		PDRs: map[uint16]rules.PDR{1: {
			ID: 1, SourceInterface: rules.SourceAccess,
			LocalFTEID: rules.FTEID{TEID: 100, IP: netip.MustParseAddr("10.1.0.1")}, FARID: 1, QERIDs: []uint32{1},
		}},
		FARs: map[uint32]rules.FAR{1: {
			ID: 1, ApplyAction: rules.ActionForward, DestinationInterface: rules.DestinationCore, OuterHeader: &outer,
		}},
		QERs: map[uint32]rules.QER{1: {ID: 1, UplinkGateOpen: true, DownlinkGateOpen: true}},
		URRs: map[uint32]rules.URR{},
	}
	if entries, err := backend.buildEntries(base); err != nil || len(entries) != 1 {
		t.Fatalf("plain rule entries=%d err=%v", len(entries), err)
	}
	rateLimited := base
	rateLimited.QERs = map[uint32]rules.QER{1: {ID: 1, UplinkGateOpen: true, DownlinkGateOpen: true, MaxUplinkBitsPerSecond: 1_000_000}}
	if entries, err := backend.buildEntries(rateLimited); err != nil || len(entries) != 0 {
		t.Fatalf("rate-limited rule bypassed fallback: entries=%d err=%v", len(entries), err)
	}
	voice := base
	voice.QERs = map[uint32]rules.QER{1: {ID: 1, UplinkGateOpen: true, DownlinkGateOpen: true, QCI: 1, ARP: 2}}
	if entries, err := backend.buildEntries(voice); err != nil || len(entries) != 0 {
		t.Fatalf("QCI 1 rule bypassed fallback: entries=%d err=%v", len(entries), err)
	}
	usage := base
	usage.PDRs = map[uint16]rules.PDR{1: {
		ID: 1, SourceInterface: rules.SourceAccess,
		LocalFTEID: rules.FTEID{TEID: 100, IP: netip.MustParseAddr("10.1.0.1")}, FARID: 1,
		QERIDs: []uint32{1}, URRIDs: []uint32{1},
	}}
	usage.URRs = map[uint32]rules.URR{1: {ID: 1, MeasureVolume: true}}
	if entries, err := backend.buildEntries(usage); err != nil || len(entries) != 1 || entries[0].value.UrrCount != 1 || entries[0].value.UrrIds[0] != 1 {
		t.Fatalf("URR rule was not kernel-accounted: entries=%#v err=%v", entries, err)
	}
	tooManyURRs := usage
	tooManyURRs.PDRs = map[uint16]rules.PDR{1: {
		ID: 1, SourceInterface: rules.SourceAccess,
		LocalFTEID: rules.FTEID{TEID: 100, IP: netip.MustParseAddr("10.1.0.1")}, FARID: 1,
		QERIDs: []uint32{1}, URRIDs: []uint32{1, 2, 3, 4, 5},
	}}
	tooManyURRs.URRs = map[uint32]rules.URR{
		1: {ID: 1, MeasureVolume: true}, 2: {ID: 2, MeasureVolume: true},
		3: {ID: 3, MeasureVolume: true}, 4: {ID: 4, MeasureVolume: true},
		5: {ID: 5, MeasureVolume: true},
	}
	if entries, err := backend.buildEntries(tooManyURRs); err != nil || len(entries) != 0 {
		t.Fatalf("rule with too many URRs bypassed fallback: entries=%d err=%v", len(entries), err)
	}
}

func TestBuildEntriesKeepsSharedURROnOneAccountingPath(t *testing.T) {
	backend := &Backend{
		core: resolvedSide{neighbours: map[netip.Addr]endpoint{
			netip.MustParseAddr("10.2.0.2"): {ifindex: 2},
		}},
	}
	outer := rules.FTEID{TEID: 200, IP: netip.MustParseAddr("10.2.0.2")}
	session := rules.Session{
		CPSEID: 1, UPSEID: 2, Revision: 1,
		PDRs: map[uint16]rules.PDR{
			1: {ID: 1, SourceInterface: rules.SourceAccess, LocalFTEID: rules.FTEID{TEID: 100, IP: netip.MustParseAddr("10.1.0.1")}, FARID: 1, QERIDs: []uint32{1}, URRIDs: []uint32{1}},
			2: {ID: 2, SourceInterface: rules.SourceAccess, LocalFTEID: rules.FTEID{TEID: 101, IP: netip.MustParseAddr("10.1.0.1")}, FARID: 2, QERIDs: []uint32{2}, URRIDs: []uint32{1}},
		},
		FARs: map[uint32]rules.FAR{
			1: {ID: 1, ApplyAction: rules.ActionForward, DestinationInterface: rules.DestinationCore, OuterHeader: &outer},
			2: {ID: 2, ApplyAction: rules.ActionForward, DestinationInterface: rules.DestinationCore, OuterHeader: &outer},
		},
		QERs: map[uint32]rules.QER{
			1: {ID: 1, UplinkGateOpen: true, DownlinkGateOpen: true},
			2: {ID: 2, UplinkGateOpen: true, DownlinkGateOpen: true, QCI: 1, ARP: 1},
		},
		URRs: map[uint32]rules.URR{1: {ID: 1, MeasureVolume: true}},
	}
	entries, err := backend.buildEntries(session)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("shared URR split across kernel and portable paths: %#v", entries)
	}
}

func mustTestAddr(value string) netip.Addr { return netip.MustParseAddr(value) }
