package session

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestStoreLifecycleAndIndexes(t *testing.T) {
	store := NewStoreWithLimit(2)
	created, err := store.Create(testSession(1))
	if err != nil {
		t.Fatal(err)
	}
	for name, found := range map[string]bool{
		"id":      hasSession(store.Find(created.ID)),
		"control": hasSession(store.FindByControlTEID(created.PGWControl.TEID)),
		"owner":   hasSession(store.FindByOwner(created.SubscriberKey, "LODESTARTEST")),
		"bearer":  hasSession(store.FindBySubscriberAndEBI(created.SubscriberKey, created.EBI)),
		"ue":      hasSession(store.FindByUEIPv4(created.UEIPv4)),
		"pfcp":    hasSession(store.FindByPFCPControlSEID(created.PFCPControlSEID)),
	} {
		if !found {
			t.Fatalf("%s index did not find session", name)
		}
	}
	updated, err := store.Update(created.ID, created.Revision, func(candidate *Session) error {
		candidate.SGWUser = FTEID{TEID: 9001, IP: netip.MustParseAddr("10.200.0.99")}
		return nil
	})
	if err != nil || updated.Revision != 2 || updated.SGWUser.TEID != 9001 {
		t.Fatalf("update = %#v, %v", updated, err)
	}
	if err := store.Delete(updated.ID, updated.Revision); err != nil {
		t.Fatal(err)
	}
	if store.Count() != 0 || hasSession(store.FindByUEIPv4(updated.UEIPv4)) {
		t.Fatal("deleted session remains indexed")
	}
}

func TestStoreRejectsSubscriberBearerCollisionAcrossAPNs(t *testing.T) {
	store := NewStore()
	first := testSession(11)
	if _, err := store.Create(first); err != nil {
		t.Fatal(err)
	}
	colliding := testSession(12)
	colliding.SubscriberKey = first.SubscriberKey
	colliding.APN = "ims"
	if _, err := store.Create(colliding); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("collision error = %v, want ErrDuplicate", err)
	}
}

func TestStoreCapacityAndUniqueness(t *testing.T) {
	store := NewStoreWithLimit(1)
	first, err := store.Create(testSession(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(testSession(1)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate error = %v", err)
	}
	if _, err := store.Create(testSession(2)); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	if err := store.Delete(first.ID, first.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(testSession(2)); err != nil {
		t.Fatalf("capacity slot was not reusable: %v", err)
	}
}

func TestStoreRejectsImmutableUpdateAndConflict(t *testing.T) {
	store := NewStore()
	created, err := store.Create(testSession(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(created.ID, created.Revision+1, func(*Session) error { return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	if _, err := store.Update(created.ID, created.Revision, func(candidate *Session) error {
		candidate.UEIPv4 = netip.MustParseAddr("10.90.0.222")
		return nil
	}); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("immutable update error = %v", err)
	}
	reconciled, err := store.ReconcilePFCPUserSEID(created.ID, created.Revision, 9999)
	if err != nil || reconciled.PFCPUserSEID != 9999 || reconciled.Revision != created.Revision+1 {
		t.Fatalf("PFCP reconciliation = %#v, %v", reconciled, err)
	}
	unchanged, err := store.ReconcilePFCPUserSEID(reconciled.ID, reconciled.Revision, reconciled.PFCPUserSEID)
	if err != nil || unchanged.Revision != reconciled.Revision {
		t.Fatalf("no-op PFCP reconciliation = %#v, %v", unchanged, err)
	}
}

func TestStoreDedicatedBearerLifecycleAndNoAliasing(t *testing.T) {
	store := NewStore()
	created, err := store.Create(testSession(40))
	if err != nil {
		t.Fatal(err)
	}
	bearer := testDedicatedBearer(6)
	updated, err := store.Update(created.ID, created.Revision, func(candidate *Session) error {
		candidate.DedicatedBearers = map[uint8]Bearer{bearer.EBI: bearer}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found, ok := store.FindBySubscriberAndEBI(updated.SubscriberKey, bearer.EBI); !ok || found.ID != updated.ID {
		t.Fatalf("dedicated EBI index = %#v, %v", found, ok)
	}

	// Returned state must never alias the store's map, TFT bytes, or PDR lists.
	got, _ := store.Find(updated.ID)
	mutated := got.DedicatedBearers[bearer.EBI]
	mutated.TFT[0] = 0
	mutated.Rules.UplinkPDRs[0] = 999
	got.DedicatedBearers[bearer.EBI] = mutated
	delete(got.DedicatedBearers, bearer.EBI)
	stable, _ := store.Find(updated.ID)
	if stable.DedicatedBearers[bearer.EBI].TFT[0] != 0x21 || stable.DedicatedBearers[bearer.EBI].Rules.UplinkPDRs[0] != 21 {
		t.Fatalf("caller mutation aliased durable state: %#v", stable.DedicatedBearers[bearer.EBI])
	}

	removed, err := store.Update(updated.ID, updated.Revision, func(candidate *Session) error {
		delete(candidate.DedicatedBearers, bearer.EBI)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.FindBySubscriberAndEBI(removed.SubscriberKey, bearer.EBI); ok {
		t.Fatal("removed dedicated EBI remains indexed")
	}
}

func TestStoreValidatesAndUniquelyOwnsPolicyIdentity(t *testing.T) {
	for _, value := range []string{"ims-voice", "pcrf.rule:42", "A_1"} {
		if !ValidPolicyID(value) {
			t.Fatalf("valid policy ID %q was rejected", value)
		}
	}
	for _, value := range []string{"", "-leading", "contains space", strings.Repeat("x", 65)} {
		if ValidPolicyID(value) {
			t.Fatalf("invalid policy ID %q was accepted", value)
		}
	}
	store := NewStore()
	created, err := store.Create(testSession(42))
	if err != nil {
		t.Fatal(err)
	}
	first := testDedicatedBearer(6)
	first.PolicyID = "ims-voice"
	second := testDedicatedBearer(7)
	second.PolicyID = first.PolicyID
	second.Rules = RuleIDs{UplinkPDRs: []uint16{23}, DownlinkPDRs: []uint16{24}, UplinkFAR: 13, DownlinkFAR: 14, QER: 3, URR: 3}
	if _, err := store.Update(created.ID, created.Revision, func(candidate *Session) error {
		candidate.DedicatedBearers = map[uint8]Bearer{first.EBI: first, second.EBI: second}
		return nil
	}); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("duplicate policy identity error = %v", err)
	}
}

func testSession(seed uint32) Session {
	return Session{
		SubscriberKey: "subscriber-" + string(rune('0'+seed)), APN: "lodestartest", State: StateActive,
		EBI: 5, QCI: 9, ARP: 8, UEIPv4: netip.AddrFrom4([4]byte{10, 90, 0, byte(seed + 1)}),
		SGWControl:      FTEID{TEID: 1000 + seed, IP: netip.MustParseAddr("10.200.0.10")},
		PGWControl:      FTEID{TEID: 2000 + seed, IP: netip.MustParseAddr("10.200.0.20")},
		SGWUser:         FTEID{TEID: 3000 + seed, IP: netip.MustParseAddr("10.200.0.11")},
		PGWUser:         FTEID{TEID: 4000 + seed, IP: netip.MustParseAddr("10.200.0.21")},
		PFCPControlSEID: uint64(5000 + seed), PFCPUserSEID: uint64(6000 + seed),
	}
}

func testDedicatedBearer(ebi uint8) Bearer {
	return Bearer{
		EBI: ebi, QCI: 1, ARP: 2,
		UplinkMBR: 8_000_000, DownlinkMBR: 12_000_000, UplinkGBR: 3_000_000, DownlinkGBR: 4_000_000,
		SGWUser: FTEID{TEID: 7000 + uint32(ebi), IP: netip.MustParseAddr("10.200.0.11")},
		PGWUser: FTEID{TEID: 8000 + uint32(ebi), IP: netip.MustParseAddr("10.200.0.21")},
		Rules: RuleIDs{
			UplinkPDRs: []uint16{21}, DownlinkPDRs: []uint16{22},
			UplinkFAR: 11, DownlinkFAR: 12, QER: 2, URR: 2,
		},
		TFT: []byte{0x21, 0x31, 10, 8, 0x30, 17, 0x40, 0x13, 0xc4, 0x50, 0x13, 0xc5},
	}
}

func hasSession(_ Session, ok bool) bool { return ok }
