package session

import (
	"errors"
	"net/netip"
	"testing"
)

func validSession(teid uint32) Session {
	return Session{
		SubscriberKey:   "subscriber-hash-a",
		APN:             "internet",
		State:           StatePending,
		MMEControl:      FTEID{TEID: 0xaabbccdd, IP: netip.MustParseAddr("10.0.0.1")},
		S11Control:      FTEID{TEID: teid, IP: netip.MustParseAddr("10.0.0.2")},
		S5Control:       FTEID{TEID: teid + 10_000},
		PFCPControlSEID: uint64(teid) + 20_000,
		PFCPUserSEID:    uint64(teid) + 30_000,
		Bearers: map[uint8]Bearer{
			5: {EBI: 5, QCI: 9, Default: true, State: BearerPending},
		},
	}
}

func TestCreateUpdateAndFindByTEID(t *testing.T) {
	store := NewStore()
	created, err := store.Create(validSession(100))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := store.Update(created.ID, created.Revision, func(session *Session) error {
		session.State = StateActive
		bearer := session.Bearers[5]
		bearer.State = BearerActive
		session.Bearers[5] = bearer
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || updated.State != StateActive {
		t.Fatalf("updated session = %#v", updated)
	}
	got, ok := store.FindByS11TEID(100)
	if !ok || got.State != StateActive {
		t.Fatalf("FindByS11TEID = %#v, %v", got, ok)
	}
	got, ok = store.FindByS5TEID(10_100)
	if !ok || got.State != StateActive {
		t.Fatalf("FindByS5TEID = %#v, %v", got, ok)
	}
	got, ok = store.FindByPFCPControlSEID(20_100)
	if !ok || got.State != StateActive {
		t.Fatalf("FindByPFCPControlSEID = %#v, %v", got, ok)
	}
	got, ok = store.FindByOwner("subscriber-hash-a", "INTERNET")
	if !ok || got.ID != created.ID {
		t.Fatalf("FindByOwner = %#v, %v", got, ok)
	}
	got, ok = store.FindBySubscriberAndEBI("subscriber-hash-a", 5)
	if !ok || got.ID != created.ID {
		t.Fatalf("FindBySubscriberAndEBI = %#v, %v", got, ok)
	}
}

func TestBearerOwnerIndexTracksDedicatedBearerLifecycle(t *testing.T) {
	store := NewStore()
	created, err := store.Create(validSession(109))
	if err != nil {
		t.Fatal(err)
	}
	withDedicated, err := store.Update(created.ID, created.Revision, func(candidate *Session) error {
		candidate.Bearers[7] = Bearer{EBI: 7, QCI: 1, Default: false, State: BearerPending}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := store.FindBySubscriberAndEBI(created.SubscriberKey, 7); !ok || got.ID != created.ID {
		t.Fatalf("dedicated bearer lookup = %#v, %v", got, ok)
	}

	withoutDedicated, err := store.Update(withDedicated.ID, withDedicated.Revision, func(candidate *Session) error {
		delete(candidate.Bearers, 7)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.FindBySubscriberAndEBI(created.SubscriberKey, 7); ok {
		t.Fatal("removed dedicated bearer remains indexed")
	}
	if got, ok := store.FindBySubscriberAndEBI(created.SubscriberKey, 5); !ok || got.ID != withoutDedicated.ID {
		t.Fatalf("default bearer index was damaged: %#v, %v", got, ok)
	}
}

func TestUpdateRejectsStaleRevisionWithoutMutation(t *testing.T) {
	store := NewStore()
	created, err := store.Create(validSession(101))
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Update(created.ID, created.Revision+1, func(session *Session) error {
		session.State = StateDeleting
		return nil
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}
	got, _ := store.Find(created.ID)
	if got.State == StateDeleting {
		t.Fatal("stale update mutated stored session")
	}
}

func TestReconcilePFCPUserSEID(t *testing.T) {
	store := NewStore()
	created, err := store.Create(validSession(107))
	if err != nil {
		t.Fatal(err)
	}
	reconciled, err := store.ReconcilePFCPUserSEID(created.ID, created.Revision, 999999)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.PFCPUserSEID != 999999 || reconciled.Revision != created.Revision+1 || reconciled.PFCPControlSEID != created.PFCPControlSEID {
		t.Fatalf("reconciled session = %#v", reconciled)
	}
}

func TestReconcilePFCPUserSEIDIsNoOpWhenUnchanged(t *testing.T) {
	store := NewStore()
	created, err := store.Create(validSession(108))
	if err != nil {
		t.Fatal(err)
	}
	reconciled, err := store.ReconcilePFCPUserSEID(created.ID, created.Revision, created.PFCPUserSEID)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Revision != created.Revision || reconciled.PFCPUserSEID != created.PFCPUserSEID {
		t.Fatalf("no-op reconciliation = %#v", reconciled)
	}
}

func TestCreateRejectsDuplicateOwner(t *testing.T) {
	store := NewStore()
	if _, err := store.Create(validSession(102)); err != nil {
		t.Fatal(err)
	}
	duplicate := validSession(103)
	if _, err := store.Create(duplicate); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("error = %v, want ErrDuplicate", err)
	}
}

func TestCreateRejectsDuplicateSubscriberBearerAcrossPDNs(t *testing.T) {
	store := NewStore()
	if _, err := store.Create(validSession(110)); err != nil {
		t.Fatal(err)
	}

	colliding := validSession(111)
	colliding.APN = "ims"
	if _, err := store.Create(colliding); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("error = %v, want ErrDuplicate for colliding [subscriber, EBI]", err)
	}
}

func TestCreateAllowsMultiplePDNsOnSharedS11Context(t *testing.T) {
	store := NewStore()
	internet, err := store.Create(validSession(105))
	if err != nil {
		t.Fatal(err)
	}
	imsCandidate := validSession(105)
	imsCandidate.APN = "ims"
	imsCandidate.S5Control.TEID++
	imsCandidate.PFCPControlSEID++
	imsCandidate.PFCPUserSEID++
	imsCandidate.Bearers = map[uint8]Bearer{
		6: {EBI: 6, QCI: 5, Default: true, State: BearerPending},
	}
	ims, err := store.Create(imsCandidate)
	if err != nil {
		t.Fatalf("create IMS PDN: %v", err)
	}

	if got, ok := store.FindByS11TEID(105); !ok || got.ID != ims.ID {
		t.Fatalf("legacy S11 lookup = %#v, %v; want newest IMS context", got, ok)
	}
	if got, ok := store.FindByS11TEIDAndEBI(105, 5); !ok || got.ID != internet.ID {
		t.Fatalf("S11+EBI 5 lookup = %#v, %v; want internet context", got, ok)
	}
	if got, ok := store.FindByS11TEIDAndEBI(105, 6); !ok || got.ID != ims.ID {
		t.Fatalf("S11+EBI 6 lookup = %#v, %v; want IMS context", got, ok)
	}
	if got := store.FindAllByS11TEID(105); len(got) != 2 || got[0].ID != internet.ID || got[1].ID != ims.ID {
		t.Fatalf("shared S11 contexts = %#v", got)
	}

	if err := store.Delete(ims.ID, ims.Revision); err != nil {
		t.Fatal(err)
	}
	if got, ok := store.FindByS11TEID(105); !ok || got.ID != internet.ID {
		t.Fatalf("S11 lookup after IMS delete = %#v, %v; want internet context", got, ok)
	}
}

func TestCreateRejectsSharedS11WithDifferentOwnerOrBearer(t *testing.T) {
	store := NewStore()
	if _, err := store.Create(validSession(106)); err != nil {
		t.Fatal(err)
	}

	differentSubscriber := validSession(106)
	differentSubscriber.SubscriberKey = "subscriber-hash-b"
	differentSubscriber.APN = "ims"
	differentSubscriber.S5Control.TEID++
	differentSubscriber.PFCPControlSEID++
	differentSubscriber.PFCPUserSEID++
	if _, err := store.Create(differentSubscriber); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("different subscriber error = %v, want ErrDuplicate", err)
	}

	overlappingBearer := validSession(106)
	overlappingBearer.APN = "ims"
	overlappingBearer.S5Control.TEID += 2
	overlappingBearer.PFCPControlSEID += 2
	overlappingBearer.PFCPUserSEID += 2
	if _, err := store.Create(overlappingBearer); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("overlapping bearer error = %v, want ErrDuplicate", err)
	}
}

func TestReturnedSessionDoesNotAliasStore(t *testing.T) {
	store := NewStore()
	created, err := store.Create(validSession(104))
	if err != nil {
		t.Fatal(err)
	}
	created.Bearers[5] = Bearer{EBI: 5, QCI: 1, Default: true}
	got, _ := store.Find(created.ID)
	if got.Bearers[5].QCI != 9 {
		t.Fatalf("stored bearer was mutated: %#v", got.Bearers[5])
	}
}

func TestCreateEnforcesCapacityAndReleasesSlotOnDelete(t *testing.T) {
	store := NewStoreWithLimit(1)
	created, err := store.Create(validSession(201))
	if err != nil {
		t.Fatal(err)
	}
	second := validSession(202)
	second.SubscriberKey = "subscriber-hash-b"
	if _, err := store.Create(second); !errors.Is(err, ErrCapacity) {
		t.Fatalf("error = %v, want ErrCapacity", err)
	}
	if err := store.Delete(created.ID, created.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(second); err != nil {
		t.Fatalf("create after delete: %v", err)
	}
}
