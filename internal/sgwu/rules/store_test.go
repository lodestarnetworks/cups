package rules

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
)

func validRules() Session {
	outer := FTEID{TEID: 200, IP: netip.MustParseAddr("10.200.0.20")}
	return Session{
		CPSEID: 10,
		UPSEID: 20,
		PDRs: map[uint16]PDR{
			1: {ID: 1, SourceInterface: SourceAccess, LocalFTEID: FTEID{TEID: 100, IP: netip.MustParseAddr("10.200.0.10")}, FARID: 1, QERIDs: []uint32{1}, URRIDs: []uint32{1}},
		},
		FARs: map[uint32]FAR{
			1: {ID: 1, ApplyAction: ActionForward, DestinationInterface: DestinationCore, OuterHeader: &outer},
		},
		QERs: map[uint32]QER{
			1: {ID: 1, UplinkGateOpen: true, DownlinkGateOpen: true},
		},
		URRs: map[uint32]URR{
			1: {ID: 1, MeasureVolume: true},
		},
	}
}

func TestTunnelLookupAndUniqueness(t *testing.T) {
	store := NewStore()
	created, err := store.Create(validRules())
	if err != nil {
		t.Fatal(err)
	}
	pdr, far, ok := store.Lookup(SourceAccess, 100)
	if !ok || pdr.ID != 1 || far.ID != 1 || !store.GatesOpen(SourceAccess, pdr) {
		t.Fatalf("unexpected lookup: pdr=%#v far=%#v ok=%v", pdr, far, ok)
	}
	duplicate := validRules()
	duplicate.CPSEID = 11
	duplicate.UPSEID = 21
	if _, err := store.Create(duplicate); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate tunnel error = %v, want ErrDuplicate", err)
	}
	if err := store.Delete(created.UPSEID, created.Revision); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := store.Lookup(SourceAccess, 100); ok {
		t.Fatal("deleted tunnel remained indexed")
	}
}

func TestCreateAndAtomicUpdate(t *testing.T) {
	store := NewStore()
	created, err := store.Create(validRules())
	if err != nil {
		t.Fatal(err)
	}
	updated, err := store.Update(created.UPSEID, created.Revision, func(session *Session) error {
		qer := session.QERs[1]
		qer.MaxDownlinkBitsPerSecond = 10_000_000
		session.QERs[1] = qer
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || updated.QERs[1].MaxDownlinkBitsPerSecond != 10_000_000 {
		t.Fatalf("updated = %#v", updated)
	}
}

func TestReconcilePreservesUPSEIDAndReplacesRules(t *testing.T) {
	store := NewStore()
	created, err := store.Create(validRules())
	if err != nil {
		t.Fatal(err)
	}
	replay := validRules()
	replay.UPSEID = 999
	pdr := replay.PDRs[1]
	pdr.LocalFTEID.TEID = 101
	replay.PDRs[1] = pdr
	reconciled, err := store.Reconcile(created.CPSEID, replay)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.UPSEID != created.UPSEID || reconciled.Revision != created.Revision+1 {
		t.Fatalf("reconciled = %#v", reconciled)
	}
	if _, _, ok := store.Lookup(SourceAccess, 100); ok {
		t.Fatal("old tunnel remained indexed")
	}
	if _, _, ok := store.Lookup(SourceAccess, 101); !ok {
		t.Fatal("replayed tunnel was not indexed")
	}
}

func TestReconcileExactReplayDoesNotAdvanceRevision(t *testing.T) {
	store := NewStore()
	created, err := store.Create(validRules())
	if err != nil {
		t.Fatal(err)
	}
	replay := validRules()
	replay.UPSEID = 999
	reconciled, err := store.Reconcile(created.CPSEID, replay)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Revision != created.Revision {
		t.Fatalf("exact replay revision = %d, want %d", reconciled.Revision, created.Revision)
	}
}

func TestUpdateRejectsDanglingRuleAndKeepsOriginal(t *testing.T) {
	store := NewStore()
	created, err := store.Create(validRules())
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Update(created.UPSEID, created.Revision, func(session *Session) error {
		delete(session.FARs, 1)
		return nil
	})
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("error = %v, want ErrInvalidSession", err)
	}
	got, _ := store.FindByUPSEID(created.UPSEID)
	if _, exists := got.FARs[1]; !exists {
		t.Fatal("failed update removed FAR from stored session")
	}
}

func TestReturnedRulesDoNotAliasStore(t *testing.T) {
	store := NewStore()
	created, err := store.Create(validRules())
	if err != nil {
		t.Fatal(err)
	}
	created.PDRs[1] = PDR{ID: 1, FARID: 99}
	got, _ := store.FindByUPSEID(created.UPSEID)
	if got.PDRs[1].FARID != 1 {
		t.Fatalf("stored PDR was mutated: %#v", got.PDRs[1])
	}
}

func TestDeleteChecksRevision(t *testing.T) {
	store := NewStore()
	created, err := store.Create(validRules())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(created.UPSEID, created.Revision+1); !errors.Is(err, ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}
	if _, ok := store.FindByUPSEID(created.UPSEID); !ok {
		t.Fatal("stale delete removed session")
	}
}

func TestCreateEnforcesCapacityAndReleasesSlotOnDelete(t *testing.T) {
	store := NewStoreWithLimit(1)
	created, err := store.Create(validRules())
	if err != nil {
		t.Fatal(err)
	}
	second := validRules()
	second.CPSEID = 11
	second.UPSEID = 21
	second.PDRs[1] = PDR{ID: 1, SourceInterface: SourceAccess, LocalFTEID: FTEID{TEID: 101, IP: netip.MustParseAddr("10.200.0.10")}, FARID: 1, QERIDs: []uint32{1}, URRIDs: []uint32{1}}
	if _, err := store.Create(second); !errors.Is(err, ErrCapacity) {
		t.Fatalf("error = %v, want ErrCapacity", err)
	}
	if err := store.Delete(created.UPSEID, created.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(second); err != nil {
		t.Fatalf("create after delete: %v", err)
	}
}

func TestLockFreePacketIndexObservesWholeRuleRevisions(t *testing.T) {
	store := NewStore()
	initial := validRules()
	far := initial.FARs[1]
	far.OuterHeader.TEID = 1_001
	initial.FARs[1] = far
	qer := initial.QERs[1]
	qer.MaxUplinkBitsPerSecond = 1_001
	initial.QERs[1] = qer
	current, err := store.Create(initial)
	if err != nil {
		t.Fatal(err)
	}

	var stop atomic.Bool
	errorsSeen := make(chan string, 1)
	var readers sync.WaitGroup
	for reader := 0; reader < 8; reader++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for !stop.Load() {
				matched, ok := store.LookupPacket(SourceAccess, 100)
				if !ok {
					continue
				}
				want := uint64(1_000 + matched.Revision)
				if matched.FAR.OuterHeader == nil || uint64(matched.FAR.OuterHeader.TEID) != want || matched.QER.MaxUplinkBitsPerSecond != want {
					select {
					case errorsSeen <- "lookup mixed fields from different rule revisions":
					default:
					}
					return
				}
			}
		}()
	}

	for revision := uint64(2); revision <= 2_000; revision++ {
		current, err = store.Update(current.UPSEID, current.Revision, func(candidate *Session) error {
			far := candidate.FARs[1]
			far.OuterHeader.TEID = uint32(1_000 + candidate.Revision + 1)
			candidate.FARs[1] = far
			qer := candidate.QERs[1]
			qer.MaxUplinkBitsPerSecond = 1_000 + candidate.Revision + 1
			candidate.QERs[1] = qer
			return nil
		})
		if err != nil {
			t.Fatalf("update revision %d: %v", revision, err)
		}
	}
	stop.Store(true)
	readers.Wait()
	select {
	case message := <-errorsSeen:
		t.Fatal(message)
	default:
	}
	matched, ok := store.LookupPacket(SourceAccess, 100)
	if !ok || matched.Revision != current.Revision || matched.FAR.OuterHeader.TEID != 3_000 {
		t.Fatalf("final lookup = %#v, ok=%v", matched, ok)
	}
}
