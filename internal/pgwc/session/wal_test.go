package session

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/lodestarnetworks/cups/internal/controlstate"
)

func TestPGWCWALRoundTripRestoreAndFence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pgwc.wal")
	identity := []byte("pgwc=london-1;apn=lodestartest;pool=10.90.0.0/24")
	log, recovered, err := OpenWAL(path, 1<<20, identity, 90)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 0 || log.RecoveryCounter() != 90 {
		t.Fatalf("new state recovered=%+v counter=%d", recovered, log.RecoveryCounter())
	}
	if _, _, err := OpenWAL(path, 1<<20, identity, 90); !errors.Is(err, controlstate.ErrLocked) {
		t.Fatalf("second PGW-C owner error = %v, want ErrLocked", err)
	}
	if err := log.Start(); err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithPersister(10, log)
	created, err := store.Create(testSession(10))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := store.Update(created.ID, created.Revision, func(candidate *Session) error {
		candidate.SGWUser.TEID++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, recovered, err := OpenWAL(path, 1<<20, identity, 90)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.RecoveryCounter() != 91 || len(recovered) != 1 || recovered[0].Revision != updated.Revision {
		t.Fatalf("reopened counter=%d recovered=%+v", reopened.RecoveryCounter(), recovered)
	}
	if err := reopened.Start(); err != nil {
		t.Fatal(err)
	}
	restored := NewStoreWithPersister(10, reopened)
	if err := restored.Restore(recovered); err != nil {
		t.Fatal(err)
	}
	got, ok := restored.FindByUEIPv4(updated.UEIPv4)
	if !ok || got.ID != updated.ID || got.SGWUser.TEID != updated.SGWUser.TEID {
		t.Fatalf("restored PGW-C session = %+v, %v", got, ok)
	}
	next, err := restored.Create(testSession(11))
	if err != nil {
		t.Fatal(err)
	}
	if next.ID <= updated.ID {
		t.Fatalf("restored next ID = %d, want greater than %d", next.ID, updated.ID)
	}
}

type failingPersister struct{ err error }

func (p failingPersister) Commit(_, _ *Session) error { return p.err }

func TestPGWCStorePoisonsAfterDurableFailure(t *testing.T) {
	store := NewStoreWithPersister(10, failingPersister{err: errors.New("disk full")})
	if _, err := store.Create(testSession(20)); !errors.Is(err, ErrPersistence) {
		t.Fatalf("durable create error = %v, want ErrPersistence", err)
	}
	if store.Count() != 0 {
		t.Fatal("failed durable create mutated PGW-C indexes")
	}
	if _, err := store.Create(testSession(21)); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("second mutation error = %v, want ErrPoisoned", err)
	}
}

func TestPGWCWALCompactsAndRestoresLatestRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pgwc-compact.wal")
	identity := []byte("pgwc=compact-test;apn=lodestartest;pool=10.90.0.0/24")
	log, _, err := OpenWAL(path, 16<<10, identity, 15)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Start(); err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithPersister(10, log)
	current, err := store.Create(testSession(30))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 80; index++ {
		current, err = store.Update(current.ID, current.Revision, func(candidate *Session) error {
			candidate.SGWUser.TEID++
			return nil
		})
		if err != nil {
			t.Fatalf("update %d: %v", index, err)
		}
	}
	if stats := log.Stats(); stats.Compactions == 0 || stats.Bytes >= 16<<10 {
		t.Fatalf("PGW-C compacted stats = %+v", stats)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, recovered, err := OpenWAL(path, 16<<10, identity, 15)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 1 || recovered[0].Revision != current.Revision || recovered[0].SGWUser != current.SGWUser {
		t.Fatalf("compacted PGW-C recovery = %+v, want revision %d SGW-U %v", recovered, current.Revision, current.SGWUser)
	}
	if err := reopened.Start(); err != nil {
		t.Fatal(err)
	}
	restored := NewStoreWithPersister(10, reopened)
	if err := restored.Restore(recovered); err != nil {
		t.Fatal(err)
	}
	if err := restored.Delete(current.ID, current.Revision); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	final, recovered, err := OpenWAL(path, 16<<10, identity, 15)
	if err != nil {
		t.Fatal(err)
	}
	defer final.Close()
	if len(recovered) != 0 {
		t.Fatalf("deleted PGW-C session recovered after compaction: %+v", recovered)
	}
}

func TestPGWCWALRestoresDedicatedBearer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pgwc-dedicated.wal")
	identity := []byte("pgwc=dedicated-test;apn=lodestartest;pool=10.90.0.0/24")
	log, _, err := OpenWAL(path, 1<<20, identity, 31)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Start(); err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithPersister(10, log)
	created, err := store.Create(testSession(41))
	if err != nil {
		t.Fatal(err)
	}
	bearer := testDedicatedBearer(6)
	bearer.PolicyID = "ims-voice"
	updated, err := store.Update(created.ID, created.Revision, func(candidate *Session) error {
		candidate.DedicatedBearers = map[uint8]Bearer{bearer.EBI: bearer}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, recovered, err := OpenWAL(path, 1<<20, identity, 31)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if len(recovered) != 1 || recovered[0].Revision != updated.Revision || len(recovered[0].DedicatedBearers) != 1 {
		t.Fatalf("recovered dedicated state = %#v", recovered)
	}
	restoredBearer := recovered[0].DedicatedBearers[bearer.EBI]
	if restoredBearer.PolicyID != bearer.PolicyID || restoredBearer.PGWUser != bearer.PGWUser || restoredBearer.SGWUser != bearer.SGWUser || restoredBearer.Rules.QER != 2 || len(restoredBearer.TFT) == 0 {
		t.Fatalf("recovered bearer = %#v", restoredBearer)
	}
}
