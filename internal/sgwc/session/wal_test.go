package session

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/lodestarnetworks/cups/internal/controlstate"
)

func TestSGWCWALRoundTripRestoreAndFence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sgwc.wal")
	identity := []byte("sgwc=london-1;s11=10.20.0.1;salt=fingerprint")
	log, recovered, err := OpenWAL(path, 1<<20, identity, 41)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 0 || log.RecoveryCounter() != 41 {
		t.Fatalf("new state recovered=%+v counter=%d", recovered, log.RecoveryCounter())
	}
	if _, _, err := OpenWAL(path, 1<<20, identity, 41); !errors.Is(err, controlstate.ErrLocked) {
		t.Fatalf("second SGW-C owner error = %v, want ErrLocked", err)
	}
	if err := log.Start(); err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithPersister(10, log)
	created, err := store.Create(validSession(700))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := store.Update(created.ID, created.Revision, func(candidate *Session) error {
		candidate.State = StateActive
		bearer := candidate.Bearers[5]
		bearer.State = BearerActive
		candidate.Bearers[5] = bearer
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, recovered, err := OpenWAL(path, 1<<20, identity, 41)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.RecoveryCounter() != 42 || len(recovered) != 1 || recovered[0].Revision != updated.Revision {
		t.Fatalf("reopened counter=%d recovered=%+v", reopened.RecoveryCounter(), recovered)
	}
	if err := reopened.Start(); err != nil {
		t.Fatal(err)
	}
	restored := NewStoreWithPersister(10, reopened)
	if err := restored.Restore(recovered); err != nil {
		t.Fatal(err)
	}
	got, ok := restored.FindByOwner(updated.SubscriberKey, updated.APN)
	if !ok || got.ID != updated.ID || got.State != StateActive {
		t.Fatalf("restored SGW-C session = %+v, %v", got, ok)
	}
	nextCandidate := validSession(701)
	nextCandidate.SubscriberKey = "subscriber-hash-b"
	next, err := restored.Create(nextCandidate)
	if err != nil {
		t.Fatal(err)
	}
	if next.ID <= updated.ID {
		t.Fatalf("restored next ID = %d, want greater than %d", next.ID, updated.ID)
	}
}

type failingPersister struct{ err error }

func (p failingPersister) Commit(_, _ *Session) error { return p.err }

func TestSGWCStorePoisonsAfterDurableFailure(t *testing.T) {
	store := NewStoreWithPersister(10, failingPersister{err: errors.New("disk full")})
	if _, err := store.Create(validSession(800)); !errors.Is(err, ErrPersistence) {
		t.Fatalf("durable create error = %v, want ErrPersistence", err)
	}
	if store.Count() != 0 {
		t.Fatal("failed durable create mutated SGW-C indexes")
	}
	if _, err := store.Create(validSession(801)); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("second mutation error = %v, want ErrPoisoned", err)
	}
}

func TestSGWCWALCompactsAndRestoresLatestRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sgwc-compact.wal")
	identity := []byte("sgwc=compact-test;s11=10.20.0.1;salt=fingerprint")
	log, _, err := OpenWAL(path, 16<<10, identity, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Start(); err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithPersister(10, log)
	current, err := store.Create(validSession(900))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 80; index++ {
		current, err = store.Update(current.ID, current.Revision, func(candidate *Session) error {
			if candidate.State == StateActive {
				candidate.State = StateIdle
			} else {
				candidate.State = StateActive
			}
			return nil
		})
		if err != nil {
			t.Fatalf("update %d: %v", index, err)
		}
	}
	if stats := log.Stats(); stats.Compactions == 0 || stats.Bytes >= 16<<10 {
		t.Fatalf("SGW-C compacted stats = %+v", stats)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, recovered, err := OpenWAL(path, 16<<10, identity, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 1 || recovered[0].Revision != current.Revision || recovered[0].State != current.State {
		t.Fatalf("compacted SGW-C recovery = %+v, want revision %d state %s", recovered, current.Revision, current.State)
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
	final, recovered, err := OpenWAL(path, 16<<10, identity, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer final.Close()
	if len(recovered) != 0 {
		t.Fatalf("deleted SGW-C session recovered after compaction: %+v", recovered)
	}
}

func TestSGWCWALSemanticFailureDoesNotCommitStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sgwc-invalid.wal")
	identity := []byte("sgwc=semantic-test")
	config := controlstate.Config{
		Path: path, Magic: sgwcWALMagic, Identity: identity, MaxBytes: 1 << 20,
		MaxRecordBytes: controlstate.DefaultMaxRecord, RecoverySeed: 12,
	}
	journal, _, err := controlstate.Open(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Start(); err != nil {
		t.Fatal(err)
	}
	if err := journal.Append([]byte("valid frame, invalid SGW-C JSON")); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenWAL(path, 1<<20, identity, 12); !errors.Is(err, controlstate.ErrCorrupt) {
		t.Fatalf("semantic decode error = %v, want ErrCorrupt", err)
	}
	audit, records, err := controlstate.Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	if len(records) != 1 || audit.Stats().Starts != 1 || audit.RecoveryCounter() != 13 {
		t.Fatalf("semantic failure changed startup history: records=%d stats=%+v", len(records), audit.Stats())
	}
}
