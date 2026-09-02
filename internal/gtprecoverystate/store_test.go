package gtprecoverystate

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/lodestarnetworks/cups/internal/controlstate"
)

func TestStorePersistsCountersAndFencesOwners(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer-recovery.wal")
	identity := []byte("sgwc=london-1;peer-recovery=v1")
	store, err := Open(path, 1<<20, identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, 1<<20, identity); !errors.Is(err, controlstate.ErrLocked) {
		t.Fatalf("second owner error = %v, want ErrLocked", err)
	}
	if err := store.Start(); err != nil {
		t.Fatal(err)
	}
	for key, counter := range map[string]uint8{
		"s11|10.250.10.2:2123": 44,
		"s5|10.250.20.2:2123":  55,
	} {
		if err := store.Commit(key, counter); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Commit("s11|not-an-endpoint", 1); err == nil {
		t.Fatal("invalid key was accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, 1<<20, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got := reopened.Snapshot()
	if got["s11|10.250.10.2:2123"] != 44 || got["s5|10.250.20.2:2123"] != 55 || len(got) != 2 {
		t.Fatalf("recovered counters = %+v", got)
	}
}

func TestStoreCompactionPreservesLatestCounters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer-recovery-compact.wal")
	identity := []byte("sgwc=compact;peer-recovery=v1")
	store, err := Open(path, 2048, identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Start(); err != nil {
		t.Fatal(err)
	}
	for counter := 0; counter < 200; counter++ {
		if err := store.Commit("s11|10.250.10.2:2123", uint8(counter)); err != nil {
			t.Fatalf("counter %d: %v", counter, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, 2048, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := reopened.Snapshot()["s11|10.250.10.2:2123"]; got != 199 {
		t.Fatalf("compacted counter = %d, want 199", got)
	}
}
