package lab

import (
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/internal/telemetry"
)

func TestAdvanceKeepsBoundedHistoryAndEvents(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	store := telemetry.NewStore(InitialSnapshot(now))
	generator := NewGenerator(store, now)

	for i := 1; i <= 200; i++ {
		generator.advance(now.Add(time.Duration(i) * time.Second))
	}
	snapshot := store.Snapshot()
	if len(snapshot.History) != historyLimit {
		t.Fatalf("history length = %d, want %d", len(snapshot.History), historyLimit)
	}
	if len(snapshot.Events) > 20 {
		t.Fatalf("events length = %d, want <= 20", len(snapshot.Events))
	}
}
