package telemetry

import "testing"

func TestStoreReturnsIndependentSnapshot(t *testing.T) {
	store := NewStore(Snapshot{SGWC: SGWC{Peers: []Peer{{Name: "mme-a"}}}})
	first := store.Snapshot()
	first.SGWC.Peers[0].Name = "mutated"

	second := store.Snapshot()
	if second.SGWC.Peers[0].Name != "mme-a" {
		t.Fatalf("store snapshot was mutated through returned value: %q", second.SGWC.Peers[0].Name)
	}
}
