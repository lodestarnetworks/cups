package userplane

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestSelectorBalancesDeterministicallyAndKeepsStickyAssignments(t *testing.T) {
	selector := newSelector(t, []Node{
		{ID: "london-a", Region: "london", Capacity: 100, State: StateReady},
		{ID: "london-b", Region: "london", Capacity: 100, State: StateReady},
	}, 200)
	first, err := selector.Assign(Request{Key: "subscriber-1", PreferredRegion: "london"})
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := selector.Assign(Request{Key: "subscriber-1", PreferredRegion: "manchester", AllowRegionFallback: true})
	if err != nil || repeated.NodeID != first.NodeID {
		t.Fatalf("sticky assignment = %#v, %v; first=%#v", repeated, err, first)
	}
	for index := 2; index <= 200; index++ {
		if _, err := selector.Assign(Request{Key: fmt.Sprintf("subscriber-%d", index), PreferredRegion: "london"}); err != nil {
			t.Fatal(err)
		}
	}
	nodes, stats := selector.Snapshot()
	if nodes[0].Assignments != 100 || nodes[1].Assignments != 100 || stats.Assignments != 200 || stats.StickyHits != 1 {
		t.Fatalf("nodes=%#v stats=%#v", nodes, stats)
	}
	if _, err := selector.Assign(Request{Key: "overflow", PreferredRegion: "london"}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("overflow error = %v", err)
	}
}

func TestSelectorDrainAndAvailabilityPreserveExistingAssignments(t *testing.T) {
	selector := newSelector(t, []Node{
		{ID: "london-a", Region: "london", Capacity: 10, State: StateReady},
		{ID: "london-b", Region: "london", Capacity: 10, State: StateDraining},
	}, 20)
	first, err := selector.Assign(Request{Key: "existing", PreferredRegion: "london"})
	if err != nil || first.NodeID != "london-a" {
		t.Fatalf("first assignment = %#v, %v", first, err)
	}
	if err := selector.SetState("london-a", StateDraining); err != nil {
		t.Fatal(err)
	}
	sticky, err := selector.Assign(Request{Key: "existing", PreferredRegion: "london"})
	if err != nil || sticky.NodeID != "london-a" {
		t.Fatalf("drained sticky assignment = %#v, %v", sticky, err)
	}
	if _, err := selector.Assign(Request{Key: "new", PreferredRegion: "london"}); !errors.Is(err, ErrNoEligibleNode) {
		t.Fatalf("all-draining error = %v", err)
	}
	if err := selector.SetState("london-b", StateReady); err != nil {
		t.Fatal(err)
	}
	second, err := selector.Assign(Request{Key: "new", PreferredRegion: "london"})
	if err != nil || second.NodeID != "london-b" {
		t.Fatalf("ready fallback assignment = %#v, %v", second, err)
	}
}

func TestSelectorRegionPreferenceAndExplicitFallback(t *testing.T) {
	selector := newSelector(t, []Node{
		{ID: "london-a", Region: "london", Capacity: 2, State: StateReady},
		{ID: "manchester-a", Region: "manchester", Capacity: 2, State: StateReady},
	}, 4)
	for index := 0; index < 2; index++ {
		placed, err := selector.Assign(Request{Key: fmt.Sprintf("lon-%d", index), PreferredRegion: "london"})
		if err != nil || placed.Region != "london" {
			t.Fatalf("London placement = %#v, %v", placed, err)
		}
	}
	if _, err := selector.Assign(Request{Key: "strict", PreferredRegion: "london"}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("strict full-region error = %v", err)
	}
	fallback, err := selector.Assign(Request{Key: "fallback", PreferredRegion: "london", AllowRegionFallback: true})
	if err != nil || fallback.Region != "manchester" {
		t.Fatalf("regional fallback = %#v, %v", fallback, err)
	}
	_, stats := selector.Snapshot()
	if stats.RegionFallbacks != 1 || stats.CapacityRejects != 1 {
		t.Fatalf("regional stats = %#v", stats)
	}
}

func TestSelectorRestoreCapacityReductionAndSafeRemoval(t *testing.T) {
	selector := newSelector(t, []Node{{ID: "london-a", Region: "london", Capacity: 10, State: StateUnavailable}}, 20)
	for index := 0; index < 5; index++ {
		key := fmt.Sprintf("restored-%d", index)
		if _, err := selector.Restore(key, "london-a"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := selector.Restore("restored-0", "london-a"); err != nil {
		t.Fatalf("idempotent restore: %v", err)
	}
	if err := selector.SetCapacity("london-a", 2); err != nil {
		t.Fatal(err)
	}
	nodes, stats := selector.Snapshot()
	if !nodes[0].OverCapacity || nodes[0].Available != 0 || stats.Restored != 5 {
		t.Fatalf("reduced-capacity snapshot=%#v stats=%#v", nodes, stats)
	}
	if err := selector.RemoveNode("london-a"); !errors.Is(err, ErrNodeInUse) {
		t.Fatalf("in-use removal error = %v", err)
	}
	for index := 0; index < 5; index++ {
		if err := selector.Release(fmt.Sprintf("restored-%d", index), "london-a"); err != nil {
			t.Fatal(err)
		}
	}
	if err := selector.RemoveNode("london-a"); err != nil {
		t.Fatal(err)
	}
}

func TestSelectorConcurrentCapacityIsExact(t *testing.T) {
	nodes := []Node{
		{ID: "london-a", Region: "london", Capacity: 500, State: StateReady},
		{ID: "london-b", Region: "london", Capacity: 500, State: StateReady},
		{ID: "london-c", Region: "london", Capacity: 500, State: StateReady},
		{ID: "london-d", Region: "london", Capacity: 500, State: StateReady},
	}
	selector := newSelector(t, nodes, 2_000)
	assignments := make([]Assignment, 2_000)
	var group sync.WaitGroup
	errorsCh := make(chan error, len(assignments))
	for index := range assignments {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			assigned, err := selector.Assign(Request{Key: fmt.Sprintf("session-%d", index), PreferredRegion: "london"})
			assignments[index] = assigned
			if err != nil {
				errorsCh <- err
			}
		}(index)
	}
	group.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
	snapshot, stats := selector.Snapshot()
	if stats.Assignments != 2_000 {
		t.Fatalf("assignments = %d", stats.Assignments)
	}
	for _, node := range snapshot {
		if node.Assignments != 500 || node.Available != 0 {
			t.Fatalf("node capacity accounting = %#v", node)
		}
	}
	releaseErrors := make(chan error, len(assignments))
	for _, current := range assignments {
		group.Add(1)
		go func(current Assignment) {
			defer group.Done()
			if err := selector.Release(current.Key, current.NodeID); err != nil {
				releaseErrors <- err
			}
		}(current)
	}
	group.Wait()
	close(releaseErrors)
	for err := range releaseErrors {
		t.Error(err)
	}
	_, stats = selector.Snapshot()
	if stats.Assignments != 0 || stats.Released != 2_000 {
		t.Fatalf("release stats = %#v", stats)
	}
}

func TestSelectorValidationAndOwnershipChecks(t *testing.T) {
	for _, nodes := range [][]Node{
		nil,
		{{ID: "London", Region: "london", Capacity: 1, State: StateReady}},
		{{ID: "london-a", Region: "", Capacity: 1, State: StateReady}},
		{{ID: "london-a", Region: "london", Capacity: 0, State: StateReady}},
		{{ID: "london-a", Region: "london", Capacity: 1, State: "active"}},
		{{ID: "london-a", Region: "london", Capacity: 1, State: StateReady}, {ID: "london-a", Region: "london", Capacity: 1, State: StateReady}},
	} {
		if _, err := New(nodes, 10); err == nil {
			t.Fatalf("invalid nodes accepted: %#v", nodes)
		}
	}
	selector := newSelector(t, []Node{{ID: "london-a", Region: "london", Capacity: 2, State: StateReady}}, 2)
	assigned, err := selector.Assign(Request{Key: "session"})
	if err != nil {
		t.Fatal(err)
	}
	if err := selector.Release(assigned.Key, "wrong-node"); !errors.Is(err, ErrAssignmentMismatch) {
		t.Fatalf("wrong-node release = %v", err)
	}
	if _, err := selector.Restore(assigned.Key, "unknown"); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("unknown-node restore = %v", err)
	}
}

func newSelector(t *testing.T, nodes []Node, maxAssignments uint64) *Selector {
	t.Helper()
	selector, err := New(nodes, maxAssignments)
	if err != nil {
		t.Fatal(err)
	}
	return selector
}
