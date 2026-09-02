package admission

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFileGateTransitionsWithoutAffectingExistingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sgw-c.drain")
	gate, err := NewFileGate(path, 25*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	event, emit := gate.Refresh()
	if !emit || event.Draining || !gate.AllowNewSession() {
		t.Fatalf("initial state = %#v allow=%v", event, gate.AllowNewSession())
	}
	if err := os.WriteFile(path, []byte("operator maintenance\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	event, emit = gate.Refresh()
	if !emit || !event.Changed || !event.Draining || gate.AllowNewSession() {
		t.Fatalf("drain state = %#v allow=%v", event, gate.AllowNewSession())
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	event, emit = gate.Refresh()
	if !emit || !event.Changed || event.Draining || !gate.AllowNewSession() {
		t.Fatalf("ready state = %#v allow=%v", event, gate.AllowNewSession())
	}
	stats := gate.Stats()
	if !stats.Enabled || stats.Draining || stats.Transitions != 2 || stats.CheckErrors != 0 || stats.LastCheck.IsZero() {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestFileGateFailsClosedOnStatError(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	gate, err := NewFileGate(filepath.Join(parent, "drain"), 25*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	event, emit := gate.Refresh()
	if !emit || event.Err == nil || !event.Draining || gate.AllowNewSession() {
		t.Fatalf("stat failure = %#v allow=%v", event, gate.AllowNewSession())
	}
	if gate.Stats().CheckErrors != 1 {
		t.Fatalf("check errors = %d", gate.Stats().CheckErrors)
	}
	if _, emit = gate.Refresh(); emit || gate.Stats().CheckErrors != 2 {
		t.Fatalf("repeated stat failure emitted=%v stats=%#v", emit, gate.Stats())
	}
}

func TestFileGateRunObservesBoundedTransitions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pgw-c.drain")
	gate, err := NewFileGate(path, 25*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan Event, 4)
	go gate.Run(ctx, func(event Event) { events <- event })
	initial := receiveEvent(t, events)
	if initial.Draining {
		t.Fatal("initial gate unexpectedly draining")
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	draining := receiveEvent(t, events)
	if !draining.Changed || !draining.Draining {
		t.Fatalf("drain event = %#v", draining)
	}
	select {
	case unexpected := <-events:
		t.Fatalf("unchanged successful poll emitted %#v", unexpected)
	case <-time.After(80 * time.Millisecond):
	}
}

func TestFileGateConcurrentHotPathReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "drain")
	gate, err := NewFileGate(path, 25*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	gate.Refresh()
	var group sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for iteration := 0; iteration < 10_000; iteration++ {
				_ = gate.AllowNewSession()
				_ = gate.Stats()
			}
		}()
	}
	group.Wait()
}

func TestFileGateValidationAndDisabledMode(t *testing.T) {
	gate, err := NewFileGate("", 0)
	if err != nil || !gate.AllowNewSession() || gate.Enabled() {
		t.Fatalf("disabled gate = %#v, %v", gate, err)
	}
	for _, test := range []struct {
		path string
		poll time.Duration
	}{
		{path: "relative", poll: time.Second},
		{path: string(filepath.Separator), poll: time.Second},
		{path: filepath.Join(t.TempDir(), "drain"), poll: time.Millisecond},
		{path: filepath.Join(t.TempDir(), "drain"), poll: time.Minute},
		{path: "", poll: time.Second},
	} {
		if _, err := NewFileGate(test.path, test.poll); err == nil {
			t.Fatalf("NewFileGate(%q, %s) succeeded", test.path, test.poll)
		}
	}
}

func receiveEvent(t *testing.T, events <-chan Event) Event {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for admission event")
		return Event{}
	}
}
