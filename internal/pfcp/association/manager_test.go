package association

import (
	"net/netip"
	"testing"
	"time"
)

func TestGraceReconcileLifecycle(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 0, 0, 0, time.UTC)
	manager, err := New(Config{Timeout: 10 * time.Second, GraceWindow: 120 * time.Second, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	peer := netip.MustParseAddr("10.20.0.2")
	recovery := now.Add(-time.Hour)
	setup := manager.Setup(peer, peer, "", recovery)
	if setup.Reconcile || setup.Record.State != StateAssociated || !manager.CanCreate(peer) {
		t.Fatalf("initial setup = %+v", setup)
	}
	now = now.Add(11 * time.Second)
	transitions := manager.Sweep()
	if len(transitions) != 1 || transitions[0].To != StateGrace || manager.CanCreate(peer) || manager.CanMutate(peer) {
		t.Fatalf("grace transition = %+v, state=%s", transitions, manager.State(peer))
	}
	if got := manager.GraceRemaining(peer); got != 120*time.Second {
		t.Fatalf("grace remaining = %s", got)
	}
	now = now.Add(time.Second)
	setup = manager.Setup(peer, peer, "", recovery)
	if !setup.Reconcile || setup.Record.State != StateReconciling || manager.CanCreate(peer) || !manager.CanMutate(peer) {
		t.Fatalf("reconnect setup = %+v", setup)
	}
	if !manager.Complete(peer) || manager.State(peer) != StateAssociated || !manager.CanCreate(peer) {
		t.Fatalf("completion state = %s", manager.State(peer))
	}
}

func TestRecoveryChangeNeverPurgesInsideGrace(t *testing.T) {
	now := time.Date(2026, 8, 30, 2, 0, 0, 0, time.UTC)
	manager, _ := New(Config{Timeout: time.Minute, GraceWindow: 120 * time.Second, Now: func() time.Time { return now }})
	peer := netip.MustParseAddr("10.20.0.3")
	first := now.Add(-time.Hour)
	manager.Setup(peer, peer, "", first)
	result := manager.Setup(peer, peer, "", first.Add(time.Second))
	if !result.RecoveryChanged || !result.Reconcile || result.Record.State != StateReconciling {
		t.Fatalf("recovery transition = %+v", result)
	}
	now = now.Add(119 * time.Second)
	if transitions := manager.Sweep(); len(transitions) != 0 {
		t.Fatalf("expired early: %+v", transitions)
	}
	now = now.Add(time.Second)
	transitions := manager.Sweep()
	if len(transitions) != 1 || transitions[0].To != StateUnavailable {
		t.Fatalf("expiry transition = %+v", transitions)
	}
}

func TestTouchDoesNotImplicitlyLeaveGrace(t *testing.T) {
	now := time.Date(2026, 8, 30, 3, 0, 0, 0, time.UTC)
	manager, _ := New(Config{Timeout: time.Second, GraceWindow: time.Minute, Now: func() time.Time { return now }})
	peer := netip.MustParseAddr("10.20.0.4")
	manager.Setup(peer, peer, "", now)
	now = now.Add(2 * time.Second)
	manager.Sweep()
	manager.Touch(peer)
	if manager.State(peer) != StateGrace {
		t.Fatalf("state after touch = %s", manager.State(peer))
	}
}

func TestRecoveredPeerRequiresReconciliation(t *testing.T) {
	now := time.Date(2026, 8, 30, 4, 0, 0, 0, time.UTC)
	manager, _ := New(Config{Timeout: time.Minute, GraceWindow: 120 * time.Second, Now: func() time.Time { return now }})
	peer := netip.MustParseAddr("10.20.0.5")
	manager.RestoreUnavailable(peer)
	result := manager.Setup(peer, peer, "", now.Add(-time.Minute))
	if !result.Reconcile || result.Record.State != StateReconciling || manager.CanCreate(peer) {
		t.Fatalf("recovered setup = %+v", result)
	}
}
