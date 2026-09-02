// Package association implements the PFCP user-plane association grace state
// machine shared by the SGW-U and PGW-U. It deliberately does not own session
// state: callers apply the returned transitions to their authoritative rule
// stores without holding the manager lock.
package association

import (
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"
)

type State string

const (
	StateUnavailable State = "unavailable"
	StateAssociated  State = "associated"
	StateGrace       State = "grace"
	StateReconciling State = "reconciling"
)

const (
	DefaultTimeout     = 15 * time.Second
	DefaultGraceWindow = 120 * time.Second
)

type Config struct {
	Timeout     time.Duration
	GraceWindow time.Duration
	Now         func() time.Time
}

type Record struct {
	Peer          netip.Addr
	NodeAddress   netip.Addr
	NodeFQDN      string
	RecoveryTime  time.Time
	State         State
	EstablishedAt time.Time
	LastSeen      time.Time
	GraceStarted  time.Time
	GraceDeadline time.Time
}

type SetupResult struct {
	Record          Record
	RecoveryChanged bool
	Reconcile       bool
}

type Transition struct {
	Peer netip.Addr
	From State
	To   State
}

type Manager struct {
	mu          sync.RWMutex
	records     map[netip.Addr]Record
	timeout     time.Duration
	graceWindow time.Duration
	now         func() time.Time
}

func New(config Config) (*Manager, error) {
	if config.Timeout == 0 {
		config.Timeout = DefaultTimeout
	}
	if config.GraceWindow == 0 {
		config.GraceWindow = DefaultGraceWindow
	}
	if config.Timeout < 0 || config.GraceWindow < 0 {
		return nil, errors.New("pfcp association: timeout and grace window must not be negative")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Manager{
		records: make(map[netip.Addr]Record), timeout: config.Timeout,
		graceWindow: config.GraceWindow, now: config.Now,
	}, nil
}

// Setup records an accepted Association Setup. A reconnect from grace, or a
// changed Recovery Time Stamp, enters reconciliation rather than deleting
// existing user-plane rules.
func (m *Manager) Setup(peer, nodeAddress netip.Addr, nodeFQDN string, recovery time.Time) SetupResult {
	peer = peer.Unmap()
	nodeAddress = nodeAddress.Unmap()
	now := m.now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	previous, existed := m.records[peer]
	recoveryChanged := existed && !previous.RecoveryTime.Equal(recovery)
	reconcile := existed && (previous.State == StateGrace || previous.State == StateReconciling || previous.State == StateUnavailable || recoveryChanged)
	established := now
	if existed && !previous.EstablishedAt.IsZero() {
		established = previous.EstablishedAt
	}
	state := StateAssociated
	if reconcile {
		state = StateReconciling
	}
	record := Record{
		Peer: peer, NodeAddress: nodeAddress, NodeFQDN: nodeFQDN,
		RecoveryTime: recovery.UTC(), State: state, EstablishedAt: established,
		LastSeen: now,
	}
	if reconcile {
		record.GraceStarted = previous.GraceStarted
		record.GraceDeadline = previous.GraceDeadline
		if record.GraceStarted.IsZero() {
			record.GraceStarted = now
			record.GraceDeadline = now.Add(m.graceWindow)
		}
	}
	m.records[peer] = record
	return SetupResult{Record: record, RecoveryChanged: recoveryChanged, Reconcile: reconcile}
}

// Touch updates liveness without implicitly leaving grace. Re-entry requires
// Association Setup followed by explicit reconciliation completion.
func (m *Manager) Touch(peer netip.Addr) {
	peer = peer.Unmap()
	now := m.now().UTC()
	m.mu.Lock()
	record, ok := m.records[peer]
	if ok {
		record.LastSeen = now
		m.records[peer] = record
	}
	m.mu.Unlock()
}

// Sweep advances inactive associations into grace and expires grace windows.
// It is deterministic and exposed so services can drive it from one ticker
// while tests use a controlled clock.
func (m *Manager) Sweep() []Transition {
	now := m.now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	transitions := make([]Transition, 0)
	for peer, record := range m.records {
		switch record.State {
		case StateAssociated:
			if m.timeout > 0 && !record.LastSeen.IsZero() && now.Sub(record.LastSeen) >= m.timeout {
				record.State = StateGrace
				record.GraceStarted = now
				record.GraceDeadline = now.Add(m.graceWindow)
				m.records[peer] = record
				transitions = append(transitions, Transition{Peer: peer, From: StateAssociated, To: StateGrace})
			}
		case StateGrace, StateReconciling:
			if !record.GraceDeadline.IsZero() && !now.Before(record.GraceDeadline) {
				from := record.State
				record.State = StateUnavailable
				record.GraceStarted = time.Time{}
				record.GraceDeadline = time.Time{}
				m.records[peer] = record
				transitions = append(transitions, Transition{Peer: peer, From: from, To: StateUnavailable})
			}
		}
	}
	sort.Slice(transitions, func(i, j int) bool { return transitions[i].Peer.Less(transitions[j].Peer) })
	return transitions
}

func (m *Manager) Complete(peer netip.Addr) bool {
	peer = peer.Unmap()
	now := m.now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.records[peer]
	if !ok || record.State != StateReconciling {
		return false
	}
	record.State = StateAssociated
	record.LastSeen = now
	record.GraceStarted = time.Time{}
	record.GraceDeadline = time.Time{}
	m.records[peer] = record
	return true
}

// RestoreUnavailable seeds a peer recovered from durable user-plane state.
// Its first Association Setup must enter reconciliation before new sessions
// are accepted.
func (m *Manager) RestoreUnavailable(peer netip.Addr) {
	peer = peer.Unmap()
	if !peer.IsValid() {
		return
	}
	m.mu.Lock()
	if _, exists := m.records[peer]; !exists {
		m.records[peer] = Record{Peer: peer, State: StateUnavailable}
	}
	m.mu.Unlock()
}

func (m *Manager) Release(peer netip.Addr) bool {
	peer = peer.Unmap()
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.records[peer]; !ok {
		return false
	}
	delete(m.records, peer)
	return true
}

func (m *Manager) State(peer netip.Addr) State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if record, ok := m.records[peer.Unmap()]; ok {
		return record.State
	}
	return StateUnavailable
}

func (m *Manager) CanCreate(peer netip.Addr) bool {
	return m.State(peer) == StateAssociated
}

func (m *Manager) CanMutate(peer netip.Addr) bool {
	state := m.State(peer)
	return state == StateAssociated || state == StateReconciling
}

func (m *Manager) Snapshot() []Record {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Record, 0, len(m.records))
	for _, record := range m.records {
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Peer.Less(out[j].Peer) })
	return out
}

func (m *Manager) GraceRemaining(peer netip.Addr) time.Duration {
	now := m.now().UTC()
	m.mu.RLock()
	record, ok := m.records[peer.Unmap()]
	m.mu.RUnlock()
	if !ok || (record.State != StateGrace && record.State != StateReconciling) || record.GraceDeadline.IsZero() {
		return 0
	}
	remaining := record.GraceDeadline.Sub(now)
	if remaining < 0 {
		return 0
	}
	return remaining
}
