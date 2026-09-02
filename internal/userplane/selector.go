// Package userplane implements bounded, deterministic placement for regional
// LTE user-plane nodes. It owns admission accounting only; PFCP association and
// durable session journals remain the control plane's source of truth.
package userplane

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

const (
	maxNodes          = 256
	maxNodeCapacity   = 100_000_000
	maxAssignmentKey  = 256
	maxPlacementLabel = 63
)

var (
	ErrNoEligibleNode     = errors.New("user-plane selector: no eligible node")
	ErrCapacity           = errors.New("user-plane selector: capacity exhausted")
	ErrUnknownNode        = errors.New("user-plane selector: unknown node")
	ErrUnknownAssignment  = errors.New("user-plane selector: unknown assignment")
	ErrAssignmentMismatch = errors.New("user-plane selector: assignment owner mismatch")
	ErrNodeInUse          = errors.New("user-plane selector: node has active assignments")
)

// State controls whether a node may receive new sessions. Draining and
// unavailable nodes retain all existing assignments.
type State string

const (
	StateReady       State = "ready"
	StateDraining    State = "draining"
	StateUnavailable State = "unavailable"
)

type Node struct {
	ID         string
	Region     string
	Capacity   uint64
	State      State
	Generation uint64
}

type Request struct {
	Key                 string
	PreferredRegion     string
	AllowRegionFallback bool
}

type Assignment struct {
	Key        string
	NodeID     string
	Region     string
	Generation uint64
}

type NodeSnapshot struct {
	ID           string
	Region       string
	State        State
	Capacity     uint64
	Assignments  uint64
	Available    uint64
	OverCapacity bool
	Generation   uint64
}

type Stats struct {
	Assignments       uint64
	PlacementAttempts uint64
	PlacementAccepted uint64
	StickyHits        uint64
	RegionFallbacks   uint64
	NoEligibleRejects uint64
	CapacityRejects   uint64
	Restored          uint64
	Released          uint64
}

type nodeState struct {
	node Node
	used uint64
}

// Selector serializes placement and release so configured capacity can never
// be oversubscribed by concurrent new assignments. Restore deliberately allows
// an operator to lower capacity below recovered usage without losing ownership.
type Selector struct {
	mu             sync.RWMutex
	nodes          map[string]*nodeState
	assignments    map[string]string
	maxAssignments uint64
	stats          Stats
}

func New(nodes []Node, maxAssignments uint64) (*Selector, error) {
	if len(nodes) == 0 || len(nodes) > maxNodes {
		return nil, fmt.Errorf("user-plane selector: node count must be between 1 and %d", maxNodes)
	}
	if maxAssignments == 0 || maxAssignments > maxNodeCapacity*maxNodes {
		return nil, errors.New("user-plane selector: max assignments is outside the supported range")
	}
	selector := &Selector{
		nodes: make(map[string]*nodeState, len(nodes)), assignments: make(map[string]string),
		maxAssignments: maxAssignments,
	}
	for index, node := range nodes {
		if err := validateNode(node); err != nil {
			return nil, fmt.Errorf("user-plane selector: node %d: %w", index, err)
		}
		if _, duplicate := selector.nodes[node.ID]; duplicate {
			return nil, fmt.Errorf("user-plane selector: duplicate node %q", node.ID)
		}
		selector.nodes[node.ID] = &nodeState{node: node}
	}
	return selector, nil
}

// Assign returns the existing sticky assignment or atomically reserves one
// capacity unit on the least-loaded eligible node. Equal-load ties use
// rendezvous hashing, making selection independent of map iteration order.
func (s *Selector) Assign(request Request) (Assignment, error) {
	if err := validateRequest(request); err != nil {
		return Assignment{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.PlacementAttempts++
	if nodeID, exists := s.assignments[request.Key]; exists {
		s.stats.StickyHits++
		return assignment(request.Key, s.nodes[nodeID].node), nil
	}
	if uint64(len(s.assignments)) >= s.maxAssignments {
		s.stats.CapacityRejects++
		return Assignment{}, ErrCapacity
	}

	candidates, readyWithCapacity, readyAny := s.candidates(request.PreferredRegion)
	if len(candidates) == 0 && request.PreferredRegion != "" && request.AllowRegionFallback {
		candidates, readyWithCapacity, readyAny = s.candidates("")
		if len(candidates) != 0 {
			s.stats.RegionFallbacks++
		}
	}
	if len(candidates) == 0 {
		if readyAny && !readyWithCapacity {
			s.stats.CapacityRejects++
			return Assignment{}, ErrCapacity
		}
		s.stats.NoEligibleRejects++
		return Assignment{}, ErrNoEligibleNode
	}
	selected := candidates[0]
	for _, candidate := range candidates[1:] {
		if prefer(candidate, selected, request.Key) {
			selected = candidate
		}
	}
	selected.used++
	s.assignments[request.Key] = selected.node.ID
	s.stats.PlacementAccepted++
	return assignment(request.Key, selected.node), nil
}

// Restore reconstructs durable ownership regardless of current drain or
// availability state. Replaying the same key/node pair is idempotent.
func (s *Selector) Restore(key, nodeID string) (Assignment, error) {
	if err := validateKey(key); err != nil {
		return Assignment{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	node, exists := s.nodes[nodeID]
	if !exists {
		return Assignment{}, ErrUnknownNode
	}
	if current, exists := s.assignments[key]; exists {
		if current != nodeID {
			return Assignment{}, ErrAssignmentMismatch
		}
		return assignment(key, node.node), nil
	}
	if uint64(len(s.assignments)) >= s.maxAssignments {
		return Assignment{}, ErrCapacity
	}
	s.assignments[key] = nodeID
	node.used++
	s.stats.Restored++
	return assignment(key, node.node), nil
}

func (s *Selector) Release(key, nodeID string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.assignments[key]
	if !exists {
		return ErrUnknownAssignment
	}
	if current != nodeID {
		return ErrAssignmentMismatch
	}
	node, exists := s.nodes[current]
	if !exists || node.used == 0 {
		return errors.New("user-plane selector: internal assignment accounting mismatch")
	}
	delete(s.assignments, key)
	node.used--
	s.stats.Released++
	return nil
}

func (s *Selector) SetState(nodeID string, state State) error {
	if !validState(state) {
		return errors.New("user-plane selector: invalid node state")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	node, exists := s.nodes[nodeID]
	if !exists {
		return ErrUnknownNode
	}
	if node.node.State != state {
		node.node.State = state
		node.node.Generation++
	}
	return nil
}

// SetCapacity affects only future placements. A value below current usage is
// visible as OverCapacity and drains naturally as sessions are released.
func (s *Selector) SetCapacity(nodeID string, capacity uint64) error {
	if capacity == 0 || capacity > maxNodeCapacity {
		return errors.New("user-plane selector: node capacity is outside the supported range")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	node, exists := s.nodes[nodeID]
	if !exists {
		return ErrUnknownNode
	}
	if node.node.Capacity != capacity {
		node.node.Capacity = capacity
		node.node.Generation++
	}
	return nil
}

func (s *Selector) RemoveNode(nodeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, exists := s.nodes[nodeID]
	if !exists {
		return ErrUnknownNode
	}
	if node.used != 0 {
		return ErrNodeInUse
	}
	delete(s.nodes, nodeID)
	return nil
}

func (s *Selector) Snapshot() ([]NodeSnapshot, Stats) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nodes := make([]NodeSnapshot, 0, len(s.nodes))
	for _, current := range s.nodes {
		available := uint64(0)
		if current.used < current.node.Capacity {
			available = current.node.Capacity - current.used
		}
		nodes = append(nodes, NodeSnapshot{
			ID: current.node.ID, Region: current.node.Region, State: current.node.State,
			Capacity: current.node.Capacity, Assignments: current.used, Available: available,
			OverCapacity: current.used > current.node.Capacity, Generation: current.node.Generation,
		})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	stats := s.stats
	stats.Assignments = uint64(len(s.assignments))
	return nodes, stats
}

func (s *Selector) candidates(region string) (candidates []*nodeState, readyWithCapacity, readyAny bool) {
	for _, node := range s.nodes {
		if node.node.State != StateReady || region != "" && node.node.Region != region {
			continue
		}
		readyAny = true
		if node.used >= node.node.Capacity {
			continue
		}
		readyWithCapacity = true
		candidates = append(candidates, node)
	}
	return candidates, readyWithCapacity, readyAny
}

func prefer(candidate, current *nodeState, key string) bool {
	left := candidate.used * current.node.Capacity
	right := current.used * candidate.node.Capacity
	if left != right {
		return left < right
	}
	return rendezvousScore(key, candidate.node.ID) > rendezvousScore(key, current.node.ID)
}

func rendezvousScore(key, nodeID string) uint64 {
	digest := sha256.Sum256([]byte(key + "\x00" + nodeID))
	return binary.BigEndian.Uint64(digest[:8])
}

func assignment(key string, node Node) Assignment {
	return Assignment{Key: key, NodeID: node.ID, Region: node.Region, Generation: node.Generation}
}

func validateNode(node Node) error {
	if !validLabel(node.ID) {
		return errors.New("node ID must be a lowercase DNS label")
	}
	if !validLabel(node.Region) {
		return errors.New("region must be a lowercase DNS label")
	}
	if node.Capacity == 0 || node.Capacity > maxNodeCapacity {
		return errors.New("capacity is outside the supported range")
	}
	if !validState(node.State) {
		return errors.New("state must be ready, draining, or unavailable")
	}
	return nil
}

func validateRequest(request Request) error {
	if err := validateKey(request.Key); err != nil {
		return err
	}
	if request.PreferredRegion != "" && !validLabel(request.PreferredRegion) {
		return errors.New("user-plane selector: preferred region must be a lowercase DNS label")
	}
	return nil
}

func validateKey(key string) error {
	if strings.TrimSpace(key) != key || key == "" || len(key) > maxAssignmentKey {
		return errors.New("user-plane selector: assignment key must contain 1 to 256 non-space-padded bytes")
	}
	return nil
}

func validState(state State) bool {
	return state == StateReady || state == StateDraining || state == StateUnavailable
}

func validLabel(value string) bool {
	if len(value) == 0 || len(value) > maxPlacementLabel || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}
