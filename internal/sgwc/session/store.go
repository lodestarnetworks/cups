// Package session owns SGW-C session and EPS bearer state.
package session

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrNotFound           = errors.New("sgwc session: not found")
	ErrConflict           = errors.New("sgwc session: revision conflict")
	ErrDuplicate          = errors.New("sgwc session: duplicate owner or TEID")
	ErrCapacity           = errors.New("sgwc session: capacity reached")
	ErrInvalidSession     = errors.New("sgwc session: invalid session")
	ErrPersistence        = errors.New("sgwc session: durable commit failed")
	ErrPoisoned           = errors.New("sgwc session: store is poisoned after a durable failure")
	ErrTEIDSpaceExhausted = errors.New("sgwc session: TEID allocation exhausted")
)

const DefaultMaxSessions = 1_000_000

type State string

const (
	StatePending  State = "pending"
	StateActive   State = "active"
	StateIdle     State = "idle"
	StateDeleting State = "deleting"
)

type BearerState string

const (
	BearerPending BearerState = "pending"
	BearerActive  BearerState = "active"
	BearerIdle    BearerState = "idle"
)

type FTEID struct {
	TEID uint32
	IP   netip.Addr
}

// RuleIDs records the PFCP rules owned by one EPS bearer. Keeping these IDs in
// durable control-plane state makes bearer removal and rollback unambiguous,
// including when several dedicated bearers share one PFCP session.
type RuleIDs struct {
	UplinkPDR   uint16
	DownlinkPDR uint16
	UplinkFAR   uint32
	DownlinkFAR uint32
	QER         uint32
	URR         uint32
}

type Bearer struct {
	EBI                  uint8
	QCI                  uint8
	ARP                  uint8
	PreemptionCapable    bool
	PreemptionVulnerable bool
	UplinkMBR            uint64
	DownlinkMBR          uint64
	UplinkGBR            uint64
	DownlinkGBR          uint64
	Default              bool
	State                BearerState
	ENBUser              FTEID
	SGWUAccess           FTEID
	SGWUCore             FTEID
	PGWUser              FTEID
	Rules                RuleIDs
}

type Session struct {
	ID              uint64
	Revision        uint64
	SubscriberKey   string
	APN             string
	State           State
	MMEControl      FTEID
	S11Control      FTEID
	S5Control       FTEID
	PGWControl      FTEID
	PFCPControlSEID uint64
	PFCPUserSEID    uint64
	Bearers         map[uint8]Bearer
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type Persister interface {
	Commit(previous, next *Session) error
}

type Store struct {
	mu        sync.RWMutex
	byID      map[uint64]*Session
	byS11     map[uint32]map[uint64]struct{}
	byS5      map[uint32]uint64
	byPFCP    map[uint64]uint64
	byOwner   map[string]uint64
	byBearer  map[bearerOwner]uint64
	nextID    atomic.Uint64
	now       func() time.Time
	max       int
	persister Persister
	poisoned  error
}

func NewStore() *Store {
	return NewStoreWithLimit(DefaultMaxSessions)
}

func NewStoreWithLimit(maxSessions int) *Store {
	return NewStoreWithPersister(maxSessions, nil)
}

func NewStoreWithPersister(maxSessions int, persister Persister) *Store {
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}
	return &Store{
		byID:      make(map[uint64]*Session),
		byS11:     make(map[uint32]map[uint64]struct{}),
		byS5:      make(map[uint32]uint64),
		byPFCP:    make(map[uint64]uint64),
		byOwner:   make(map[string]uint64),
		byBearer:  make(map[bearerOwner]uint64),
		now:       time.Now,
		max:       maxSessions,
		persister: persister,
	}
}

func (s *Store) Create(candidate Session) (Session, error) {
	if err := validate(candidate); err != nil {
		return Session{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkMutable(); err != nil {
		return Session{}, err
	}
	owner := ownerKey(candidate.SubscriberKey, candidate.APN)
	if _, exists := s.byOwner[owner]; exists {
		return Session{}, ErrDuplicate
	}
	for ebi := range candidate.Bearers {
		if _, exists := s.byBearer[bearerOwnerKey(candidate.SubscriberKey, ebi)]; exists {
			return Session{}, ErrDuplicate
		}
	}
	if ids := s.byS11[candidate.S11Control.TEID]; len(ids) > 0 {
		for id := range ids {
			existing := s.byID[id]
			if !sameS11Owner(*existing, candidate) || bearersOverlap(*existing, candidate) {
				return Session{}, ErrDuplicate
			}
		}
	}
	if _, exists := s.byS5[candidate.S5Control.TEID]; exists {
		return Session{}, ErrDuplicate
	}
	if _, exists := s.byPFCP[candidate.PFCPControlSEID]; exists {
		return Session{}, ErrDuplicate
	}
	if len(s.byID) >= s.max {
		return Session{}, ErrCapacity
	}
	now := s.now().UTC()
	candidate.ID = s.nextID.Add(1)
	candidate.Revision = 1
	candidate.CreatedAt = now
	candidate.UpdatedAt = now
	if err := s.persist(nil, &candidate); err != nil {
		return Session{}, err
	}
	stored := clone(candidate)
	s.byID[candidate.ID] = &stored
	if s.byS11[candidate.S11Control.TEID] == nil {
		s.byS11[candidate.S11Control.TEID] = make(map[uint64]struct{})
	}
	s.byS11[candidate.S11Control.TEID][candidate.ID] = struct{}{}
	s.byS5[candidate.S5Control.TEID] = candidate.ID
	s.byPFCP[candidate.PFCPControlSEID] = candidate.ID
	s.byOwner[owner] = candidate.ID
	for ebi := range candidate.Bearers {
		s.byBearer[bearerOwnerKey(candidate.SubscriberKey, ebi)] = candidate.ID
	}
	return clone(candidate), nil
}

func (s *Store) Find(id uint64) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stored, ok := s.byID[id]
	if !ok {
		return Session{}, false
	}
	return clone(*stored), true
}

func (s *Store) FindByS11TEID(teid uint32) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := newestID(s.byS11[teid])
	if !ok {
		return Session{}, false
	}
	return clone(*s.byID[id]), true
}

// FindByS11TEIDAndEBI returns the PDN session beneath an S11 control tunnel
// that owns ebi. A UE can have multiple PDNs (for example internet and IMS)
// sharing one SGW S11 TEID, while each default bearer EBI remains distinct.
func (s *Store) FindByS11TEIDAndEBI(teid uint32, ebi uint8) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := sortedIDs(s.byS11[teid])
	for index := len(ids) - 1; index >= 0; index-- {
		stored := s.byID[ids[index]]
		if _, ok := stored.Bearers[ebi]; ok {
			return clone(*stored), true
		}
	}
	return Session{}, false
}

// FindAllByS11TEID returns every PDN session sharing an S11 control tunnel in
// creation order. The returned sessions do not alias the store.
func (s *Store) FindAllByS11TEID(teid uint32) []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := sortedIDs(s.byS11[teid])
	out := make([]Session, 0, len(ids))
	for _, id := range ids {
		if stored, ok := s.byID[id]; ok {
			out = append(out, clone(*stored))
		}
	}
	return out
}

func (s *Store) FindByS5TEID(teid uint32) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byS5[teid]
	if !ok {
		return Session{}, false
	}
	return clone(*s.byID[id]), true
}

func (s *Store) FindByPFCPControlSEID(seid uint64) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byPFCP[seid]
	if !ok {
		return Session{}, false
	}
	return clone(*s.byID[id]), true
}

// FindByOwner resolves one subscriber/APN PDN in constant time. The owner
// index is the authoritative duplicate guard used by Create.
func (s *Store) FindByOwner(subscriberKey, apn string) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byOwner[ownerKey(subscriberKey, apn)]
	if !ok {
		return Session{}, false
	}
	return clone(*s.byID[id]), true
}

// FindBySubscriberAndEBI resolves the PDN that currently owns an EPS bearer
// identity for a subscriber. TS 29.274 defines a colliding SGW Create Session
// by the [IMSI, EBI] tuple, so this index must remain independent of APN and
// S11 TEID. Subscriber keys are already privacy-preserving hashes here.
func (s *Store) FindBySubscriberAndEBI(subscriberKey string, ebi uint8) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byBearer[bearerOwnerKey(subscriberKey, ebi)]
	if !ok {
		return Session{}, false
	}
	return clone(*s.byID[id]), true
}

func (s *Store) Update(id, expectedRevision uint64, mutate func(*Session) error) (Session, error) {
	if mutate == nil {
		return Session{}, fmt.Errorf("%w: nil mutation", ErrInvalidSession)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkMutable(); err != nil {
		return Session{}, err
	}
	current, ok := s.byID[id]
	if !ok {
		return Session{}, ErrNotFound
	}
	if current.Revision != expectedRevision {
		return Session{}, ErrConflict
	}
	next := clone(*current)
	if err := mutate(&next); err != nil {
		return Session{}, err
	}
	if next.ID != current.ID || next.SubscriberKey != current.SubscriberKey || !strings.EqualFold(next.APN, current.APN) {
		return Session{}, fmt.Errorf("%w: immutable owner fields changed", ErrInvalidSession)
	}
	if next.PFCPControlSEID != current.PFCPControlSEID || next.PFCPUserSEID != current.PFCPUserSEID {
		return Session{}, fmt.Errorf("%w: immutable PFCP SEIDs changed", ErrInvalidSession)
	}
	if err := validate(next); err != nil {
		return Session{}, err
	}
	for siblingID := range s.byS11[next.S11Control.TEID] {
		if siblingID == id {
			continue
		}
		if sibling, exists := s.byID[siblingID]; exists && bearersOverlap(*sibling, next) {
			return Session{}, ErrDuplicate
		}
	}
	for ebi := range next.Bearers {
		if ownerID, exists := s.byBearer[bearerOwnerKey(next.SubscriberKey, ebi)]; exists && ownerID != id {
			return Session{}, ErrDuplicate
		}
	}
	if next.S11Control != current.S11Control || next.MMEControl != current.MMEControl {
		return Session{}, fmt.Errorf("%w: immutable S11 control context changed", ErrInvalidSession)
	}
	if next.S5Control.TEID != current.S5Control.TEID {
		if _, exists := s.byS5[next.S5Control.TEID]; exists {
			return Session{}, ErrDuplicate
		}
	}
	next.Revision++
	next.UpdatedAt = s.now().UTC()
	previous := clone(*current)
	if err := s.persist(&previous, &next); err != nil {
		return Session{}, err
	}
	if next.S5Control.TEID != current.S5Control.TEID {
		delete(s.byS5, current.S5Control.TEID)
		s.byS5[next.S5Control.TEID] = id
	}
	for ebi := range current.Bearers {
		if _, exists := next.Bearers[ebi]; !exists {
			delete(s.byBearer, bearerOwnerKey(current.SubscriberKey, ebi))
		}
	}
	for ebi := range next.Bearers {
		s.byBearer[bearerOwnerKey(next.SubscriberKey, ebi)] = id
	}
	stored := clone(next)
	s.byID[id] = &stored
	return clone(next), nil
}

// ReconcilePFCPUserSEID records the replacement UP-SEID returned while
// replaying authoritative SGW-C state after an SGW-U restart. All GTP tunnel
// and subscriber identity remains unchanged.
func (s *Store) ReconcilePFCPUserSEID(id, expectedRevision, upSEID uint64) (Session, error) {
	if upSEID == 0 {
		return Session{}, fmt.Errorf("%w: zero reconciled UP-SEID", ErrInvalidSession)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkMutable(); err != nil {
		return Session{}, err
	}
	current, ok := s.byID[id]
	if !ok {
		return Session{}, ErrNotFound
	}
	if current.Revision != expectedRevision {
		return Session{}, ErrConflict
	}
	if current.PFCPUserSEID == upSEID {
		return clone(*current), nil
	}
	next := clone(*current)
	next.PFCPUserSEID = upSEID
	next.Revision++
	next.UpdatedAt = s.now().UTC()
	previous := clone(*current)
	if err := s.persist(&previous, &next); err != nil {
		return Session{}, err
	}
	stored := clone(next)
	s.byID[id] = &stored
	return clone(next), nil
}

func (s *Store) Delete(id, expectedRevision uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkMutable(); err != nil {
		return err
	}
	current, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	if current.Revision != expectedRevision {
		return ErrConflict
	}
	previous := clone(*current)
	if err := s.persist(&previous, nil); err != nil {
		return err
	}
	delete(s.byID, id)
	if ids := s.byS11[current.S11Control.TEID]; ids != nil {
		delete(ids, id)
		if len(ids) == 0 {
			delete(s.byS11, current.S11Control.TEID)
		}
	}
	delete(s.byS5, current.S5Control.TEID)
	delete(s.byPFCP, current.PFCPControlSEID)
	delete(s.byOwner, ownerKey(current.SubscriberKey, current.APN))
	for ebi := range current.Bearers {
		delete(s.byBearer, bearerOwnerKey(current.SubscriberKey, ebi))
	}
	return nil
}

func (s *Store) Snapshot() []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]uint64, 0, len(s.byID))
	for id := range s.byID {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := make([]Session, 0, len(ids))
	for _, id := range ids {
		out = append(out, clone(*s.byID[id]))
	}
	return out
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

func (s *Store) Capacity() int { return s.max }

// Restore validates and atomically indexes sessions recovered from the
// journal. Recovered records are not appended again.
func (s *Store) Restore(recovered []Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkMutable(); err != nil {
		return err
	}
	if len(s.byID) != 0 {
		return fmt.Errorf("%w: restore requires an empty store", ErrConflict)
	}
	if len(recovered) > s.max {
		return ErrCapacity
	}
	byID := make(map[uint64]*Session, len(recovered))
	byS11 := make(map[uint32]map[uint64]struct{})
	byS5 := make(map[uint32]uint64, len(recovered))
	byPFCP := make(map[uint64]uint64, len(recovered))
	byOwner := make(map[string]uint64, len(recovered))
	byBearer := make(map[bearerOwner]uint64, len(recovered))
	var maxID uint64
	for index, candidate := range recovered {
		if err := validateWALSession(candidate); err != nil {
			return fmt.Errorf("recovered SGW-C session %d: %w", index, err)
		}
		if _, exists := byID[candidate.ID]; exists {
			return ErrDuplicate
		}
		owner := ownerKey(candidate.SubscriberKey, candidate.APN)
		if _, exists := byOwner[owner]; exists {
			return ErrDuplicate
		}
		for ebi := range candidate.Bearers {
			key := bearerOwnerKey(candidate.SubscriberKey, ebi)
			if _, exists := byBearer[key]; exists {
				return ErrDuplicate
			}
			byBearer[key] = candidate.ID
		}
		if _, exists := byS5[candidate.S5Control.TEID]; exists {
			return ErrDuplicate
		}
		if _, exists := byPFCP[candidate.PFCPControlSEID]; exists {
			return ErrDuplicate
		}
		if ids := byS11[candidate.S11Control.TEID]; len(ids) > 0 {
			for siblingID := range ids {
				sibling := byID[siblingID]
				if !sameS11Owner(*sibling, candidate) || bearersOverlap(*sibling, candidate) {
					return ErrDuplicate
				}
			}
		}
		stored := clone(candidate)
		byID[candidate.ID] = &stored
		if byS11[candidate.S11Control.TEID] == nil {
			byS11[candidate.S11Control.TEID] = make(map[uint64]struct{})
		}
		byS11[candidate.S11Control.TEID][candidate.ID] = struct{}{}
		byS5[candidate.S5Control.TEID] = candidate.ID
		byPFCP[candidate.PFCPControlSEID] = candidate.ID
		byOwner[owner] = candidate.ID
		if candidate.ID > maxID {
			maxID = candidate.ID
		}
	}
	s.byID, s.byS11, s.byS5, s.byPFCP, s.byOwner, s.byBearer = byID, byS11, byS5, byPFCP, byOwner, byBearer
	s.nextID.Store(maxID)
	return nil
}

func (s *Store) persist(previous, next *Session) error {
	if s.persister == nil {
		return nil
	}
	if err := s.persister.Commit(previous, next); err != nil {
		s.poisoned = err
		return fmt.Errorf("%w: %w", ErrPersistence, err)
	}
	return nil
}

func (s *Store) checkMutable() error {
	if s.poisoned != nil {
		return fmt.Errorf("%w: %v", ErrPoisoned, s.poisoned)
	}
	return nil
}

func (s *Store) AllocateControlTEID() (uint32, error) {
	for attempt := 0; attempt < 256; attempt++ {
		var raw [4]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return 0, fmt.Errorf("allocate control TEID: %w", err)
		}
		candidate := binary.BigEndian.Uint32(raw[:])
		if candidate == 0 {
			continue
		}
		s.mu.RLock()
		_, s11Exists := s.byS11[candidate]
		_, s5Exists := s.byS5[candidate]
		s.mu.RUnlock()
		if !s11Exists && !s5Exists {
			return candidate, nil
		}
	}
	return 0, ErrTEIDSpaceExhausted
}

func (s *Store) AllocateS11TEID() (uint32, error) {
	return s.AllocateControlTEID()
}

func validate(candidate Session) error {
	if candidate.SubscriberKey == "" || candidate.APN == "" || candidate.S11Control.TEID == 0 || candidate.S5Control.TEID == 0 || candidate.PFCPControlSEID == 0 || candidate.PFCPUserSEID == 0 {
		return fmt.Errorf("%w: owner, APN, control TEIDs, and PFCP SEIDs are required", ErrInvalidSession)
	}
	if len(candidate.APN) > 100 || strings.ContainsAny(candidate.APN, " \t\r\n") {
		return fmt.Errorf("%w: malformed APN", ErrInvalidSession)
	}
	defaultBearers := 0
	for key, bearer := range candidate.Bearers {
		if key != bearer.EBI || bearer.EBI < 5 || bearer.EBI > 15 || bearer.QCI == 0 {
			return fmt.Errorf("%w: invalid bearer EBI/QCI", ErrInvalidSession)
		}
		if bearer.Default {
			defaultBearers++
		}
	}
	if defaultBearers != 1 {
		return fmt.Errorf("%w: exactly one default bearer is required", ErrInvalidSession)
	}
	return nil
}

func ownerKey(subscriberKey, apn string) string {
	return subscriberKey + "\x00" + strings.ToLower(apn)
}

type bearerOwner struct {
	subscriber string
	ebi        uint8
}

func bearerOwnerKey(subscriberKey string, ebi uint8) bearerOwner {
	return bearerOwner{subscriber: subscriberKey, ebi: ebi}
}

func sameS11Owner(left, right Session) bool {
	return left.SubscriberKey == right.SubscriberKey &&
		left.MMEControl == right.MMEControl &&
		left.S11Control == right.S11Control
}

func bearersOverlap(left, right Session) bool {
	for ebi := range left.Bearers {
		if _, exists := right.Bearers[ebi]; exists {
			return true
		}
	}
	return false
}

func newestID(ids map[uint64]struct{}) (uint64, bool) {
	var newest uint64
	for id := range ids {
		if id > newest {
			newest = id
		}
	}
	return newest, newest != 0
}

func sortedIDs(ids map[uint64]struct{}) []uint64 {
	out := make([]uint64, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func clone(in Session) Session {
	out := in
	out.Bearers = make(map[uint8]Bearer, len(in.Bearers))
	for ebi, bearer := range in.Bearers {
		out.Bearers[ebi] = bearer
	}
	return out
}
