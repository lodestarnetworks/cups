// Package session owns PGW-C PDN session state and its packet/control-plane
// lookup indexes.
package session

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

var (
	ErrNotFound       = errors.New("pgwc session: not found")
	ErrConflict       = errors.New("pgwc session: revision conflict")
	ErrDuplicate      = errors.New("pgwc session: duplicate owner, tunnel, or UE address")
	ErrCapacity       = errors.New("pgwc session: capacity reached")
	ErrInvalidSession = errors.New("pgwc session: invalid session")
	ErrPersistence    = errors.New("pgwc session: durable commit failed")
	ErrPoisoned       = errors.New("pgwc session: store is poisoned after a durable failure")
)

const (
	DefaultMaxSessions  = 1_000_000
	MaxDedicatedBearers = 10
)

type State string

const (
	StateActive   State = "active"
	StateDeleting State = "deleting"
)

type FTEID struct {
	TEID uint32
	IP   netip.Addr
}

// RuleIDs are the durable Sxb rules owned by one dedicated EPS bearer. A TFT
// filter can expand into multiple standards-based SDF PDRs.
type RuleIDs struct {
	UplinkPDRs   []uint16
	DownlinkPDRs []uint16
	UplinkFAR    uint32
	DownlinkFAR  uint32
	QER          uint32
	URR          uint32
}

type Bearer struct {
	PolicyID             string
	EBI                  uint8
	QCI                  uint8
	ARP                  uint8
	PreemptionCapable    bool
	PreemptionVulnerable bool
	UplinkMBR            uint64
	DownlinkMBR          uint64
	UplinkGBR            uint64
	DownlinkGBR          uint64
	SGWUser              FTEID
	PGWUser              FTEID
	Rules                RuleIDs
	TFT                  []byte
}

type Session struct {
	ID                 uint64
	Revision           uint64
	SubscriberKey      string
	APN                string
	State              State
	EBI                uint8
	QCI                uint8
	ARP                uint8
	UplinkMBR          uint64
	DownlinkMBR        uint64
	UplinkGBR          uint64
	DownlinkGBR        uint64
	APNAMBRUplinkBPS   uint64
	APNAMBRDownlinkBPS uint64
	UEIPv4             netip.Addr
	SGWControl         FTEID
	PGWControl         FTEID
	SGWUser            FTEID
	PGWUser            FTEID
	PFCPControlSEID    uint64
	PFCPUserSEID       uint64
	DedicatedBearers   map[uint8]Bearer
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type Persister interface {
	Commit(previous, next *Session) error
}

type Store struct {
	mu        sync.RWMutex
	byID      map[uint64]*Session
	byControl map[uint32]uint64
	byOwner   map[string]uint64
	byBearer  map[bearerOwner]uint64
	byUE      map[netip.Addr]uint64
	byPFCP    map[uint64]uint64
	nextID    atomic.Uint64
	now       func() time.Time
	max       int
	persister Persister
	poisoned  error
}

func NewStore() *Store { return NewStoreWithLimit(DefaultMaxSessions) }

func NewStoreWithLimit(maxSessions int) *Store {
	return NewStoreWithPersister(maxSessions, nil)
}

func NewStoreWithPersister(maxSessions int, persister Persister) *Store {
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}
	return &Store{
		byID: make(map[uint64]*Session), byControl: make(map[uint32]uint64),
		byOwner: make(map[string]uint64), byBearer: make(map[bearerOwner]uint64), byUE: make(map[netip.Addr]uint64),
		byPFCP: make(map[uint64]uint64), now: time.Now, max: maxSessions, persister: persister,
	}
}

func (s *Store) Create(candidate Session) (Session, error) {
	canonicalize(&candidate)
	if err := validate(candidate); err != nil {
		return Session{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkMutable(); err != nil {
		return Session{}, err
	}
	owner := ownerKey(candidate.SubscriberKey, candidate.APN)
	if _, ok := s.byOwner[owner]; ok {
		return Session{}, ErrDuplicate
	}
	if _, ok := s.byBearer[bearerOwnerKey(candidate.SubscriberKey, candidate.EBI)]; ok {
		return Session{}, ErrDuplicate
	}
	for ebi := range candidate.DedicatedBearers {
		if _, ok := s.byBearer[bearerOwnerKey(candidate.SubscriberKey, ebi)]; ok {
			return Session{}, ErrDuplicate
		}
	}
	if _, ok := s.byControl[candidate.PGWControl.TEID]; ok {
		return Session{}, ErrDuplicate
	}
	if _, ok := s.byUE[candidate.UEIPv4]; ok {
		return Session{}, ErrDuplicate
	}
	if _, ok := s.byPFCP[candidate.PFCPControlSEID]; ok {
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
	s.byControl[candidate.PGWControl.TEID] = candidate.ID
	s.byOwner[owner] = candidate.ID
	s.byBearer[bearerOwnerKey(candidate.SubscriberKey, candidate.EBI)] = candidate.ID
	for ebi := range candidate.DedicatedBearers {
		s.byBearer[bearerOwnerKey(candidate.SubscriberKey, ebi)] = candidate.ID
	}
	s.byUE[candidate.UEIPv4] = candidate.ID
	s.byPFCP[candidate.PFCPControlSEID] = candidate.ID
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

func (s *Store) FindByControlTEID(teid uint32) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findLocked(s.byControl[teid])
}

func (s *Store) FindByOwner(subscriber, apn string) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findLocked(s.byOwner[ownerKey(subscriber, apn)])
}

// FindBySubscriberAndEBI resolves the PDN that owns an EPS bearer identity.
// Create Session collision handling is defined on this tuple independently of
// APN and control TEID, so it has a dedicated constant-time index.
func (s *Store) FindBySubscriberAndEBI(subscriber string, ebi uint8) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findLocked(s.byBearer[bearerOwnerKey(subscriber, ebi)])
}

func (s *Store) FindByUEIPv4(addr netip.Addr) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findLocked(s.byUE[addr.Unmap()])
}

func (s *Store) FindByPFCPControlSEID(seid uint64) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findLocked(s.byPFCP[seid])
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
	canonicalize(&next)
	if next.ID != current.ID || next.SubscriberKey != current.SubscriberKey ||
		!strings.EqualFold(next.APN, current.APN) || next.UEIPv4 != current.UEIPv4 ||
		next.PGWControl != current.PGWControl || next.PGWUser != current.PGWUser ||
		next.PFCPControlSEID != current.PFCPControlSEID || next.PFCPUserSEID != current.PFCPUserSEID ||
		next.EBI != current.EBI {
		return Session{}, fmt.Errorf("%w: immutable identity changed", ErrInvalidSession)
	}
	if err := validate(next); err != nil {
		return Session{}, err
	}
	for ebi := range next.DedicatedBearers {
		if ownerID, exists := s.byBearer[bearerOwnerKey(next.SubscriberKey, ebi)]; exists && ownerID != id {
			return Session{}, ErrDuplicate
		}
	}
	next.Revision++
	next.UpdatedAt = s.now().UTC()
	previous := clone(*current)
	if err := s.persist(&previous, &next); err != nil {
		return Session{}, err
	}
	for ebi := range current.DedicatedBearers {
		if _, exists := next.DedicatedBearers[ebi]; !exists {
			delete(s.byBearer, bearerOwnerKey(current.SubscriberKey, ebi))
		}
	}
	for ebi := range next.DedicatedBearers {
		s.byBearer[bearerOwnerKey(next.SubscriberKey, ebi)] = id
	}
	stored := clone(next)
	s.byID[id] = &stored
	return clone(next), nil
}

// ReconcilePFCPUserSEID records a replacement UP-SEID after the PGW-U has
// restarted and the PGW-C has replayed the authoritative session. All other
// session identity remains immutable.
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
	delete(s.byControl, current.PGWControl.TEID)
	delete(s.byOwner, ownerKey(current.SubscriberKey, current.APN))
	delete(s.byBearer, bearerOwnerKey(current.SubscriberKey, current.EBI))
	for ebi := range current.DedicatedBearers {
		delete(s.byBearer, bearerOwnerKey(current.SubscriberKey, ebi))
	}
	delete(s.byUE, current.UEIPv4)
	delete(s.byPFCP, current.PFCPControlSEID)
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
	byControl := make(map[uint32]uint64, len(recovered))
	byOwner := make(map[string]uint64, len(recovered))
	byBearer := make(map[bearerOwner]uint64, len(recovered))
	byUE := make(map[netip.Addr]uint64, len(recovered))
	byPFCP := make(map[uint64]uint64, len(recovered))
	var maxID uint64
	for index, candidate := range recovered {
		canonicalize(&candidate)
		if err := validateWALSession(candidate); err != nil {
			return fmt.Errorf("recovered PGW-C session %d: %w", index, err)
		}
		if _, exists := byID[candidate.ID]; exists {
			return ErrDuplicate
		}
		if _, exists := byControl[candidate.PGWControl.TEID]; exists {
			return ErrDuplicate
		}
		owner := ownerKey(candidate.SubscriberKey, candidate.APN)
		if _, exists := byOwner[owner]; exists {
			return ErrDuplicate
		}
		bearer := bearerOwnerKey(candidate.SubscriberKey, candidate.EBI)
		if _, exists := byBearer[bearer]; exists {
			return ErrDuplicate
		}
		for ebi := range candidate.DedicatedBearers {
			key := bearerOwnerKey(candidate.SubscriberKey, ebi)
			if _, exists := byBearer[key]; exists {
				return ErrDuplicate
			}
			byBearer[key] = candidate.ID
		}
		if _, exists := byUE[candidate.UEIPv4]; exists {
			return ErrDuplicate
		}
		if _, exists := byPFCP[candidate.PFCPControlSEID]; exists {
			return ErrDuplicate
		}
		stored := clone(candidate)
		byID[candidate.ID] = &stored
		byControl[candidate.PGWControl.TEID] = candidate.ID
		byOwner[owner] = candidate.ID
		byBearer[bearer] = candidate.ID
		byUE[candidate.UEIPv4] = candidate.ID
		byPFCP[candidate.PFCPControlSEID] = candidate.ID
		if candidate.ID > maxID {
			maxID = candidate.ID
		}
	}
	s.byID, s.byControl, s.byOwner, s.byBearer, s.byUE, s.byPFCP = byID, byControl, byOwner, byBearer, byUE, byPFCP
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

func (s *Store) findLocked(id uint64) (Session, bool) {
	if id == 0 {
		return Session{}, false
	}
	stored, ok := s.byID[id]
	if !ok {
		return Session{}, false
	}
	return clone(*stored), true
}

func canonicalize(candidate *Session) {
	candidate.APN = strings.ToLower(strings.TrimSpace(candidate.APN))
	candidate.UEIPv4 = candidate.UEIPv4.Unmap()
	candidate.SGWControl.IP = candidate.SGWControl.IP.Unmap()
	candidate.PGWControl.IP = candidate.PGWControl.IP.Unmap()
	candidate.SGWUser.IP = candidate.SGWUser.IP.Unmap()
	candidate.PGWUser.IP = candidate.PGWUser.IP.Unmap()
	for ebi, bearer := range candidate.DedicatedBearers {
		bearer.PolicyID = strings.TrimSpace(bearer.PolicyID)
		bearer.SGWUser.IP = bearer.SGWUser.IP.Unmap()
		bearer.PGWUser.IP = bearer.PGWUser.IP.Unmap()
		candidate.DedicatedBearers[ebi] = bearer
	}
}

func validate(candidate Session) error {
	if candidate.SubscriberKey == "" || candidate.APN == "" || len(candidate.APN) > 100 ||
		strings.ContainsAny(candidate.APN, " \t\r\n") {
		return fmt.Errorf("%w: owner and APN are required", ErrInvalidSession)
	}
	if candidate.State != StateActive && candidate.State != StateDeleting {
		return fmt.Errorf("%w: invalid state %q", ErrInvalidSession, candidate.State)
	}
	if candidate.EBI < 5 || candidate.EBI > 15 || candidate.QCI == 0 || candidate.ARP == 0 || candidate.ARP > 15 {
		return fmt.Errorf("%w: invalid default bearer", ErrInvalidSession)
	}
	if !candidate.UEIPv4.Is4() || candidate.UEIPv4.IsUnspecified() || candidate.UEIPv4.IsMulticast() {
		return fmt.Errorf("%w: invalid UE IPv4 address", ErrInvalidSession)
	}
	for name, tunnel := range map[string]FTEID{
		"SGW control": candidate.SGWControl, "PGW control": candidate.PGWControl,
		"SGW user": candidate.SGWUser, "PGW user": candidate.PGWUser,
	} {
		if tunnel.TEID == 0 || !tunnel.IP.Is4() {
			return fmt.Errorf("%w: invalid %s F-TEID", ErrInvalidSession, name)
		}
	}
	if candidate.PFCPControlSEID == 0 || candidate.PFCPUserSEID == 0 {
		return fmt.Errorf("%w: PFCP SEIDs are required", ErrInvalidSession)
	}
	if len(candidate.DedicatedBearers) > MaxDedicatedBearers {
		return fmt.Errorf("%w: too many dedicated bearers", ErrInvalidSession)
	}
	usedPDR := map[uint16]struct{}{1: {}, 2: {}}
	usedFAR := map[uint32]struct{}{1: {}, 2: {}}
	usedQER := map[uint32]struct{}{1: {}}
	usedURR := map[uint32]struct{}{1: {}}
	localTEID := map[uint32]struct{}{candidate.PGWUser.TEID: {}}
	remoteTEID := map[uint32]struct{}{candidate.SGWUser.TEID: {}}
	policyIDs := make(map[string]struct{}, len(candidate.DedicatedBearers))
	for key, bearer := range candidate.DedicatedBearers {
		if err := validateDedicatedBearer(key, bearer); err != nil {
			return err
		}
		if key == candidate.EBI {
			return fmt.Errorf("%w: dedicated bearer reuses default EBI %d", ErrInvalidSession, key)
		}
		if _, duplicate := localTEID[bearer.PGWUser.TEID]; duplicate {
			return fmt.Errorf("%w: duplicate local user-plane TEID %d", ErrInvalidSession, bearer.PGWUser.TEID)
		}
		if _, duplicate := remoteTEID[bearer.SGWUser.TEID]; duplicate {
			return fmt.Errorf("%w: duplicate remote user-plane TEID %d", ErrInvalidSession, bearer.SGWUser.TEID)
		}
		localTEID[bearer.PGWUser.TEID], remoteTEID[bearer.SGWUser.TEID] = struct{}{}, struct{}{}
		if bearer.PolicyID != "" {
			if !ValidPolicyID(bearer.PolicyID) {
				return fmt.Errorf("%w: invalid dedicated-bearer policy identity", ErrInvalidSession)
			}
			if _, duplicate := policyIDs[bearer.PolicyID]; duplicate {
				return fmt.Errorf("%w: duplicate dedicated-bearer policy identity", ErrInvalidSession)
			}
			policyIDs[bearer.PolicyID] = struct{}{}
		}
		for _, id := range append(append([]uint16(nil), bearer.Rules.UplinkPDRs...), bearer.Rules.DownlinkPDRs...) {
			if _, duplicate := usedPDR[id]; duplicate {
				return fmt.Errorf("%w: duplicate PDR ID %d", ErrInvalidSession, id)
			}
			usedPDR[id] = struct{}{}
		}
		for _, id := range []uint32{bearer.Rules.UplinkFAR, bearer.Rules.DownlinkFAR} {
			if _, duplicate := usedFAR[id]; duplicate {
				return fmt.Errorf("%w: duplicate FAR ID %d", ErrInvalidSession, id)
			}
			usedFAR[id] = struct{}{}
		}
		if _, duplicate := usedQER[bearer.Rules.QER]; duplicate {
			return fmt.Errorf("%w: duplicate QER ID %d", ErrInvalidSession, bearer.Rules.QER)
		}
		if _, duplicate := usedURR[bearer.Rules.URR]; duplicate {
			return fmt.Errorf("%w: duplicate URR ID %d", ErrInvalidSession, bearer.Rules.URR)
		}
		usedQER[bearer.Rules.QER], usedURR[bearer.Rules.URR] = struct{}{}, struct{}{}
	}
	return nil
}

// ValidPolicyID validates the stable, URL-safe identity assigned by an
// authoritative policy service to one dedicated bearer.
func ValidPolicyID(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for index := range value {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("_.:-", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func validateDedicatedBearer(key uint8, bearer Bearer) error {
	if key != bearer.EBI || bearer.EBI < 5 || bearer.EBI > 15 || bearer.QCI == 0 || bearer.QCI == 255 || bearer.ARP == 0 || bearer.ARP > 15 {
		return fmt.Errorf("%w: invalid dedicated bearer identity or QoS", ErrInvalidSession)
	}
	for name, tunnel := range map[string]FTEID{"SGW user": bearer.SGWUser, "PGW user": bearer.PGWUser} {
		if tunnel.TEID == 0 || !tunnel.IP.Is4() {
			return fmt.Errorf("%w: invalid dedicated-bearer %s F-TEID", ErrInvalidSession, name)
		}
	}
	const maxBitrate = uint64(^uint32(0)) * 1000
	for _, rate := range []uint64{bearer.UplinkMBR, bearer.DownlinkMBR, bearer.UplinkGBR, bearer.DownlinkGBR} {
		if rate%1000 != 0 || rate > maxBitrate {
			return fmt.Errorf("%w: dedicated-bearer bitrate is outside the PFCP range", ErrInvalidSession)
		}
	}
	if bearer.UplinkGBR > bearer.UplinkMBR || bearer.DownlinkGBR > bearer.DownlinkMBR {
		return fmt.Errorf("%w: dedicated-bearer GBR exceeds MBR", ErrInvalidSession)
	}
	if len(bearer.Rules.UplinkPDRs) == 0 || len(bearer.Rules.DownlinkPDRs) == 0 ||
		bearer.Rules.UplinkFAR == 0 || bearer.Rules.DownlinkFAR == 0 || bearer.Rules.UplinkFAR == bearer.Rules.DownlinkFAR || bearer.Rules.QER == 0 || bearer.Rules.URR == 0 {
		return fmt.Errorf("%w: incomplete dedicated-bearer PFCP rule IDs", ErrInvalidSession)
	}
	seenPDR := make(map[uint16]struct{}, len(bearer.Rules.UplinkPDRs)+len(bearer.Rules.DownlinkPDRs))
	for _, id := range append(append([]uint16(nil), bearer.Rules.UplinkPDRs...), bearer.Rules.DownlinkPDRs...) {
		if id == 0 {
			return fmt.Errorf("%w: zero dedicated-bearer PDR ID", ErrInvalidSession)
		}
		if _, duplicate := seenPDR[id]; duplicate {
			return fmt.Errorf("%w: duplicate dedicated-bearer PDR ID %d", ErrInvalidSession, id)
		}
		seenPDR[id] = struct{}{}
	}
	tft, err := gtpv2.ParseBearerTFT(bearer.TFT)
	if err != nil || tft.Operation != gtpv2.TFTOperationCreate {
		return fmt.Errorf("%w: invalid dedicated-bearer TFT: %v", ErrInvalidSession, err)
	}
	uplink, downlink := 0, 0
	for _, filter := range tft.Filters {
		ipv4, err := filter.IPv4()
		if err != nil {
			return fmt.Errorf("%w: unsupported dedicated-bearer TFT: %v", ErrInvalidSession, err)
		}
		expansion := 1
		if !ipv4.HasProtocol && (ipv4.HasLocalPort || ipv4.HasRemotePort) {
			expansion = 2
		}
		switch filter.Direction {
		case gtpv2.TFTDirectionUplink:
			uplink += expansion
		case gtpv2.TFTDirectionDownlink:
			downlink += expansion
		case gtpv2.TFTDirectionBidirectional:
			uplink += expansion
			downlink += expansion
		default:
			return fmt.Errorf("%w: unsupported dedicated-bearer TFT direction", ErrInvalidSession)
		}
	}
	if uplink != len(bearer.Rules.UplinkPDRs) || downlink != len(bearer.Rules.DownlinkPDRs) || uplink+downlink > 64 {
		return fmt.Errorf("%w: TFT and PFCP PDR counts do not match", ErrInvalidSession)
	}
	return nil
}

func clone(candidate Session) Session {
	out := candidate
	if candidate.DedicatedBearers != nil {
		out.DedicatedBearers = make(map[uint8]Bearer, len(candidate.DedicatedBearers))
		for ebi, bearer := range candidate.DedicatedBearers {
			bearer.Rules.UplinkPDRs = append([]uint16(nil), bearer.Rules.UplinkPDRs...)
			bearer.Rules.DownlinkPDRs = append([]uint16(nil), bearer.Rules.DownlinkPDRs...)
			bearer.TFT = append([]byte(nil), bearer.TFT...)
			out.DedicatedBearers[ebi] = bearer
		}
	}
	return out
}

func ownerKey(subscriber, apn string) string {
	return subscriber + "\x00" + strings.ToLower(strings.TrimSpace(apn))
}

type bearerOwner struct {
	subscriber string
	ebi        uint8
}

func bearerOwnerKey(subscriber string, ebi uint8) bearerOwner {
	return bearerOwner{subscriber: subscriber, ebi: ebi}
}
