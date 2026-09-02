// Package rules owns the PGW-U's atomically indexed Sxb session state.
package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

var (
	ErrNotFound       = errors.New("pgwu rules: session not found")
	ErrConflict       = errors.New("pgwu rules: revision conflict")
	ErrDuplicate      = errors.New("pgwu rules: duplicate session, tunnel, or UE address")
	ErrCapacity       = errors.New("pgwu rules: session capacity reached")
	ErrInvalidSession = errors.New("pgwu rules: invalid session")
	ErrDataplane      = errors.New("pgwu rules: dataplane apply failed")
	ErrPersistence    = errors.New("pgwu rules: durable commit failed")
	ErrPoisoned       = errors.New("pgwu rules: store is poisoned after rollback failure")
)

const (
	DefaultMaxSessions  = 1_000_000
	MaxDedicatedBearers = 10
	MaxFiltersPerBearer = 64
)

type Tunnel struct {
	TEID uint32
	IP   netip.Addr
}

// FlowFilter is one direction-specific SDF attached to a dedicated bearer.
// Filter uses UE-relative local/remote semantics from TS 24.008; the PFCP
// decoder translates the standard SDF Flow Description into this typed form.
type FlowFilter struct {
	PDRID      uint16
	Precedence uint32
	Direction  gtpv2.TFTDirection
	Filter     gtpv2.IPv4PacketFilter
}

// Bearer is an additional EPS bearer within one PGW-U PFCP session. The
// top-level Session forwarding fields remain the default bearer to avoid
// inflating the overwhelmingly common one-bearer session.
type Bearer struct {
	Local                    Tunnel
	Remote                   Tunnel
	UplinkFARID              uint32
	DownlinkFARID            uint32
	UplinkGateOpen           bool
	DownlinkGateOpen         bool
	MaxUplinkBitsPerSecond   uint64
	MaxDownlinkBitsPerSecond uint64
	QERID                    uint32
	URRID                    uint32
	MeasureVolume            bool
	MeasureDuration          bool
	UsageReportingThreshold  uint64
	QCI                      uint8
	ARP                      uint8
	Filters                  []FlowFilter
}

type Session struct {
	CPSEID                   uint64
	UPSEID                   uint64
	Revision                 uint64
	UEIPv4                   netip.Addr
	Local                    Tunnel
	Remote                   Tunnel
	UplinkPDRID              uint16
	DownlinkPDRID            uint16
	UplinkFARID              uint32
	DownlinkFARID            uint32
	UplinkGateOpen           bool
	DownlinkGateOpen         bool
	MaxUplinkBitsPerSecond   uint64
	MaxDownlinkBitsPerSecond uint64
	QERID                    uint32
	URRID                    uint32
	MeasureVolume            bool
	MeasureDuration          bool
	UsageReportingThreshold  uint64
	DedicatedBearers         []Bearer
	ControlPeer              netip.AddrPort
}

// PacketRule is the complete immutable bearer view consumed by the portable
// packet path. A generation remains active only while every index belongs to
// the same committed session revision.
type PacketRule struct {
	UPSEID                   uint64
	Revision                 uint64
	UEIPv4                   netip.Addr
	Local                    Tunnel
	Remote                   Tunnel
	UplinkGateOpen           bool
	DownlinkGateOpen         bool
	MaxUplinkBitsPerSecond   uint64
	MaxDownlinkBitsPerSecond uint64
	QERID                    uint32
	URRID                    uint32
	MeasureVolume            bool
	MeasureDuration          bool
	UsageReportingThreshold  uint64
	QCI                      uint8
	ARP                      uint8
	Default                  bool
	Filters                  []FlowFilter
	generation               *ruleGeneration
}

// Observer receives committed in-memory session changes. It is intended for
// telemetry and portable policy state which cannot fail a PFCP transaction.
// Implementations must not call back into Store.
type Observer interface {
	ReconcileSession(Session)
	DeleteSession(uint64)
}

// Applier commits one validated session transition to a forwarding backend.
// Store calls Apply while holding its write lock and commits desired state only
// after Apply succeeds. Implementations must not call back into Store and must
// roll back any partial external mutation before returning an error.
type Applier interface {
	Apply(previous, next *Session) error
}

// Reconciler atomically makes an external dataplane match recovered durable
// state, including removal of stale external entries.
type Reconciler interface {
	ReconcileSessions([]Session) error
}

// Persister durably records a validated transition. Store invokes it after
// the dataplane transition and before committing in-memory indexes.
type Persister interface {
	Commit(previous, next *Session) error
}

type Store struct {
	mu          sync.RWMutex
	byUP        map[uint64]*sessionRecord
	byCP        map[uint64]uint64
	uplink      sync.Map // uint32 TEID -> PacketRule
	downlink    sync.Map // netip.Addr -> downlinkRuleSet
	generations map[uint64]*ruleGeneration
	max         int
	applier     Applier
	persister   Persister
	observer    Observer
	poisoned    error
	installed   atomic.Uint64
	removed     atomic.Uint64
}

type sessionRecord struct {
	current atomic.Pointer[Session]
}

type ruleGeneration struct {
	active atomic.Bool
}

type downlinkCandidate struct {
	precedence uint32
	pdrID      uint16
	filter     gtpv2.IPv4PacketFilter
	rule       PacketRule
}

type downlinkRuleSet struct {
	generation *ruleGeneration
	candidates []downlinkCandidate
	fallback   PacketRule
}

type LifecycleCounters struct {
	Installed uint64
	Removed   uint64
}

func NewStore() *Store { return NewStoreWithLimit(DefaultMaxSessions) }

func NewStoreWithLimit(maxSessions int) *Store {
	return NewStoreWithApplier(maxSessions, nil)
}

func NewStoreWithApplier(maxSessions int, applier Applier) *Store {
	return NewStoreWithParticipants(maxSessions, applier, nil)
}

func NewStoreWithParticipants(maxSessions int, applier Applier, persister Persister) *Store {
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}
	return &Store{
		byUP: make(map[uint64]*sessionRecord), byCP: make(map[uint64]uint64),
		generations: make(map[uint64]*ruleGeneration), max: maxSessions,
		applier: applier, persister: persister,
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
	if _, ok := s.byUP[candidate.UPSEID]; ok {
		return Session{}, ErrDuplicate
	}
	if _, ok := s.byCP[candidate.CPSEID]; ok {
		return Session{}, ErrDuplicate
	}
	if _, ok := s.downlink.Load(candidate.UEIPv4); ok {
		return Session{}, ErrDuplicate
	}
	if err := s.checkTunnelConflicts(candidate, 0); err != nil {
		return Session{}, err
	}
	if len(s.byUP) >= s.max {
		return Session{}, ErrCapacity
	}
	candidate.Revision = 1
	if err := s.commit(nil, &candidate); err != nil {
		return Session{}, err
	}
	stored := clone(candidate)
	record := &sessionRecord{}
	record.current.Store(&stored)
	s.byUP[candidate.UPSEID] = record
	s.byCP[candidate.CPSEID] = candidate.UPSEID
	generation := &ruleGeneration{}
	s.indexSession(stored, generation)
	s.generations[candidate.UPSEID] = generation
	s.notifySession(stored)
	generation.active.Store(true)
	s.installed.Add(1)
	return clone(stored), nil
}

func (s *Store) FindByUPSEID(seid uint64) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findLocked(seid)
}

func (s *Store) FindByCPSEID(seid uint64) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findLocked(s.byCP[seid])
}

// LookupUplink is the compatibility control/test lookup. Packet workers use
// LookupUplinkPacket so TFTs are enforced before a bearer is selected.
func (s *Store) LookupUplink(teid uint32) (Session, bool) {
	value, ok := s.uplink.Load(teid)
	if !ok {
		return Session{}, false
	}
	rule := value.(PacketRule)
	if rule.generation == nil || !rule.generation.active.Load() {
		return Session{}, false
	}
	return s.FindByUPSEID(rule.UPSEID)
}

// LookupDownlink is the compatibility control/test lookup. Packet workers use
// LookupDownlinkPacket to classify dedicated-bearer SDFs by precedence.
func (s *Store) LookupDownlink(ueIPv4 netip.Addr) (Session, bool) {
	value, ok := s.downlink.Load(ueIPv4.Unmap())
	if !ok {
		return Session{}, false
	}
	rules := value.(downlinkRuleSet)
	if rules.generation == nil || !rules.generation.active.Load() {
		return Session{}, false
	}
	return s.FindByUPSEID(rules.fallback.UPSEID)
}

func (s *Store) LookupUplinkPacket(teid uint32, packet []byte) (PacketRule, bool) {
	value, ok := s.uplink.Load(teid)
	if !ok {
		return PacketRule{}, false
	}
	rule := value.(PacketRule)
	if rule.generation == nil || !rule.generation.active.Load() {
		return PacketRule{}, false
	}
	if rule.Default {
		return clonePacketRule(rule), true
	}
	for _, filter := range rule.Filters {
		if filter.Filter.Matches(packet, gtpv2.TFTDirectionUplink) {
			return clonePacketRule(rule), true
		}
	}
	return PacketRule{}, false
}

func (s *Store) LookupDownlinkPacket(ueIPv4 netip.Addr, packet []byte) (PacketRule, bool) {
	value, ok := s.downlink.Load(ueIPv4.Unmap())
	if !ok {
		return PacketRule{}, false
	}
	rules := value.(downlinkRuleSet)
	if rules.generation == nil || !rules.generation.active.Load() {
		return PacketRule{}, false
	}
	for _, candidate := range rules.candidates {
		if candidate.filter.Matches(packet, gtpv2.TFTDirectionDownlink) {
			return clonePacketRule(candidate.rule), true
		}
	}
	return clonePacketRule(rules.fallback), true
}

func (s *Store) Update(upSEID, expectedRevision uint64, mutate func(*Session) error) (Session, error) {
	if mutate == nil {
		return Session{}, fmt.Errorf("%w: nil mutation", ErrInvalidSession)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkMutable(); err != nil {
		return Session{}, err
	}
	record, ok := s.byUP[upSEID]
	if !ok {
		return Session{}, ErrNotFound
	}
	current := record.current.Load()
	if current.Revision != expectedRevision {
		return Session{}, ErrConflict
	}
	next := clone(*current)
	if err := mutate(&next); err != nil {
		return Session{}, err
	}
	canonicalize(&next)
	if next.CPSEID != current.CPSEID || next.UPSEID != current.UPSEID ||
		next.UEIPv4 != current.UEIPv4 || next.Local != current.Local || next.ControlPeer != current.ControlPeer {
		return Session{}, fmt.Errorf("%w: immutable identity changed", ErrInvalidSession)
	}
	if err := validate(next); err != nil {
		return Session{}, err
	}
	if err := s.checkTunnelConflicts(next, upSEID); err != nil {
		return Session{}, err
	}
	next.Revision++
	previous := clone(*current)
	if err := s.commit(&previous, &next); err != nil {
		return Session{}, err
	}
	oldGeneration := s.generations[upSEID]
	if oldGeneration != nil {
		oldGeneration.active.Store(false)
	}
	s.unindexSession(previous, oldGeneration)
	stored := clone(next)
	record.current.Store(&stored)
	generation := &ruleGeneration{}
	s.indexSession(stored, generation)
	s.generations[upSEID] = generation
	s.notifySession(stored)
	generation.active.Store(true)
	return clone(stored), nil
}

// Reconcile atomically replaces the rule set identified by CP-SEID while
// preserving the UP-SEID used by the existing forwarding path. It is only
// called while the PFCP association is in reconciliation state.
func (s *Store) Reconcile(cpSEID uint64, candidate Session) (Session, error) {
	if cpSEID == 0 || candidate.CPSEID != cpSEID {
		return Session{}, fmt.Errorf("%w: CP-SEID mismatch", ErrInvalidSession)
	}
	canonicalize(&candidate)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkMutable(); err != nil {
		return Session{}, err
	}
	upSEID, ok := s.byCP[cpSEID]
	if !ok {
		return Session{}, ErrNotFound
	}
	record := s.byUP[upSEID]
	current := record.current.Load()
	candidate.UPSEID = upSEID
	if err := validate(candidate); err != nil {
		return Session{}, err
	}
	if candidate.UEIPv4 != current.UEIPv4 || candidate.Local != current.Local || candidate.ControlPeer != current.ControlPeer {
		return Session{}, fmt.Errorf("%w: reconciliation cannot change UE, default local tunnel, or control owner", ErrInvalidSession)
	}
	if err := s.checkTunnelConflicts(candidate, upSEID); err != nil {
		return Session{}, err
	}
	candidate.Revision = current.Revision
	if reflect.DeepEqual(candidate, *current) {
		return clone(*current), nil
	}
	candidate.Revision = current.Revision + 1
	previous := clone(*current)
	if err := s.commit(&previous, &candidate); err != nil {
		return Session{}, err
	}
	oldGeneration := s.generations[upSEID]
	if oldGeneration != nil {
		oldGeneration.active.Store(false)
	}
	s.unindexSession(previous, oldGeneration)
	stored := clone(candidate)
	record.current.Store(&stored)
	generation := &ruleGeneration{}
	s.indexSession(stored, generation)
	s.generations[upSEID] = generation
	s.notifySession(stored)
	generation.active.Store(true)
	return clone(stored), nil
}

func (s *Store) Delete(upSEID, expectedRevision uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkMutable(); err != nil {
		return err
	}
	record, ok := s.byUP[upSEID]
	if !ok {
		return ErrNotFound
	}
	current := record.current.Load()
	if current.Revision != expectedRevision {
		return ErrConflict
	}
	previous := clone(*current)
	if err := s.commit(&previous, nil); err != nil {
		return err
	}
	generation := s.generations[upSEID]
	if generation != nil {
		generation.active.Store(false)
	}
	s.unindexSession(previous, generation)
	delete(s.byUP, upSEID)
	delete(s.byCP, current.CPSEID)
	delete(s.generations, upSEID)
	record.current.Store(nil)
	s.notifyDelete(upSEID)
	s.removed.Add(1)
	return nil
}

func (s *Store) DeleteByCPPeerSession(cpSEID uint64) bool {
	current, ok := s.FindByCPSEID(cpSEID)
	if !ok {
		return false
	}
	return s.Delete(current.UPSEID, current.Revision) == nil
}

func (s *Store) Snapshot() []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]uint64, 0, len(s.byUP))
	for id := range s.byUP {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := make([]Session, 0, len(ids))
	for _, id := range ids {
		if current := s.byUP[id].current.Load(); current != nil {
			out = append(out, clone(*current))
		}
	}
	return out
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byUP)
}

func (s *Store) Capacity() int { return s.max }

func (s *Store) LifecycleCounters() LifecycleCounters {
	return LifecycleCounters{Installed: s.installed.Load(), Removed: s.removed.Load()}
}

// SetObserver installs a non-failing observer and immediately reconciles it
// with the complete committed snapshot. It is safe to call once during
// startup after a portable dataplane has been constructed.
func (s *Store) SetObserver(observer Observer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observer = observer
	if observer == nil {
		return
	}
	for _, record := range s.byUP {
		if current := record.current.Load(); current != nil {
			observer.ReconcileSession(clone(*current))
		}
	}
}

// Restore validates and atomically indexes recovered sessions after making the
// dataplane match them. It deliberately does not append them to Persister: the
// records are already durable.
func (s *Store) Restore(recovered []Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkMutable(); err != nil {
		return err
	}
	if len(s.byUP) != 0 {
		return fmt.Errorf("%w: restore requires an empty store", ErrConflict)
	}
	if len(recovered) > s.max {
		return ErrCapacity
	}
	byUP := make(map[uint64]*sessionRecord, len(recovered))
	byCP := make(map[uint64]uint64, len(recovered))
	seenTunnel := make(map[uint32]struct{}, len(recovered))
	seenUE := make(map[netip.Addr]struct{}, len(recovered))
	canonical := make([]Session, len(recovered))
	for index, current := range recovered {
		canonicalize(&current)
		if current.Revision == 0 {
			return fmt.Errorf("%w: recovered session %d has zero revision", ErrInvalidSession, index)
		}
		if err := validate(current); err != nil {
			return fmt.Errorf("recovered session %d: %w", index, err)
		}
		if _, exists := byUP[current.UPSEID]; exists {
			return ErrDuplicate
		}
		if _, exists := byCP[current.CPSEID]; exists {
			return ErrDuplicate
		}
		if _, exists := seenUE[current.UEIPv4]; exists {
			return ErrDuplicate
		}
		for _, tunnel := range sessionLocalTunnels(current) {
			if _, exists := seenTunnel[tunnel.TEID]; exists {
				return ErrDuplicate
			}
			seenTunnel[tunnel.TEID] = struct{}{}
		}
		stored := clone(current)
		record := &sessionRecord{}
		record.current.Store(&stored)
		byUP[current.UPSEID] = record
		byCP[current.CPSEID] = current.UPSEID
		seenUE[current.UEIPv4] = struct{}{}
		canonical[index] = stored
	}
	if reconciler, ok := s.applier.(Reconciler); ok {
		if err := reconciler.ReconcileSessions(cloneSessions(canonical)); err != nil {
			return fmt.Errorf("%w: %w", ErrDataplane, err)
		}
	} else if s.applier != nil {
		applied := make([]Session, 0, len(canonical))
		for index := range canonical {
			if err := s.applier.Apply(nil, &canonical[index]); err != nil {
				var rollback error
				for appliedIndex := len(applied) - 1; appliedIndex >= 0; appliedIndex-- {
					rollback = errors.Join(rollback, s.applier.Apply(&applied[appliedIndex], nil))
				}
				if rollback != nil {
					s.poisoned = rollback
				}
				return errors.Join(fmt.Errorf("%w: restore session %d: %w", ErrDataplane, index, err), rollback)
			}
			applied = append(applied, clone(canonical[index]))
		}
	}
	s.byUP, s.byCP = byUP, byCP
	for _, current := range canonical {
		generation := &ruleGeneration{}
		s.indexSession(current, generation)
		s.generations[current.UPSEID] = generation
		generation.active.Store(true)
	}
	s.installed.Add(uint64(len(recovered)))
	if s.observer != nil {
		for _, current := range canonical {
			s.observer.ReconcileSession(clone(current))
		}
	}
	return nil
}

func (s *Store) notifySession(current Session) {
	if s.observer != nil {
		s.observer.ReconcileSession(clone(current))
	}
}

func (s *Store) notifyDelete(upSEID uint64) {
	if s.observer != nil {
		s.observer.DeleteSession(upSEID)
	}
}

func (s *Store) apply(previous, next *Session) error {
	if s.applier == nil {
		return nil
	}
	if err := s.applier.Apply(previous, next); err != nil {
		return fmt.Errorf("%w: %w", ErrDataplane, err)
	}
	return nil
}

func (s *Store) commit(previous, next *Session) error {
	if err := s.apply(previous, next); err != nil {
		return err
	}
	if s.persister == nil {
		return nil
	}
	if err := s.persister.Commit(previous, next); err != nil {
		var rollback error
		if s.applier != nil {
			rollback = s.applier.Apply(next, previous)
			if rollback != nil {
				s.poisoned = errors.Join(err, rollback)
			}
		}
		if s.poisoned == nil {
			s.poisoned = err
		}
		return errors.Join(fmt.Errorf("%w: %w", ErrPersistence, err), rollback)
	}
	return nil
}

func (s *Store) checkMutable() error {
	if s.poisoned != nil {
		return fmt.Errorf("%w: %v", ErrPoisoned, s.poisoned)
	}
	return nil
}

func (s *Store) findLocked(upSEID uint64) (Session, bool) {
	if upSEID == 0 {
		return Session{}, false
	}
	record, ok := s.byUP[upSEID]
	if !ok {
		return Session{}, false
	}
	return loadRecord(record)
}

func loadRecord(record *sessionRecord) (Session, bool) {
	if record == nil {
		return Session{}, false
	}
	current := record.current.Load()
	if current == nil {
		return Session{}, false
	}
	return clone(*current), true
}

func (s *Store) checkTunnelConflicts(candidate Session, replacingUPSEID uint64) error {
	for _, tunnel := range sessionLocalTunnels(candidate) {
		if value, ok := s.uplink.Load(tunnel.TEID); ok {
			rule := value.(PacketRule)
			if rule.UPSEID != replacingUPSEID {
				return fmt.Errorf("%w: uplink TEID %d", ErrDuplicate, tunnel.TEID)
			}
		}
	}
	return nil
}

func (s *Store) indexSession(current Session, generation *ruleGeneration) {
	fallback := compileDefaultRule(current, generation)
	s.uplink.Store(fallback.Local.TEID, fallback)
	set := downlinkRuleSet{generation: generation, fallback: fallback}
	for index := range current.DedicatedBearers {
		rule := compileDedicatedRule(current, current.DedicatedBearers[index], generation)
		s.uplink.Store(rule.Local.TEID, rule)
		for _, filter := range rule.Filters {
			if !filter.Filter.AppliesTo(gtpv2.TFTDirectionDownlink) {
				continue
			}
			set.candidates = append(set.candidates, downlinkCandidate{
				precedence: filter.Precedence, pdrID: filter.PDRID,
				filter: filter.Filter, rule: rule,
			})
		}
	}
	sort.SliceStable(set.candidates, func(i, j int) bool {
		if set.candidates[i].precedence != set.candidates[j].precedence {
			return set.candidates[i].precedence < set.candidates[j].precedence
		}
		return set.candidates[i].pdrID < set.candidates[j].pdrID
	})
	s.downlink.Store(current.UEIPv4, set)
}

func (s *Store) unindexSession(current Session, generation *ruleGeneration) {
	for _, tunnel := range sessionLocalTunnels(current) {
		if value, ok := s.uplink.Load(tunnel.TEID); ok && value.(PacketRule).generation == generation {
			s.uplink.Delete(tunnel.TEID)
		}
	}
	if value, ok := s.downlink.Load(current.UEIPv4); ok && value.(downlinkRuleSet).generation == generation {
		s.downlink.Delete(current.UEIPv4)
	}
}

func compileDefaultRule(current Session, generation *ruleGeneration) PacketRule {
	return PacketRule{
		UPSEID: current.UPSEID, Revision: current.Revision, UEIPv4: current.UEIPv4,
		Local: current.Local, Remote: current.Remote,
		UplinkGateOpen: current.UplinkGateOpen, DownlinkGateOpen: current.DownlinkGateOpen,
		MaxUplinkBitsPerSecond: current.MaxUplinkBitsPerSecond, MaxDownlinkBitsPerSecond: current.MaxDownlinkBitsPerSecond,
		QERID: current.QERID, URRID: current.URRID, MeasureVolume: current.MeasureVolume,
		MeasureDuration: current.MeasureDuration, UsageReportingThreshold: current.UsageReportingThreshold,
		Default: true, generation: generation,
	}
}

func compileDedicatedRule(current Session, bearer Bearer, generation *ruleGeneration) PacketRule {
	return PacketRule{
		UPSEID: current.UPSEID, Revision: current.Revision, UEIPv4: current.UEIPv4,
		Local: bearer.Local, Remote: bearer.Remote,
		UplinkGateOpen: bearer.UplinkGateOpen, DownlinkGateOpen: bearer.DownlinkGateOpen,
		MaxUplinkBitsPerSecond: bearer.MaxUplinkBitsPerSecond, MaxDownlinkBitsPerSecond: bearer.MaxDownlinkBitsPerSecond,
		QERID: bearer.QERID, URRID: bearer.URRID, MeasureVolume: bearer.MeasureVolume,
		MeasureDuration: bearer.MeasureDuration, UsageReportingThreshold: bearer.UsageReportingThreshold,
		QCI: bearer.QCI, ARP: bearer.ARP, Filters: cloneFilters(bearer.Filters), generation: generation,
	}
}

func sessionLocalTunnels(current Session) []Tunnel {
	out := make([]Tunnel, 0, 1+len(current.DedicatedBearers))
	out = append(out, current.Local)
	for _, bearer := range current.DedicatedBearers {
		out = append(out, bearer.Local)
	}
	return out
}

func canonicalize(candidate *Session) {
	candidate.UEIPv4 = candidate.UEIPv4.Unmap()
	candidate.Local.IP = candidate.Local.IP.Unmap()
	candidate.Remote.IP = candidate.Remote.IP.Unmap()
	if candidate.ControlPeer.IsValid() {
		candidate.ControlPeer = netip.AddrPortFrom(candidate.ControlPeer.Addr().Unmap(), candidate.ControlPeer.Port())
	}
	for index := range candidate.DedicatedBearers {
		bearer := &candidate.DedicatedBearers[index]
		bearer.Local.IP = bearer.Local.IP.Unmap()
		bearer.Remote.IP = bearer.Remote.IP.Unmap()
		for filterIndex := range bearer.Filters {
			filter := &bearer.Filters[filterIndex]
			filter.Filter.Direction = filter.Direction
			if filter.Filter.LocalAddress.IsValid() {
				filter.Filter.LocalAddress = filter.Filter.LocalAddress.Unmap()
			}
			if filter.Filter.LocalAddressMask.IsValid() {
				filter.Filter.LocalAddressMask = filter.Filter.LocalAddressMask.Unmap()
			}
			if filter.Filter.RemoteAddress.IsValid() {
				filter.Filter.RemoteAddress = filter.Filter.RemoteAddress.Unmap()
			}
			if filter.Filter.RemoteAddressMask.IsValid() {
				filter.Filter.RemoteAddressMask = filter.Filter.RemoteAddressMask.Unmap()
			}
		}
		sort.SliceStable(bearer.Filters, func(i, j int) bool {
			if bearer.Filters[i].Precedence != bearer.Filters[j].Precedence {
				return bearer.Filters[i].Precedence < bearer.Filters[j].Precedence
			}
			if bearer.Filters[i].Direction != bearer.Filters[j].Direction {
				return bearer.Filters[i].Direction < bearer.Filters[j].Direction
			}
			return bearer.Filters[i].PDRID < bearer.Filters[j].PDRID
		})
	}
	sort.SliceStable(candidate.DedicatedBearers, func(i, j int) bool {
		if candidate.DedicatedBearers[i].QERID != candidate.DedicatedBearers[j].QERID {
			return candidate.DedicatedBearers[i].QERID < candidate.DedicatedBearers[j].QERID
		}
		return candidate.DedicatedBearers[i].Local.TEID < candidate.DedicatedBearers[j].Local.TEID
	})
}

func validate(candidate Session) error {
	if candidate.CPSEID == 0 || candidate.UPSEID == 0 {
		return fmt.Errorf("%w: CP-SEID and UP-SEID are required", ErrInvalidSession)
	}
	if !candidate.UEIPv4.Is4() || candidate.UEIPv4.IsUnspecified() || candidate.UEIPv4.IsMulticast() {
		return fmt.Errorf("%w: valid UE IPv4 address is required", ErrInvalidSession)
	}
	if err := validateTunnel("default local", candidate.Local); err != nil {
		return err
	}
	if err := validateTunnel("default remote", candidate.Remote); err != nil {
		return err
	}
	legacyRuleIDs := candidate.UplinkPDRID == 0 && candidate.DownlinkPDRID == 0 && candidate.UplinkFARID == 0 && candidate.DownlinkFARID == 0
	if !legacyRuleIDs && (candidate.UplinkPDRID == 0 || candidate.DownlinkPDRID == 0 || candidate.UplinkPDRID == candidate.DownlinkPDRID ||
		candidate.UplinkFARID == 0 || candidate.DownlinkFARID == 0 || candidate.UplinkFARID == candidate.DownlinkFARID) {
		return fmt.Errorf("%w: default bearer has invalid rule IDs", ErrInvalidSession)
	}
	if candidate.ControlPeer.IsValid() && (!candidate.ControlPeer.Addr().Is4() || candidate.ControlPeer.Port() == 0) {
		return fmt.Errorf("%w: invalid control peer", ErrInvalidSession)
	}
	if err := validateUsage(candidate.URRID, candidate.MeasureVolume, candidate.MeasureDuration, candidate.UsageReportingThreshold); err != nil {
		return fmt.Errorf("default bearer: %w", err)
	}
	if len(candidate.DedicatedBearers) > MaxDedicatedBearers {
		return fmt.Errorf("%w: %d dedicated bearers exceeds %d", ErrInvalidSession, len(candidate.DedicatedBearers), MaxDedicatedBearers)
	}
	seenTEID := map[uint32]struct{}{candidate.Local.TEID: {}}
	seenQER := make(map[uint32]struct{}, 1+len(candidate.DedicatedBearers))
	seenURR := make(map[uint32]struct{}, 1+len(candidate.DedicatedBearers))
	seenFAR := make(map[uint32]struct{}, 2*len(candidate.DedicatedBearers))
	seenPDR := make(map[uint16]struct{}, 2*len(candidate.DedicatedBearers))
	if !legacyRuleIDs {
		seenFAR[candidate.UplinkFARID], seenFAR[candidate.DownlinkFARID] = struct{}{}, struct{}{}
		seenPDR[candidate.UplinkPDRID], seenPDR[candidate.DownlinkPDRID] = struct{}{}, struct{}{}
	}
	if candidate.QERID != 0 {
		seenQER[candidate.QERID] = struct{}{}
	}
	if candidate.URRID != 0 {
		seenURR[candidate.URRID] = struct{}{}
	}
	for index, bearer := range candidate.DedicatedBearers {
		if err := validateTunnel(fmt.Sprintf("dedicated bearer %d local", index), bearer.Local); err != nil {
			return err
		}
		if err := validateTunnel(fmt.Sprintf("dedicated bearer %d remote", index), bearer.Remote); err != nil {
			return err
		}
		if _, duplicate := seenTEID[bearer.Local.TEID]; duplicate {
			return fmt.Errorf("%w: duplicate local TEID %d", ErrInvalidSession, bearer.Local.TEID)
		}
		seenTEID[bearer.Local.TEID] = struct{}{}
		if bearer.QERID == 0 || bearer.URRID == 0 || bearer.UplinkFARID == 0 || bearer.DownlinkFARID == 0 || bearer.UplinkFARID == bearer.DownlinkFARID {
			return fmt.Errorf("%w: dedicated bearer %d has invalid rule IDs", ErrInvalidSession, index)
		}
		for _, farID := range []uint32{bearer.UplinkFARID, bearer.DownlinkFARID} {
			if _, duplicate := seenFAR[farID]; duplicate {
				return fmt.Errorf("%w: duplicate FAR ID %d", ErrInvalidSession, farID)
			}
			seenFAR[farID] = struct{}{}
		}
		if _, duplicate := seenQER[bearer.QERID]; duplicate {
			return fmt.Errorf("%w: duplicate QER ID %d", ErrInvalidSession, bearer.QERID)
		}
		if _, duplicate := seenURR[bearer.URRID]; duplicate {
			return fmt.Errorf("%w: duplicate URR ID %d", ErrInvalidSession, bearer.URRID)
		}
		seenQER[bearer.QERID], seenURR[bearer.URRID] = struct{}{}, struct{}{}
		// ARP zero is an explicit "not present on Sxb" value. Standard LTE
		// PFCP QERs do not carry ARP, while a deployment can still infer QCI 1
		// from its dedicated S5-U address. A non-zero ARP without QCI remains
		// invalid, as does the reserved QCI value 255.
		if (bearer.QCI == 0 && bearer.ARP != 0) || bearer.QCI == 255 || bearer.ARP > 15 {
			return fmt.Errorf("%w: dedicated bearer %d has invalid QCI/ARP metadata", ErrInvalidSession, index)
		}
		if err := validateUsage(bearer.URRID, bearer.MeasureVolume, bearer.MeasureDuration, bearer.UsageReportingThreshold); err != nil {
			return fmt.Errorf("dedicated bearer %d: %w", index, err)
		}
		if len(bearer.Filters) == 0 || len(bearer.Filters) > MaxFiltersPerBearer {
			return fmt.Errorf("%w: dedicated bearer %d has %d filters", ErrInvalidSession, index, len(bearer.Filters))
		}
		uplink, downlink := false, false
		for filterIndex, filter := range bearer.Filters {
			if filter.PDRID == 0 {
				return fmt.Errorf("%w: dedicated bearer %d filter %d has zero PDR ID", ErrInvalidSession, index, filterIndex)
			}
			if _, duplicate := seenPDR[filter.PDRID]; duplicate {
				return fmt.Errorf("%w: dedicated bearer %d duplicates PDR ID %d", ErrInvalidSession, index, filter.PDRID)
			}
			seenPDR[filter.PDRID] = struct{}{}
			switch filter.Direction {
			case gtpv2.TFTDirectionUplink:
				uplink = true
			case gtpv2.TFTDirectionDownlink:
				downlink = true
			case gtpv2.TFTDirectionBidirectional:
				uplink, downlink = true, true
			default:
				return fmt.Errorf("%w: dedicated bearer %d filter %d has invalid direction", ErrInvalidSession, index, filterIndex)
			}
			if err := validatePacketFilter(filter.Filter); err != nil {
				return fmt.Errorf("%w: dedicated bearer %d filter %d: %v", ErrInvalidSession, index, filterIndex, err)
			}
		}
		if !uplink || !downlink {
			return fmt.Errorf("%w: dedicated bearer %d must have uplink and downlink filters", ErrInvalidSession, index)
		}
	}
	return nil
}

func validatePacketFilter(filter gtpv2.IPv4PacketFilter) error {
	if filter.Direction != gtpv2.TFTDirectionDownlink && filter.Direction != gtpv2.TFTDirectionUplink && filter.Direction != gtpv2.TFTDirectionBidirectional {
		return errors.New("invalid packet-filter direction")
	}
	if err := validateFilterAddress("local", filter.HasLocalAddress, filter.LocalAddress, filter.LocalAddressMask); err != nil {
		return err
	}
	if err := validateFilterAddress("remote", filter.HasRemoteAddress, filter.RemoteAddress, filter.RemoteAddressMask); err != nil {
		return err
	}
	if !filter.HasProtocol && filter.Protocol != 0 {
		return errors.New("protocol value is present without protocol matching")
	}
	if err := validateFilterPort("local", filter.HasLocalPort, filter.LocalPortLow, filter.LocalPortHigh); err != nil {
		return err
	}
	if err := validateFilterPort("remote", filter.HasRemotePort, filter.RemotePortLow, filter.RemotePortHigh); err != nil {
		return err
	}
	if (filter.HasLocalPort || filter.HasRemotePort) && filter.HasProtocol && filter.Protocol != 6 && filter.Protocol != 17 && filter.Protocol != 132 {
		return fmt.Errorf("port matching is unsupported for IP protocol %d", filter.Protocol)
	}
	if !filter.HasTypeOfService && (filter.TypeOfService != 0 || filter.TypeOfServiceMask != 0) {
		return errors.New("ToS value is present without ToS matching")
	}
	return nil
}

func validateFilterAddress(name string, present bool, address, mask netip.Addr) error {
	if !present {
		if address.IsValid() || mask.IsValid() {
			return fmt.Errorf("%s address value is present without address matching", name)
		}
		return nil
	}
	if !address.Is4() || address.IsUnspecified() || address.IsMulticast() || !mask.Is4() || mask.IsUnspecified() {
		return fmt.Errorf("invalid %s IPv4 address or mask", name)
	}
	return nil
}

func validateFilterPort(name string, present bool, low, high uint16) error {
	if !present {
		if low != 0 || high != 0 {
			return fmt.Errorf("%s port value is present without port matching", name)
		}
		return nil
	}
	if low > high {
		return fmt.Errorf("descending %s port range", name)
	}
	return nil
}

func validateTunnel(name string, tunnel Tunnel) error {
	if tunnel.TEID == 0 || !tunnel.IP.Is4() || tunnel.IP.IsUnspecified() || tunnel.IP.IsMulticast() {
		return fmt.Errorf("%w: invalid %s tunnel", ErrInvalidSession, name)
	}
	return nil
}

func validateUsage(urrID uint32, measureVolume, measureDuration bool, threshold uint64) error {
	if urrID == 0 && (measureVolume || measureDuration || threshold != 0) {
		return fmt.Errorf("%w: usage policy requires a URR ID", ErrInvalidSession)
	}
	if urrID != 0 && !measureVolume && !measureDuration {
		return fmt.Errorf("%w: URR requires volume or duration measurement", ErrInvalidSession)
	}
	if threshold != 0 && !measureVolume {
		return fmt.Errorf("%w: usage threshold requires volume measurement", ErrInvalidSession)
	}
	return nil
}

func clone(in Session) Session {
	out := in
	if in.DedicatedBearers == nil {
		out.DedicatedBearers = nil
		return out
	}
	out.DedicatedBearers = make([]Bearer, len(in.DedicatedBearers))
	for index, bearer := range in.DedicatedBearers {
		out.DedicatedBearers[index] = bearer
		out.DedicatedBearers[index].Filters = cloneFilters(bearer.Filters)
	}
	return out
}

func cloneSessions(in []Session) []Session {
	out := make([]Session, len(in))
	for index := range in {
		out[index] = clone(in[index])
	}
	return out
}

func cloneFilters(in []FlowFilter) []FlowFilter {
	return append([]FlowFilter(nil), in...)
}

func clonePacketRule(in PacketRule) PacketRule {
	in.Filters = cloneFilters(in.Filters)
	return in
}
