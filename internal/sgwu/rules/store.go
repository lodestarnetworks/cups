// Package rules owns SGW-U PFCP session rules and validates rule references atomically.
package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrNotFound       = errors.New("sgwu rules: session not found")
	ErrConflict       = errors.New("sgwu rules: revision conflict")
	ErrDuplicate      = errors.New("sgwu rules: duplicate SEID")
	ErrCapacity       = errors.New("sgwu rules: session capacity reached")
	ErrInvalidSession = errors.New("sgwu rules: invalid PFCP session")
)

const DefaultMaxSessions = 1_000_000

type SourceInterface uint8

const (
	SourceAccess SourceInterface = iota
	SourceCore
)

type DestinationInterface uint8

const (
	DestinationAccess DestinationInterface = iota
	DestinationCore
)

type ApplyAction uint8

const (
	ActionDrop ApplyAction = 1 << iota
	ActionForward
	ActionBuffer
	ActionNotifyControlPlane
)

type FTEID struct {
	TEID uint32
	IP   netip.Addr
}

type PDR struct {
	ID              uint16
	Precedence      uint32
	SourceInterface SourceInterface
	LocalFTEID      FTEID
	FARID           uint32
	QERIDs          []uint32
	URRIDs          []uint32
}

type FAR struct {
	ID                   uint32
	ApplyAction          ApplyAction
	DestinationInterface DestinationInterface
	OuterHeader          *FTEID
	BARID                uint8
}

type QER struct {
	ID                       uint32
	UplinkGateOpen           bool
	DownlinkGateOpen         bool
	MaxUplinkBitsPerSecond   uint64
	MaxDownlinkBitsPerSecond uint64
	QCI                      uint8
	ARP                      uint8
	PreemptionCapable        bool
	PreemptionVulnerable     bool
}

type BAR struct {
	ID                        uint8
	DownlinkNotificationDelay time.Duration
}

type URR struct {
	ID                 uint32
	MeasureVolume      bool
	MeasureDuration    bool
	ReportingThreshold uint64
}

type Session struct {
	CPSEID   uint64
	UPSEID   uint64
	Revision uint64
	PDRs     map[uint16]PDR
	FARs     map[uint32]FAR
	QERs     map[uint32]QER
	URRs     map[uint32]URR
	BARs     map[uint8]BAR
}

// PacketRule is an immutable packet-path view of one matched PDR and its
// referenced rules. QoS is selected from the first QER carrying LTE metadata.
type PacketRule struct {
	UPSEID     uint64
	Revision   uint64
	PDR        PDR
	FAR        FAR
	QER        QER
	QERs       []QER
	URRs       []URR
	BAR        BAR
	generation *ruleGeneration
}

// Active reports whether the immutable packet view still belongs to the
// currently committed session generation. Standalone rules used by policy
// unit tests have no generation and are treated as active.
func (r PacketRule) Active() bool {
	return r.generation == nil || r.generation.active.Load()
}

type ruleGeneration struct {
	active atomic.Bool
}

type Store struct {
	mu          sync.RWMutex
	byUP        map[uint64]*Session
	byCP        map[uint64]uint64
	byTunnel    sync.Map // tunnelKey -> PacketRule
	byPDR       sync.Map // pdrKey -> PacketRule
	generations map[uint64]*ruleGeneration
	max         int
	installed   atomic.Uint64
	removed     atomic.Uint64
}

type LifecycleCounters struct {
	Installed uint64
	Removed   uint64
}

func NewStore() *Store {
	return NewStoreWithLimit(DefaultMaxSessions)
}

func NewStoreWithLimit(maxSessions int) *Store {
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}
	return &Store{
		byUP:        make(map[uint64]*Session),
		byCP:        make(map[uint64]uint64),
		generations: make(map[uint64]*ruleGeneration),
		max:         maxSessions,
	}
}

type tunnelKey struct {
	Source SourceInterface
	TEID   uint32
}

type pdrKey struct {
	UPSEID uint64
	PDRID  uint16
}

func (s *Store) Create(candidate Session) (Session, error) {
	if err := validate(candidate); err != nil {
		return Session{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byUP[candidate.UPSEID]; exists {
		return Session{}, ErrDuplicate
	}
	if _, exists := s.byCP[candidate.CPSEID]; exists {
		return Session{}, ErrDuplicate
	}
	if err := s.checkTunnelConflicts(candidate, 0); err != nil {
		return Session{}, err
	}
	if len(s.byUP) >= s.max {
		return Session{}, ErrCapacity
	}
	candidate.Revision = 1
	stored := clone(candidate)
	s.byUP[candidate.UPSEID] = &stored
	s.byCP[candidate.CPSEID] = candidate.UPSEID
	generation := &ruleGeneration{}
	s.indexSession(candidate, generation)
	s.generations[candidate.UPSEID] = generation
	generation.active.Store(true)
	s.installed.Add(1)
	return clone(candidate), nil
}

func (s *Store) FindByUPSEID(seid uint64) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stored, ok := s.byUP[seid]
	if !ok {
		return Session{}, false
	}
	return clone(*stored), true
}

func (s *Store) FindByCPSEID(seid uint64) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	upSEID, ok := s.byCP[seid]
	if !ok {
		return Session{}, false
	}
	return clone(*s.byUP[upSEID]), true
}

func (s *Store) Update(upSEID, expectedRevision uint64, mutate func(*Session) error) (Session, error) {
	if mutate == nil {
		return Session{}, fmt.Errorf("%w: nil mutation", ErrInvalidSession)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.byUP[upSEID]
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
	if next.CPSEID != current.CPSEID || next.UPSEID != current.UPSEID {
		return Session{}, fmt.Errorf("%w: SEIDs are immutable", ErrInvalidSession)
	}
	if err := validate(next); err != nil {
		return Session{}, err
	}
	if err := s.checkTunnelConflicts(next, upSEID); err != nil {
		return Session{}, err
	}
	next.Revision++
	if generation := s.generations[upSEID]; generation != nil {
		generation.active.Store(false)
	}
	s.unindexSession(*current)
	stored := clone(next)
	s.byUP[upSEID] = &stored
	generation := &ruleGeneration{}
	s.indexSession(next, generation)
	s.generations[upSEID] = generation
	generation.active.Store(true)
	return clone(next), nil
}

// Reconcile atomically replaces a CP-owned rule set while preserving its
// existing UP-SEID, allowing the packet path to remain stable through PFCP
// control-plane recovery.
func (s *Store) Reconcile(cpSEID uint64, candidate Session) (Session, error) {
	if cpSEID == 0 || candidate.CPSEID != cpSEID {
		return Session{}, fmt.Errorf("%w: CP-SEID mismatch", ErrInvalidSession)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	upSEID, ok := s.byCP[cpSEID]
	if !ok {
		return Session{}, ErrNotFound
	}
	current := s.byUP[upSEID]
	candidate.UPSEID = upSEID
	if err := validate(candidate); err != nil {
		return Session{}, err
	}
	if err := s.checkTunnelConflicts(candidate, upSEID); err != nil {
		return Session{}, err
	}
	candidate.Revision = current.Revision
	candidate = clone(candidate)
	if reflect.DeepEqual(candidate, *current) {
		return clone(*current), nil
	}
	candidate.Revision = current.Revision + 1
	if generation := s.generations[upSEID]; generation != nil {
		generation.active.Store(false)
	}
	s.unindexSession(*current)
	stored := clone(candidate)
	s.byUP[upSEID] = &stored
	generation := &ruleGeneration{}
	s.indexSession(candidate, generation)
	s.generations[upSEID] = generation
	generation.active.Store(true)
	return clone(candidate), nil
}

func (s *Store) Delete(upSEID, expectedRevision uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.byUP[upSEID]
	if !ok {
		return ErrNotFound
	}
	if current.Revision != expectedRevision {
		return ErrConflict
	}
	delete(s.byUP, upSEID)
	delete(s.byCP, current.CPSEID)
	if generation := s.generations[upSEID]; generation != nil {
		generation.active.Store(false)
	}
	s.unindexSession(*current)
	delete(s.generations, upSEID)
	s.removed.Add(1)
	return nil
}

func (s *Store) Capacity() int { return s.max }

func (s *Store) LifecycleCounters() LifecycleCounters {
	return LifecycleCounters{Installed: s.installed.Load(), Removed: s.removed.Load()}
}

// Lookup resolves the highest-precedence PDR and its FAR in constant time for
// an incoming GTP-U tunnel. PFCP validation guarantees that the FAR exists.
func (s *Store) Lookup(source SourceInterface, teid uint32) (PDR, FAR, bool) {
	_, pdr, far, ok := s.LookupSession(source, teid)
	return pdr, far, ok
}

// LookupSession also returns the owning UP-SEID. The user plane uses it to
// identify the PFCP session when reporting the first downlink packet for an
// idle bearer.
func (s *Store) LookupSession(source SourceInterface, teid uint32) (uint64, PDR, FAR, bool) {
	matched, ok := s.LookupPacket(source, teid)
	if !ok {
		return 0, PDR{}, FAR{}, false
	}
	return matched.UPSEID, matched.PDR, matched.FAR, true
}

// LookupPacket returns the complete immutable rule view used by the hot path.
func (s *Store) LookupPacket(source SourceInterface, teid uint32) (PacketRule, bool) {
	value, ok := s.byTunnel.Load(tunnelKey{Source: source, TEID: teid})
	if !ok {
		return PacketRule{}, false
	}
	matched := value.(PacketRule)
	if matched.generation == nil || !matched.generation.active.Load() {
		return PacketRule{}, false
	}
	return matched, true
}

// LookupByPDR resolves a previously matched bearer after a PFCP update. It is
// used when releasing buffered packets and therefore does not depend on a
// tunnel index that may have changed during handover.
func (s *Store) LookupByPDR(upSEID uint64, pdrID uint16) (PacketRule, bool) {
	value, ok := s.byPDR.Load(pdrKey{UPSEID: upSEID, PDRID: pdrID})
	if !ok {
		return PacketRule{}, false
	}
	matched := value.(PacketRule)
	if matched.generation == nil || !matched.generation.active.Load() {
		return PacketRule{}, false
	}
	return matched, true
}

func compilePacketRule(session Session, pdrID uint16) (PacketRule, bool) {
	pdr, ok := session.PDRs[pdrID]
	if !ok {
		return PacketRule{}, false
	}
	far, ok := session.FARs[pdr.FARID]
	if !ok {
		return PacketRule{}, false
	}
	pdr.QERIDs = append([]uint32(nil), pdr.QERIDs...)
	pdr.URRIDs = append([]uint32(nil), pdr.URRIDs...)
	if far.OuterHeader != nil {
		outer := *far.OuterHeader
		far.OuterHeader = &outer
	}
	matched := PacketRule{UPSEID: session.UPSEID, Revision: session.Revision, PDR: pdr, FAR: far}
	for _, qerID := range pdr.QERIDs {
		qer, exists := session.QERs[qerID]
		if !exists {
			return PacketRule{}, false
		}
		matched.QERs = append(matched.QERs, qer)
		if matched.QER.ID == 0 || (qer.QCI != 0 && matched.QER.QCI == 0) {
			matched.QER = qer
		}
	}
	for _, urrID := range pdr.URRIDs {
		urr, exists := session.URRs[urrID]
		if !exists {
			return PacketRule{}, false
		}
		matched.URRs = append(matched.URRs, urr)
	}
	if far.BARID != 0 {
		bar, exists := session.BARs[far.BARID]
		if !exists {
			return PacketRule{}, false
		}
		matched.BAR = bar
	}
	return matched, true
}

func (s *Store) GatesOpen(source SourceInterface, pdr PDR) bool {
	matched, ok := s.LookupPacket(source, pdr.LocalFTEID.TEID)
	if !ok || matched.PDR.ID != pdr.ID {
		return false
	}
	for _, qer := range matched.QERs {
		if source == SourceAccess && !qer.UplinkGateOpen {
			return false
		}
		if source == SourceCore && !qer.DownlinkGateOpen {
			return false
		}
	}
	return true
}

func (s *Store) Snapshot() []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Session, 0, len(s.byUP))
	for _, session := range s.byUP {
		out = append(out, clone(*session))
	}
	return out
}

func validate(candidate Session) error {
	if candidate.CPSEID == 0 || candidate.UPSEID == 0 {
		return fmt.Errorf("%w: CP-SEID and UP-SEID are required", ErrInvalidSession)
	}
	if len(candidate.PDRs) == 0 {
		return fmt.Errorf("%w: at least one PDR is required", ErrInvalidSession)
	}
	for id, pdr := range candidate.PDRs {
		if id == 0 || id != pdr.ID || pdr.LocalFTEID.TEID == 0 || !pdr.LocalFTEID.IP.IsValid() {
			return fmt.Errorf("%w: malformed PDR %d", ErrInvalidSession, id)
		}
		if _, exists := candidate.FARs[pdr.FARID]; !exists {
			return fmt.Errorf("%w: PDR %d references missing FAR %d", ErrInvalidSession, id, pdr.FARID)
		}
		for _, qerID := range pdr.QERIDs {
			if _, exists := candidate.QERs[qerID]; !exists {
				return fmt.Errorf("%w: PDR %d references missing QER %d", ErrInvalidSession, id, qerID)
			}
		}
		for _, urrID := range pdr.URRIDs {
			if _, exists := candidate.URRs[urrID]; !exists {
				return fmt.Errorf("%w: PDR %d references missing URR %d", ErrInvalidSession, id, urrID)
			}
		}
	}
	for id, far := range candidate.FARs {
		if id == 0 || id != far.ID || far.ApplyAction == 0 {
			return fmt.Errorf("%w: malformed FAR %d", ErrInvalidSession, id)
		}
		if far.ApplyAction&ActionDrop != 0 && far.ApplyAction&ActionForward != 0 {
			return fmt.Errorf("%w: FAR %d combines DROP and FORWARD", ErrInvalidSession, id)
		}
		if far.ApplyAction&ActionForward != 0 && (far.OuterHeader == nil || far.OuterHeader.TEID == 0 || !far.OuterHeader.IP.IsValid()) {
			return fmt.Errorf("%w: forwarding FAR %d lacks outer header", ErrInvalidSession, id)
		}
		if far.BARID != 0 {
			if _, exists := candidate.BARs[far.BARID]; !exists {
				return fmt.Errorf("%w: FAR %d references missing BAR %d", ErrInvalidSession, id, far.BARID)
			}
		}
	}
	for id, qer := range candidate.QERs {
		if id == 0 || id != qer.ID {
			return fmt.Errorf("%w: malformed QER %d", ErrInvalidSession, id)
		}
		if (qer.QCI == 0) != (qer.ARP == 0) || qer.ARP > 15 {
			return fmt.Errorf("%w: malformed QER %d bearer QoS metadata", ErrInvalidSession, id)
		}
	}
	for id, urr := range candidate.URRs {
		if id == 0 || id != urr.ID || (!urr.MeasureVolume && !urr.MeasureDuration) {
			return fmt.Errorf("%w: malformed URR %d", ErrInvalidSession, id)
		}
	}
	for id, bar := range candidate.BARs {
		if id == 0 || id != bar.ID || bar.DownlinkNotificationDelay < 0 || bar.DownlinkNotificationDelay > 12_750*time.Millisecond || bar.DownlinkNotificationDelay%(50*time.Millisecond) != 0 {
			return fmt.Errorf("%w: malformed BAR %d", ErrInvalidSession, id)
		}
	}
	return nil
}

func (s *Store) checkTunnelConflicts(candidate Session, replacingUPSEID uint64) error {
	for _, pdr := range candidate.PDRs {
		key := tunnelKey{Source: pdr.SourceInterface, TEID: pdr.LocalFTEID.TEID}
		if value, ok := s.byTunnel.Load(key); ok && value.(PacketRule).UPSEID != replacingUPSEID {
			return fmt.Errorf("%w: tunnel source=%d teid=%d", ErrDuplicate, key.Source, key.TEID)
		}
	}
	return nil
}

func (s *Store) indexSession(candidate Session, generation *ruleGeneration) {
	for _, pdr := range candidate.PDRs {
		matched, ok := compilePacketRule(candidate, pdr.ID)
		if !ok {
			continue
		}
		matched.generation = generation
		s.byPDR.Store(pdrKey{UPSEID: candidate.UPSEID, PDRID: pdr.ID}, matched)
		key := tunnelKey{Source: pdr.SourceInterface, TEID: pdr.LocalFTEID.TEID}
		value, exists := s.byTunnel.Load(key)
		if !exists || value.(PacketRule).PDR.Precedence > pdr.Precedence {
			s.byTunnel.Store(key, matched)
		}
	}
}

func (s *Store) unindexSession(candidate Session) {
	for _, pdr := range candidate.PDRs {
		s.byPDR.Delete(pdrKey{UPSEID: candidate.UPSEID, PDRID: pdr.ID})
		key := tunnelKey{Source: pdr.SourceInterface, TEID: pdr.LocalFTEID.TEID}
		if value, ok := s.byTunnel.Load(key); ok && value.(PacketRule).UPSEID == candidate.UPSEID {
			s.byTunnel.Delete(key)
		}
	}
}

func clone(in Session) Session {
	out := in
	out.PDRs = make(map[uint16]PDR, len(in.PDRs))
	for id, pdr := range in.PDRs {
		pdr.QERIDs = append([]uint32(nil), pdr.QERIDs...)
		pdr.URRIDs = append([]uint32(nil), pdr.URRIDs...)
		out.PDRs[id] = pdr
	}
	out.FARs = make(map[uint32]FAR, len(in.FARs))
	for id, far := range in.FARs {
		if far.OuterHeader != nil {
			outer := *far.OuterHeader
			far.OuterHeader = &outer
		}
		out.FARs[id] = far
	}
	out.QERs = make(map[uint32]QER, len(in.QERs))
	for id, qer := range in.QERs {
		out.QERs[id] = qer
	}
	out.URRs = make(map[uint32]URR, len(in.URRs))
	for id, urr := range in.URRs {
		out.URRs[id] = urr
	}
	out.BARs = make(map[uint8]BAR, len(in.BARs))
	for id, bar := range in.BARs {
		out.BARs[id] = bar
	}
	return out
}
