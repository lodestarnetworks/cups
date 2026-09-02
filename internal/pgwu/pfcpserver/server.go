// Package pfcpserver implements the PGW-U side of the LTE Sxb interface.
package pfcpserver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	pfcpassociation "github.com/lodestarnetworks/cups/internal/pfcp/association"
	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	"github.com/lodestarnetworks/cups/internal/pfcp/usagereport"
	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
	"github.com/lodestarnetworks/cups/pkg/pfcp"
)

type Config struct {
	Listen             netip.AddrPort
	Advertise          netip.Addr
	UserIP             netip.Addr
	DedicatedUserIP    netip.Addr
	AllowedCP          []netip.Addr
	StartedAt          time.Time
	AssociationTimeout time.Duration
	GraceWindow        time.Duration
	EnterpriseID       uint16
	Transport          pfcptransport.Config
	OnError            func(ErrorEvent)
}

// ErrorEvent reports the internal reason a PFCP operation was rejected. The
// protocol response remains deliberately coarse; operators receive enough
// local context to distinguish malformed rules, dataplane failures, and
// durable-state failures without exposing implementation details to peers.
type ErrorEvent struct {
	Procedure string
	Peer      netip.AddrPort
	Err       error
}

type Association = pfcpassociation.Record

type Counters struct {
	AssociationsEstablished uint64
	SessionsEstablished     uint64
	SessionsModified        uint64
	SessionsDeleted         uint64
	RejectedRequests        uint64
	PeerRestarts            uint64
	GraceEntries            uint64
	GraceExpirations        uint64
	Reconciliations         uint64
	StaleSessionsPurged     uint64
	UsageReportsGenerated   uint64
	UsageReportsSent        uint64
	UsageReportsRetried     uint64
	UsageReportsFailed      uint64
	UsageReportsPending     uint64
	UsageReportQueueFull    uint64
	UsageCounterResets      uint64
	UsageTrackedURRs        uint64
}

type Server struct {
	config   Config
	endpoint *pfcptransport.Endpoint
	store    *rules.Store

	mu               sync.RWMutex
	associations     *pfcpassociation.Manager
	sessionOwner     map[uint64]netip.AddrPort
	reconcilePending map[netip.Addr]map[uint64]struct{}
	usageEmitter     *usagereport.Emitter

	associationsEstablished atomic.Uint64
	sessionsEstablished     atomic.Uint64
	sessionsModified        atomic.Uint64
	sessionsDeleted         atomic.Uint64
	rejectedRequests        atomic.Uint64
	peerRestarts            atomic.Uint64
	graceEntries            atomic.Uint64
	graceExpirations        atomic.Uint64
	reconciliations         atomic.Uint64
	staleSessionsPurged     atomic.Uint64
}

func New(config Config, store *rules.Store) (*Server, error) {
	if store == nil {
		return nil, errors.New("pgwu PFCP: nil rule store")
	}
	if !config.Listen.Addr().IsValid() || !config.Advertise.Is4() || !config.UserIP.Is4() {
		return nil, errors.New("pgwu PFCP: valid IPv4 listen, advertise, and user-plane addresses are required")
	}
	if len(config.AllowedCP) == 0 {
		return nil, errors.New("pgwu PFCP: at least one allowed PGW-C address is required")
	}
	if config.EnterpriseID == 10415 {
		return nil, errors.New("pgwu PFCP: enterprise ID 10415 is reserved for 3GPP")
	}
	config.Advertise = config.Advertise.Unmap()
	config.UserIP = config.UserIP.Unmap()
	if config.DedicatedUserIP.IsValid() {
		if !config.DedicatedUserIP.Is4() {
			return nil, errors.New("pgwu PFCP: dedicated user-plane address must be IPv4")
		}
		config.DedicatedUserIP = config.DedicatedUserIP.Unmap()
		if config.DedicatedUserIP == config.UserIP {
			return nil, errors.New("pgwu PFCP: dedicated user-plane address must differ from the default address")
		}
	}
	for index, peer := range config.AllowedCP {
		if !peer.Is4() {
			return nil, fmt.Errorf("pgwu PFCP: allowed PGW-C address %d is not IPv4", index)
		}
		config.AllowedCP[index] = peer.Unmap()
	}
	if config.StartedAt.IsZero() {
		config.StartedAt = time.Now().UTC()
	}
	associations, err := pfcpassociation.New(pfcpassociation.Config{
		Timeout: config.AssociationTimeout, GraceWindow: config.GraceWindow,
	})
	if err != nil {
		return nil, err
	}
	server := &Server{
		config: config, store: store, associations: associations,
		sessionOwner: make(map[uint64]netip.AddrPort), reconcilePending: make(map[netip.Addr]map[uint64]struct{}),
	}
	for _, session := range store.Snapshot() {
		peer := session.ControlPeer
		if !peer.IsValid() || peer.Port() == 0 || !server.allowed(peer.Addr().Unmap()) {
			return nil, fmt.Errorf("pgwu PFCP: recovered session %d has an invalid or unallowlisted control peer", session.UPSEID)
		}
		peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
		server.sessionOwner[session.UPSEID] = peer
		server.associations.RestoreUnavailable(peer.Addr())
	}
	endpoint, err := pfcptransport.Listen(config.Listen, server.handle, config.Transport)
	if err != nil {
		return nil, err
	}
	server.endpoint = endpoint
	return server, nil
}

func (s *Server) Serve(ctx context.Context) error {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.associationLoop(child)
	s.mu.RLock()
	emitter := s.usageEmitter
	s.mu.RUnlock()
	if emitter != nil {
		go emitter.Run(child)
	}
	return s.endpoint.Serve(child)
}
func (s *Server) Close() error              { return s.endpoint.Close() }
func (s *Server) LocalAddr() netip.AddrPort { return s.endpoint.LocalAddr() }
func (s *Server) TransportCounters() pfcptransport.Counters {
	return s.endpoint.Counters()
}

func (s *Server) Associations() []Association {
	return s.associations.Snapshot()
}

func (s *Server) Counters() Counters {
	usage := usagereport.EmitterStats{}
	s.mu.RLock()
	emitter := s.usageEmitter
	s.mu.RUnlock()
	if emitter != nil {
		usage = emitter.Stats()
	}
	return Counters{
		AssociationsEstablished: s.associationsEstablished.Load(),
		SessionsEstablished:     s.sessionsEstablished.Load(), SessionsModified: s.sessionsModified.Load(),
		SessionsDeleted: s.sessionsDeleted.Load(), RejectedRequests: s.rejectedRequests.Load(),
		PeerRestarts: s.peerRestarts.Load(), GraceEntries: s.graceEntries.Load(),
		GraceExpirations: s.graceExpirations.Load(), Reconciliations: s.reconciliations.Load(),
		StaleSessionsPurged:   s.staleSessionsPurged.Load(),
		UsageReportsGenerated: usage.ReportsGenerated, UsageReportsSent: usage.ReportsSent,
		UsageReportsRetried: usage.ReportsRetried, UsageReportsFailed: usage.ReportsFailed,
		UsageReportsPending: usage.PendingReports, UsageReportQueueFull: usage.QueueFull,
		UsageCounterResets: usage.CounterResets, UsageTrackedURRs: usage.TrackedURRs,
	}
}

// SetUsageSource enables telemetry-only PFCP Usage Reports. It must be called
// before Serve so the emitter has one stable dataplane snapshot source.
func (s *Server) SetUsageSource(snapshot func() []usagereport.Measurement) error {
	emitter, err := usagereport.NewEmitter(usagereport.EmitterConfig{
		Snapshot: snapshot, ReportTimeout: 5 * time.Second,
		ResolveCPSEID: s.resolveUsageCPSEID, Send: s.sendUsageReport,
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.usageEmitter != nil {
		return errors.New("pgwu PFCP: usage source is already configured")
	}
	s.usageEmitter = emitter
	return nil
}

func (s *Server) resolveUsageCPSEID(upSEID uint64) (uint64, bool) {
	current, ok := s.store.FindByUPSEID(upSEID)
	if !ok {
		return 0, false
	}
	s.mu.RLock()
	owner, owned := s.sessionOwner[upSEID]
	s.mu.RUnlock()
	if !owned || s.associations.State(owner.Addr()) != pfcpassociation.StateAssociated {
		return 0, false
	}
	return current.CPSEID, true
}

func (s *Server) sendUsageReport(ctx context.Context, upSEID uint64, report usagereport.Report) error {
	current, ok := s.store.FindByUPSEID(upSEID)
	if !ok || current.CPSEID != report.CPSEID {
		return errors.New("pgwu PFCP: usage report session no longer exists")
	}
	s.mu.RLock()
	owner, owned := s.sessionOwner[upSEID]
	s.mu.RUnlock()
	if !owned || s.associations.State(owner.Addr()) != pfcpassociation.StateAssociated {
		return errors.New("pgwu PFCP: usage report association is unavailable")
	}
	reportType, _ := pfcp.NewReportTypeIE(pfcp.ReportUsage)
	usage, err := usagereport.Encode(report)
	if err != nil {
		return err
	}
	response, err := s.endpoint.Do(ctx, owner, pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, HasSEID: true, MessageType: pfcp.MessageSessionReportRequest, SEID: current.CPSEID},
		IEs:    []pfcp.IE{reportType, usage},
	})
	if err != nil {
		return err
	}
	if !response.Header.HasSEID || response.Header.SEID != current.UPSEID {
		return errors.New("pgwu PFCP: usage report response has the wrong UP-SEID")
	}
	causeIE, ok := response.Find(pfcp.IECause)
	if !ok {
		return pfcp.ErrMissingIE
	}
	cause, err := causeIE.Cause()
	if err != nil {
		return err
	}
	if cause != pfcp.CauseRequestAccepted {
		return fmt.Errorf("pgwu PFCP: usage report rejected with cause %d", cause)
	}
	return nil
}

func (s *Server) AssociationState(peer netip.Addr) pfcpassociation.State {
	return s.associations.State(peer)
}

func (s *Server) GraceRemaining(peer netip.Addr) time.Duration {
	return s.associations.GraceRemaining(peer)
}

func (s *Server) handle(_ context.Context, peer netip.AddrPort, request pfcp.Message) (*pfcp.Message, error) {
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	peerIP := peer.Addr()
	if !s.allowed(peerIP) {
		s.rejectedRequests.Add(1)
		return nil, nil
	}
	s.associations.Touch(peerIP)
	switch request.Header.MessageType {
	case pfcp.MessageHeartbeatRequest:
		return s.heartbeatResponse(), nil
	case pfcp.MessageAssociationSetupRequest:
		return s.associationSetup(peerIP, request), nil
	case pfcp.MessageAssociationUpdateRequest:
		return s.associationUpdate(peerIP), nil
	case pfcp.MessageAssociationReleaseRequest:
		return s.associationRelease(peerIP), nil
	case pfcp.MessageSessionEstablishmentRequest:
		return s.sessionEstablishment(peer, request), nil
	case pfcp.MessageSessionModificationRequest:
		return s.sessionModification(peer, request), nil
	case pfcp.MessageSessionDeletionRequest:
		return s.sessionDeletion(peer, request), nil
	default:
		s.rejectedRequests.Add(1)
		return s.unsupportedResponse(request), nil
	}
}

func (s *Server) heartbeatResponse() *pfcp.Message {
	recovery, _ := pfcp.NewRecoveryTimeStampIE(s.config.StartedAt)
	return &pfcp.Message{Header: pfcp.Header{Version: pfcp.Version, MessageType: pfcp.MessageHeartbeatResponse}, IEs: []pfcp.IE{recovery}}
}

func (s *Server) associationSetup(peer netip.Addr, request pfcp.Message) *pfcp.Message {
	nodeIE, nodeOK := request.Find(pfcp.IENodeID)
	recoveryIE, recoveryOK := request.Find(pfcp.IERecoveryTimeStamp)
	if !nodeOK || !recoveryOK {
		s.rejectedRequests.Add(1)
		return s.associationResponse(pfcp.MessageAssociationSetupResponse, pfcp.CauseMandatoryIEMissing)
	}
	nodeAddress, nodeFQDN, err := nodeIE.NodeID()
	if err != nil {
		s.rejectedRequests.Add(1)
		return s.associationResponse(pfcp.MessageAssociationSetupResponse, pfcp.CauseMandatoryIEIncorrect)
	}
	recoveryTime, err := recoveryIE.RecoveryTimeStamp()
	if err != nil {
		s.rejectedRequests.Add(1)
		return s.associationResponse(pfcp.MessageAssociationSetupResponse, pfcp.CauseMandatoryIEIncorrect)
	}
	result := s.associations.Setup(peer, nodeAddress, nodeFQDN, recoveryTime)
	if result.Reconcile {
		s.beginReconciliation(peer)
	}
	if result.RecoveryChanged {
		s.peerRestarts.Add(1)
	}
	s.associationsEstablished.Add(1)
	return s.associationResponse(pfcp.MessageAssociationSetupResponse, pfcp.CauseRequestAccepted)
}

func (s *Server) associationUpdate(peer netip.Addr) *pfcp.Message {
	cause := pfcp.CauseRequestAccepted
	state := s.associations.State(peer)
	if state == pfcpassociation.StateReconciling {
		purged, completed := s.completeReconciliation(peer)
		if !completed {
			cause = pfcp.CauseSystemFailure
			s.rejectedRequests.Add(1)
		} else {
			s.staleSessionsPurged.Add(uint64(purged))
			s.reconciliations.Add(1)
		}
	} else if state != pfcpassociation.StateAssociated {
		cause = pfcp.CauseNoAssociation
		s.rejectedRequests.Add(1)
	}
	return s.associationResponse(pfcp.MessageAssociationUpdateResponse, cause)
}

func (s *Server) associationRelease(peer netip.Addr) *pfcp.Message {
	cause := pfcp.CauseRequestAccepted
	if s.associations.State(peer) == pfcpassociation.StateUnavailable {
		cause = pfcp.CauseNoAssociation
		s.rejectedRequests.Add(1)
	} else {
		_, complete := s.purgePeerSessions(peer)
		if !complete {
			cause = pfcp.CauseSystemFailure
			s.rejectedRequests.Add(1)
		} else {
			s.associations.Release(peer)
			s.mu.Lock()
			delete(s.reconcilePending, peer.Unmap())
			s.mu.Unlock()
		}
	}
	return s.associationResponse(pfcp.MessageAssociationReleaseResponse, cause)
}

func (s *Server) associationResponse(messageType, cause uint8) *pfcp.Message {
	nodeID, _ := pfcp.NewNodeIDIE(s.config.Advertise, "")
	recovery, _ := pfcp.NewRecoveryTimeStampIE(s.config.StartedAt)
	return &pfcp.Message{Header: pfcp.Header{Version: pfcp.Version, MessageType: messageType}, IEs: []pfcp.IE{nodeID, pfcp.NewCauseIE(cause), recovery}}
}

func (s *Server) sessionEstablishment(peer netip.AddrPort, request pfcp.Message) *pfcp.Message {
	if request.Header.SEID != 0 {
		s.rejectedRequests.Add(1)
		return s.establishmentResponse(0, 0, pfcp.CauseMandatoryIEIncorrect)
	}
	cpFSEIDIE, ok := request.Find(pfcp.IEFSEID)
	if !ok {
		s.rejectedRequests.Add(1)
		return s.establishmentResponse(0, 0, pfcp.CauseMandatoryIEMissing)
	}
	cpFSEID, err := cpFSEIDIE.FSEID()
	if err != nil || cpFSEID.IPv4.Unmap() != peer.Addr() {
		s.rejectedRequests.Add(1)
		return s.establishmentResponse(0, 0, pfcp.CauseMandatoryIEIncorrect)
	}
	state := s.associations.State(peer.Addr())
	if state == pfcpassociation.StateReconciling {
		current, ok := s.store.FindByCPSEID(cpFSEID.SEID)
		if !ok {
			s.rejectedRequests.Add(1)
			return s.establishmentResponse(cpFSEID.SEID, 0, pfcp.CauseNoAssociation)
		}
		candidate, err := s.decodeSession(request.IEs, cpFSEID.SEID, current.UPSEID)
		if err != nil {
			s.emitError(ErrorEvent{Procedure: "session_reconciliation", Peer: peer, Err: err})
			s.rejectedRequests.Add(1)
			return s.establishmentResponse(cpFSEID.SEID, 0, pfcp.CauseRuleCreationFailure)
		}
		candidate.ControlPeer = peer
		reconciled, err := s.store.Reconcile(cpFSEID.SEID, candidate)
		if err != nil {
			s.emitError(ErrorEvent{Procedure: "session_reconciliation", Peer: peer, Err: err})
			s.rejectedRequests.Add(1)
			return s.establishmentResponse(cpFSEID.SEID, 0, pfcp.CauseRuleCreationFailure)
		}
		s.mu.Lock()
		s.sessionOwner[reconciled.UPSEID] = peer
		if pending := s.reconcilePending[peer.Addr()]; pending != nil {
			delete(pending, reconciled.UPSEID)
		}
		s.mu.Unlock()
		return s.establishmentResponse(cpFSEID.SEID, reconciled.UPSEID, pfcp.CauseRequestAccepted)
	}
	if state != pfcpassociation.StateAssociated {
		s.rejectedRequests.Add(1)
		return s.establishmentResponse(cpFSEID.SEID, 0, pfcp.CauseNoAssociation)
	}
	upSEID, err := s.allocateSEID()
	if err != nil {
		s.rejectedRequests.Add(1)
		return s.establishmentResponse(cpFSEID.SEID, 0, pfcp.CauseNoResources)
	}
	candidate, err := s.decodeSession(request.IEs, cpFSEID.SEID, upSEID)
	if err != nil {
		s.emitError(ErrorEvent{Procedure: "session_establishment", Peer: peer, Err: err})
		s.rejectedRequests.Add(1)
		return s.establishmentResponse(cpFSEID.SEID, 0, pfcp.CauseRuleCreationFailure)
	}
	candidate.ControlPeer = peer
	if _, err := s.store.Create(candidate); err != nil {
		s.emitError(ErrorEvent{Procedure: "session_establishment", Peer: peer, Err: err})
		s.rejectedRequests.Add(1)
		cause := pfcp.CauseRuleCreationFailure
		if errors.Is(err, rules.ErrDuplicate) || errors.Is(err, rules.ErrCapacity) {
			cause = pfcp.CauseNoResources
		}
		return s.establishmentResponse(cpFSEID.SEID, 0, cause)
	}
	s.mu.Lock()
	s.sessionOwner[upSEID] = peer
	s.mu.Unlock()
	s.sessionsEstablished.Add(1)
	return s.establishmentResponse(cpFSEID.SEID, upSEID, pfcp.CauseRequestAccepted)
}

func (s *Server) establishmentResponse(cpSEID, upSEID uint64, cause uint8) *pfcp.Message {
	nodeID, _ := pfcp.NewNodeIDIE(s.config.Advertise, "")
	ies := []pfcp.IE{nodeID, pfcp.NewCauseIE(cause)}
	if cause == pfcp.CauseRequestAccepted {
		fseid, _ := pfcp.NewFSEIDIE(pfcp.FSEID{SEID: upSEID, IPv4: s.config.Advertise})
		ies = append(ies, fseid)
	}
	return &pfcp.Message{Header: pfcp.Header{Version: pfcp.Version, HasSEID: true, MessageType: pfcp.MessageSessionEstablishmentResponse, SEID: cpSEID}, IEs: ies}
}

func (s *Server) sessionModification(peer netip.AddrPort, request pfcp.Message) *pfcp.Message {
	if !s.associations.CanMutate(peer.Addr()) {
		s.rejectedRequests.Add(1)
		return s.sessionResponse(pfcp.MessageSessionModificationResponse, 0, pfcp.CauseNoAssociation)
	}
	current, ok := s.store.FindByUPSEID(request.Header.SEID)
	if !ok || !s.owns(peer, request.Header.SEID) {
		s.rejectedRequests.Add(1)
		return s.sessionResponse(pfcp.MessageSessionModificationResponse, 0, pfcp.CauseSessionNotFound)
	}
	updated, err := s.store.Update(current.UPSEID, current.Revision, func(candidate *rules.Session) error {
		return s.applyModifications(candidate, request.IEs)
	})
	if err != nil {
		s.emitError(ErrorEvent{Procedure: "session_modification", Peer: peer, Err: err})
		s.rejectedRequests.Add(1)
		return s.sessionResponse(pfcp.MessageSessionModificationResponse, current.CPSEID, pfcp.CauseRuleCreationFailure)
	}
	_ = updated
	s.sessionsModified.Add(1)
	return s.sessionResponse(pfcp.MessageSessionModificationResponse, current.CPSEID, pfcp.CauseRequestAccepted)
}

func (s *Server) emitError(event ErrorEvent) {
	callback := s.config.OnError
	if callback == nil {
		return
	}
	// Observability must never alter PFCP transaction semantics. A faulty
	// embedding callback is isolated from the user-plane request handler.
	defer func() { _ = recover() }()
	callback(event)
}

func (s *Server) sessionDeletion(peer netip.AddrPort, request pfcp.Message) *pfcp.Message {
	if !s.associations.CanMutate(peer.Addr()) {
		s.rejectedRequests.Add(1)
		return s.sessionResponse(pfcp.MessageSessionDeletionResponse, 0, pfcp.CauseNoAssociation)
	}
	current, ok := s.store.FindByUPSEID(request.Header.SEID)
	if !ok || !s.owns(peer, request.Header.SEID) {
		s.rejectedRequests.Add(1)
		return s.sessionResponse(pfcp.MessageSessionDeletionResponse, 0, pfcp.CauseSessionNotFound)
	}
	if err := s.store.Delete(current.UPSEID, current.Revision); err != nil {
		s.emitError(ErrorEvent{Procedure: "session_deletion", Peer: peer, Err: err})
		s.rejectedRequests.Add(1)
		return s.sessionResponse(pfcp.MessageSessionDeletionResponse, current.CPSEID, pfcp.CauseSystemFailure)
	}
	s.mu.Lock()
	delete(s.sessionOwner, current.UPSEID)
	s.mu.Unlock()
	s.sessionsDeleted.Add(1)
	return s.sessionResponse(pfcp.MessageSessionDeletionResponse, current.CPSEID, pfcp.CauseRequestAccepted)
}

func (s *Server) sessionResponse(messageType uint8, cpSEID uint64, cause uint8) *pfcp.Message {
	return &pfcp.Message{Header: pfcp.Header{Version: pfcp.Version, HasSEID: true, MessageType: messageType, SEID: cpSEID}, IEs: []pfcp.IE{pfcp.NewCauseIE(cause)}}
}

func (s *Server) unsupportedResponse(request pfcp.Message) *pfcp.Message {
	typ, ok := pfcptransport.ExpectedResponseType(request.Header.MessageType)
	if !ok {
		return nil
	}
	return &pfcp.Message{Header: pfcp.Header{Version: pfcp.Version, HasSEID: request.Header.HasSEID, MessageType: typ}, IEs: []pfcp.IE{pfcp.NewCauseIE(pfcp.CauseServiceNotSupported)}}
}

type decodedPDR struct {
	id          uint16
	precedence  uint32
	source      uint8
	ue          pfcp.UEIPAddress
	local       *pfcp.FTEID
	sdf         *pfcp.SDFFilter
	removeOuter bool
	farID       uint32
	qerID       uint32
	urrID       uint32
}

type decodedFAR struct {
	id          uint32
	destination uint8
	outer       *pfcp.OuterHeader
}

type decodedQER struct {
	id              uint32
	uplinkOpen      bool
	downlinkOpen    bool
	uplinkBitrate   uint64
	downlinkBitrate uint64
	qci             uint8
	arp             uint8
}

type decodedURR struct {
	id                 uint32
	measureVolume      bool
	measureDuration    bool
	reportingThreshold uint64
}

func (s *Server) decodeSession(ies []pfcp.IE, cpSEID, upSEID uint64) (rules.Session, error) {
	pdnType, ok := pfcp.FindIE(ies, pfcp.IEPDNType)
	if !ok || len(pdnType.Value) != 1 || pdnType.Value[0]&0x07 != 1 {
		return rules.Session{}, errors.New("IPv4 PDN Type is required")
	}
	fars := make(map[uint32]decodedFAR)
	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IECreateFAR) {
		far, err := decodeFAR(grouped, pfcp.IEForwardingParameters)
		if err != nil {
			return rules.Session{}, err
		}
		if _, exists := fars[far.id]; exists {
			return rules.Session{}, fmt.Errorf("duplicate FAR %d", far.id)
		}
		fars[far.id] = far
	}
	qers := make(map[uint32]decodedQER)
	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IECreateQER) {
		qer, err := decodeQER(grouped, s.config.EnterpriseID)
		if err != nil {
			return rules.Session{}, err
		}
		if _, exists := qers[qer.id]; exists {
			return rules.Session{}, fmt.Errorf("duplicate QER %d", qer.id)
		}
		qers[qer.id] = qer
	}
	urrs := make(map[uint32]decodedURR)
	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IECreateURR) {
		urr, err := decodeURR(grouped)
		if err != nil {
			return rules.Session{}, err
		}
		if _, exists := urrs[urr.id]; exists {
			return rules.Session{}, fmt.Errorf("duplicate URR %d", urr.id)
		}
		urrs[urr.id] = urr
	}
	pdrs := make([]decodedPDR, 0, len(pfcp.FindAllIEs(ies, pfcp.IECreatePDR)))
	seenPDR := make(map[uint16]struct{})
	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IECreatePDR) {
		pdr, err := decodePDR(grouped)
		if err != nil {
			return rules.Session{}, err
		}
		if _, duplicate := seenPDR[pdr.id]; duplicate {
			return rules.Session{}, fmt.Errorf("duplicate PDR %d", pdr.id)
		}
		seenPDR[pdr.id] = struct{}{}
		pdrs = append(pdrs, pdr)
	}
	return s.compileSession(cpSEID, upSEID, pdrs, fars, qers, urrs)
}

type bearerGroupKey struct {
	qerID uint32
	urrID uint32
}

type decodedBearerGroup struct {
	key      bearerGroupKey
	uplink   []decodedPDR
	downlink []decodedPDR
}

func (s *Server) compileSession(cpSEID, upSEID uint64, pdrs []decodedPDR, fars map[uint32]decodedFAR, qers map[uint32]decodedQER, urrs map[uint32]decodedURR) (rules.Session, error) {
	if len(pdrs) < 2 || len(fars) < 2 || len(qers) == 0 || len(urrs) == 0 {
		return rules.Session{}, errors.New("PDR, FAR, QER, and URR rules are required")
	}
	groups := make(map[bearerGroupKey]*decodedBearerGroup)
	usedFAR := make(map[uint32]struct{})
	usedQER := make(map[uint32]struct{})
	usedURR := make(map[uint32]struct{})
	ue := netip.Addr{}
	for _, pdr := range pdrs {
		far, farOK := fars[pdr.farID]
		_, qerOK := qers[pdr.qerID]
		_, urrOK := urrs[pdr.urrID]
		if !farOK || !qerOK || !urrOK {
			return rules.Session{}, fmt.Errorf("PDR %d references a missing FAR, QER, or URR", pdr.id)
		}
		if err := s.validatePDRTopology(pdr, far); err != nil {
			return rules.Session{}, fmt.Errorf("PDR %d: %w", pdr.id, err)
		}
		if !ue.IsValid() {
			ue = pdr.ue.IPv4.Unmap()
		} else if pdr.ue.IPv4.Unmap() != ue {
			return rules.Session{}, errors.New("all PDRs in one PFCP session must use the same UE IPv4 address")
		}
		key := bearerGroupKey{qerID: pdr.qerID, urrID: pdr.urrID}
		group := groups[key]
		if group == nil {
			group = &decodedBearerGroup{key: key}
			groups[key] = group
		}
		switch pdr.source {
		case pfcp.InterfaceAccess:
			group.uplink = append(group.uplink, pdr)
		case pfcp.InterfaceCore:
			group.downlink = append(group.downlink, pdr)
		default:
			return rules.Session{}, fmt.Errorf("PDR %d has unsupported source interface", pdr.id)
		}
		usedFAR[pdr.farID], usedQER[pdr.qerID], usedURR[pdr.urrID] = struct{}{}, struct{}{}, struct{}{}
	}
	if len(usedFAR) != len(fars) || len(usedQER) != len(qers) || len(usedURR) != len(urrs) {
		return rules.Session{}, errors.New("unreferenced FAR, QER, or URR is not allowed")
	}

	var session rules.Session
	session.CPSEID, session.UPSEID, session.UEIPv4 = cpSEID, upSEID, ue
	defaultFound := false
	for _, group := range groups {
		if len(group.uplink) == 0 || len(group.downlink) == 0 {
			return rules.Session{}, fmt.Errorf("bearer QER %d/URR %d is missing one direction", group.key.qerID, group.key.urrID)
		}
		withoutSDF := 0
		for _, pdr := range append(append([]decodedPDR(nil), group.uplink...), group.downlink...) {
			if pdr.sdf == nil {
				withoutSDF++
			}
		}
		total := len(group.uplink) + len(group.downlink)
		if withoutSDF == total {
			if defaultFound || len(group.uplink) != 1 || len(group.downlink) != 1 {
				return rules.Session{}, errors.New("exactly one two-direction default bearer without SDF filters is required")
			}
			if err := populateDefaultBearer(&session, *group, fars, qers, urrs); err != nil {
				return rules.Session{}, err
			}
			defaultFound = true
			continue
		}
		if withoutSDF != 0 {
			return rules.Session{}, fmt.Errorf("bearer QER %d/URR %d mixes filtered and unfiltered PDRs", group.key.qerID, group.key.urrID)
		}
		bearer, err := compileDedicatedBearer(*group, session.UEIPv4, fars, qers, urrs)
		if err != nil {
			return rules.Session{}, err
		}
		session.DedicatedBearers = append(session.DedicatedBearers, bearer)
	}
	if !defaultFound {
		return rules.Session{}, errors.New("default bearer PDR pair is missing")
	}
	if session.Local.IP.Unmap() != s.config.UserIP {
		return rules.Session{}, errors.New("default bearer uses the dedicated user-plane address")
	}
	for index := range session.DedicatedBearers {
		if err := s.normalizeDedicatedUserPlane(&session.DedicatedBearers[index]); err != nil {
			return rules.Session{}, err
		}
	}
	return session, nil
}

func (s *Server) validatePDRTopology(pdr decodedPDR, far decodedFAR) error {
	switch pdr.source {
	case pfcp.InterfaceAccess:
		if pdr.local == nil || !s.allowedUserPlaneIP(pdr.local.IPv4) || pdr.local.IPv6.IsValid() || !pdr.removeOuter || pdr.ue.Destination {
			return errors.New("invalid uplink F-TEID, UE address selector, or outer-header removal")
		}
		if far.destination != pfcp.InterfaceCore || far.outer != nil {
			return errors.New("uplink FAR must forward plain IP to the core interface")
		}
	case pfcp.InterfaceCore:
		if pdr.local != nil || pdr.removeOuter || !pdr.ue.Destination {
			return errors.New("invalid downlink UE address selector or tunnel fields")
		}
		if far.destination != pfcp.InterfaceAccess || far.outer == nil || far.outer.Description != pfcp.OuterHeaderGTPUUDPIPv4 ||
			!far.outer.IPv4.Is4() || far.outer.IPv6.IsValid() {
			return errors.New("downlink FAR must create a GTP-U/UDP/IPv4 access tunnel")
		}
	default:
		return errors.New("unsupported source interface")
	}
	return nil
}

func (s *Server) allowedUserPlaneIP(address netip.Addr) bool {
	address = address.Unmap()
	return address == s.config.UserIP || (s.config.DedicatedUserIP.IsValid() && address == s.config.DedicatedUserIP)
}

func (s *Server) normalizeDedicatedUserPlane(bearer *rules.Bearer) error {
	if bearer == nil {
		return errors.New("nil dedicated bearer")
	}
	expected := s.config.UserIP
	if s.config.DedicatedUserIP.IsValid() {
		expected = s.config.DedicatedUserIP
		// TS 29.244 QERs carry gates and bit rates, but no LTE QCI/ARP.
		// When private metadata is disabled, the explicitly configured QCI 1
		// S5-U F-TEID remains an unambiguous, standards-shaped selector. Keep
		// ARP at zero to mean "not present on Sxb" rather than inventing one.
		if bearer.QCI == 0 && bearer.ARP == 0 {
			bearer.QCI = 1
		}
		if bearer.QCI != 1 {
			return fmt.Errorf("dedicated QCI %d is unsupported by the configured QCI 1 user plane", bearer.QCI)
		}
	}
	if bearer.Local.IP.Unmap() != expected {
		return fmt.Errorf("dedicated bearer uses user-plane address %s, expected %s", bearer.Local.IP, expected)
	}
	return nil
}

func populateDefaultBearer(session *rules.Session, group decodedBearerGroup, fars map[uint32]decodedFAR, qers map[uint32]decodedQER, urrs map[uint32]decodedURR) error {
	uplink, downlink := group.uplink[0], group.downlink[0]
	uplinkFAR, downlinkFAR := fars[uplink.farID], fars[downlink.farID]
	qer, urr := qers[group.key.qerID], urrs[group.key.urrID]
	session.Local = rules.Tunnel{TEID: uplink.local.TEID, IP: uplink.local.IPv4}
	session.Remote = rules.Tunnel{TEID: downlinkFAR.outer.TEID, IP: downlinkFAR.outer.IPv4}
	session.UplinkPDRID, session.DownlinkPDRID = uplink.id, downlink.id
	session.UplinkFARID, session.DownlinkFARID = uplinkFAR.id, downlinkFAR.id
	session.UplinkGateOpen, session.DownlinkGateOpen = qer.uplinkOpen, qer.downlinkOpen
	session.MaxUplinkBitsPerSecond, session.MaxDownlinkBitsPerSecond = qer.uplinkBitrate, qer.downlinkBitrate
	session.QERID, session.URRID = qer.id, urr.id
	session.MeasureVolume, session.MeasureDuration = urr.measureVolume, urr.measureDuration
	session.UsageReportingThreshold = urr.reportingThreshold
	return nil
}

func compileDedicatedBearer(group decodedBearerGroup, ue netip.Addr, fars map[uint32]decodedFAR, qers map[uint32]decodedQER, urrs map[uint32]decodedURR) (rules.Bearer, error) {
	uplinkFARID, downlinkFARID := group.uplink[0].farID, group.downlink[0].farID
	local := *group.uplink[0].local
	outer := *fars[downlinkFARID].outer
	for _, pdr := range group.uplink {
		if pdr.farID != uplinkFARID || pdr.local == nil || *pdr.local != local {
			return rules.Bearer{}, fmt.Errorf("dedicated bearer QER %d has inconsistent uplink tunnel/FAR", group.key.qerID)
		}
	}
	for _, pdr := range group.downlink {
		far := fars[pdr.farID]
		if pdr.farID != downlinkFARID || far.outer == nil || *far.outer != outer {
			return rules.Bearer{}, fmt.Errorf("dedicated bearer QER %d has inconsistent downlink tunnel/FAR", group.key.qerID)
		}
	}
	qer, urr := qers[group.key.qerID], urrs[group.key.urrID]
	bearer := rules.Bearer{
		Local: rules.Tunnel{TEID: local.TEID, IP: local.IPv4}, Remote: rules.Tunnel{TEID: outer.TEID, IP: outer.IPv4},
		UplinkFARID: uplinkFARID, DownlinkFARID: downlinkFARID,
		UplinkGateOpen: qer.uplinkOpen, DownlinkGateOpen: qer.downlinkOpen,
		MaxUplinkBitsPerSecond: qer.uplinkBitrate, MaxDownlinkBitsPerSecond: qer.downlinkBitrate,
		QERID: qer.id, URRID: urr.id, MeasureVolume: urr.measureVolume, MeasureDuration: urr.measureDuration,
		UsageReportingThreshold: urr.reportingThreshold, QCI: qer.qci, ARP: qer.arp,
	}
	for _, pdr := range append(append([]decodedPDR(nil), group.uplink...), group.downlink...) {
		filter, err := packetFilterFromSDF(pdr, ue)
		if err != nil {
			return rules.Bearer{}, fmt.Errorf("PDR %d SDF: %w", pdr.id, err)
		}
		bearer.Filters = append(bearer.Filters, rules.FlowFilter{
			PDRID: pdr.id, Precedence: pdr.precedence, Direction: filter.Direction, Filter: filter,
		})
	}
	return bearer, nil
}

func packetFilterFromSDF(pdr decodedPDR, ue netip.Addr) (gtpv2.IPv4PacketFilter, error) {
	if pdr.sdf == nil {
		return gtpv2.IPv4PacketFilter{}, errors.New("missing SDF Filter")
	}
	sdf := *pdr.sdf
	if sdf.HasSPI || sdf.HasFlowLabel {
		return gtpv2.IPv4PacketFilter{}, errors.New("SPI and IPv6 flow-label matching are unsupported")
	}
	direction := gtpv2.TFTDirectionDownlink
	if pdr.source == pfcp.InterfaceAccess {
		direction = gtpv2.TFTDirectionUplink
	}
	filter := gtpv2.IPv4PacketFilter{Direction: direction}
	if sdf.HasFlowDescription {
		description, err := pfcp.ParseIPv4FlowDescription(sdf.FlowDescription)
		if err != nil {
			return gtpv2.IPv4PacketFilter{}, err
		}
		if !description.AnyProtocol {
			filter.HasProtocol, filter.Protocol = true, description.Protocol
		}
		if !description.SourceAny {
			filter.HasRemoteAddress = true
			filter.RemoteAddress, filter.RemoteAddressMask = prefixAddressMask(description.SourcePrefix)
		}
		if description.DestinationAssigned {
			filter.HasLocalAddress = true
			filter.LocalAddress, filter.LocalAddressMask = ue, netip.AddrFrom4([4]byte{255, 255, 255, 255})
		} else if !description.DestinationAny {
			filter.HasLocalAddress = true
			filter.LocalAddress, filter.LocalAddressMask = prefixAddressMask(description.DestinationPrefix)
		}
		if description.SourcePort.Present {
			filter.HasRemotePort = true
			filter.RemotePortLow, filter.RemotePortHigh = description.SourcePort.Low, description.SourcePort.High
		}
		if description.DestinationPort.Present {
			filter.HasLocalPort = true
			filter.LocalPortLow, filter.LocalPortHigh = description.DestinationPort.Low, description.DestinationPort.High
		}
	}
	if sdf.HasToSTrafficClass {
		filter.HasTypeOfService = true
		filter.TypeOfService, filter.TypeOfServiceMask = sdf.ToSTrafficClass, sdf.ToSTrafficMask
	}
	return filter, nil
}

func prefixAddressMask(prefix netip.Prefix) (netip.Addr, netip.Addr) {
	prefix = prefix.Masked()
	mask := [4]byte{}
	for bit := 0; bit < prefix.Bits(); bit++ {
		mask[bit/8] |= 1 << (7 - uint(bit%8))
	}
	return prefix.Addr().Unmap(), netip.AddrFrom4(mask)
}

func decodePDR(grouped pfcp.IE) (decodedPDR, error) {
	children, err := grouped.Children()
	if err != nil {
		return decodedPDR{}, err
	}
	idIE, err := exactlyOneIE(children, pfcp.IEPDRID)
	if err != nil {
		return decodedPDR{}, err
	}
	precedenceIE, err := exactlyOneIE(children, pfcp.IEPrecedence)
	if err != nil {
		return decodedPDR{}, err
	}
	pdiIE, err := exactlyOneIE(children, pfcp.IEPDI)
	if err != nil {
		return decodedPDR{}, err
	}
	farIE, err := exactlyOneIE(children, pfcp.IEFARID)
	if err != nil {
		return decodedPDR{}, err
	}
	qerIE, err := exactlyOneIE(children, pfcp.IEQERID)
	if err != nil {
		return decodedPDR{}, err
	}
	urrIE, err := exactlyOneIE(children, pfcp.IEURRID)
	if err != nil {
		return decodedPDR{}, err
	}
	id, err := idIE.PDRID()
	if err != nil {
		return decodedPDR{}, err
	}
	precedence, err := precedenceIE.Uint32()
	if err != nil {
		return decodedPDR{}, err
	}
	pdi, err := pdiIE.Children()
	if err != nil {
		return decodedPDR{}, err
	}
	sourceIE, err := exactlyOneIE(pdi, pfcp.IESourceInterface)
	if err != nil {
		return decodedPDR{}, err
	}
	ueIE, err := exactlyOneIE(pdi, pfcp.IEUEIPAddress)
	if err != nil {
		return decodedPDR{}, err
	}
	source, err := sourceIE.Interface()
	if err != nil {
		return decodedPDR{}, err
	}
	ue, err := ueIE.UEIPAddress()
	if err != nil {
		return decodedPDR{}, err
	}
	farID, err := farIE.Uint32()
	if err != nil {
		return decodedPDR{}, err
	}
	qerID, err := qerIE.Uint32()
	if err != nil {
		return decodedPDR{}, err
	}
	urrID, err := urrIE.Uint32()
	if err != nil || urrID == 0 {
		return decodedPDR{}, errors.New("invalid URR ID")
	}
	out := decodedPDR{id: id, precedence: precedence, source: source, ue: ue, farID: farID, qerID: qerID, urrID: urrID}
	if fteids := pfcp.FindAllIEs(pdi, pfcp.IEFTEID); len(fteids) > 1 {
		return decodedPDR{}, errors.New("multiple F-TEIDs in one PDI")
	} else if len(fteids) == 1 {
		fteidIE := fteids[0]
		fteid, err := fteidIE.FTEID()
		if err != nil {
			return decodedPDR{}, err
		}
		out.local = &fteid
	}
	if sdfs := pfcp.FindAllIEs(pdi, pfcp.IESDFFilter); len(sdfs) > 1 {
		return decodedPDR{}, errors.New("multiple SDF Filters in one PDI")
	} else if len(sdfs) == 1 {
		sdf, err := sdfs[0].SDFFilter()
		if err != nil {
			return decodedPDR{}, err
		}
		out.sdf = &sdf
	}
	if removals := pfcp.FindAllIEs(children, pfcp.IEOuterHeaderRemoval); len(removals) > 1 {
		return decodedPDR{}, errors.New("multiple outer-header removals in one PDR")
	} else if len(removals) == 1 {
		removalIE := removals[0]
		removal, err := removalIE.OuterHeaderRemoval()
		if err != nil || removal != pfcp.OuterHeaderRemovalGTPUUDPIPv4 {
			return decodedPDR{}, errors.New("invalid outer-header removal")
		}
		out.removeOuter = true
	}
	return out, nil
}

func exactlyOneIE(ies []pfcp.IE, typ uint16) (pfcp.IE, error) {
	matches := pfcp.FindAllIEs(ies, typ)
	if len(matches) != 1 {
		if len(matches) == 0 {
			return pfcp.IE{}, pfcp.ErrMissingIE
		}
		return pfcp.IE{}, fmt.Errorf("duplicate IE type %d", typ)
	}
	return matches[0], nil
}

func decodeFAR(grouped pfcp.IE, parametersType uint16) (decodedFAR, error) {
	children, err := grouped.Children()
	if err != nil {
		return decodedFAR{}, err
	}
	idIE, idOK := pfcp.FindIE(children, pfcp.IEFARID)
	actionIE, actionOK := pfcp.FindIE(children, pfcp.IEApplyAction)
	parametersIE, parametersOK := pfcp.FindIE(children, parametersType)
	if !idOK || !actionOK || !parametersOK {
		return decodedFAR{}, pfcp.ErrMissingIE
	}
	id, err := idIE.Uint32()
	if err != nil {
		return decodedFAR{}, err
	}
	action, err := actionIE.ApplyAction()
	if err != nil || action != pfcp.ApplyForward {
		return decodedFAR{}, errors.New("PGW-U FAR must forward")
	}
	parameters, err := parametersIE.Children()
	if err != nil {
		return decodedFAR{}, err
	}
	destinationIE, ok := pfcp.FindIE(parameters, pfcp.IEDestinationInterface)
	if !ok {
		return decodedFAR{}, pfcp.ErrMissingIE
	}
	destination, err := destinationIE.Interface()
	if err != nil {
		return decodedFAR{}, err
	}
	out := decodedFAR{id: id, destination: destination}
	if outerIE, ok := pfcp.FindIE(parameters, pfcp.IEOuterHeaderCreation); ok {
		outer, err := outerIE.OuterHeaderCreation()
		if err != nil {
			return decodedFAR{}, err
		}
		out.outer = &outer
	}
	return out, nil
}

func decodeQER(grouped pfcp.IE, enterpriseID uint16) (decodedQER, error) {
	children, err := grouped.Children()
	if err != nil {
		return decodedQER{}, err
	}
	idIE, idOK := pfcp.FindIE(children, pfcp.IEQERID)
	gateIE, gateOK := pfcp.FindIE(children, pfcp.IEGateStatus)
	if !idOK || !gateOK {
		return decodedQER{}, pfcp.ErrMissingIE
	}
	id, err := idIE.Uint32()
	if err != nil {
		return decodedQER{}, err
	}
	uplinkOpen, downlinkOpen, err := gateIE.GateStatus()
	if err != nil {
		return decodedQER{}, err
	}
	out := decodedQER{id: id, uplinkOpen: uplinkOpen, downlinkOpen: downlinkOpen}
	if mbrIE, ok := pfcp.FindIE(children, pfcp.IEMBR); ok {
		uplink, downlink, err := mbrIE.BitRate()
		if err != nil {
			return decodedQER{}, err
		}
		out.uplinkBitrate = uplink * 1000
		out.downlinkBitrate = downlink * 1000
	}
	if metadataIE, ok := pfcp.FindIE(children, pfcp.IEVendorBearerQoS); ok && enterpriseID != 0 {
		metadata, err := metadataIE.VendorBearerQoS()
		if err != nil {
			return decodedQER{}, err
		}
		if metadata.EnterpriseID == enterpriseID {
			out.qci, out.arp = metadata.QCI, metadata.ARP
		}
	}
	return out, nil
}

func decodeURR(grouped pfcp.IE) (decodedURR, error) {
	children, err := grouped.Children()
	if err != nil {
		return decodedURR{}, err
	}
	idIE, idOK := pfcp.FindIE(children, pfcp.IEURRID)
	methodIE, methodOK := pfcp.FindIE(children, pfcp.IEMeasurementMethod)
	triggersIE, triggersOK := pfcp.FindIE(children, pfcp.IEReportingTriggers)
	thresholdIE, thresholdOK := pfcp.FindIE(children, pfcp.IEVolumeThreshold)
	if !idOK || !methodOK || !triggersOK || !thresholdOK {
		return decodedURR{}, pfcp.ErrMissingIE
	}
	id, err := idIE.Uint32()
	if err != nil || id == 0 {
		return decodedURR{}, errors.New("invalid URR ID")
	}
	volume, duration, err := methodIE.MeasurementMethod()
	if err != nil || !volume {
		return decodedURR{}, errors.New("PGW-U URR requires volume measurement")
	}
	triggers, err := triggersIE.ReportingTriggers()
	if err != nil || triggers != pfcp.ReportingTriggerVolumeThreshold {
		return decodedURR{}, errors.New("PGW-U URR supports only telemetry volume-threshold reporting")
	}
	threshold, err := thresholdIE.VolumeThreshold()
	if err != nil || !threshold.HasTotal || threshold.HasUplink || threshold.HasDownlink {
		return decodedURR{}, errors.New("PGW-U URR requires one total-volume threshold")
	}
	return decodedURR{id: id, measureVolume: volume, measureDuration: duration, reportingThreshold: threshold.Total}, nil
}

func (s *Server) applyModifications(candidate *rules.Session, ies []pfcp.IE) error {
	if len(ies) == 0 {
		return errors.New("empty PFCP session modification")
	}
	allowed := map[uint16]struct{}{
		pfcp.IECreatePDR: {}, pfcp.IECreateFAR: {}, pfcp.IECreateQER: {}, pfcp.IECreateURR: {},
		pfcp.IEUpdateFAR: {}, pfcp.IEUpdateQER: {}, pfcp.IEUpdateURR: {},
		pfcp.IERemovePDR: {}, pfcp.IERemoveFAR: {}, pfcp.IERemoveQER: {}, pfcp.IERemoveURR: {},
	}
	for _, ie := range ies {
		if _, ok := allowed[ie.Type]; !ok {
			return fmt.Errorf("unsupported PFCP session modification IE %d", ie.Type)
		}
	}
	if len(pfcp.FindAllIEs(ies, pfcp.IEUpdatePDR)) != 0 {
		return errors.New("Update PDR is unsupported; replace the dedicated bearer rules atomically")
	}
	if err := removeDedicatedBearers(candidate, ies); err != nil {
		return err
	}
	created, err := s.decodeCreatedDedicatedBearers(candidate, ies)
	if err != nil {
		return err
	}
	candidate.DedicatedBearers = append(candidate.DedicatedBearers, created...)
	if err := s.applyFARUpdates(candidate, pfcp.FindAllIEs(ies, pfcp.IEUpdateFAR)); err != nil {
		return err
	}
	if err := s.applyQERUpdates(candidate, pfcp.FindAllIEs(ies, pfcp.IEUpdateQER)); err != nil {
		return err
	}
	if err := applyURRUpdates(candidate, pfcp.FindAllIEs(ies, pfcp.IEUpdateURR)); err != nil {
		return err
	}
	return nil
}

func removeDedicatedBearers(candidate *rules.Session, ies []pfcp.IE) error {
	pdrs, err := removedPDRIDs(pfcp.FindAllIEs(ies, pfcp.IERemovePDR))
	if err != nil {
		return err
	}
	fars, err := removedUint32IDs(pfcp.FindAllIEs(ies, pfcp.IERemoveFAR), pfcp.IEFARID)
	if err != nil {
		return err
	}
	qers, err := removedUint32IDs(pfcp.FindAllIEs(ies, pfcp.IERemoveQER), pfcp.IEQERID)
	if err != nil {
		return err
	}
	urrs, err := removedUint32IDs(pfcp.FindAllIEs(ies, pfcp.IERemoveURR), pfcp.IEURRID)
	if err != nil {
		return err
	}
	if len(pdrs)+len(fars)+len(qers)+len(urrs) == 0 {
		return nil
	}
	kept := make([]rules.Bearer, 0, len(candidate.DedicatedBearers))
	for _, bearer := range candidate.DedicatedBearers {
		touched := fars[bearer.UplinkFARID] || fars[bearer.DownlinkFARID] || qers[bearer.QERID] || urrs[bearer.URRID]
		for _, filter := range bearer.Filters {
			touched = touched || pdrs[filter.PDRID]
		}
		if !touched {
			kept = append(kept, bearer)
			continue
		}
		if !fars[bearer.UplinkFARID] || !fars[bearer.DownlinkFARID] || !qers[bearer.QERID] || !urrs[bearer.URRID] {
			return fmt.Errorf("dedicated bearer QER %d removal is incomplete", bearer.QERID)
		}
		for _, filter := range bearer.Filters {
			if !pdrs[filter.PDRID] {
				return fmt.Errorf("dedicated bearer QER %d PDR removal is incomplete", bearer.QERID)
			}
			delete(pdrs, filter.PDRID)
		}
		delete(fars, bearer.UplinkFARID)
		delete(fars, bearer.DownlinkFARID)
		delete(qers, bearer.QERID)
		delete(urrs, bearer.URRID)
	}
	if len(pdrs)+len(fars)+len(qers)+len(urrs) != 0 {
		return errors.New("remove operation references an unknown or default-bearer rule")
	}
	candidate.DedicatedBearers = kept
	return nil
}

func removedPDRIDs(grouped []pfcp.IE) (map[uint16]bool, error) {
	out := make(map[uint16]bool, len(grouped))
	for _, ie := range grouped {
		children, err := ie.Children()
		if err != nil {
			return nil, err
		}
		idIE, err := exactlyOneIE(children, pfcp.IEPDRID)
		if err != nil {
			return nil, err
		}
		id, err := idIE.PDRID()
		if err != nil {
			return nil, err
		}
		if out[id] {
			return nil, fmt.Errorf("duplicate removed PDR %d", id)
		}
		out[id] = true
	}
	return out, nil
}

func removedUint32IDs(grouped []pfcp.IE, idType uint16) (map[uint32]bool, error) {
	out := make(map[uint32]bool, len(grouped))
	for _, ie := range grouped {
		children, err := ie.Children()
		if err != nil {
			return nil, err
		}
		idIE, err := exactlyOneIE(children, idType)
		if err != nil {
			return nil, err
		}
		id, err := idIE.Uint32()
		if err != nil {
			return nil, err
		}
		if out[id] {
			return nil, fmt.Errorf("duplicate removed rule %d", id)
		}
		out[id] = true
	}
	return out, nil
}

func (s *Server) decodeCreatedDedicatedBearers(candidate *rules.Session, ies []pfcp.IE) ([]rules.Bearer, error) {
	pdrIEs := pfcp.FindAllIEs(ies, pfcp.IECreatePDR)
	farIEs := pfcp.FindAllIEs(ies, pfcp.IECreateFAR)
	qerIEs := pfcp.FindAllIEs(ies, pfcp.IECreateQER)
	urrIEs := pfcp.FindAllIEs(ies, pfcp.IECreateURR)
	if len(pdrIEs)+len(farIEs)+len(qerIEs)+len(urrIEs) == 0 {
		return nil, nil
	}
	if len(pdrIEs) == 0 || len(farIEs) == 0 || len(qerIEs) == 0 || len(urrIEs) == 0 {
		return nil, errors.New("creating a dedicated bearer requires PDR, FAR, QER, and URR rules")
	}
	existingPDR, existingFAR, existingQER, existingURR := sessionRuleIDs(*candidate)
	pdrs := make([]decodedPDR, 0, len(pdrIEs))
	seenPDR := make(map[uint16]struct{})
	for _, ie := range pdrIEs {
		pdr, err := decodePDR(ie)
		if err != nil {
			return nil, err
		}
		if _, exists := existingPDR[pdr.id]; exists {
			return nil, fmt.Errorf("PDR %d already exists", pdr.id)
		}
		if _, duplicate := seenPDR[pdr.id]; duplicate {
			return nil, fmt.Errorf("duplicate PDR %d", pdr.id)
		}
		seenPDR[pdr.id] = struct{}{}
		pdrs = append(pdrs, pdr)
	}
	fars := make(map[uint32]decodedFAR)
	for _, ie := range farIEs {
		far, err := decodeFAR(ie, pfcp.IEForwardingParameters)
		if err != nil {
			return nil, err
		}
		if _, exists := existingFAR[far.id]; exists {
			return nil, fmt.Errorf("FAR %d already exists", far.id)
		}
		if _, duplicate := fars[far.id]; duplicate {
			return nil, fmt.Errorf("duplicate FAR %d", far.id)
		}
		fars[far.id] = far
	}
	qers := make(map[uint32]decodedQER)
	for _, ie := range qerIEs {
		qer, err := decodeQER(ie, s.config.EnterpriseID)
		if err != nil {
			return nil, err
		}
		if _, exists := existingQER[qer.id]; exists {
			return nil, fmt.Errorf("QER %d already exists", qer.id)
		}
		if _, duplicate := qers[qer.id]; duplicate {
			return nil, fmt.Errorf("duplicate QER %d", qer.id)
		}
		qers[qer.id] = qer
	}
	urrs := make(map[uint32]decodedURR)
	for _, ie := range urrIEs {
		urr, err := decodeURR(ie)
		if err != nil {
			return nil, err
		}
		if _, exists := existingURR[urr.id]; exists {
			return nil, fmt.Errorf("URR %d already exists", urr.id)
		}
		if _, duplicate := urrs[urr.id]; duplicate {
			return nil, fmt.Errorf("duplicate URR %d", urr.id)
		}
		urrs[urr.id] = urr
	}
	return s.compileDedicatedOnly(candidate.UEIPv4, pdrs, fars, qers, urrs)
}

func (s *Server) compileDedicatedOnly(ue netip.Addr, pdrs []decodedPDR, fars map[uint32]decodedFAR, qers map[uint32]decodedQER, urrs map[uint32]decodedURR) ([]rules.Bearer, error) {
	groups := make(map[bearerGroupKey]*decodedBearerGroup)
	usedFAR, usedQER, usedURR := make(map[uint32]struct{}), make(map[uint32]struct{}), make(map[uint32]struct{})
	for _, pdr := range pdrs {
		far, farOK := fars[pdr.farID]
		_, qerOK := qers[pdr.qerID]
		_, urrOK := urrs[pdr.urrID]
		if !farOK || !qerOK || !urrOK {
			return nil, fmt.Errorf("PDR %d references a missing created rule", pdr.id)
		}
		if pdr.ue.IPv4.Unmap() != ue.Unmap() || pdr.sdf == nil {
			return nil, fmt.Errorf("created PDR %d must use the session UE address and an SDF Filter", pdr.id)
		}
		if err := s.validatePDRTopology(pdr, far); err != nil {
			return nil, fmt.Errorf("PDR %d: %w", pdr.id, err)
		}
		key := bearerGroupKey{qerID: pdr.qerID, urrID: pdr.urrID}
		group := groups[key]
		if group == nil {
			group = &decodedBearerGroup{key: key}
			groups[key] = group
		}
		if pdr.source == pfcp.InterfaceAccess {
			group.uplink = append(group.uplink, pdr)
		} else {
			group.downlink = append(group.downlink, pdr)
		}
		usedFAR[pdr.farID], usedQER[pdr.qerID], usedURR[pdr.urrID] = struct{}{}, struct{}{}, struct{}{}
	}
	if len(usedFAR) != len(fars) || len(usedQER) != len(qers) || len(usedURR) != len(urrs) {
		return nil, errors.New("created modification contains an unreferenced FAR, QER, or URR")
	}
	out := make([]rules.Bearer, 0, len(groups))
	for _, group := range groups {
		if len(group.uplink) == 0 || len(group.downlink) == 0 {
			return nil, fmt.Errorf("created bearer QER %d is missing one direction", group.key.qerID)
		}
		bearer, err := compileDedicatedBearer(*group, ue, fars, qers, urrs)
		if err != nil {
			return nil, err
		}
		if err := s.normalizeDedicatedUserPlane(&bearer); err != nil {
			return nil, err
		}
		out = append(out, bearer)
	}
	return out, nil
}

func sessionRuleIDs(session rules.Session) (map[uint16]struct{}, map[uint32]struct{}, map[uint32]struct{}, map[uint32]struct{}) {
	pdrs, fars, qers, urrs := make(map[uint16]struct{}), make(map[uint32]struct{}), make(map[uint32]struct{}), make(map[uint32]struct{})
	uplinkPDR, downlinkPDR := session.UplinkPDRID, session.DownlinkPDRID
	uplinkFAR, downlinkFAR := session.UplinkFARID, session.DownlinkFARID
	if uplinkPDR == 0 && downlinkPDR == 0 {
		uplinkPDR, downlinkPDR = 1, 2
	}
	if uplinkFAR == 0 && downlinkFAR == 0 {
		uplinkFAR, downlinkFAR = 1, 2
	}
	pdrs[uplinkPDR], pdrs[downlinkPDR] = struct{}{}, struct{}{}
	fars[uplinkFAR], fars[downlinkFAR] = struct{}{}, struct{}{}
	if session.QERID != 0 {
		qers[session.QERID] = struct{}{}
	}
	if session.URRID != 0 {
		urrs[session.URRID] = struct{}{}
	}
	for _, bearer := range session.DedicatedBearers {
		for _, filter := range bearer.Filters {
			pdrs[filter.PDRID] = struct{}{}
		}
		fars[bearer.UplinkFARID], fars[bearer.DownlinkFARID] = struct{}{}, struct{}{}
		qers[bearer.QERID], urrs[bearer.URRID] = struct{}{}, struct{}{}
	}
	return pdrs, fars, qers, urrs
}

func (s *Server) applyFARUpdates(candidate *rules.Session, updates []pfcp.IE) error {
	seen := make(map[uint32]struct{})
	for _, update := range updates {
		far, err := decodeFAR(update, pfcp.IEUpdateForwardingParameters)
		if err != nil {
			return err
		}
		if _, duplicate := seen[far.id]; duplicate {
			return fmt.Errorf("duplicate updated FAR %d", far.id)
		}
		seen[far.id] = struct{}{}
		if far.destination != pfcp.InterfaceAccess || far.outer == nil || far.outer.Description != pfcp.OuterHeaderGTPUUDPIPv4 || !far.outer.IPv4.Is4() {
			return fmt.Errorf("updated FAR %d is not a downlink access tunnel", far.id)
		}
		defaultDownlink := candidate.DownlinkFARID
		if defaultDownlink == 0 {
			defaultDownlink = 2
		}
		if far.id == defaultDownlink {
			candidate.Remote = rules.Tunnel{TEID: far.outer.TEID, IP: far.outer.IPv4}
			continue
		}
		found := false
		for index := range candidate.DedicatedBearers {
			if candidate.DedicatedBearers[index].DownlinkFARID == far.id {
				candidate.DedicatedBearers[index].Remote = rules.Tunnel{TEID: far.outer.TEID, IP: far.outer.IPv4}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unknown downlink FAR %d", far.id)
		}
	}
	return nil
}

func (s *Server) applyQERUpdates(candidate *rules.Session, updates []pfcp.IE) error {
	seen := make(map[uint32]struct{})
	for _, update := range updates {
		qer, err := decodeQER(update, s.config.EnterpriseID)
		if err != nil {
			return err
		}
		if _, duplicate := seen[qer.id]; duplicate {
			return fmt.Errorf("duplicate updated QER %d", qer.id)
		}
		seen[qer.id] = struct{}{}
		if qer.id == candidate.QERID {
			candidate.UplinkGateOpen, candidate.DownlinkGateOpen = qer.uplinkOpen, qer.downlinkOpen
			candidate.MaxUplinkBitsPerSecond, candidate.MaxDownlinkBitsPerSecond = qer.uplinkBitrate, qer.downlinkBitrate
			continue
		}
		found := false
		for index := range candidate.DedicatedBearers {
			bearer := &candidate.DedicatedBearers[index]
			if bearer.QERID != qer.id {
				continue
			}
			bearer.UplinkGateOpen, bearer.DownlinkGateOpen = qer.uplinkOpen, qer.downlinkOpen
			bearer.MaxUplinkBitsPerSecond, bearer.MaxDownlinkBitsPerSecond = qer.uplinkBitrate, qer.downlinkBitrate
			if qer.qci != 0 {
				bearer.QCI, bearer.ARP = qer.qci, qer.arp
			}
			found = true
			break
		}
		if !found {
			return fmt.Errorf("unknown QER %d", qer.id)
		}
	}
	return nil
}

func applyURRUpdates(candidate *rules.Session, updates []pfcp.IE) error {
	seen := make(map[uint32]struct{})
	for _, update := range updates {
		urr, err := decodeURR(update)
		if err != nil {
			return err
		}
		if _, duplicate := seen[urr.id]; duplicate {
			return fmt.Errorf("duplicate updated URR %d", urr.id)
		}
		seen[urr.id] = struct{}{}
		if urr.id == candidate.URRID {
			candidate.MeasureVolume, candidate.MeasureDuration, candidate.UsageReportingThreshold = urr.measureVolume, urr.measureDuration, urr.reportingThreshold
			continue
		}
		found := false
		for index := range candidate.DedicatedBearers {
			bearer := &candidate.DedicatedBearers[index]
			if bearer.URRID != urr.id {
				continue
			}
			bearer.MeasureVolume, bearer.MeasureDuration, bearer.UsageReportingThreshold = urr.measureVolume, urr.measureDuration, urr.reportingThreshold
			found = true
			break
		}
		if !found {
			return fmt.Errorf("unknown URR %d", urr.id)
		}
	}
	return nil
}

func (s *Server) allocateSEID() (uint64, error) {
	for attempt := 0; attempt < 256; attempt++ {
		var raw [8]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return 0, err
		}
		seid := binary.BigEndian.Uint64(raw[:])
		if seid != 0 {
			if _, exists := s.store.FindByUPSEID(seid); !exists {
				return seid, nil
			}
		}
	}
	return 0, errors.New("pgwu PFCP: SEID allocation exhausted")
}

func (s *Server) allowed(peer netip.Addr) bool {
	for _, allowed := range s.config.AllowedCP {
		if peer == allowed {
			return true
		}
	}
	return false
}

func (s *Server) owns(peer netip.AddrPort, upSEID uint64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	owner, ok := s.sessionOwner[upSEID]
	return ok && owner == peer
}

func (s *Server) purgePeerSessions(peer netip.Addr) (int, bool) {
	s.mu.RLock()
	ids := make([]uint64, 0)
	for upSEID, owner := range s.sessionOwner {
		if owner.Addr() == peer {
			ids = append(ids, upSEID)
		}
	}
	s.mu.RUnlock()
	purged := 0
	complete := true
	for _, upSEID := range ids {
		if current, ok := s.store.FindByUPSEID(upSEID); ok {
			if s.store.Delete(upSEID, current.Revision) != nil {
				complete = false
				continue
			}
			purged++
		}
		s.mu.Lock()
		delete(s.sessionOwner, upSEID)
		s.mu.Unlock()
	}
	return purged, complete
}

func (s *Server) beginReconciliation(peer netip.Addr) {
	peer = peer.Unmap()
	s.mu.Lock()
	pending := make(map[uint64]struct{})
	for upSEID, owner := range s.sessionOwner {
		if owner.Addr().Unmap() == peer {
			pending[upSEID] = struct{}{}
		}
	}
	s.reconcilePending[peer] = pending
	s.mu.Unlock()
}

func (s *Server) completeReconciliation(peer netip.Addr) (int, bool) {
	peer = peer.Unmap()
	s.mu.RLock()
	pending := s.reconcilePending[peer]
	ids := make([]uint64, 0, len(pending))
	for upSEID := range pending {
		ids = append(ids, upSEID)
	}
	s.mu.RUnlock()
	purged := 0
	complete := true
	for _, upSEID := range ids {
		if current, ok := s.store.FindByUPSEID(upSEID); ok {
			if s.store.Delete(upSEID, current.Revision) != nil {
				complete = false
				continue
			}
			purged++
		}
		s.mu.Lock()
		delete(s.sessionOwner, upSEID)
		delete(s.reconcilePending[peer], upSEID)
		s.mu.Unlock()
	}
	if !complete {
		return purged, false
	}
	s.mu.Lock()
	delete(s.reconcilePending, peer)
	s.mu.Unlock()
	return purged, s.associations.Complete(peer)
}

func (s *Server) associationLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.sweepAssociations()
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) sweepAssociations() {
	for _, transition := range s.associations.Sweep() {
		switch transition.To {
		case pfcpassociation.StateGrace:
			s.graceEntries.Add(1)
		case pfcpassociation.StateUnavailable:
			purged, _ := s.purgePeerSessions(transition.Peer)
			s.staleSessionsPurged.Add(uint64(purged))
			s.graceExpirations.Add(1)
			s.mu.Lock()
			delete(s.reconcilePending, transition.Peer)
			s.mu.Unlock()
		}
	}
}
