// Package pfcpserver implements the SGW-U side of the 3GPP Sxa interface.
package pfcpserver

import (
	"container/heap"
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
	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/pfcp"
)

type Config struct {
	Listen             netip.AddrPort
	Advertise          netip.Addr
	AccessUserIP       netip.Addr
	CoreUserIP         netip.Addr
	AllowedCP          []netip.Addr
	StartedAt          time.Time
	ReportQueueSize    int
	ReportSuppression  time.Duration
	ReportTimeout      time.Duration
	AssociationTimeout time.Duration
	GraceWindow        time.Duration
	EnterpriseID       uint16
	Transport          pfcptransport.Config
}

type Association = pfcpassociation.Record

type Counters struct {
	AssociationsEstablished   uint64
	SessionsEstablished       uint64
	SessionsModified          uint64
	SessionsDeleted           uint64
	RejectedRequests          uint64
	DownlinkReportsQueued     uint64
	DownlinkReportsSent       uint64
	DownlinkReportsFailed     uint64
	DownlinkReportsSuppressed uint64
	DownlinkReportsDropped    uint64
	PeerRestarts              uint64
	GraceEntries              uint64
	GraceExpirations          uint64
	Reconciliations           uint64
	StaleSessionsPurged       uint64
	UsageReportsGenerated     uint64
	UsageReportsSent          uint64
	UsageReportsRetried       uint64
	UsageReportsFailed        uint64
	UsageReportsPending       uint64
	UsageReportQueueFull      uint64
	UsageCounterResets        uint64
	UsageTrackedURRs          uint64
}

type downlinkReport struct {
	UPSEID    uint64
	PDRID     uint16
	QCI       uint8
	ARP       uint8
	NotBefore time.Time
	Sequence  uint64
}

type reportKey struct {
	UPSEID uint64
	PDRID  uint16
}

type reportHeap []downlinkReport

func (h reportHeap) Len() int { return len(h) }
func (h reportHeap) Less(i, j int) bool {
	if !h[i].NotBefore.Equal(h[j].NotBefore) {
		return h[i].NotBefore.Before(h[j].NotBefore)
	}
	iIMS, jIMS := h[i].QCI == 5, h[j].QCI == 5
	if iIMS != jIMS {
		return iIMS
	}
	if h[i].ARP != h[j].ARP {
		if h[i].ARP == 0 {
			return false
		}
		if h[j].ARP == 0 {
			return true
		}
		return h[i].ARP < h[j].ARP
	}
	return h[i].Sequence < h[j].Sequence
}
func (h reportHeap) Swap(i, j int)   { h[i], h[j] = h[j], h[i] }
func (h *reportHeap) Push(value any) { *h = append(*h, value.(downlinkReport)) }
func (h *reportHeap) Pop() any {
	old := *h
	last := len(old) - 1
	value := old[last]
	old[last] = downlinkReport{}
	*h = old[:last]
	return value
}

type SessionObserver interface {
	SessionChanged(upSEID uint64)
	SessionDeleted(upSEID uint64)
}

type Server struct {
	config   Config
	endpoint *pfcptransport.Endpoint
	store    *rules.Store

	mu               sync.RWMutex
	associations     *pfcpassociation.Manager
	sessionOwner     map[uint64]netip.AddrPort
	reconcilePending map[netip.Addr]map[uint64]struct{}
	reportNotBefore  map[reportKey]time.Time
	reports          chan downlinkReport
	readyReports     chan downlinkReport
	observer         SessionObserver
	usageEmitter     *usagereport.Emitter

	associationsEstablished   atomic.Uint64
	sessionsEstablished       atomic.Uint64
	sessionsModified          atomic.Uint64
	sessionsDeleted           atomic.Uint64
	rejectedRequests          atomic.Uint64
	downlinkReportsQueued     atomic.Uint64
	downlinkReportsSent       atomic.Uint64
	downlinkReportsFailed     atomic.Uint64
	downlinkReportsSuppressed atomic.Uint64
	downlinkReportsDropped    atomic.Uint64
	reportSequence            atomic.Uint64
	pendingReports            atomic.Int64
	peerRestarts              atomic.Uint64
	graceEntries              atomic.Uint64
	graceExpirations          atomic.Uint64
	reconciliations           atomic.Uint64
	staleSessionsPurged       atomic.Uint64
}

func New(config Config, store *rules.Store) (*Server, error) {
	if store == nil {
		return nil, errors.New("sgwu PFCP: nil rule store")
	}
	if !config.Listen.Addr().IsValid() || !config.Advertise.IsValid() || !config.AccessUserIP.IsValid() || !config.CoreUserIP.IsValid() {
		return nil, errors.New("sgwu PFCP: listen, advertise, access, and core addresses are required")
	}
	if len(config.AllowedCP) == 0 {
		return nil, errors.New("sgwu PFCP: at least one allowed SGW-C address is required")
	}
	if config.EnterpriseID == 10415 {
		return nil, errors.New("sgwu PFCP: enterprise ID 10415 is reserved for 3GPP")
	}
	for index, addr := range config.AllowedCP {
		if !addr.IsValid() {
			return nil, fmt.Errorf("sgwu PFCP: invalid allowed SGW-C address at index %d", index)
		}
		config.AllowedCP[index] = addr.Unmap()
	}
	config.Advertise = config.Advertise.Unmap()
	config.AccessUserIP = config.AccessUserIP.Unmap()
	config.CoreUserIP = config.CoreUserIP.Unmap()
	if config.StartedAt.IsZero() {
		config.StartedAt = time.Now().UTC()
	}
	if config.ReportQueueSize < 0 || config.ReportSuppression < 0 || config.ReportTimeout < 0 {
		return nil, errors.New("sgwu PFCP: invalid downlink report configuration")
	}
	if config.ReportQueueSize == 0 {
		config.ReportQueueSize = 1024
	}
	if config.ReportSuppression == 0 {
		config.ReportSuppression = time.Second
	}
	if config.ReportTimeout == 0 {
		config.ReportTimeout = 5 * time.Second
	}
	associations, err := pfcpassociation.New(pfcpassociation.Config{
		Timeout: config.AssociationTimeout, GraceWindow: config.GraceWindow,
	})
	if err != nil {
		return nil, err
	}
	server := &Server{
		config:           config,
		store:            store,
		associations:     associations,
		sessionOwner:     make(map[uint64]netip.AddrPort),
		reconcilePending: make(map[netip.Addr]map[uint64]struct{}),
		reportNotBefore:  make(map[reportKey]time.Time),
		reports:          make(chan downlinkReport, config.ReportQueueSize),
		readyReports:     make(chan downlinkReport, config.ReportQueueSize),
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
	go s.reportLoop(child)
	for worker := 0; worker < 4; worker++ {
		go s.reportWorker(child)
	}
	go s.associationLoop(child)
	s.mu.RLock()
	emitter := s.usageEmitter
	s.mu.RUnlock()
	if emitter != nil {
		go emitter.Run(child)
	}
	return s.endpoint.Serve(child)
}

func (s *Server) Close() error {
	return s.endpoint.Close()
}

func (s *Server) LocalAddr() netip.AddrPort {
	return s.endpoint.LocalAddr()
}

// SetSessionObserver wires post-commit packet-path actions. It must be called
// before Serve starts.
func (s *Server) SetSessionObserver(observer SessionObserver) {
	s.mu.Lock()
	s.observer = observer
	s.mu.Unlock()
}

func (s *Server) notifyChanged(upSEID uint64) {
	s.mu.RLock()
	observer := s.observer
	s.mu.RUnlock()
	if observer != nil {
		observer.SessionChanged(upSEID)
	}
}

func (s *Server) notifyDeleted(upSEID uint64) {
	s.mu.RLock()
	observer := s.observer
	s.mu.RUnlock()
	if observer != nil {
		observer.SessionDeleted(upSEID)
	}
}

func (s *Server) TransportCounters() pfcptransport.Counters {
	return s.endpoint.Counters()
}

func (s *Server) Associations() []Association {
	return s.associations.Snapshot()
}

func (s *Server) AssociationState(peer netip.Addr) pfcpassociation.State {
	return s.associations.State(peer)
}

func (s *Server) GraceRemaining(peer netip.Addr) time.Duration {
	return s.associations.GraceRemaining(peer)
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
		AssociationsEstablished:   s.associationsEstablished.Load(),
		SessionsEstablished:       s.sessionsEstablished.Load(),
		SessionsModified:          s.sessionsModified.Load(),
		SessionsDeleted:           s.sessionsDeleted.Load(),
		RejectedRequests:          s.rejectedRequests.Load(),
		DownlinkReportsQueued:     s.downlinkReportsQueued.Load(),
		DownlinkReportsSent:       s.downlinkReportsSent.Load(),
		DownlinkReportsFailed:     s.downlinkReportsFailed.Load(),
		DownlinkReportsSuppressed: s.downlinkReportsSuppressed.Load(),
		DownlinkReportsDropped:    s.downlinkReportsDropped.Load(),
		PeerRestarts:              s.peerRestarts.Load(),
		GraceEntries:              s.graceEntries.Load(),
		GraceExpirations:          s.graceExpirations.Load(),
		Reconciliations:           s.reconciliations.Load(),
		StaleSessionsPurged:       s.staleSessionsPurged.Load(),
		UsageReportsGenerated:     usage.ReportsGenerated,
		UsageReportsSent:          usage.ReportsSent,
		UsageReportsRetried:       usage.ReportsRetried,
		UsageReportsFailed:        usage.ReportsFailed,
		UsageReportsPending:       usage.PendingReports,
		UsageReportQueueFull:      usage.QueueFull,
		UsageCounterResets:        usage.CounterResets,
		UsageTrackedURRs:          usage.TrackedURRs,
	}
}

// SetUsageSource enables telemetry-only PFCP Usage Reports. It must be called
// before Serve so the emitter has one stable dataplane snapshot source.
func (s *Server) SetUsageSource(snapshot func() []usagereport.Measurement) error {
	emitter, err := usagereport.NewEmitter(usagereport.EmitterConfig{
		Snapshot: snapshot, ReportTimeout: s.config.ReportTimeout,
		QueueSize:     s.config.ReportQueueSize,
		ResolveCPSEID: s.resolveUsageCPSEID, Send: s.sendUsageReport,
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.usageEmitter != nil {
		return errors.New("sgwu PFCP: usage source is already configured")
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
		return errors.New("sgwu PFCP: usage report session no longer exists")
	}
	s.mu.RLock()
	owner, owned := s.sessionOwner[upSEID]
	s.mu.RUnlock()
	if !owned || s.associations.State(owner.Addr()) != pfcpassociation.StateAssociated {
		return errors.New("sgwu PFCP: usage report association is unavailable")
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
		return errors.New("sgwu PFCP: usage report response has the wrong UP-SEID")
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
		return fmt.Errorf("sgwu PFCP: usage report rejected with cause %d", cause)
	}
	return nil
}

// QueueDownlinkReport is safe for the packet loop: it never blocks. Normal
// bearers are suppressed independently per PDR; QCI 5 deliberately bypasses
// suppression so IMS signalling cannot be hidden behind bulk bearer traffic.
func (s *Server) QueueDownlinkReport(upSEID uint64, pdrID uint16, qci, arp uint8, delay time.Duration) bool {
	if upSEID == 0 || pdrID == 0 {
		return false
	}
	now := time.Now()
	key := reportKey{UPSEID: upSEID, PDRID: pdrID}
	s.mu.Lock()
	if _, ok := s.sessionOwner[upSEID]; !ok {
		s.mu.Unlock()
		return false
	}
	if qci != 5 && s.reportNotBefore[key].After(now) {
		s.mu.Unlock()
		s.downlinkReportsSuppressed.Add(1)
		return false
	}
	for {
		pending := s.pendingReports.Load()
		if pending >= int64(s.config.ReportQueueSize) {
			s.mu.Unlock()
			s.downlinkReportsDropped.Add(1)
			return false
		}
		if s.pendingReports.CompareAndSwap(pending, pending+1) {
			break
		}
	}
	select {
	case s.reports <- downlinkReport{
		UPSEID: upSEID, PDRID: pdrID, QCI: qci, ARP: arp,
		NotBefore: now.Add(delay), Sequence: s.reportSequence.Add(1),
	}:
		if qci != 5 {
			s.reportNotBefore[key] = now.Add(s.config.ReportSuppression)
		}
		s.mu.Unlock()
		s.downlinkReportsQueued.Add(1)
		return true
	default:
		s.pendingReports.Add(-1)
		s.mu.Unlock()
		s.downlinkReportsDropped.Add(1)
		return false
	}
}

func (s *Server) reportLoop(ctx context.Context) {
	queue := make(reportHeap, 0, s.config.ReportQueueSize)
	heap.Init(&queue)
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	for {
		var ready chan<- downlinkReport
		var next downlinkReport
		var wake <-chan time.Time
		if queue.Len() > 0 {
			next = queue[0]
			until := time.Until(next.NotBefore)
			if until <= 0 {
				ready = s.readyReports
			} else {
				timer.Reset(until)
				wake = timer.C
			}
		}
		select {
		case report := <-s.reports:
			heap.Push(&queue, report)
		case ready <- next:
			heap.Pop(&queue)
		case <-wake:
		case <-ctx.Done():
			return
		}
		if wake != nil && !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

func (s *Server) reportWorker(ctx context.Context) {
	for {
		select {
		case report := <-s.readyReports:
			s.sendDownlinkReport(ctx, report)
			s.pendingReports.Add(-1)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) sendDownlinkReport(parent context.Context, report downlinkReport) {
	current, ok := s.store.FindByUPSEID(report.UPSEID)
	if !ok {
		s.downlinkReportsFailed.Add(1)
		return
	}
	s.mu.RLock()
	owner, owned := s.sessionOwner[report.UPSEID]
	s.mu.RUnlock()
	if !owned {
		s.downlinkReportsFailed.Add(1)
		return
	}
	reportType, _ := pfcp.NewReportTypeIE(pfcp.ReportDownlinkData)
	pdrID, _ := pfcp.NewPDRIDIE(report.PDRID)
	downlink, err := pfcp.NewGroupedIE(pfcp.IEDownlinkDataReport, pdrID)
	if err != nil {
		s.downlinkReportsFailed.Add(1)
		return
	}
	ctx, cancel := context.WithTimeout(parent, s.config.ReportTimeout)
	response, err := s.endpoint.Do(ctx, owner, pfcp.Message{
		Header: pfcp.Header{
			Version: pfcp.Version, HasSEID: true,
			MessageType: pfcp.MessageSessionReportRequest, SEID: current.CPSEID,
		},
		IEs: []pfcp.IE{reportType, downlink},
	})
	cancel()
	if err != nil || !response.Header.HasSEID || response.Header.SEID != current.UPSEID {
		s.downlinkReportsFailed.Add(1)
		return
	}
	causeIE, ok := response.Find(pfcp.IECause)
	if !ok {
		s.downlinkReportsFailed.Add(1)
		return
	}
	cause, err := causeIE.Cause()
	if err != nil || cause != pfcp.CauseRequestAccepted {
		s.downlinkReportsFailed.Add(1)
		return
	}
	s.downlinkReportsSent.Add(1)
}

func (s *Server) handle(_ context.Context, peer netip.AddrPort, request pfcp.Message) (*pfcp.Message, error) {
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	peerIP := peer.Addr().Unmap()
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
	return &pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, MessageType: pfcp.MessageHeartbeatResponse},
		IEs:    []pfcp.IE{recovery},
	}
}

func (s *Server) associationSetup(peer netip.Addr, request pfcp.Message) *pfcp.Message {
	nodeIE, nodeOK := request.Find(pfcp.IENodeID)
	recoveryIE, recoveryOK := request.Find(pfcp.IERecoveryTimeStamp)
	if !nodeOK || !recoveryOK {
		s.rejectedRequests.Add(1)
		return s.associationResponse(pfcp.CauseMandatoryIEMissing)
	}
	nodeAddress, nodeFQDN, err := nodeIE.NodeID()
	if err != nil {
		s.rejectedRequests.Add(1)
		return s.associationResponse(pfcp.CauseMandatoryIEIncorrect)
	}
	recoveryTime, err := recoveryIE.RecoveryTimeStamp()
	if err != nil {
		s.rejectedRequests.Add(1)
		return s.associationResponse(pfcp.CauseMandatoryIEIncorrect)
	}
	result := s.associations.Setup(peer, nodeAddress, nodeFQDN, recoveryTime)
	if result.Reconcile {
		s.beginReconciliation(peer)
	}
	if result.RecoveryChanged {
		s.peerRestarts.Add(1)
	}
	s.associationsEstablished.Add(1)
	return s.associationResponse(pfcp.CauseRequestAccepted)
}

func (s *Server) associationResponse(cause uint8) *pfcp.Message {
	nodeID, _ := pfcp.NewNodeIDIE(s.config.Advertise, "")
	recovery, _ := pfcp.NewRecoveryTimeStampIE(s.config.StartedAt)
	return &pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, MessageType: pfcp.MessageAssociationSetupResponse},
		IEs:    []pfcp.IE{nodeID, pfcp.NewCauseIE(cause), recovery},
	}
}

func (s *Server) associationUpdate(peer netip.Addr) *pfcp.Message {
	cause := pfcp.CauseRequestAccepted
	state := s.associations.State(peer)
	if state == pfcpassociation.StateReconciling {
		purged := s.completeReconciliation(peer)
		s.staleSessionsPurged.Add(uint64(purged))
		s.reconciliations.Add(1)
	} else if state != pfcpassociation.StateAssociated {
		cause = pfcp.CauseNoAssociation
		s.rejectedRequests.Add(1)
	}
	nodeID, _ := pfcp.NewNodeIDIE(s.config.Advertise, "")
	return &pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, MessageType: pfcp.MessageAssociationUpdateResponse},
		IEs:    []pfcp.IE{nodeID, pfcp.NewCauseIE(cause)},
	}
}

func (s *Server) associationRelease(peer netip.Addr) *pfcp.Message {
	cause := pfcp.CauseRequestAccepted
	if s.associations.State(peer) == pfcpassociation.StateUnavailable {
		cause = pfcp.CauseNoAssociation
		s.rejectedRequests.Add(1)
	} else {
		s.purgePeerSessions(peer)
		s.associations.Release(peer)
		s.mu.Lock()
		delete(s.reconcilePending, peer.Unmap())
		s.mu.Unlock()
	}
	nodeID, _ := pfcp.NewNodeIDIE(s.config.Advertise, "")
	return &pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, MessageType: pfcp.MessageAssociationReleaseResponse},
		IEs:    []pfcp.IE{nodeID, pfcp.NewCauseIE(cause)},
	}
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
	if err != nil || cpFSEID.IPv4.Unmap() != peer.Addr().Unmap() {
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
			s.rejectedRequests.Add(1)
			return s.establishmentResponse(cpFSEID.SEID, 0, pfcp.CauseRuleCreationFailure)
		}
		reconciled, err := s.store.Reconcile(cpFSEID.SEID, candidate)
		if err != nil {
			s.rejectedRequests.Add(1)
			return s.establishmentResponse(cpFSEID.SEID, 0, pfcp.CauseRuleCreationFailure)
		}
		s.mu.Lock()
		s.sessionOwner[reconciled.UPSEID] = peer
		if pending := s.reconcilePending[peer.Addr()]; pending != nil {
			delete(pending, reconciled.UPSEID)
		}
		s.mu.Unlock()
		s.notifyChanged(reconciled.UPSEID)
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
		s.rejectedRequests.Add(1)
		return s.establishmentResponse(cpFSEID.SEID, 0, pfcp.CauseRuleCreationFailure)
	}
	if _, err := s.store.Create(candidate); err != nil {
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
	s.notifyChanged(upSEID)
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
	return &pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, HasSEID: true, MessageType: pfcp.MessageSessionEstablishmentResponse, SEID: cpSEID},
		IEs:    ies,
	}
}

func (s *Server) sessionModification(peer netip.AddrPort, request pfcp.Message) *pfcp.Message {
	if !s.associations.CanMutate(peer.Addr()) {
		s.rejectedRequests.Add(1)
		return s.sessionResponse(pfcp.MessageSessionModificationResponse, 0, pfcp.CauseNoAssociation)
	}
	upSEID := request.Header.SEID
	current, ok := s.store.FindByUPSEID(upSEID)
	if !ok || !s.owns(peer, upSEID) {
		s.rejectedRequests.Add(1)
		return s.sessionResponse(pfcp.MessageSessionModificationResponse, 0, pfcp.CauseSessionNotFound)
	}
	_, err := s.store.Update(upSEID, current.Revision, func(session *rules.Session) error {
		return s.applyModifications(session, request.IEs)
	})
	if err != nil {
		s.rejectedRequests.Add(1)
		return s.sessionResponse(pfcp.MessageSessionModificationResponse, current.CPSEID, pfcp.CauseRuleCreationFailure)
	}
	s.notifyChanged(upSEID)
	s.sessionsModified.Add(1)
	return s.sessionResponse(pfcp.MessageSessionModificationResponse, current.CPSEID, pfcp.CauseRequestAccepted)
}

func (s *Server) sessionDeletion(peer netip.AddrPort, request pfcp.Message) *pfcp.Message {
	if !s.associations.CanMutate(peer.Addr()) {
		s.rejectedRequests.Add(1)
		return s.sessionResponse(pfcp.MessageSessionDeletionResponse, 0, pfcp.CauseNoAssociation)
	}
	upSEID := request.Header.SEID
	current, ok := s.store.FindByUPSEID(upSEID)
	if !ok || !s.owns(peer, upSEID) {
		s.rejectedRequests.Add(1)
		return s.sessionResponse(pfcp.MessageSessionDeletionResponse, 0, pfcp.CauseSessionNotFound)
	}
	if err := s.store.Delete(upSEID, current.Revision); err != nil {
		s.rejectedRequests.Add(1)
		return s.sessionResponse(pfcp.MessageSessionDeletionResponse, current.CPSEID, pfcp.CauseSystemFailure)
	}
	s.mu.Lock()
	delete(s.sessionOwner, upSEID)
	s.clearReportSuppressionLocked(upSEID)
	s.mu.Unlock()
	s.notifyDeleted(upSEID)
	s.sessionsDeleted.Add(1)
	return s.sessionResponse(pfcp.MessageSessionDeletionResponse, current.CPSEID, pfcp.CauseRequestAccepted)
}

func (s *Server) sessionResponse(messageType uint8, cpSEID uint64, cause uint8) *pfcp.Message {
	return &pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, HasSEID: true, MessageType: messageType, SEID: cpSEID},
		IEs:    []pfcp.IE{pfcp.NewCauseIE(cause)},
	}
}

func (s *Server) unsupportedResponse(request pfcp.Message) *pfcp.Message {
	typ, ok := pfcptransport.ExpectedResponseType(request.Header.MessageType)
	if !ok {
		return nil
	}
	return &pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, HasSEID: request.Header.HasSEID, MessageType: typ, SEID: 0},
		IEs:    []pfcp.IE{pfcp.NewCauseIE(pfcp.CauseServiceNotSupported)},
	}
}

func (s *Server) decodeSession(ies []pfcp.IE, cpSEID, upSEID uint64) (rules.Session, error) {
	session := rules.Session{
		CPSEID: cpSEID,
		UPSEID: upSEID,
		PDRs:   make(map[uint16]rules.PDR),
		FARs:   make(map[uint32]rules.FAR),
		QERs:   make(map[uint32]rules.QER),
		URRs:   make(map[uint32]rules.URR),
		BARs:   make(map[uint8]rules.BAR),
	}
	for _, ie := range pfcp.FindAllIEs(ies, pfcp.IECreateBAR) {
		bar, err := decodeBAR(ie)
		if err != nil {
			return rules.Session{}, err
		}
		if _, exists := session.BARs[bar.ID]; exists {
			return rules.Session{}, fmt.Errorf("duplicate BAR %d", bar.ID)
		}
		session.BARs[bar.ID] = bar
	}
	for _, ie := range pfcp.FindAllIEs(ies, pfcp.IECreateFAR) {
		far, err := decodeFAR(ie)
		if err != nil {
			return rules.Session{}, err
		}
		if _, exists := session.FARs[far.ID]; exists {
			return rules.Session{}, fmt.Errorf("duplicate FAR %d", far.ID)
		}
		session.FARs[far.ID] = far
	}
	for _, ie := range pfcp.FindAllIEs(ies, pfcp.IECreateQER) {
		qer, err := decodeQER(ie, s.config.EnterpriseID)
		if err != nil {
			return rules.Session{}, err
		}
		if _, exists := session.QERs[qer.ID]; exists {
			return rules.Session{}, fmt.Errorf("duplicate QER %d", qer.ID)
		}
		session.QERs[qer.ID] = qer
	}
	for _, ie := range pfcp.FindAllIEs(ies, pfcp.IECreateURR) {
		urr, err := decodeURR(ie)
		if err != nil {
			return rules.Session{}, err
		}
		if _, exists := session.URRs[urr.ID]; exists {
			return rules.Session{}, fmt.Errorf("duplicate URR %d", urr.ID)
		}
		session.URRs[urr.ID] = urr
	}
	for _, ie := range pfcp.FindAllIEs(ies, pfcp.IECreatePDR) {
		pdr, err := decodePDR(ie)
		if err != nil {
			return rules.Session{}, err
		}
		expectedIP := s.config.AccessUserIP
		if pdr.SourceInterface == rules.SourceCore {
			expectedIP = s.config.CoreUserIP
		}
		if pdr.LocalFTEID.IP.Unmap() != expectedIP {
			return rules.Session{}, fmt.Errorf("PDR %d local F-TEID address %s does not match %s", pdr.ID, pdr.LocalFTEID.IP, expectedIP)
		}
		if _, exists := session.PDRs[pdr.ID]; exists {
			return rules.Session{}, fmt.Errorf("duplicate PDR %d", pdr.ID)
		}
		session.PDRs[pdr.ID] = pdr
	}
	return session, nil
}

func decodePDR(grouped pfcp.IE) (rules.PDR, error) {
	children, err := grouped.Children()
	if err != nil {
		return rules.PDR{}, err
	}
	idIE, ok := pfcp.FindIE(children, pfcp.IEPDRID)
	if !ok {
		return rules.PDR{}, pfcp.ErrMissingIE
	}
	id, err := idIE.PDRID()
	if err != nil {
		return rules.PDR{}, err
	}
	pdiIE, ok := pfcp.FindIE(children, pfcp.IEPDI)
	if !ok {
		return rules.PDR{}, pfcp.ErrMissingIE
	}
	pdi, err := pdiIE.Children()
	if err != nil {
		return rules.PDR{}, err
	}
	sourceIE, sourceOK := pfcp.FindIE(pdi, pfcp.IESourceInterface)
	fteidIE, fteidOK := pfcp.FindIE(pdi, pfcp.IEFTEID)
	farIDIE, farOK := pfcp.FindIE(children, pfcp.IEFARID)
	removalIE, removalOK := pfcp.FindIE(children, pfcp.IEOuterHeaderRemoval)
	if !sourceOK || !fteidOK || !farOK || !removalOK {
		return rules.PDR{}, pfcp.ErrMissingIE
	}
	source, err := sourceIE.Interface()
	if err != nil || source > pfcp.InterfaceCore {
		return rules.PDR{}, fmt.Errorf("invalid PDR source interface")
	}
	fteid, err := fteidIE.FTEID()
	if err != nil || !fteid.IPv4.IsValid() {
		return rules.PDR{}, fmt.Errorf("invalid PDR F-TEID")
	}
	if _, err := removalIE.OuterHeaderRemoval(); err != nil {
		return rules.PDR{}, err
	}
	farID, err := farIDIE.Uint32()
	if err != nil || farID == 0 {
		return rules.PDR{}, fmt.Errorf("invalid PDR FAR ID")
	}
	precedence := uint32(0)
	if precedenceIE, ok := pfcp.FindIE(children, pfcp.IEPrecedence); ok {
		precedence, err = precedenceIE.Uint32()
		if err != nil {
			return rules.PDR{}, err
		}
	}
	pdr := rules.PDR{
		ID:              id,
		Precedence:      precedence,
		SourceInterface: rules.SourceInterface(source),
		LocalFTEID:      rules.FTEID{TEID: fteid.TEID, IP: fteid.IPv4},
		FARID:           farID,
	}
	for _, qerIE := range pfcp.FindAllIEs(children, pfcp.IEQERID) {
		qerID, err := qerIE.Uint32()
		if err != nil || qerID == 0 {
			return rules.PDR{}, fmt.Errorf("invalid PDR QER ID")
		}
		pdr.QERIDs = append(pdr.QERIDs, qerID)
	}
	for _, urrIE := range pfcp.FindAllIEs(children, pfcp.IEURRID) {
		urrID, err := urrIE.Uint32()
		if err != nil || urrID == 0 {
			return rules.PDR{}, fmt.Errorf("invalid PDR URR ID")
		}
		pdr.URRIDs = append(pdr.URRIDs, urrID)
	}
	return pdr, nil
}

func decodeFAR(grouped pfcp.IE) (rules.FAR, error) {
	children, err := grouped.Children()
	if err != nil {
		return rules.FAR{}, err
	}
	idIE, idOK := pfcp.FindIE(children, pfcp.IEFARID)
	actionIE, actionOK := pfcp.FindIE(children, pfcp.IEApplyAction)
	if !idOK || !actionOK {
		return rules.FAR{}, pfcp.ErrMissingIE
	}
	id, err := idIE.Uint32()
	if err != nil || id == 0 {
		return rules.FAR{}, fmt.Errorf("invalid FAR ID")
	}
	action, err := actionIE.ApplyAction()
	if err != nil {
		return rules.FAR{}, err
	}
	far := rules.FAR{ID: id, ApplyAction: rules.ApplyAction(action)}
	if barIDIE, ok := pfcp.FindIE(children, pfcp.IEBARID); ok {
		barID, err := barIDIE.BARID()
		if err != nil {
			return rules.FAR{}, err
		}
		far.BARID = barID
	}
	if action&pfcp.ApplyForward == 0 {
		return far, nil
	}
	forwardingIE, ok := pfcp.FindIE(children, pfcp.IEForwardingParameters)
	if !ok {
		return rules.FAR{}, pfcp.ErrMissingIE
	}
	if err := applyForwardingParameters(&far, forwardingIE); err != nil {
		return rules.FAR{}, err
	}
	return far, nil
}

func applyForwardingParameters(far *rules.FAR, grouped pfcp.IE) error {
	children, err := grouped.Children()
	if err != nil {
		return err
	}
	destinationIE, ok := pfcp.FindIE(children, pfcp.IEDestinationInterface)
	if !ok {
		return pfcp.ErrMissingIE
	}
	destination, err := destinationIE.Interface()
	if err != nil || destination > pfcp.InterfaceCore {
		return fmt.Errorf("invalid FAR destination interface")
	}
	far.DestinationInterface = rules.DestinationInterface(destination)
	outerIE, ok := pfcp.FindIE(children, pfcp.IEOuterHeaderCreation)
	if !ok {
		return pfcp.ErrMissingIE
	}
	outer, err := outerIE.OuterHeaderCreation()
	if err != nil || !outer.IPv4.IsValid() {
		return fmt.Errorf("invalid FAR outer header")
	}
	far.OuterHeader = &rules.FTEID{TEID: outer.TEID, IP: outer.IPv4}
	return nil
}

func decodeQER(grouped pfcp.IE, enterpriseID uint16) (rules.QER, error) {
	children, err := grouped.Children()
	if err != nil {
		return rules.QER{}, err
	}
	idIE, idOK := pfcp.FindIE(children, pfcp.IEQERID)
	gateIE, gateOK := pfcp.FindIE(children, pfcp.IEGateStatus)
	if !idOK || !gateOK {
		return rules.QER{}, pfcp.ErrMissingIE
	}
	id, err := idIE.Uint32()
	if err != nil || id == 0 {
		return rules.QER{}, fmt.Errorf("invalid QER ID")
	}
	uplinkOpen, downlinkOpen, err := gateIE.GateStatus()
	if err != nil {
		return rules.QER{}, err
	}
	qer := rules.QER{ID: id, UplinkGateOpen: uplinkOpen, DownlinkGateOpen: downlinkOpen}
	if mbrIE, ok := pfcp.FindIE(children, pfcp.IEMBR); ok {
		uplink, downlink, err := mbrIE.BitRate()
		if err != nil {
			return rules.QER{}, err
		}
		qer.MaxUplinkBitsPerSecond = uplink * 1000
		qer.MaxDownlinkBitsPerSecond = downlink * 1000
	}
	if metadataIE, ok := pfcp.FindIE(children, pfcp.IEVendorBearerQoS); ok && enterpriseID != 0 {
		metadata, err := metadataIE.VendorBearerQoS()
		if err != nil {
			return rules.QER{}, err
		}
		if metadata.EnterpriseID == enterpriseID {
			qer.QCI = metadata.QCI
			qer.ARP = metadata.ARP
			qer.PreemptionCapable = metadata.PreemptionCapable
			qer.PreemptionVulnerable = metadata.PreemptionVulnerable
		}
	}
	return qer, nil
}

func decodeURR(grouped pfcp.IE) (rules.URR, error) {
	children, err := grouped.Children()
	if err != nil {
		return rules.URR{}, err
	}
	idIE, idOK := pfcp.FindIE(children, pfcp.IEURRID)
	methodIE, methodOK := pfcp.FindIE(children, pfcp.IEMeasurementMethod)
	triggersIE, triggersOK := pfcp.FindIE(children, pfcp.IEReportingTriggers)
	thresholdIE, thresholdOK := pfcp.FindIE(children, pfcp.IEVolumeThreshold)
	if !idOK || !methodOK || !triggersOK || !thresholdOK {
		return rules.URR{}, pfcp.ErrMissingIE
	}
	id, err := idIE.Uint32()
	if err != nil || id == 0 {
		return rules.URR{}, errors.New("invalid URR ID")
	}
	volume, duration, err := methodIE.MeasurementMethod()
	if err != nil || !volume {
		return rules.URR{}, errors.New("SGW-U URR requires volume measurement")
	}
	triggers, err := triggersIE.ReportingTriggers()
	if err != nil || triggers != pfcp.ReportingTriggerVolumeThreshold {
		return rules.URR{}, errors.New("SGW-U URR supports only telemetry volume-threshold reporting")
	}
	threshold, err := thresholdIE.VolumeThreshold()
	if err != nil || !threshold.HasTotal || threshold.HasUplink || threshold.HasDownlink {
		return rules.URR{}, errors.New("SGW-U URR requires one total-volume threshold")
	}
	return rules.URR{ID: id, MeasureVolume: volume, MeasureDuration: duration, ReportingThreshold: threshold.Total}, nil
}

func updateURR(current rules.URR, grouped pfcp.IE) (rules.URR, error) {
	children, err := grouped.Children()
	if err != nil {
		return rules.URR{}, err
	}
	idIE, ok := pfcp.FindIE(children, pfcp.IEURRID)
	if !ok {
		return rules.URR{}, pfcp.ErrMissingIE
	}
	id, err := idIE.Uint32()
	if err != nil || id != current.ID {
		return rules.URR{}, errors.New("invalid updated URR ID")
	}
	updated := current
	if methodIE, ok := pfcp.FindIE(children, pfcp.IEMeasurementMethod); ok {
		volume, duration, err := methodIE.MeasurementMethod()
		if err != nil || !volume {
			return rules.URR{}, errors.New("SGW-U URR requires volume measurement")
		}
		updated.MeasureVolume, updated.MeasureDuration = volume, duration
	}
	if triggersIE, ok := pfcp.FindIE(children, pfcp.IEReportingTriggers); ok {
		triggers, err := triggersIE.ReportingTriggers()
		if err != nil || triggers != pfcp.ReportingTriggerVolumeThreshold {
			return rules.URR{}, errors.New("SGW-U URR supports only telemetry volume-threshold reporting")
		}
	}
	if thresholdIE, ok := pfcp.FindIE(children, pfcp.IEVolumeThreshold); ok {
		threshold, err := thresholdIE.VolumeThreshold()
		if err != nil || !threshold.HasTotal || threshold.HasUplink || threshold.HasDownlink {
			return rules.URR{}, errors.New("SGW-U URR requires one total-volume threshold")
		}
		updated.ReportingThreshold = threshold.Total
	}
	return updated, nil
}

func decodeBAR(grouped pfcp.IE) (rules.BAR, error) {
	children, err := grouped.Children()
	if err != nil {
		return rules.BAR{}, err
	}
	idIE, ok := pfcp.FindIE(children, pfcp.IEBARID)
	if !ok {
		return rules.BAR{}, pfcp.ErrMissingIE
	}
	id, err := idIE.BARID()
	if err != nil {
		return rules.BAR{}, err
	}
	bar := rules.BAR{ID: id}
	if delayIE, ok := pfcp.FindIE(children, pfcp.IEDownlinkDataNotifyDelay); ok {
		bar.DownlinkNotificationDelay, err = delayIE.DownlinkDataNotificationDelay()
		if err != nil {
			return rules.BAR{}, err
		}
	}
	return bar, nil
}

func (s *Server) applyModifications(session *rules.Session, ies []pfcp.IE) error {
	if session.BARs == nil {
		session.BARs = make(map[uint8]rules.BAR)
	}
	if session.URRs == nil {
		session.URRs = make(map[uint32]rules.URR)
	}
	// Apply removals before creates so a control-plane transaction can replace
	// a rule ID. The rules store validates the fully mutated snapshot and only
	// then swaps it into the packet-path indexes.
	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IERemovePDR) {
		id, err := groupedPDRID(grouped)
		if err != nil {
			return err
		}
		if _, ok := session.PDRs[id]; !ok {
			return fmt.Errorf("unknown PDR %d", id)
		}
		delete(session.PDRs, id)
	}
	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IERemoveFAR) {
		id, err := groupedUint32ID(grouped, pfcp.IEFARID)
		if err != nil {
			return err
		}
		if _, ok := session.FARs[id]; !ok {
			return fmt.Errorf("unknown FAR %d", id)
		}
		delete(session.FARs, id)
	}
	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IERemoveQER) {
		id, err := groupedUint32ID(grouped, pfcp.IEQERID)
		if err != nil {
			return err
		}
		if _, ok := session.QERs[id]; !ok {
			return fmt.Errorf("unknown QER %d", id)
		}
		delete(session.QERs, id)
	}
	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IERemoveURR) {
		id, err := groupedUint32ID(grouped, pfcp.IEURRID)
		if err != nil {
			return err
		}
		if _, ok := session.URRs[id]; !ok {
			return fmt.Errorf("unknown URR %d", id)
		}
		delete(session.URRs, id)
	}
	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IERemoveBAR) {
		children, err := grouped.Children()
		if err != nil {
			return err
		}
		idIE, ok := pfcp.FindIE(children, pfcp.IEBARID)
		if !ok {
			return pfcp.ErrMissingIE
		}
		id, err := idIE.BARID()
		if err != nil {
			return err
		}
		if _, ok := session.BARs[id]; !ok {
			return fmt.Errorf("unknown BAR %d", id)
		}
		delete(session.BARs, id)
	}

	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IECreateBAR) {
		bar, err := decodeBAR(grouped)
		if err != nil {
			return err
		}
		if _, exists := session.BARs[bar.ID]; exists {
			return fmt.Errorf("duplicate BAR %d", bar.ID)
		}
		session.BARs[bar.ID] = bar
	}
	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IECreateFAR) {
		far, err := decodeFAR(grouped)
		if err != nil {
			return err
		}
		if _, exists := session.FARs[far.ID]; exists {
			return fmt.Errorf("duplicate FAR %d", far.ID)
		}
		session.FARs[far.ID] = far
	}
	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IECreateQER) {
		qer, err := decodeQER(grouped, s.config.EnterpriseID)
		if err != nil {
			return err
		}
		if _, exists := session.QERs[qer.ID]; exists {
			return fmt.Errorf("duplicate QER %d", qer.ID)
		}
		session.QERs[qer.ID] = qer
	}
	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IECreateURR) {
		urr, err := decodeURR(grouped)
		if err != nil {
			return err
		}
		if _, exists := session.URRs[urr.ID]; exists {
			return fmt.Errorf("duplicate URR %d", urr.ID)
		}
		session.URRs[urr.ID] = urr
	}
	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IECreatePDR) {
		pdr, err := decodePDR(grouped)
		if err != nil {
			return err
		}
		expectedIP := s.config.AccessUserIP
		if pdr.SourceInterface == rules.SourceCore {
			expectedIP = s.config.CoreUserIP
		}
		if pdr.LocalFTEID.IP.Unmap() != expectedIP {
			return fmt.Errorf("PDR %d local F-TEID address %s does not match %s", pdr.ID, pdr.LocalFTEID.IP, expectedIP)
		}
		if _, exists := session.PDRs[pdr.ID]; exists {
			return fmt.Errorf("duplicate PDR %d", pdr.ID)
		}
		session.PDRs[pdr.ID] = pdr
	}

	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IEUpdateFAR) {
		children, err := grouped.Children()
		if err != nil {
			return err
		}
		idIE, ok := pfcp.FindIE(children, pfcp.IEFARID)
		if !ok {
			return pfcp.ErrMissingIE
		}
		id, err := idIE.Uint32()
		if err != nil {
			return err
		}
		far, ok := session.FARs[id]
		if !ok {
			return fmt.Errorf("unknown FAR %d", id)
		}
		if actionIE, ok := pfcp.FindIE(children, pfcp.IEApplyAction); ok {
			action, err := actionIE.ApplyAction()
			if err != nil {
				return err
			}
			far.ApplyAction = rules.ApplyAction(action)
		}
		if barIDIE, ok := pfcp.FindIE(children, pfcp.IEBARID); ok {
			barID, err := barIDIE.BARID()
			if err != nil {
				return err
			}
			far.BARID = barID
		}
		if forwardingIE, ok := pfcp.FindIE(children, pfcp.IEUpdateForwardingParameters); ok {
			if err := applyForwardingParameters(&far, forwardingIE); err != nil {
				return err
			}
		}
		session.FARs[id] = far
	}
	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IEUpdateBAR) {
		updated, err := decodeBAR(grouped)
		if err != nil {
			return err
		}
		current, ok := session.BARs[updated.ID]
		if !ok {
			return fmt.Errorf("unknown BAR %d", updated.ID)
		}
		children, err := grouped.Children()
		if err != nil {
			return err
		}
		if _, ok := pfcp.FindIE(children, pfcp.IEDownlinkDataNotifyDelay); ok {
			current.DownlinkNotificationDelay = updated.DownlinkNotificationDelay
		}
		session.BARs[current.ID] = current
	}
	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IEUpdateQER) {
		qer, err := decodeQER(grouped, s.config.EnterpriseID)
		if err != nil {
			return err
		}
		current, ok := session.QERs[qer.ID]
		if !ok {
			return fmt.Errorf("unknown QER %d", qer.ID)
		}
		if qer.QCI == 0 {
			qer.QCI = current.QCI
			qer.ARP = current.ARP
			qer.PreemptionCapable = current.PreemptionCapable
			qer.PreemptionVulnerable = current.PreemptionVulnerable
		}
		session.QERs[qer.ID] = qer
	}
	for _, grouped := range pfcp.FindAllIEs(ies, pfcp.IEUpdateURR) {
		id, err := groupedUint32ID(grouped, pfcp.IEURRID)
		if err != nil {
			return err
		}
		current, ok := session.URRs[id]
		if !ok {
			return fmt.Errorf("unknown URR %d", id)
		}
		updated, err := updateURR(current, grouped)
		if err != nil {
			return err
		}
		session.URRs[id] = updated
	}
	if len(pfcp.FindAllIEs(ies, pfcp.IEUpdatePDR)) > 0 {
		return errors.New("unsupported PFCP rule operation in LTE bearer profile")
	}
	return nil
}

func groupedPDRID(grouped pfcp.IE) (uint16, error) {
	children, err := grouped.Children()
	if err != nil {
		return 0, err
	}
	idIE, ok := pfcp.FindIE(children, pfcp.IEPDRID)
	if !ok {
		return 0, pfcp.ErrMissingIE
	}
	return idIE.PDRID()
}

func groupedUint32ID(grouped pfcp.IE, typ uint16) (uint32, error) {
	children, err := grouped.Children()
	if err != nil {
		return 0, err
	}
	idIE, ok := pfcp.FindIE(children, typ)
	if !ok {
		return 0, pfcp.ErrMissingIE
	}
	id, err := idIE.Uint32()
	if err != nil || id == 0 {
		return 0, fmt.Errorf("invalid rule ID")
	}
	return id, nil
}

func (s *Server) allocateSEID() (uint64, error) {
	for attempt := 0; attempt < 256; attempt++ {
		var raw [8]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return 0, err
		}
		seid := binary.BigEndian.Uint64(raw[:])
		if seid == 0 {
			continue
		}
		if _, exists := s.store.FindByUPSEID(seid); !exists {
			return seid, nil
		}
	}
	return 0, errors.New("PFCP SEID allocation exhausted")
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

func (s *Server) clearReportSuppressionLocked(upSEID uint64) {
	for key := range s.reportNotBefore {
		if key.UPSEID == upSEID {
			delete(s.reportNotBefore, key)
		}
	}
}

func (s *Server) purgePeerSessions(peer netip.Addr) int {
	peer = peer.Unmap()
	s.mu.RLock()
	ids := make([]uint64, 0)
	for upSEID, owner := range s.sessionOwner {
		if owner.Addr().Unmap() == peer {
			ids = append(ids, upSEID)
		}
	}
	s.mu.RUnlock()
	purged := 0
	for _, upSEID := range ids {
		deleted := false
		if session, ok := s.store.FindByUPSEID(upSEID); ok {
			if s.store.Delete(upSEID, session.Revision) == nil {
				purged++
				deleted = true
			}
		}
		s.mu.Lock()
		delete(s.sessionOwner, upSEID)
		s.clearReportSuppressionLocked(upSEID)
		s.mu.Unlock()
		if deleted {
			s.notifyDeleted(upSEID)
		}
	}
	return purged
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

func (s *Server) completeReconciliation(peer netip.Addr) int {
	peer = peer.Unmap()
	s.mu.Lock()
	pending := s.reconcilePending[peer]
	delete(s.reconcilePending, peer)
	s.mu.Unlock()
	purged := 0
	for upSEID := range pending {
		deleted := false
		if current, ok := s.store.FindByUPSEID(upSEID); ok && s.store.Delete(upSEID, current.Revision) == nil {
			purged++
			deleted = true
		}
		s.mu.Lock()
		delete(s.sessionOwner, upSEID)
		s.clearReportSuppressionLocked(upSEID)
		s.mu.Unlock()
		if deleted {
			s.notifyDeleted(upSEID)
		}
	}
	s.associations.Complete(peer)
	return purged
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
			purged := s.purgePeerSessions(transition.Peer)
			s.staleSessionsPurged.Add(uint64(purged))
			s.graceExpirations.Add(1)
			s.mu.Lock()
			delete(s.reconcilePending, transition.Peer)
			s.mu.Unlock()
		}
	}
}
