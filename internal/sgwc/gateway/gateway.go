// Package gateway implements the SGW-C LTE S11, S5-C, and Sxa procedures.
package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gtptransport "github.com/lodestarnetworks/cups/internal/gtpv2/transport"
	"github.com/lodestarnetworks/cups/internal/sgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/sgwc/session"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

type UserPlane interface {
	Establish(context.Context, pfcpclient.Establishment) (pfcpclient.Session, error)
	ActivateDownlink(context.Context, *pfcpclient.Session, pfcpclient.Tunnel) error
	DeactivateDownlink(context.Context, *pfcpclient.Session) error
	AddBearer(context.Context, *pfcpclient.Session, pfcpclient.BearerPlan) error
	ActivateBearer(context.Context, *pfcpclient.Session, pfcpclient.RuleIDs, pfcpclient.Tunnel) error
	DeactivateBearer(context.Context, *pfcpclient.Session, pfcpclient.RuleIDs) error
	UpdateBearerQoS(context.Context, *pfcpclient.Session, pfcpclient.RuleIDs, uint8, uint8, bool, bool, uint64, uint64) error
	RemoveBearer(context.Context, *pfcpclient.Session, pfcpclient.RuleIDs) error
	Delete(context.Context, pfcpclient.Session) error
}

type gtpTransactionClient interface {
	Do(context.Context, netip.AddrPort, gtpv2.Message) (gtpv2.Message, error)
}

type Config struct {
	S11Listen          netip.AddrPort
	S11Advertise       netip.Addr
	S5Listen           netip.AddrPort
	S5Advertise        netip.Addr
	PGWControl         netip.AddrPort
	PGWRoutes          map[string]netip.AddrPort
	SGWUAccessIP       netip.Addr
	SGWUCoreIP         netip.Addr
	AllowedMME         []netip.Addr
	RecoveryCounter    uint8
	ProcedureTimeout   time.Duration
	ReconcileWorkers   int
	SubscriberSalt     []byte
	Transport          gtptransport.Config
	PeerRecovery       map[string]uint8
	CommitPeerRecovery func(string, uint8) error
	AllowNewSessions   func() bool
	OnEvent            func(Event)
}

type Event struct {
	Time       time.Time
	Severity   string
	Procedure  string
	Peer       netip.AddrPort
	Subscriber string
	Message    string
}

type Counters struct {
	CreateRequests           uint64
	CreateAccepted           uint64
	CreateRejected           uint64
	CreateAdmissionRejected  uint64
	CreateReplacements       uint64
	ModifyRequests           uint64
	ModifyAccepted           uint64
	ModifyRejected           uint64
	ReleaseRequests          uint64
	ReleaseAccepted          uint64
	ReleaseRejected          uint64
	DeleteRequests           uint64
	DeleteAccepted           uint64
	DeleteRejected           uint64
	DeleteContextNotFound    uint64
	DownlinkReports          uint64
	DDNRequests              uint64
	DDNAccepted              uint64
	DDNRejected              uint64
	DDNPeerTEIDFallbacks     uint64
	S11PeerTEIDFallbacks     uint64
	Rejected                 uint64
	PeerRestarts             uint64
	PeerRestartPurgeFailures uint64
	CreateBearerRequests     uint64
	CreateBearerAccepted     uint64
	CreateBearerRejected     uint64
	UpdateBearerRequests     uint64
	UpdateBearerAccepted     uint64
	UpdateBearerRejected     uint64
	DeleteBearerRequests     uint64
	DeleteBearerAccepted     uint64
	DeleteBearerRejected     uint64
}

type counterSet struct {
	createRequests           atomic.Uint64
	createAccepted           atomic.Uint64
	createRejected           atomic.Uint64
	createAdmissionRejected  atomic.Uint64
	createReplacements       atomic.Uint64
	modifyRequests           atomic.Uint64
	modifyAccepted           atomic.Uint64
	modifyRejected           atomic.Uint64
	releaseRequests          atomic.Uint64
	releaseAccepted          atomic.Uint64
	releaseRejected          atomic.Uint64
	deleteRequests           atomic.Uint64
	deleteAccepted           atomic.Uint64
	deleteRejected           atomic.Uint64
	deleteContextNotFound    atomic.Uint64
	downlinkReports          atomic.Uint64
	ddnRequests              atomic.Uint64
	ddnAccepted              atomic.Uint64
	ddnRejected              atomic.Uint64
	ddnPeerTEIDFallbacks     atomic.Uint64
	s11PeerTEIDFallbacks     atomic.Uint64
	rejected                 atomic.Uint64
	peerRestarts             atomic.Uint64
	peerRestartPurgeFailures atomic.Uint64
	createBearerRequests     atomic.Uint64
	createBearerAccepted     atomic.Uint64
	createBearerRejected     atomic.Uint64
	updateBearerRequests     atomic.Uint64
	updateBearerAccepted     atomic.Uint64
	updateBearerRejected     atomic.Uint64
	deleteBearerRequests     atomic.Uint64
	deleteBearerAccepted     atomic.Uint64
	deleteBearerRejected     atomic.Uint64
}

type Gateway struct {
	config Config
	store  *session.Store
	up     UserPlane
	s11    *gtptransport.Endpoint
	s5     *gtptransport.Endpoint
	s5Tx   gtpTransactionClient
	ids    *idAllocator
	locks  lockSet

	subscriberLocks lockSet
	recoveryMu      sync.Mutex
	recovery        map[peerKey]uint8
	paging          *pagingTracker
	counters        counterSet
	closeOnce       sync.Once
}

type peerKey struct {
	side uint8
	peer netip.AddrPort
}

const (
	gtpControlPort          uint16 = 2123
	defaultReconcileWorkers        = 64
	maxReconcileWorkers            = 1024
	maxPeerRecoveryEntries         = 4096
)

func New(config Config, store *session.Store, userPlane UserPlane) (*Gateway, error) {
	if store == nil || userPlane == nil {
		return nil, errors.New("sgwc: session store and SGW-U client are required")
	}
	if !config.S11Listen.Addr().IsValid() || !config.S11Advertise.Is4() ||
		!config.S5Listen.Addr().IsValid() || !config.S5Advertise.Is4() ||
		!config.PGWControl.Addr().Is4() || config.PGWControl.Port() == 0 ||
		!config.SGWUAccessIP.Is4() || !config.SGWUCoreIP.Is4() {
		return nil, errors.New("sgwc: valid IPv4 S11, S5-C, PGW, and SGW-U addresses are required")
	}
	if len(config.AllowedMME) == 0 {
		return nil, errors.New("sgwc: at least one allowed MME address is required")
	}
	for index, addr := range config.AllowedMME {
		if !addr.Is4() {
			return nil, fmt.Errorf("sgwc: allowed MME address %d is not IPv4", index)
		}
		config.AllowedMME[index] = addr.Unmap()
	}
	if config.ProcedureTimeout <= 0 {
		return nil, errors.New("sgwc: procedure timeout must be positive")
	}
	if config.ReconcileWorkers < 0 || config.ReconcileWorkers > maxReconcileWorkers {
		return nil, fmt.Errorf("sgwc: reconciliation workers must be between 1 and %d when set", maxReconcileWorkers)
	}
	if config.ReconcileWorkers == 0 {
		config.ReconcileWorkers = defaultReconcileWorkers
	}
	config.S11Advertise = config.S11Advertise.Unmap()
	config.S5Advertise = config.S5Advertise.Unmap()
	config.SGWUAccessIP = config.SGWUAccessIP.Unmap()
	config.SGWUCoreIP = config.SGWUCoreIP.Unmap()
	config.PGWControl = netip.AddrPortFrom(config.PGWControl.Addr().Unmap(), config.PGWControl.Port())
	routes := make(map[string]netip.AddrPort, len(config.PGWRoutes))
	for apn, address := range config.PGWRoutes {
		normalizedAPN := strings.ToLower(strings.TrimSpace(apn))
		if normalizedAPN == "" || !address.Addr().Is4() || address.Port() == 0 {
			return nil, fmt.Errorf("sgwc: PGW route %q requires an APN and valid IPv4 endpoint", apn)
		}
		if _, duplicate := routes[normalizedAPN]; duplicate {
			return nil, fmt.Errorf("sgwc: duplicate PGW route for APN %q", normalizedAPN)
		}
		routes[normalizedAPN] = netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
	}
	config.PGWRoutes = routes
	gateway := &Gateway{
		config: config, store: store, up: userPlane, ids: newIDAllocator(),
		recovery: make(map[peerKey]uint8), paging: newPagingTracker(),
	}
	for rawKey, counter := range config.PeerRecovery {
		key, err := parsePeerRecoveryKey(rawKey)
		if err != nil {
			return nil, err
		}
		if _, duplicate := gateway.recovery[key]; duplicate {
			return nil, fmt.Errorf("sgwc: duplicate recovered peer key %q", rawKey)
		}
		gateway.recovery[key] = counter
	}
	if len(gateway.recovery) > maxPeerRecoveryEntries {
		return nil, fmt.Errorf("sgwc: recovered peer state exceeds %d entries", maxPeerRecoveryEntries)
	}
	reservedS11 := make(map[uint32]struct{})
	for _, recovered := range store.Snapshot() {
		if _, exists := reservedS11[recovered.S11Control.TEID]; !exists {
			if !gateway.ids.reserveTEID(recovered.S11Control.TEID) {
				return nil, fmt.Errorf("sgwc: reserve recovered S11 TEID %d", recovered.S11Control.TEID)
			}
			reservedS11[recovered.S11Control.TEID] = struct{}{}
		}
		if !gateway.ids.reserveTEID(recovered.S5Control.TEID) {
			return nil, fmt.Errorf("sgwc: duplicate recovered S5 TEID %d", recovered.S5Control.TEID)
		}
		for _, bearer := range recovered.Bearers {
			if !gateway.ids.reserveTEID(bearer.SGWUAccess.TEID) || !gateway.ids.reserveTEID(bearer.SGWUCore.TEID) {
				return nil, fmt.Errorf("sgwc: duplicate recovered user-plane TEID in session %d bearer %d", recovered.ID, bearer.EBI)
			}
		}
		if !gateway.ids.reserveSEID(recovered.PFCPControlSEID) {
			return nil, fmt.Errorf("sgwc: duplicate recovered PFCP control SEID %d", recovered.PFCPControlSEID)
		}
	}
	s11, err := gtptransport.Listen(config.S11Listen, gateway.handleS11, config.Transport)
	if err != nil {
		return nil, err
	}
	gateway.s11 = s11
	s5, err := gtptransport.Listen(config.S5Listen, gateway.handleS5, config.Transport)
	if err != nil {
		_ = s11.Close()
		return nil, err
	}
	gateway.s5 = s5
	gateway.s5Tx = s5
	return gateway, nil
}

func (g *Gateway) Serve(ctx context.Context) error {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- g.s11.Serve(child) }()
	go func() { errorsChannel <- g.s5.Serve(child) }()
	err := <-errorsChannel
	cancel()
	_ = g.Close()
	if ctx.Err() != nil || err == nil {
		return nil
	}
	return err
}

func (g *Gateway) Close() error {
	var result error
	g.closeOnce.Do(func() {
		errS11 := g.s11.Close()
		errS5 := g.s5.Close()
		result = errors.Join(errS11, errS5)
	})
	return result
}

func (g *Gateway) S11Addr() netip.AddrPort     { return g.s11.LocalAddr() }
func (g *Gateway) S5Addr() netip.AddrPort      { return g.s5.LocalAddr() }
func (g *Gateway) Sessions() []session.Session { return g.store.Snapshot() }

func (g *Gateway) Counters() Counters {
	return Counters{
		CreateRequests:           g.counters.createRequests.Load(),
		CreateAccepted:           g.counters.createAccepted.Load(),
		CreateRejected:           g.counters.createRejected.Load(),
		CreateAdmissionRejected:  g.counters.createAdmissionRejected.Load(),
		CreateReplacements:       g.counters.createReplacements.Load(),
		ModifyRequests:           g.counters.modifyRequests.Load(),
		ModifyAccepted:           g.counters.modifyAccepted.Load(),
		ModifyRejected:           g.counters.modifyRejected.Load(),
		ReleaseRequests:          g.counters.releaseRequests.Load(),
		ReleaseAccepted:          g.counters.releaseAccepted.Load(),
		ReleaseRejected:          g.counters.releaseRejected.Load(),
		DeleteRequests:           g.counters.deleteRequests.Load(),
		DeleteAccepted:           g.counters.deleteAccepted.Load(),
		DeleteRejected:           g.counters.deleteRejected.Load(),
		DeleteContextNotFound:    g.counters.deleteContextNotFound.Load(),
		DownlinkReports:          g.counters.downlinkReports.Load(),
		DDNRequests:              g.counters.ddnRequests.Load(),
		DDNAccepted:              g.counters.ddnAccepted.Load(),
		DDNRejected:              g.counters.ddnRejected.Load(),
		DDNPeerTEIDFallbacks:     g.counters.ddnPeerTEIDFallbacks.Load(),
		S11PeerTEIDFallbacks:     g.counters.s11PeerTEIDFallbacks.Load(),
		Rejected:                 g.counters.rejected.Load(),
		PeerRestarts:             g.counters.peerRestarts.Load(),
		PeerRestartPurgeFailures: g.counters.peerRestartPurgeFailures.Load(),
		CreateBearerRequests:     g.counters.createBearerRequests.Load(),
		CreateBearerAccepted:     g.counters.createBearerAccepted.Load(),
		CreateBearerRejected:     g.counters.createBearerRejected.Load(),
		UpdateBearerRequests:     g.counters.updateBearerRequests.Load(),
		UpdateBearerAccepted:     g.counters.updateBearerAccepted.Load(),
		UpdateBearerRejected:     g.counters.updateBearerRejected.Load(),
		DeleteBearerRequests:     g.counters.deleteBearerRequests.Load(),
		DeleteBearerAccepted:     g.counters.deleteBearerAccepted.Load(),
		DeleteBearerRejected:     g.counters.deleteBearerRejected.Load(),
	}
}

func (g *Gateway) TransportCounters() (s11, s5 gtptransport.Counters) {
	return g.s11.Counters(), g.s5.Counters()
}

// PagingLatencyHistograms returns DDN-to-successful-Modify-Bearer latency by
// QCI and eNodeB, plus the current number of outstanding paging requests.
func (g *Gateway) PagingLatencyHistograms() ([]PagingLatencyHistogram, uint64) {
	return g.paging.snapshot(time.Now())
}

// PurgeAll removes stale local and SGW-U state after a detected SGW-U restart.
// PFCP deletion is best effort because the restarted peer commonly no longer
// has the old UP-SEIDs.
func (g *Gateway) PurgeAll(ctx context.Context, reason string) int {
	purged := 0
	for _, current := range g.store.Snapshot() {
		unlock := g.locks.lock(current.ID)
		latest, ok := g.store.Find(current.ID)
		if ok {
			opCtx, cancel := g.operationContext(ctx)
			_ = g.up.Delete(opCtx, pfcpSession(latest))
			cancel()
			if g.store.Delete(latest.ID, latest.Revision) == nil {
				g.paging.purgeSession(latest.ID)
				g.releaseIDs(latest)
				purged++
			}
		}
		unlock()
	}
	if purged > 0 {
		g.emit(Event{Severity: "warning", Procedure: "recovery", Message: fmt.Sprintf("purged %d sessions: %s", purged, reason)})
	}
	return purged
}

// ReconcileAll atomically replays each complete SGW-C PFCP session after an
// SGW-U restart or association outage. Every bearer in a PDN is included in a
// single Session Establishment so dedicated voice rules never disappear
// halfway through replay.
func (g *Gateway) ReconcileAll(ctx context.Context) (int, error) {
	sessions := g.store.Snapshot()
	if len(sessions) == 0 {
		return 0, ctx.Err()
	}
	workers := g.config.ReconcileWorkers
	if workers > len(sessions) {
		workers = len(sessions)
	}
	jobs := make(chan session.Session)
	var group sync.WaitGroup
	var reconciled atomic.Uint64
	var failuresMu sync.Mutex
	failureCount := 0
	failureSamples := make([]error, 0, 16)
	recordFailures := func(count int, err error) {
		failuresMu.Lock()
		failureCount += count
		if err != nil && len(failureSamples) < cap(failureSamples) {
			failureSamples = append(failureSamples, err)
		}
		failuresMu.Unlock()
	}
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for current := range jobs {
				done, err := g.reconcileSession(ctx, current)
				if err != nil {
					recordFailures(1, err)
				} else if done {
					reconciled.Add(1)
				}
			}
		}()
	}
	queued := 0
feed:
	for _, current := range sessions {
		select {
		case jobs <- current:
			queued++
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	if queued != len(sessions) {
		recordFailures(len(sessions)-queued, ctx.Err())
	}
	group.Wait()
	reconciledCount := int(reconciled.Load())
	var result error
	if failureCount != 0 {
		result = fmt.Errorf("%d of %d SGW-U session replays failed: %w", failureCount, len(sessions), errors.Join(failureSamples...))
	}
	if reconciledCount > 0 {
		g.emit(Event{Severity: "info", Procedure: "reconciliation", Message: fmt.Sprintf("replayed %d SGW-U sessions", reconciledCount)})
	}
	return reconciledCount, result
}

func (g *Gateway) reconcileSession(ctx context.Context, current session.Session) (bool, error) {
	unlock := g.locks.lock(current.ID)
	defer unlock()
	latest, ok := g.store.Find(current.ID)
	if !ok {
		return false, nil
	}
	plan, err := reconciliationPlan(latest)
	if err != nil {
		return false, fmt.Errorf("session %d plan: %w", latest.ID, err)
	}
	opCtx, cancel := g.operationContext(ctx)
	userSession, err := g.up.Establish(opCtx, plan)
	cancel()
	if err != nil {
		return false, fmt.Errorf("session %d replay: %w", latest.ID, err)
	}
	if _, err := g.store.ReconcilePFCPUserSEID(latest.ID, latest.Revision, userSession.UPSEID); err != nil {
		// A newly allocated UP-SEID belongs only to this failed replay and can
		// be removed. An in-place reconciliation preserved the old UP-SEID;
		// deleting it would make a transient CP revision race destructive.
		if userSession.UPSEID != latest.PFCPUserSEID {
			opCtx, cancel = g.operationContext(ctx)
			_ = g.up.Delete(opCtx, userSession)
			cancel()
		}
		return false, fmt.Errorf("session %d commit: %w", latest.ID, err)
	}
	return true, nil
}

func reconciliationPlan(current session.Session) (pfcpclient.Establishment, error) {
	defaultEPSBearer := defaultBearer(current)
	if !defaultEPSBearer.Default {
		return pfcpclient.Establishment{}, errors.New("default bearer missing")
	}
	plan := pfcpclient.Establishment{
		CPSEID:        current.PFCPControlSEID,
		AccessLocal:   pfcpclient.Tunnel{TEID: defaultEPSBearer.SGWUAccess.TEID, IP: defaultEPSBearer.SGWUAccess.IP},
		CoreLocal:     pfcpclient.Tunnel{TEID: defaultEPSBearer.SGWUCore.TEID, IP: defaultEPSBearer.SGWUCore.IP},
		CoreRemote:    pfcpclient.Tunnel{TEID: defaultEPSBearer.PGWUser.TEID, IP: defaultEPSBearer.PGWUser.IP},
		UplinkBitrate: defaultEPSBearer.UplinkMBR, DownlinkBitrate: defaultEPSBearer.DownlinkMBR,
		QCI: defaultEPSBearer.QCI, ARP: defaultEPSBearer.ARP,
		PreemptionCapable: defaultEPSBearer.PreemptionCapable, PreemptionVulnerable: defaultEPSBearer.PreemptionVulnerable,
	}
	if defaultEPSBearer.State == session.BearerActive && defaultEPSBearer.ENBUser.TEID != 0 {
		plan.AccessRemote = &pfcpclient.Tunnel{TEID: defaultEPSBearer.ENBUser.TEID, IP: defaultEPSBearer.ENBUser.IP}
	}
	ebis := make([]int, 0, len(current.Bearers))
	for ebi, bearer := range current.Bearers {
		if !bearer.Default {
			ebis = append(ebis, int(ebi))
		}
	}
	sort.Ints(ebis)
	for _, rawEBI := range ebis {
		bearer := current.Bearers[uint8(rawEBI)]
		additional := pfcpclient.BearerPlan{
			Rules:         pfcpRules(bearer),
			AccessLocal:   pfcpclient.Tunnel{TEID: bearer.SGWUAccess.TEID, IP: bearer.SGWUAccess.IP},
			CoreLocal:     pfcpclient.Tunnel{TEID: bearer.SGWUCore.TEID, IP: bearer.SGWUCore.IP},
			CoreRemote:    pfcpclient.Tunnel{TEID: bearer.PGWUser.TEID, IP: bearer.PGWUser.IP},
			UplinkBitrate: bearer.UplinkMBR, DownlinkBitrate: bearer.DownlinkMBR,
			QCI: bearer.QCI, ARP: bearer.ARP,
			PreemptionCapable: bearer.PreemptionCapable, PreemptionVulnerable: bearer.PreemptionVulnerable,
		}
		if bearer.State == session.BearerActive && bearer.ENBUser.TEID != 0 {
			additional.AccessRemote = &pfcpclient.Tunnel{TEID: bearer.ENBUser.TEID, IP: bearer.ENBUser.IP}
		}
		plan.AdditionalBearers = append(plan.AdditionalBearers, additional)
	}
	return plan, nil
}

// HandleDownlinkReport translates a standard PFCP Downlink Data Report from
// the SGW-U into an S11 Downlink Data Notification for an idle UE.
func (g *Gateway) HandleDownlinkReport(ctx context.Context, report pfcpclient.DownlinkReport) error {
	g.counters.downlinkReports.Add(1)
	current, ok := g.store.FindByPFCPControlSEID(report.CPSEID)
	if !ok {
		g.counters.ddnRejected.Add(1)
		return fmt.Errorf("DDN: PFCP session %d not found", report.CPSEID)
	}
	unlock := g.locks.lock(current.ID)
	defer unlock()
	current, ok = g.store.Find(current.ID)
	if !ok {
		g.counters.ddnRejected.Add(1)
		return errors.New("DDN: session disappeared")
	}
	bearer := bearerForDownlinkPDR(current, report.PDRID)
	if current.State != session.StateIdle || bearer.State != session.BearerIdle {
		g.emit(Event{
			Severity: "info", Procedure: "ddn", Subscriber: current.SubscriberKey,
			Message: "stale downlink report ignored because bearer is no longer idle",
		})
		return nil
	}
	if bearer.EBI == 0 || current.MMEControl.TEID == 0 || !current.MMEControl.IP.Is4() {
		g.counters.ddnRejected.Add(1)
		return errors.New("DDN: idle session has no valid MME control tunnel or default bearer")
	}
	ebi, err := gtpv2.NewEBIIE(bearer.EBI, 0)
	if err != nil {
		g.counters.ddnRejected.Add(1)
		return fmt.Errorf("DDN: encode EBI: %w", err)
	}
	arp, err := gtpv2.NewARPIE(0, bearer.ARP, bearer.PreemptionCapable, bearer.PreemptionVulnerable)
	if err != nil {
		g.counters.ddnRejected.Add(1)
		return fmt.Errorf("DDN: encode ARP: %w", err)
	}
	destination := netip.AddrPortFrom(current.MMEControl.IP.Unmap(), gtpControlPort)
	g.counters.ddnRequests.Add(1)
	ddnStarted := time.Now()
	tracking := g.paging.start(current.ID, bearer.EBI, bearer.QCI, ddnStarted)
	keepTracking := false
	defer func() {
		if tracking && !keepTracking {
			g.paging.cancel(current.ID, bearer.EBI)
		}
	}()
	ddn := gtpv2.Message{
		Header: gtpv2.Header{
			Version: gtpv2.Version, HasTEID: true,
			MessageType: gtpv2.MessageDownlinkDataNotification, TEID: current.MMEControl.TEID,
		},
		IEs: []gtpv2.IE{ebi, arp},
	}
	g.stampRecovery(&ddn)
	opCtx, cancel := g.operationContext(ctx)
	response, err := g.s11.Do(opCtx, destination, ddn)
	cancel()
	if err != nil {
		g.counters.ddnRejected.Add(1)
		g.emit(Event{
			Severity: "warning", Procedure: "ddn", Peer: destination,
			Subscriber: current.SubscriberKey, Message: "Downlink Data Notification failed: " + err.Error(),
		})
		return fmt.Errorf("DDN to MME %s: %w", destination, err)
	}
	fallback, err := g.acceptMMEResponseTEID(response, current, "ddn", destination)
	if err != nil {
		g.counters.ddnRejected.Add(1)
		return fmt.Errorf("DDN: %w", err)
	}
	if fallback {
		g.counters.ddnPeerTEIDFallbacks.Add(1)
	}
	causeIE, ok := response.Find(gtpv2.IECause, 0)
	if !ok {
		g.counters.ddnRejected.Add(1)
		return fmt.Errorf("DDN acknowledgement: %w", gtpv2.ErrMissingIE)
	}
	cause, err := causeIE.Cause()
	if err != nil || cause.Value != gtpv2.CauseRequestAccepted {
		g.counters.ddnRejected.Add(1)
		if err != nil {
			return fmt.Errorf("DDN acknowledgement: %w", err)
		}
		return fmt.Errorf("DDN acknowledgement rejected with cause %d", cause.Value)
	}
	g.counters.ddnAccepted.Add(1)
	keepTracking = true
	g.emit(Event{
		Severity: "info", Procedure: "ddn", Peer: destination,
		Subscriber: current.SubscriberKey, Message: "Downlink Data Notification acknowledged by MME",
	})
	return nil
}

// acceptMMEResponseTEID validates a response to an SGW-initiated S11
// transaction. 3GPP peers should address the response to the SGW's S11 TEID,
// but some deployed MMEs echo their own TEID. The transport has already bound
// this response to the exact destination address, port, sequence, and expected
// message type, so the peer TEID is accepted only for this known session.
func (g *Gateway) acceptMMEResponseTEID(response gtpv2.Message, current session.Session, procedure string, peer netip.AddrPort) (bool, error) {
	if !response.Header.HasTEID {
		return false, errors.New("MME response omitted its S11 TEID")
	}
	if response.Header.TEID == current.S11Control.TEID {
		return false, nil
	}
	if response.Header.TEID != current.MMEControl.TEID {
		return false, fmt.Errorf("MME response TEID %#x, expected SGW %#x or peer-compatible MME %#x", response.Header.TEID, current.S11Control.TEID, current.MMEControl.TEID)
	}
	g.counters.s11PeerTEIDFallbacks.Add(1)
	g.emit(Event{
		Severity: "warning", Procedure: procedure, Peer: peer,
		Subscriber: current.SubscriberKey, Message: "MME echoed its own S11 TEID in an SGW-initiated response; accepted in compatibility mode",
	})
	return true, nil
}

func (g *Gateway) handleS11(ctx context.Context, peer netip.AddrPort, request gtpv2.Message) (*gtpv2.Message, error) {
	if !g.allowedMME(peer.Addr().Unmap()) {
		g.counters.rejected.Add(1)
		g.emit(Event{Severity: "warning", Procedure: "s11", Peer: peer, Message: "request from non-allowlisted MME dropped"})
		return nil, nil
	}
	if err := g.observeRecovery(ctx, 0, peer, request); err != nil {
		g.counters.rejected.Add(1)
		g.emit(Event{Severity: "error", Procedure: "recovery", Peer: peer, Message: "peer restart purge incomplete; request withheld for retry"})
		return nil, nil
	}
	switch request.Header.MessageType {
	case gtpv2.MessageEchoRequest:
		return g.echoResponse(), nil
	case gtpv2.MessageCreateSessionRequest:
		g.counters.createRequests.Add(1)
		return g.createSession(ctx, peer, request), nil
	case gtpv2.MessageModifyBearerRequest:
		g.counters.modifyRequests.Add(1)
		return g.modifyBearer(ctx, peer, request), nil
	case gtpv2.MessageReleaseAccessBearersRequest:
		g.counters.releaseRequests.Add(1)
		return g.releaseAccessBearers(ctx, peer, request), nil
	case gtpv2.MessageDeleteSessionRequest:
		g.counters.deleteRequests.Add(1)
		return g.deleteSession(ctx, peer, request), nil
	default:
		g.counters.rejected.Add(1)
		return g.unsupportedResponse(request, true), nil
	}
}

func (g *Gateway) handleS5(ctx context.Context, peer netip.AddrPort, request gtpv2.Message) (*gtpv2.Message, error) {
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	allowed := g.configuredPGWPeer(peer)
	if request.Header.HasTEID {
		if current, found := g.store.FindByS5TEID(request.Header.TEID); found {
			storedPeer := g.pgwControlPeer(current.PGWControl.IP)
			routedPeer := g.pgwControlForAPN(current.APN)
			allowed = peer == storedPeer || peer == routedPeer
		}
	}
	if !allowed {
		g.counters.rejected.Add(1)
		return nil, nil
	}
	if err := g.observeRecovery(ctx, 1, peer, request); err != nil {
		g.counters.rejected.Add(1)
		g.emit(Event{Severity: "error", Procedure: "recovery", Peer: peer, Message: "peer restart purge incomplete; request withheld for retry"})
		return nil, nil
	}
	switch request.Header.MessageType {
	case gtpv2.MessageEchoRequest:
		return g.echoResponse(), nil
	case gtpv2.MessageCreateBearerRequest:
		g.counters.createBearerRequests.Add(1)
		return g.createBearer(ctx, peer, request), nil
	case gtpv2.MessageUpdateBearerRequest:
		g.counters.updateBearerRequests.Add(1)
		return g.updateBearer(ctx, peer, request), nil
	case gtpv2.MessageDeleteBearerRequest:
		g.counters.deleteBearerRequests.Add(1)
		return g.deleteBearer(ctx, peer, request), nil
	default:
		g.counters.rejected.Add(1)
		return g.unsupportedResponse(request, false), nil
	}
}

func (g *Gateway) pgwControlForAPN(apn string) netip.AddrPort {
	if peer, ok := g.config.PGWRoutes[strings.ToLower(strings.TrimSpace(apn))]; ok {
		return peer
	}
	return g.config.PGWControl
}

// pgwControlPeer resolves the control F-TEID advertised by a PGW so inbound
// bearer requests can be checked against durable session ownership. The APN
// route remains the outbound transaction endpoint because multi-homed PGWs
// can advertise an address different from the socket that sources responses.
func (g *Gateway) pgwControlPeer(address netip.Addr) netip.AddrPort {
	address = address.Unmap()
	if g.config.PGWControl.Addr() == address {
		return g.config.PGWControl
	}
	for _, peer := range g.config.PGWRoutes {
		if peer.Addr() == address {
			return peer
		}
	}
	return netip.AddrPortFrom(address, gtpControlPort)
}

func (g *Gateway) configuredPGWPeer(peer netip.AddrPort) bool {
	if peer == g.config.PGWControl {
		return true
	}
	for _, candidate := range g.config.PGWRoutes {
		if peer == candidate {
			return true
		}
	}
	return false
}

func (g *Gateway) echoResponse() *gtpv2.Message {
	return &gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, MessageType: gtpv2.MessageEchoResponse},
		IEs:    []gtpv2.IE{gtpv2.NewRecoveryIE(g.config.RecoveryCounter)},
	}
}

func (g *Gateway) unsupportedResponse(request gtpv2.Message, s11 bool) *gtpv2.Message {
	responseType, ok := gtptransport.ExpectedResponseType(request.Header.MessageType)
	if !ok {
		return nil
	}
	teid := uint32(0)
	if request.Header.HasTEID {
		if s11 {
			if current, found := g.store.FindByS11TEID(request.Header.TEID); found {
				teid = current.MMEControl.TEID
			}
		} else if current, found := g.store.FindByS5TEID(request.Header.TEID); found {
			teid = current.PGWControl.TEID
		}
	}
	return &gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: request.Header.HasTEID, MessageType: responseType, TEID: teid},
		IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseServiceNotSupported, 0)},
	}
}

func (g *Gateway) allowedMME(peer netip.Addr) bool {
	for _, allowed := range g.config.AllowedMME {
		if peer == allowed {
			return true
		}
	}
	return false
}

func (g *Gateway) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, g.config.ProcedureTimeout)
}

func (g *Gateway) doS5(ctx context.Context, peer netip.AddrPort, request gtpv2.Message) (gtpv2.Message, error) {
	client := g.s5Tx
	if client == nil {
		client = g.s5
	}
	if client == nil {
		return gtpv2.Message{}, errors.New("SGW-C S5 transaction endpoint is unavailable")
	}
	return client.Do(ctx, peer, request)
}

func (g *Gateway) stampRecovery(request *gtpv2.Message) {
	request.Upsert(gtpv2.NewRecoveryIE(g.config.RecoveryCounter))
}

func (g *Gateway) subscriberKey(imsi string) string {
	hash := sha256.New()
	_, _ = hash.Write(g.config.SubscriberSalt)
	_, _ = hash.Write([]byte(imsi))
	return hex.EncodeToString(hash.Sum(nil)[:12])
}

func (g *Gateway) emit(event Event) {
	if g.config.OnEvent == nil {
		return
	}
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	g.config.OnEvent(event)
}

func (g *Gateway) observeRecovery(ctx context.Context, side uint8, peer netip.AddrPort, request gtpv2.Message) error {
	recoveryIE, ok := request.Find(gtpv2.IERecovery, 0)
	if !ok {
		return nil
	}
	counter, err := recoveryIE.Recovery()
	if err != nil {
		return nil
	}
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	key := peerKey{side: side, peer: peer}
	g.recoveryMu.Lock()
	defer g.recoveryMu.Unlock()
	previous, existed := g.recovery[key]
	if !existed {
		if len(g.recovery) >= maxPeerRecoveryEntries {
			g.counters.peerRestartPurgeFailures.Add(1)
			return fmt.Errorf("peer recovery state capacity %d reached", maxPeerRecoveryEntries)
		}
		if err := g.commitPeerRecovery(side, peer, counter); err != nil {
			g.counters.peerRestartPurgeFailures.Add(1)
			return err
		}
		g.recovery[key] = counter
		return nil
	}
	if previous == counter {
		return nil
	}
	g.emit(Event{Severity: "warning", Procedure: "recovery", Peer: peer, Message: "peer recovery counter changed; purging stale sessions"})
	var purgeErr error
	for _, current := range g.store.Snapshot() {
		matches := side == 0 && current.MMEControl.IP.Unmap() == key.peer.Addr() || side == 1 && current.PGWControl.IP.Unmap() == key.peer.Addr()
		if !matches {
			continue
		}
		unlock := g.locks.lock(current.ID)
		latest, found := g.store.Find(current.ID)
		if found {
			if side == 0 {
				opCtx, cancel := g.operationContext(ctx)
				deleteErr := g.deletePGWSessionForRecovery(opCtx, latest)
				cancel()
				if deleteErr != nil {
					purgeErr = errors.Join(purgeErr, fmt.Errorf("delete PGW session %d: %w", latest.ID, deleteErr))
					unlock()
					continue
				}
			}
			opCtx, cancel := g.operationContext(ctx)
			deleteErr := g.up.Delete(opCtx, pfcpSession(latest))
			cancel()
			if deleteErr != nil {
				purgeErr = errors.Join(purgeErr, fmt.Errorf("delete user-plane session %d: %w", latest.ID, deleteErr))
				unlock()
				continue
			}
			if err := g.store.Delete(latest.ID, latest.Revision); err != nil {
				purgeErr = errors.Join(purgeErr, fmt.Errorf("delete control session %d: %w", latest.ID, err))
				unlock()
				continue
			}
			g.paging.purgeSession(latest.ID)
			g.releaseIDs(latest)
		}
		unlock()
	}
	if purgeErr != nil {
		g.counters.peerRestartPurgeFailures.Add(1)
		return purgeErr
	}
	if err := g.commitPeerRecovery(side, peer, counter); err != nil {
		g.counters.peerRestartPurgeFailures.Add(1)
		return err
	}
	g.recovery[key] = counter
	g.counters.peerRestarts.Add(1)
	return nil
}

// deletePGWSessionForRecovery removes the downstream PDN context before an
// MME-restart purge forgets its local ownership. Context Not Found is a
// successful idempotent result: a previous attempt may have reached PGW-C/U
// before SGW-U or durable SGW-C deletion failed.
func (g *Gateway) deletePGWSessionForRecovery(ctx context.Context, current session.Session) error {
	bearer := defaultBearer(current)
	if bearer.EBI == 0 {
		return errors.New("session has no default bearer")
	}
	ebi, err := gtpv2.NewEBIIE(bearer.EBI, 0)
	if err != nil {
		return fmt.Errorf("construct linked bearer EBI: %w", err)
	}
	sender, err := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8SGWGTPC,
		TEID:          current.S5Control.TEID,
		IPv4:          current.S5Control.IP,
	})
	if err != nil {
		return fmt.Errorf("construct SGW S5-C F-TEID: %w", err)
	}
	request := gtpv2.Message{
		Header: gtpv2.Header{
			Version: gtpv2.Version, HasTEID: true,
			MessageType: gtpv2.MessageDeleteSessionRequest, TEID: current.PGWControl.TEID,
		},
		IEs: []gtpv2.IE{ebi, sender},
	}
	g.stampRecovery(&request)
	response, err := g.doS5(ctx, g.pgwControlForAPN(current.APN), request)
	if err != nil {
		return fmt.Errorf("PGW transaction failed: %w", err)
	}
	cause, err := messageCause(response)
	if err != nil {
		return fmt.Errorf("invalid PGW response: %w", err)
	}
	if cause == gtpv2.CauseContextNotFound {
		return nil
	}
	if response.Header.TEID != current.S5Control.TEID {
		return fmt.Errorf("PGW response TEID %#x, expected %#x", response.Header.TEID, current.S5Control.TEID)
	}
	if cause != gtpv2.CauseRequestAccepted {
		return fmt.Errorf("PGW rejected request with cause %d", cause)
	}
	return nil
}

func (g *Gateway) commitPeerRecovery(side uint8, peer netip.AddrPort, counter uint8) error {
	if g.config.CommitPeerRecovery == nil {
		return nil
	}
	if err := g.config.CommitPeerRecovery(peerRecoveryKey(side, peer), counter); err != nil {
		return fmt.Errorf("persist peer recovery counter: %w", err)
	}
	return nil
}

func peerRecoveryKey(side uint8, peer netip.AddrPort) string {
	name := "s11"
	if side == 1 {
		name = "s5"
	}
	return name + "|" + netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()).String()
}

func parsePeerRecoveryKey(raw string) (peerKey, error) {
	sideName, rawPeer, ok := strings.Cut(raw, "|")
	if !ok || sideName != "s11" && sideName != "s5" {
		return peerKey{}, fmt.Errorf("sgwc: invalid recovered peer key %q", raw)
	}
	peer, err := netip.ParseAddrPort(rawPeer)
	if err != nil || !peer.Addr().Is4() || peer.Port() == 0 || peer.String() != rawPeer {
		return peerKey{}, fmt.Errorf("sgwc: invalid recovered peer endpoint %q", rawPeer)
	}
	side := uint8(0)
	if sideName == "s5" {
		side = 1
	}
	return peerKey{side: side, peer: peer}, nil
}

func subscriberLockKey(subscriber string) uint64 {
	hash := sha256.Sum256([]byte(subscriber))
	return binary.BigEndian.Uint64(hash[:8])
}

func pfcpSession(current session.Session) pfcpclient.Session {
	bearer := defaultBearer(current)
	out := pfcpclient.Session{
		CPSEID:      current.PFCPControlSEID,
		UPSEID:      current.PFCPUserSEID,
		BARID:       bearer.QCI,
		AccessLocal: pfcpclient.Tunnel{TEID: bearer.SGWUAccess.TEID, IP: bearer.SGWUAccess.IP},
		CoreLocal:   pfcpclient.Tunnel{TEID: bearer.SGWUCore.TEID, IP: bearer.SGWUCore.IP},
		CoreRemote:  pfcpclient.Tunnel{TEID: bearer.PGWUser.TEID, IP: bearer.PGWUser.IP},
	}
	if bearer.ENBUser.TEID != 0 {
		out.AccessRemote = &pfcpclient.Tunnel{TEID: bearer.ENBUser.TEID, IP: bearer.ENBUser.IP}
	}
	return out
}

func defaultBearer(current session.Session) session.Bearer {
	for _, bearer := range current.Bearers {
		if bearer.Default {
			return bearer
		}
	}
	return session.Bearer{}
}

func bearerForDownlinkPDR(current session.Session, pdrID uint16) session.Bearer {
	for _, bearer := range current.Bearers {
		if bearer.Rules.DownlinkPDR == pdrID {
			return bearer
		}
	}
	return defaultBearer(current)
}

func (g *Gateway) releaseIDs(current session.Session) {
	teids := []uint32{current.S5Control.TEID}
	for _, bearer := range current.Bearers {
		teids = append(teids, bearer.SGWUAccess.TEID, bearer.SGWUCore.TEID)
	}
	if len(g.store.FindAllByS11TEID(current.S11Control.TEID)) == 0 {
		teids = append(teids, current.S11Control.TEID)
	}
	g.ids.releaseTEIDs(teids...)
	g.ids.releaseSEID(current.PFCPControlSEID)
}
