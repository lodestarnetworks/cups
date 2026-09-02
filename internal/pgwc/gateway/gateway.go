// Package gateway implements the PGW-C LTE S5-C and Sxb procedures.
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
	"github.com/lodestarnetworks/cups/internal/pgwc/ipam"
	"github.com/lodestarnetworks/cups/internal/pgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/pgwc/session"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

type UserPlane interface {
	Establish(context.Context, pfcpclient.Establishment) (pfcpclient.Session, error)
	UpdateRemote(context.Context, *pfcpclient.Session, pfcpclient.Tunnel) error
	AddBearer(context.Context, *pfcpclient.Session, pfcpclient.BearerPlan) error
	UpdateBearerQoS(context.Context, *pfcpclient.Session, pfcpclient.RuleIDs, uint8, uint8, uint64, uint64) error
	RemoveBearer(context.Context, *pfcpclient.Session, pfcpclient.RuleIDs) error
	Delete(context.Context, pfcpclient.Session) error
}

type Config struct {
	S5Listen           netip.AddrPort
	S5Advertise        netip.Addr
	PGWUUserIP         netip.Addr
	PGWUQCI1UserIP     netip.Addr
	AllowedSGW         []netip.Addr
	APN                string
	DNSIPv4            []netip.Addr
	PCSCFIPv4          []netip.Addr
	IPv4LinkMTU        uint16
	APNAMBRUplinkBPS   uint64
	APNAMBRDownlinkBPS uint64
	APNProfiles        []APNProfile
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

// APNProfile binds one served APN to its own IPAM pool and UE-facing PCO/QoS
// policy. Pool ownership must never be shared between profiles.
type APNProfile struct {
	APN                string
	Pool               *ipam.Pool
	DNSIPv4            []netip.Addr
	PCSCFIPv4          []netip.Addr
	IPv4LinkMTU        uint16
	APNAMBRUplinkBPS   uint64
	APNAMBRDownlinkBPS uint64
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
	DeleteRequests           uint64
	DeleteAccepted           uint64
	DeleteRejected           uint64
	CreateBearerRequests     uint64
	CreateBearerAccepted     uint64
	CreateBearerRejected     uint64
	UpdateBearerRequests     uint64
	UpdateBearerAccepted     uint64
	UpdateBearerRejected     uint64
	DeleteBearerRequests     uint64
	DeleteBearerAccepted     uint64
	DeleteBearerRejected     uint64
	Rejected                 uint64
	PeerRestarts             uint64
	PeerRestartPurgeFailures uint64
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
	deleteRequests           atomic.Uint64
	deleteAccepted           atomic.Uint64
	deleteRejected           atomic.Uint64
	createBearerRequests     atomic.Uint64
	createBearerAccepted     atomic.Uint64
	createBearerRejected     atomic.Uint64
	updateBearerRequests     atomic.Uint64
	updateBearerAccepted     atomic.Uint64
	updateBearerRejected     atomic.Uint64
	deleteBearerRequests     atomic.Uint64
	deleteBearerAccepted     atomic.Uint64
	deleteBearerRejected     atomic.Uint64
	rejected                 atomic.Uint64
	peerRestarts             atomic.Uint64
	peerRestartPurgeFailures atomic.Uint64
}

const (
	defaultReconcileWorkers = 64
	maxReconcileWorkers     = 1024
	maxPeerRecoveryEntries  = 4096
)

type Gateway struct {
	config   Config
	store    *session.Store
	profiles map[string]APNProfile
	up       UserPlane
	s5       *gtptransport.Endpoint
	ids      *idAllocator
	locks    lockSet

	subscriberLocks lockSet
	recoveryMu      sync.Mutex
	recovery        map[netip.AddrPort]uint8
	counters        counterSet
	closeOnce       sync.Once
}

func New(config Config, store *session.Store, pool *ipam.Pool, userPlane UserPlane) (*Gateway, error) {
	if store == nil || userPlane == nil {
		return nil, errors.New("pgwc: session store and PGW-U client are required")
	}
	if !config.S5Listen.Addr().IsValid() || !config.S5Advertise.Is4() || !config.PGWUUserIP.Is4() {
		return nil, errors.New("pgwc: valid IPv4 S5-C and PGW-U addresses are required")
	}
	if len(config.AllowedSGW) == 0 {
		return nil, errors.New("pgwc: at least one allowed SGW-C address is required")
	}
	for index, address := range config.AllowedSGW {
		if !address.Is4() {
			return nil, fmt.Errorf("pgwc: allowed SGW-C address %d is not IPv4", index)
		}
		config.AllowedSGW[index] = address.Unmap()
	}
	if config.ProcedureTimeout <= 0 {
		return nil, errors.New("pgwc: procedure timeout must be positive")
	}
	if config.ReconcileWorkers < 0 || config.ReconcileWorkers > maxReconcileWorkers {
		return nil, fmt.Errorf("pgwc: reconciliation workers must be between 1 and %d when set", maxReconcileWorkers)
	}
	if config.ReconcileWorkers == 0 {
		config.ReconcileWorkers = defaultReconcileWorkers
	}
	profiles, err := normalizeAPNProfiles(&config, pool)
	if err != nil {
		return nil, err
	}
	config.S5Advertise = config.S5Advertise.Unmap()
	config.PGWUUserIP = config.PGWUUserIP.Unmap()
	if config.PGWUQCI1UserIP.IsValid() {
		if !config.PGWUQCI1UserIP.Is4() {
			return nil, errors.New("pgwc: QCI 1 PGW-U address must be IPv4")
		}
		config.PGWUQCI1UserIP = config.PGWUQCI1UserIP.Unmap()
		if config.PGWUQCI1UserIP == config.PGWUUserIP {
			return nil, errors.New("pgwc: QCI 1 PGW-U address must differ from the default address")
		}
	} else {
		config.PGWUQCI1UserIP = config.PGWUUserIP
	}
	gateway := &Gateway{
		config: config, store: store, profiles: profiles, up: userPlane,
		ids: newIDAllocator(), recovery: make(map[netip.AddrPort]uint8),
	}
	for rawKey, counter := range config.PeerRecovery {
		peer, err := parsePeerRecoveryKey(rawKey)
		if err != nil {
			return nil, err
		}
		if _, duplicate := gateway.recovery[peer]; duplicate {
			return nil, fmt.Errorf("pgwc: duplicate recovered peer key %q", rawKey)
		}
		gateway.recovery[peer] = counter
	}
	if len(gateway.recovery) > maxPeerRecoveryEntries {
		return nil, fmt.Errorf("pgwc: recovered peer state exceeds %d entries", maxPeerRecoveryEntries)
	}
	for _, recovered := range store.Snapshot() {
		profile, served := gateway.profiles[strings.ToLower(strings.TrimSpace(recovered.APN))]
		if !served || !profile.Pool.Prefix().Contains(recovered.UEIPv4) {
			return nil, fmt.Errorf("pgwc: recovered session %d has an APN or UE address outside configured profiles", recovered.ID)
		}
		if !gateway.ids.reserveTEID(recovered.PGWControl.TEID) || !gateway.ids.reserveTEID(recovered.PGWUser.TEID) {
			return nil, fmt.Errorf("pgwc: duplicate recovered local TEID in session %d", recovered.ID)
		}
		for _, bearer := range recovered.DedicatedBearers {
			if expected, err := gateway.dedicatedUserIP(bearer.QCI); err != nil || bearer.PGWUser.IP.Unmap() != expected {
				return nil, fmt.Errorf("pgwc: recovered session %d has an incompatible dedicated-bearer user-plane address", recovered.ID)
			}
			if !gateway.ids.reserveTEID(bearer.PGWUser.TEID) {
				return nil, fmt.Errorf("pgwc: duplicate recovered dedicated-bearer TEID in session %d", recovered.ID)
			}
		}
		if !gateway.ids.reserveSEID(recovered.PFCPControlSEID) {
			return nil, fmt.Errorf("pgwc: duplicate recovered PFCP control SEID %d", recovered.PFCPControlSEID)
		}
	}
	endpoint, err := gtptransport.Listen(config.S5Listen, gateway.handleS5, config.Transport)
	if err != nil {
		return nil, err
	}
	gateway.s5 = endpoint
	return gateway, nil
}

func normalizeAPNProfiles(config *Config, legacyPool *ipam.Pool) (map[string]APNProfile, error) {
	profiles := append([]APNProfile(nil), config.APNProfiles...)
	if len(profiles) == 0 {
		if legacyPool == nil {
			return nil, errors.New("pgwc: a legacy address pool or APN profiles are required")
		}
		profiles = []APNProfile{{
			APN: config.APN, Pool: legacyPool, DNSIPv4: config.DNSIPv4, PCSCFIPv4: config.PCSCFIPv4,
			IPv4LinkMTU: config.IPv4LinkMTU, APNAMBRUplinkBPS: config.APNAMBRUplinkBPS,
			APNAMBRDownlinkBPS: config.APNAMBRDownlinkBPS,
		}}
	} else if legacyPool != nil {
		return nil, errors.New("pgwc: APN profiles cannot be combined with a legacy address pool")
	}
	out := make(map[string]APNProfile, len(profiles))
	prefixes := make([]netip.Prefix, 0, len(profiles))
	for index := range profiles {
		profile := profiles[index]
		profile.APN = strings.ToLower(strings.TrimSpace(profile.APN))
		if profile.APN == "" || len(profile.APN) > 100 || strings.ContainsAny(profile.APN, " \t\r\n") {
			return nil, fmt.Errorf("pgwc: APN profile %d has an invalid APN", index)
		}
		if profile.Pool == nil {
			return nil, fmt.Errorf("pgwc: APN profile %q has no address pool", profile.APN)
		}
		if _, exists := out[profile.APN]; exists {
			return nil, fmt.Errorf("pgwc: duplicate APN profile %q", profile.APN)
		}
		for existing := range out {
			if matchesAPN(profile.APN, existing) || matchesAPN(existing, profile.APN) {
				return nil, fmt.Errorf("pgwc: ambiguous APN profiles %q and %q", profile.APN, existing)
			}
		}
		prefix := profile.Pool.Prefix().Masked()
		for _, other := range prefixes {
			if prefix.Contains(other.Addr()) || other.Contains(prefix.Addr()) {
				return nil, fmt.Errorf("pgwc: APN profile %q has an overlapping address pool", profile.APN)
			}
		}
		var err error
		profile.DNSIPv4, err = normalizeProfileIPv4(profile.DNSIPv4, "DNS server", true)
		if err != nil {
			return nil, fmt.Errorf("pgwc: APN profile %q: %w", profile.APN, err)
		}
		profile.PCSCFIPv4, err = normalizeProfileIPv4(profile.PCSCFIPv4, "P-CSCF", false)
		if err != nil {
			return nil, fmt.Errorf("pgwc: APN profile %q: %w", profile.APN, err)
		}
		if profile.IPv4LinkMTU != 0 && (profile.IPv4LinkMTU < 1280 || profile.IPv4LinkMTU > 1500) {
			return nil, fmt.Errorf("pgwc: APN profile %q IPv4 link MTU must be between 1280 and 1500 bytes", profile.APN)
		}
		if profile.APNAMBRUplinkBPS != 0 || profile.APNAMBRDownlinkBPS != 0 {
			if _, err := gtpv2.NewAMBRIE(0, profile.APNAMBRUplinkBPS, profile.APNAMBRDownlinkBPS); err != nil {
				return nil, fmt.Errorf("pgwc: APN profile %q has invalid APN-AMBR: %w", profile.APN, err)
			}
		}
		profiles[index] = profile
		out[profile.APN] = profile
		prefixes = append(prefixes, prefix)
	}
	config.APNProfiles = profiles
	return out, nil
}

func normalizeProfileIPv4(addresses []netip.Addr, purpose string, requireTwo bool) ([]netip.Addr, error) {
	// The strict runtime configuration requires two DNS servers. The gateway
	// layer also supports direct embedders and tests which intentionally omit
	// UE-facing PCO policy, so an empty list remains valid here.
	if requireTwo && len(addresses) != 0 && len(addresses) != 2 {
		return nil, fmt.Errorf("exactly two IPv4 %ss are required", purpose)
	}
	if len(addresses) > 2 {
		return nil, fmt.Errorf("at most two IPv4 %s addresses are supported", purpose)
	}
	out := make([]netip.Addr, len(addresses))
	for index, address := range addresses {
		if !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return nil, fmt.Errorf("%s %d is not usable IPv4", purpose, index)
		}
		out[index] = address.Unmap()
	}
	return out, nil
}

func (g *Gateway) profileForRequestedAPN(requested string) (APNProfile, bool) {
	requested = strings.ToLower(strings.TrimSpace(requested))
	if profile, ok := g.profiles[requested]; ok {
		return profile, true
	}
	for configured, profile := range g.profiles {
		if matchesAPN(requested, configured) {
			return profile, true
		}
	}
	return APNProfile{}, false
}

func (g *Gateway) Serve(ctx context.Context) error { return g.s5.Serve(ctx) }

func (g *Gateway) Close() error {
	var result error
	g.closeOnce.Do(func() { result = g.s5.Close() })
	return result
}

func (g *Gateway) S5Addr() netip.AddrPort                   { return g.s5.LocalAddr() }
func (g *Gateway) Sessions() []session.Session              { return g.store.Snapshot() }
func (g *Gateway) TransportCounters() gtptransport.Counters { return g.s5.Counters() }

func (g *Gateway) Counters() Counters {
	return Counters{
		CreateRequests: g.counters.createRequests.Load(), CreateAccepted: g.counters.createAccepted.Load(), CreateRejected: g.counters.createRejected.Load(), CreateAdmissionRejected: g.counters.createAdmissionRejected.Load(), CreateReplacements: g.counters.createReplacements.Load(),
		ModifyRequests: g.counters.modifyRequests.Load(), ModifyAccepted: g.counters.modifyAccepted.Load(), ModifyRejected: g.counters.modifyRejected.Load(),
		DeleteRequests: g.counters.deleteRequests.Load(), DeleteAccepted: g.counters.deleteAccepted.Load(), DeleteRejected: g.counters.deleteRejected.Load(),
		CreateBearerRequests: g.counters.createBearerRequests.Load(), CreateBearerAccepted: g.counters.createBearerAccepted.Load(), CreateBearerRejected: g.counters.createBearerRejected.Load(),
		UpdateBearerRequests: g.counters.updateBearerRequests.Load(), UpdateBearerAccepted: g.counters.updateBearerAccepted.Load(), UpdateBearerRejected: g.counters.updateBearerRejected.Load(),
		DeleteBearerRequests: g.counters.deleteBearerRequests.Load(), DeleteBearerAccepted: g.counters.deleteBearerAccepted.Load(), DeleteBearerRejected: g.counters.deleteBearerRejected.Load(),
		Rejected: g.counters.rejected.Load(), PeerRestarts: g.counters.peerRestarts.Load(),
		PeerRestartPurgeFailures: g.counters.peerRestartPurgeFailures.Load(),
	}
}

func (g *Gateway) handleS5(ctx context.Context, peer netip.AddrPort, request gtpv2.Message) (*gtpv2.Message, error) {
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	if !g.allowedSGW(peer.Addr()) {
		g.counters.rejected.Add(1)
		g.emit(Event{Severity: "warning", Procedure: "s5", Peer: peer, Message: "request from non-allowlisted SGW-C dropped"})
		return nil, nil
	}
	if err := g.observeRecovery(ctx, peer, request); err != nil {
		g.counters.rejected.Add(1)
		g.emit(Event{Severity: "error", Procedure: "recovery", Peer: peer, Message: "SGW-C restart purge incomplete; request withheld for retry"})
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
	case gtpv2.MessageDeleteSessionRequest:
		g.counters.deleteRequests.Add(1)
		return g.deleteSession(ctx, peer, request), nil
	default:
		g.counters.rejected.Add(1)
		return g.unsupportedResponse(request), nil
	}
}

func (g *Gateway) echoResponse() *gtpv2.Message {
	return &gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, MessageType: gtpv2.MessageEchoResponse},
		IEs:    []gtpv2.IE{gtpv2.NewRecoveryIE(g.config.RecoveryCounter)},
	}
}

func (g *Gateway) unsupportedResponse(request gtpv2.Message) *gtpv2.Message {
	responseType, ok := gtptransport.ExpectedResponseType(request.Header.MessageType)
	if !ok {
		return nil
	}
	teid := uint32(0)
	if current, found := g.store.FindByControlTEID(request.Header.TEID); found {
		teid = current.SGWControl.TEID
	}
	return &gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: request.Header.HasTEID, MessageType: responseType, TEID: teid},
		IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseServiceNotSupported, 0)},
	}
}

func (g *Gateway) allowedSGW(peer netip.Addr) bool {
	for _, allowed := range g.config.AllowedSGW {
		if peer == allowed {
			return true
		}
	}
	return false
}

func (g *Gateway) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, g.config.ProcedureTimeout)
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

func (g *Gateway) observeRecovery(ctx context.Context, peer netip.AddrPort, request gtpv2.Message) error {
	recoveryIE, ok := request.Find(gtpv2.IERecovery, 0)
	if !ok {
		return nil
	}
	counter, err := recoveryIE.Recovery()
	if err != nil {
		return nil
	}
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	g.recoveryMu.Lock()
	defer g.recoveryMu.Unlock()
	previous, existed := g.recovery[peer]
	if !existed {
		if len(g.recovery) >= maxPeerRecoveryEntries {
			g.counters.peerRestartPurgeFailures.Add(1)
			return fmt.Errorf("peer recovery state capacity %d reached", maxPeerRecoveryEntries)
		}
		if err := g.commitPeerRecovery(peer, counter); err != nil {
			g.counters.peerRestartPurgeFailures.Add(1)
			return err
		}
		g.recovery[peer] = counter
		return nil
	}
	if previous == counter {
		return nil
	}
	g.emit(Event{Severity: "warning", Procedure: "recovery", Peer: peer, Message: "SGW-C recovery counter changed; purging stale sessions"})
	var purgeErr error
	for _, current := range g.store.Snapshot() {
		if current.SGWControl.IP.Unmap() != peer.Addr() {
			continue
		}
		unlock := g.locks.lock(current.ID)
		latest, ok := g.store.Find(current.ID)
		if ok {
			opCtx, cancel := g.operationContext(ctx)
			deleteErr := g.up.Delete(opCtx, userPlaneSession(latest))
			cancel()
			if deleteErr != nil {
				purgeErr = errors.Join(purgeErr, fmt.Errorf("delete PGW-U session %d: %w", latest.ID, deleteErr))
				unlock()
				continue
			}
			if err := g.store.Delete(latest.ID, latest.Revision); err != nil {
				purgeErr = errors.Join(purgeErr, fmt.Errorf("delete PGW-C session %d: %w", latest.ID, err))
				unlock()
				continue
			}
			g.releaseResources(latest)
		}
		unlock()
	}
	if purgeErr != nil {
		g.counters.peerRestartPurgeFailures.Add(1)
		return purgeErr
	}
	if err := g.commitPeerRecovery(peer, counter); err != nil {
		g.counters.peerRestartPurgeFailures.Add(1)
		return err
	}
	g.recovery[peer] = counter
	g.counters.peerRestarts.Add(1)
	return nil
}

func (g *Gateway) commitPeerRecovery(peer netip.AddrPort, counter uint8) error {
	if g.config.CommitPeerRecovery == nil {
		return nil
	}
	if err := g.config.CommitPeerRecovery(peerRecoveryKey(peer), counter); err != nil {
		return fmt.Errorf("persist peer recovery counter: %w", err)
	}
	return nil
}

func peerRecoveryKey(peer netip.AddrPort) string {
	return "s5|" + netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()).String()
}

func parsePeerRecoveryKey(raw string) (netip.AddrPort, error) {
	side, rawPeer, ok := strings.Cut(raw, "|")
	if !ok || side != "s5" {
		return netip.AddrPort{}, fmt.Errorf("pgwc: invalid peer recovery key %q", raw)
	}
	peer, err := netip.ParseAddrPort(rawPeer)
	if err != nil || !peer.Addr().Is4() || peer.Port() == 0 || peer.String() != rawPeer {
		return netip.AddrPort{}, fmt.Errorf("pgwc: invalid peer recovery endpoint %q", rawPeer)
	}
	return netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()), nil
}

// ReconcileAll replays authoritative PGW-C state after a confirmed PGW-U
// restart. Existing GTP-C and UE addressing remain stable; only UP-SEIDs are
// replaced.
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
		result = fmt.Errorf("%d of %d PGW-U session replays failed: %w", failureCount, len(sessions), errors.Join(failureSamples...))
	}
	if reconciledCount > 0 {
		g.emit(Event{Severity: "info", Procedure: "reconciliation", Message: fmt.Sprintf("replayed %d PGW-U sessions", reconciledCount)})
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
	plan, err := userPlaneEstablishment(latest)
	if err != nil {
		return false, fmt.Errorf("session %d durable bearer state: %w", latest.ID, err)
	}
	opCtx, cancel := g.operationContext(ctx)
	userSession, err := g.up.Establish(opCtx, plan)
	cancel()
	if err != nil {
		return false, fmt.Errorf("session %d replay: %w", latest.ID, err)
	}
	if _, err := g.store.ReconcilePFCPUserSEID(latest.ID, latest.Revision, userSession.UPSEID); err != nil {
		// Do not delete a stable in-place reconciliation after a concurrent CP
		// revision change; only a newly allocated UP-SEID belongs to this attempt.
		if userSession.UPSEID != latest.PFCPUserSEID {
			opCtx, cancel = g.operationContext(ctx)
			_ = g.up.Delete(opCtx, userSession)
			cancel()
		}
		return false, fmt.Errorf("session %d commit: %w", latest.ID, err)
	}
	return true, nil
}

func (g *Gateway) releaseResources(current session.Session) {
	if profile, ok := g.profiles[strings.ToLower(strings.TrimSpace(current.APN))]; ok {
		_ = profile.Pool.Release(leaseOwner(current.SubscriberKey, current.APN), current.UEIPv4)
	}
	teids := []uint32{current.PGWControl.TEID, current.PGWUser.TEID}
	for _, bearer := range current.DedicatedBearers {
		teids = append(teids, bearer.PGWUser.TEID)
	}
	g.ids.release(teids, current.PFCPControlSEID)
}

func userPlaneSession(current session.Session) pfcpclient.Session {
	out := pfcpclient.Session{
		CPSEID: current.PFCPControlSEID, UPSEID: current.PFCPUserSEID, UEIPv4: current.UEIPv4,
		Local:  pfcpclient.Tunnel{TEID: current.PGWUser.TEID, IP: current.PGWUser.IP},
		Remote: pfcpclient.Tunnel{TEID: current.SGWUser.TEID, IP: current.SGWUser.IP}, DefaultRules: pfcpclient.DefaultRuleIDs(),
	}
	for _, ebi := range sortedDedicatedEBIs(current) {
		bearer := current.DedicatedBearers[ebi]
		out.Bearers = append(out.Bearers, pfcpclient.Bearer{
			Rules:         pfcpRuleIDs(bearer.Rules),
			Local:         pfcpclient.Tunnel{TEID: bearer.PGWUser.TEID, IP: bearer.PGWUser.IP},
			Remote:        pfcpclient.Tunnel{TEID: bearer.SGWUser.TEID, IP: bearer.SGWUser.IP},
			UplinkBitrate: bearer.UplinkMBR, DownlinkBitrate: bearer.DownlinkMBR, QCI: bearer.QCI, ARP: bearer.ARP,
		})
	}
	return out
}

func userPlaneEstablishment(current session.Session) (pfcpclient.Establishment, error) {
	out := pfcpclient.Establishment{
		CPSEID: current.PFCPControlSEID, UEIPv4: current.UEIPv4,
		Local:           pfcpclient.Tunnel{TEID: current.PGWUser.TEID, IP: current.PGWUser.IP},
		Remote:          pfcpclient.Tunnel{TEID: current.SGWUser.TEID, IP: current.SGWUser.IP},
		UplinkBitrate:   effectiveBitrate(current.APNAMBRUplinkBPS, current.UplinkMBR),
		DownlinkBitrate: effectiveBitrate(current.APNAMBRDownlinkBPS, current.DownlinkMBR),
		QCI:             current.QCI, ARP: current.ARP,
	}
	for _, ebi := range sortedDedicatedEBIs(current) {
		bearer := current.DedicatedBearers[ebi]
		tft, err := gtpv2.ParseBearerTFT(bearer.TFT)
		if err != nil {
			return pfcpclient.Establishment{}, fmt.Errorf("bearer EBI %d TFT: %w", ebi, err)
		}
		out.AdditionalBearers = append(out.AdditionalBearers, pfcpclient.BearerPlan{
			Rules:         pfcpRuleIDs(bearer.Rules),
			Local:         pfcpclient.Tunnel{TEID: bearer.PGWUser.TEID, IP: bearer.PGWUser.IP},
			Remote:        pfcpclient.Tunnel{TEID: bearer.SGWUser.TEID, IP: bearer.SGWUser.IP},
			UplinkBitrate: bearer.UplinkMBR, DownlinkBitrate: bearer.DownlinkMBR,
			QCI: bearer.QCI, ARP: bearer.ARP, TFT: tft,
		})
	}
	return out, nil
}

func sortedDedicatedEBIs(current session.Session) []uint8 {
	ebis := make([]uint8, 0, len(current.DedicatedBearers))
	for ebi := range current.DedicatedBearers {
		ebis = append(ebis, ebi)
	}
	sort.Slice(ebis, func(i, j int) bool { return ebis[i] < ebis[j] })
	return ebis
}

func pfcpRuleIDs(ids session.RuleIDs) pfcpclient.RuleIDs {
	return pfcpclient.RuleIDs{
		UplinkPDRs: append([]uint16(nil), ids.UplinkPDRs...), DownlinkPDRs: append([]uint16(nil), ids.DownlinkPDRs...),
		UplinkFAR: ids.UplinkFAR, DownlinkFAR: ids.DownlinkFAR, QER: ids.QER, URR: ids.URR,
	}
}

func sessionRuleIDs(ids pfcpclient.RuleIDs) session.RuleIDs {
	return session.RuleIDs{
		UplinkPDRs: append([]uint16(nil), ids.UplinkPDRs...), DownlinkPDRs: append([]uint16(nil), ids.DownlinkPDRs...),
		UplinkFAR: ids.UplinkFAR, DownlinkFAR: ids.DownlinkFAR, QER: ids.QER, URR: ids.URR,
	}
}

func subscriberLockKey(subscriber string) uint64 {
	hash := sha256.Sum256([]byte(subscriber))
	return binary.BigEndian.Uint64(hash[:8])
}

func leaseOwner(subscriber, apn string) string { return subscriber + "\x00" + strings.ToLower(apn) }
