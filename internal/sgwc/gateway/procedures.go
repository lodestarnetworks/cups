package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	gtptransport "github.com/lodestarnetworks/cups/internal/gtpv2/transport"
	"github.com/lodestarnetworks/cups/internal/sgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/sgwc/session"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

type createRequest struct {
	imsi            string
	apn             string
	mmeControl      gtpv2.FTEID
	ebi             uint8
	qos             gtpv2.BearerQoS
	uplinkBitrate   uint64
	downlinkBitrate uint64
}

type pgwSession struct {
	control gtpv2.FTEID
	user    gtpv2.FTEID
}

type modifyBearerItem struct {
	ebi       uint8
	enodeb    gtpv2.FTEID
	grouped   gtpv2.IE
	sessionID uint64
}

type modifyBearerGroup struct {
	current session.Session
	items   []modifyBearerItem
}

type modifyBearerActivation struct {
	current session.Session
	bearer  session.Bearer
}

type modifyBearerCommit struct {
	previous session.Session
	updated  session.Session
}

func (g *Gateway) createSession(parent context.Context, peer netip.AddrPort, request gtpv2.Message) *gtpv2.Message {
	parsed, cause, err := parseCreateRequest(peer, request)
	if err != nil {
		g.reject("create-session", peer, "invalid MME request: "+err.Error())
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, cause, parsed.ebi)
	}
	if g.config.AllowNewSessions != nil && !g.config.AllowNewSessions() {
		g.counters.rejected.Add(1)
		g.counters.createRejected.Add(1)
		g.counters.createAdmissionRejected.Add(1)
		g.emit(Event{Severity: "warning", Procedure: "create-session", Peer: peer, Message: "new session rejected while SGW-C is draining"})
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, gtpv2.CauseNoResourcesAvailable, parsed.ebi)
	}
	subscriber := g.subscriberKey(parsed.imsi)
	unlockSubscriber := g.subscriberLocks.lock(subscriberLockKey(subscriber))
	defer unlockSubscriber()
	if err := g.replaceCreateCollision(parent, peer, subscriber, parsed.ebi, request.Header.TEID); err != nil {
		g.reject("create-session", peer, "colliding context cleanup failed: "+err.Error())
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, gtpv2.CauseSystemFailure, parsed.ebi)
	}

	if existing := g.findOwner(subscriber, parsed.apn); existing {
		g.reject("create-session", peer, "subscriber/APN context already exists")
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, gtpv2.CauseNoResourcesAvailable, parsed.ebi)
	}

	allocated := make([]uint32, 0, 4)
	allocate := func() (uint32, error) {
		id, allocateErr := g.ids.allocateTEID()
		if allocateErr == nil {
			allocated = append(allocated, id)
		}
		return id, allocateErr
	}
	s11TEID := request.Header.TEID
	if s11TEID == 0 {
		s11TEID, err = allocate()
		if err != nil {
			return g.createResourceFailure(peer, parsed, err)
		}
	} else {
		existing, ok := g.store.FindByS11TEID(s11TEID)
		if !ok {
			g.reject("create-session", peer, "additional PDN references an unknown S11 context")
			return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, gtpv2.CauseContextNotFound, parsed.ebi)
		}
		if existing.SubscriberKey != subscriber ||
			existing.MMEControl.TEID != parsed.mmeControl.TEID ||
			existing.MMEControl.IP.Unmap() != parsed.mmeControl.IPv4.Unmap() ||
			existing.S11Control.IP.Unmap() != g.config.S11Advertise.Unmap() {
			g.reject("create-session", peer, "additional PDN does not own the referenced S11 context")
			return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, gtpv2.CauseContextNotFound, parsed.ebi)
		}
	}
	s5TEID, err := allocate()
	if err != nil {
		g.ids.releaseTEIDs(allocated...)
		return g.createResourceFailure(peer, parsed, err)
	}
	accessTEID, err := allocate()
	if err != nil {
		g.ids.releaseTEIDs(allocated...)
		return g.createResourceFailure(peer, parsed, err)
	}
	coreTEID, err := allocate()
	if err != nil {
		g.ids.releaseTEIDs(allocated...)
		return g.createResourceFailure(peer, parsed, err)
	}
	cpSEID, err := g.ids.allocateSEID()
	if err != nil {
		g.ids.releaseTEIDs(allocated...)
		return g.createResourceFailure(peer, parsed, err)
	}
	committed := false
	defer func() {
		if !committed {
			g.ids.releaseTEIDs(allocated...)
			g.ids.releaseSEID(cpSEID)
		}
	}()

	sgwS5, _ := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8SGWGTPC, TEID: s5TEID, IPv4: g.config.S5Advertise,
	})
	sgwS5User, err := gtpv2.NewFTEIDIE(2, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8SGWGTPU, TEID: coreTEID, IPv4: g.config.SGWUCoreIP,
	})
	if err != nil {
		g.reject("create-session", peer, "S5-U F-TEID construction failed: "+err.Error())
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, gtpv2.CauseSystemFailure, parsed.ebi)
	}
	bearerIE, ok := request.Find(gtpv2.IEBearerContext, 0)
	if !ok {
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, gtpv2.CauseMandatoryIEMissing, parsed.ebi)
	}
	bearerChildren, err := bearerIE.Children()
	if err != nil {
		g.reject("create-session", peer, "default bearer construction failed: "+err.Error())
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, gtpv2.CauseMandatoryIEIncorrect, parsed.ebi)
	}
	bearerChildren = gtpv2.UpsertIE(bearerChildren, sgwS5User)
	s5Bearer, err := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, bearerChildren...)
	if err != nil {
		g.reject("create-session", peer, "default bearer construction failed: "+err.Error())
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, gtpv2.CauseSystemFailure, parsed.ebi)
	}
	toPGW := request.Clone()
	toPGW.Header = gtpv2.Header{
		Version: gtpv2.Version, HasTEID: true,
		MessageType: gtpv2.MessageCreateSessionRequest,
	}
	toPGW.Upsert(sgwS5)
	toPGW.Upsert(s5Bearer)
	g.stampRecovery(&toPGW)
	pgwPeer := g.pgwControlForAPN(parsed.apn)
	opCtx, cancel := g.operationContext(parent)
	pgwResponse, err := g.doS5(opCtx, pgwPeer, toPGW)
	cancel()
	if err != nil {
		g.reject("create-session", peer, "PGW transaction failed: "+err.Error())
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, transportCause(err), parsed.ebi)
	}
	topCause, err := messageCause(pgwResponse)
	if err != nil {
		g.reject("create-session", peer, "PGW response has no valid cause")
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, gtpv2.CauseInvalidReplyFromPeer, parsed.ebi)
	}
	if topCause != gtpv2.CauseRequestAccepted {
		g.reject("create-session", peer, fmt.Sprintf("PGW rejected request with cause %d", topCause))
		return relayResponse(pgwResponse, gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID)
	}
	pgw, err := parsePGWSessionResponse(pgwResponse, s5TEID, parsed.ebi)
	if err != nil {
		g.reject("create-session", peer, "invalid accepted PGW response: "+err.Error())
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, gtpv2.CauseInvalidReplyFromPeer, parsed.ebi)
	}

	pfcpPlan := pfcpclient.Establishment{
		CPSEID:        cpSEID,
		AccessLocal:   pfcpclient.Tunnel{TEID: accessTEID, IP: g.config.SGWUAccessIP},
		CoreLocal:     pfcpclient.Tunnel{TEID: coreTEID, IP: g.config.SGWUCoreIP},
		CoreRemote:    pfcpclient.Tunnel{TEID: pgw.user.TEID, IP: pgw.user.IPv4},
		UplinkBitrate: parsed.uplinkBitrate, DownlinkBitrate: parsed.downlinkBitrate,
		QCI: parsed.qos.QCI, ARP: parsed.qos.Priority,
		PreemptionCapable: parsed.qos.PreemptionCapable, PreemptionVulnerable: parsed.qos.PreemptionVulnerable,
	}
	opCtx, cancel = g.operationContext(parent)
	userSession, err := g.up.Establish(opCtx, pfcpPlan)
	cancel()
	if err != nil {
		g.reject("create-session", peer, "SGW-U session establishment failed: "+err.Error())
		g.bestEffortDeletePGW(parent, pgwPeer, pgw.control, parsed.ebi)
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, gtpv2.CauseSystemFailure, parsed.ebi)
	}

	stored, err := g.store.Create(session.Session{
		SubscriberKey:   subscriber,
		APN:             parsed.apn,
		State:           session.StatePending,
		MMEControl:      session.FTEID{TEID: parsed.mmeControl.TEID, IP: parsed.mmeControl.IPv4},
		S11Control:      session.FTEID{TEID: s11TEID, IP: g.config.S11Advertise},
		S5Control:       session.FTEID{TEID: s5TEID, IP: g.config.S5Advertise},
		PGWControl:      session.FTEID{TEID: pgw.control.TEID, IP: pgw.control.IPv4},
		PFCPControlSEID: userSession.CPSEID,
		PFCPUserSEID:    userSession.UPSEID,
		Bearers: map[uint8]session.Bearer{
			parsed.ebi: {
				EBI: parsed.ebi, QCI: parsed.qos.QCI, ARP: parsed.qos.Priority,
				PreemptionCapable: parsed.qos.PreemptionCapable, PreemptionVulnerable: parsed.qos.PreemptionVulnerable,
				UplinkMBR: parsed.uplinkBitrate, DownlinkMBR: parsed.downlinkBitrate,
				UplinkGBR: parsed.qos.UplinkGBR, DownlinkGBR: parsed.qos.DownlinkGBR,
				Default:    true,
				State:      session.BearerPending,
				SGWUAccess: session.FTEID{TEID: accessTEID, IP: g.config.SGWUAccessIP},
				SGWUCore:   session.FTEID{TEID: coreTEID, IP: g.config.SGWUCoreIP},
				PGWUser:    session.FTEID{TEID: pgw.user.TEID, IP: pgw.user.IPv4},
				Rules: session.RuleIDs{
					UplinkPDR: 1, DownlinkPDR: 2, UplinkFAR: 1, DownlinkFAR: 2, QER: 1, URR: 1,
				},
			},
		},
	})
	if err != nil {
		opCtx, cancel = g.operationContext(parent)
		_ = g.up.Delete(opCtx, userSession)
		cancel()
		g.bestEffortDeletePGW(parent, pgwPeer, pgw.control, parsed.ebi)
		g.reject("create-session", peer, "local session commit failed: "+err.Error())
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, gtpv2.CauseNoResourcesAvailable, parsed.ebi)
	}

	response, err := g.createResponseForMME(pgwResponse, stored, parsed.ebi)
	if err != nil {
		opCtx, cancel = g.operationContext(parent)
		_ = g.up.Delete(opCtx, userSession)
		cancel()
		_ = g.store.Delete(stored.ID, stored.Revision)
		g.bestEffortDeletePGW(parent, pgwPeer, pgw.control, parsed.ebi)
		g.reject("create-session", peer, "MME response construction failed: "+err.Error())
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, gtpv2.CauseSystemFailure, parsed.ebi)
	}
	committed = true
	g.counters.createAccepted.Add(1)
	g.emit(Event{Severity: "info", Procedure: "create-session", Peer: peer, Subscriber: subscriber, Message: "default bearer created; downlink awaiting eNodeB F-TEID"})
	return response
}

// replaceCreateCollision implements the SGW collision rules in TS 29.274
// clause 7.2.1. A Create Session that collides on [IMSI, EBI] is a request for
// a new session, not a resource-exhaustion error. The old SGW-local PDN is
// removed when the header TEID is zero or the collision is with its default
// bearer; a non-zero-TEID collision with a dedicated bearer removes only that
// bearer. PGW collision handling remains the PGW's responsibility when the
// configured S5/S8 peer is unchanged.
func (g *Gateway) replaceCreateCollision(parent context.Context, peer netip.AddrPort, subscriber string, ebi uint8, headerTEID uint32) error {
	current, ok := g.store.FindBySubscriberAndEBI(subscriber, ebi)
	if !ok {
		return nil
	}
	unlock := g.locks.lock(current.ID)
	defer unlock()
	current, ok = g.store.Find(current.ID)
	if !ok {
		return nil
	}
	bearer, ok := current.Bearers[ebi]
	if !ok {
		return nil
	}

	userSession := pfcpSession(current)
	opCtx, cancel := g.operationContext(parent)
	if headerTEID == 0 || bearer.Default {
		err := g.up.Delete(opCtx, userSession)
		cancel()
		if err != nil {
			return fmt.Errorf("delete stale SGW-U PDN: %w", err)
		}
		if err := g.store.Delete(current.ID, current.Revision); err != nil {
			return fmt.Errorf("delete stale SGW-C PDN: %w", err)
		}
		g.paging.purgeSession(current.ID)
		g.releaseIDs(current)
		g.counters.createReplacements.Add(1)
		g.emit(Event{Severity: "warning", Procedure: "create-session", Peer: peer, Subscriber: subscriber, Message: fmt.Sprintf("replaced colliding PDN context for EBI %d", ebi)})
		return nil
	}

	err := g.up.RemoveBearer(opCtx, &userSession, pfcpRules(bearer))
	cancel()
	if err != nil {
		return fmt.Errorf("delete stale SGW-U dedicated bearer: %w", err)
	}
	if _, err := g.store.Update(current.ID, current.Revision, func(candidate *session.Session) error {
		delete(candidate.Bearers, ebi)
		return nil
	}); err != nil {
		return fmt.Errorf("delete stale SGW-C dedicated bearer: %w", err)
	}
	g.paging.cancel(current.ID, ebi)
	g.ids.releaseTEIDs(bearer.SGWUAccess.TEID, bearer.SGWUCore.TEID)
	g.counters.createReplacements.Add(1)
	g.emit(Event{Severity: "warning", Procedure: "create-session", Peer: peer, Subscriber: subscriber, Message: fmt.Sprintf("replaced colliding dedicated bearer EBI %d", ebi)})
	return nil
}

func (g *Gateway) modifyBearer(parent context.Context, peer netip.AddrPort, request gtpv2.Message) *gtpv2.Message {
	items, err := parseModifyBearers(request)
	if err != nil {
		responseTEID := uint32(0)
		if control, ok := g.store.FindByS11TEID(request.Header.TEID); ok {
			responseTEID = control.MMEControl.TEID
		}
		g.reject("modify-bearer", peer, "invalid request: "+err.Error())
		return modifyBearerResponse(responseTEID, gtpv2.CauseMandatoryIEIncorrect, items)
	}
	control, ok := g.store.FindByS11TEIDAndEBI(request.Header.TEID, items[0].ebi)
	if !ok {
		g.reject("modify-bearer", peer, "unknown S11 TEID or bearer EBI")
		return modifyBearerResponse(0, gtpv2.CauseContextNotFound, items)
	}
	responseTEID := control.MMEControl.TEID
	unlockSubscriber := g.subscriberLocks.lock(subscriberLockKey(control.SubscriberKey))
	defer unlockSubscriber()

	// Resolve every repeated Bearer Context before changing the user plane. An
	// MME commonly resumes all PDNs (for example internet and IMS) in one S11
	// request after UE idle, even though each PDN has an independent S5 tunnel.
	sessionIDs := make([]uint64, 0, len(items))
	seenSessions := make(map[uint64]struct{}, len(items))
	for index := range items {
		current, found := g.store.FindByS11TEIDAndEBI(request.Header.TEID, items[index].ebi)
		if !found || current.SubscriberKey != control.SubscriberKey || current.MMEControl != control.MMEControl {
			g.reject("modify-bearer", peer, fmt.Sprintf("bearer EBI %d does not belong to the shared S11 context", items[index].ebi))
			return modifyBearerResponse(responseTEID, gtpv2.CauseContextNotFound, items)
		}
		items[index].sessionID = current.ID
		if _, exists := seenSessions[current.ID]; !exists {
			seenSessions[current.ID] = struct{}{}
			sessionIDs = append(sessionIDs, current.ID)
		}
	}

	unlockSessions := g.locks.lockMany(sessionIDs)
	defer unlockSessions()
	if peer.Addr().Unmap() != control.MMEControl.IP.Unmap() {
		g.reject("modify-bearer", peer, "MME does not own session")
		return modifyBearerResponse(responseTEID, gtpv2.CauseContextNotFound, items)
	}

	groups := make([]modifyBearerGroup, 0, len(sessionIDs))
	groupBySession := make(map[uint64]int, len(sessionIDs))
	for _, item := range items {
		current, found := g.store.Find(item.sessionID)
		if !found || current.S11Control.TEID != request.Header.TEID || current.SubscriberKey != control.SubscriberKey {
			g.reject("modify-bearer", peer, "shared S11 context changed while processing request")
			return modifyBearerResponse(responseTEID, gtpv2.CauseContextNotFound, items)
		}
		if _, found := current.Bearers[item.ebi]; !found {
			g.reject("modify-bearer", peer, fmt.Sprintf("unknown bearer EBI %d", item.ebi))
			return modifyBearerResponse(responseTEID, gtpv2.CauseContextNotFound, items)
		}
		groupIndex, exists := groupBySession[current.ID]
		if !exists {
			groupIndex = len(groups)
			groupBySession[current.ID] = groupIndex
			groups = append(groups, modifyBearerGroup{current: current})
		}
		groups[groupIndex].items = append(groups[groupIndex].items, item)
	}

	activations := make([]modifyBearerActivation, 0, len(items))
	for _, group := range groups {
		for _, item := range group.items {
			bearer := group.current.Bearers[item.ebi]
			userSession := pfcpSession(group.current)
			opCtx, cancel := g.operationContext(parent)
			err = g.up.ActivateBearer(opCtx, &userSession, pfcpRules(bearer), pfcpclient.Tunnel{TEID: item.enodeb.TEID, IP: item.enodeb.IPv4})
			cancel()
			if err != nil {
				g.rollbackModifyBearerActivations(parent, activations)
				g.reject("modify-bearer", peer, fmt.Sprintf("SGW-U activation failed for EBI %d: %v", item.ebi, err))
				return modifyBearerResponse(responseTEID, gtpv2.CauseSystemFailure, items)
			}
			activations = append(activations, modifyBearerActivation{current: group.current, bearer: bearer})
		}
	}

	for _, group := range groups {
		toPGW, buildErr := modifyBearerRequestForPGW(request, group)
		if buildErr != nil {
			g.rollbackModifyBearerActivations(parent, activations)
			g.reject("modify-bearer", peer, "could not construct per-PDN S5 request: "+buildErr.Error())
			return modifyBearerResponse(responseTEID, gtpv2.CauseSystemFailure, items)
		}
		g.stampRecovery(&toPGW)
		opCtx, cancel := g.operationContext(parent)
		pgwResponse, transactionErr := g.doS5(opCtx, g.pgwControlForAPN(group.current.APN), toPGW)
		cancel()
		if transactionErr != nil {
			g.rollbackModifyBearerActivations(parent, activations)
			g.reject("modify-bearer", peer, fmt.Sprintf("PGW transaction failed for APN %q: %v", group.current.APN, transactionErr))
			return modifyBearerResponse(responseTEID, transportCause(transactionErr), items)
		}
		if pgwResponse.Header.TEID != group.current.S5Control.TEID {
			g.rollbackModifyBearerActivations(parent, activations)
			g.reject("modify-bearer", peer, fmt.Sprintf("PGW for APN %q replied on the wrong S5 tunnel", group.current.APN))
			return modifyBearerResponse(responseTEID, gtpv2.CauseInvalidReplyFromPeer, items)
		}
		cause, responseErr := modifyBearerResponseCause(pgwResponse, group.items)
		if responseErr != nil {
			g.rollbackModifyBearerActivations(parent, activations)
			g.reject("modify-bearer", peer, fmt.Sprintf("invalid PGW response for APN %q: %v", group.current.APN, responseErr))
			return modifyBearerResponse(responseTEID, gtpv2.CauseInvalidReplyFromPeer, items)
		}
		if cause != gtpv2.CauseRequestAccepted {
			g.rollbackModifyBearerActivations(parent, activations)
			g.reject("modify-bearer", peer, fmt.Sprintf("PGW for APN %q rejected request with cause %d", group.current.APN, cause))
			return modifyBearerResponse(responseTEID, cause, items)
		}
	}

	committed := make([]modifyBearerCommit, 0, len(groups))
	for _, group := range groups {
		updated, updateErr := g.store.Update(group.current.ID, group.current.Revision, func(candidate *session.Session) error {
			for _, item := range group.items {
				updatedBearer, exists := candidate.Bearers[item.ebi]
				if !exists {
					return session.ErrNotFound
				}
				updatedBearer.ENBUser = session.FTEID{TEID: item.enodeb.TEID, IP: item.enodeb.IPv4}
				updatedBearer.State = session.BearerActive
				candidate.Bearers[item.ebi] = updatedBearer
			}
			candidate.State = session.StateActive
			return nil
		})
		if updateErr != nil {
			g.rollbackModifyBearerState(committed)
			g.rollbackModifyBearerActivations(parent, activations)
			g.reject("modify-bearer", peer, "local multi-PDN state update failed: "+updateErr.Error())
			return modifyBearerResponse(responseTEID, gtpv2.CauseSystemFailure, items)
		}
		committed = append(committed, modifyBearerCommit{previous: group.current, updated: updated})
	}

	observedAt := time.Now()
	for _, item := range items {
		g.paging.observe(item.sessionID, item.ebi, item.enodeb.IPv4, observedAt)
	}
	g.counters.modifyAccepted.Add(1)
	g.emit(Event{
		Severity: "info", Procedure: "modify-bearer", Peer: peer, Subscriber: control.SubscriberKey,
		Message: fmt.Sprintf("reactivated %d bearer(s) across %d PDN context(s)", len(items), len(groups)),
	})
	return modifyBearerResponse(responseTEID, gtpv2.CauseRequestAccepted, items)
}

func (g *Gateway) releaseAccessBearers(parent context.Context, peer netip.AddrPort, request gtpv2.Message) *gtpv2.Message {
	contexts := g.store.FindAllByS11TEID(request.Header.TEID)
	if len(contexts) == 0 {
		g.reject("release-access-bearers", peer, "unknown S11 TEID")
		return failureResponse(gtpv2.MessageReleaseAccessBearersResponse, 0, gtpv2.CauseContextNotFound, 0)
	}
	control := contexts[len(contexts)-1]
	unlockSubscriber := g.subscriberLocks.lock(subscriberLockKey(control.SubscriberKey))
	defer unlockSubscriber()
	contexts = g.store.FindAllByS11TEID(request.Header.TEID)
	if len(contexts) == 0 {
		return failureResponse(gtpv2.MessageReleaseAccessBearersResponse, 0, gtpv2.CauseContextNotFound, 0)
	}
	control = contexts[len(contexts)-1]
	if peer.Addr().Unmap() != control.MMEControl.IP.Unmap() {
		g.reject("release-access-bearers", peer, "MME does not own S11 context")
		return failureResponse(gtpv2.MessageReleaseAccessBearersResponse, control.MMEControl.TEID, gtpv2.CauseContextNotFound, 0)
	}

	deactivated := make([]session.Session, 0, len(contexts))
	for _, candidate := range contexts {
		unlock := g.locks.lock(candidate.ID)
		current, ok := g.store.Find(candidate.ID)
		if !ok {
			unlock()
			g.reactivateDownlinks(parent, deactivated)
			return failureResponse(gtpv2.MessageReleaseAccessBearersResponse, control.MMEControl.TEID, gtpv2.CauseSystemFailure, 0)
		}
		userSession := pfcpSession(current)
		deactivatedInCurrent := false
		var err error
		for _, bearer := range current.Bearers {
			opCtx, cancel := g.operationContext(parent)
			err = g.up.DeactivateBearer(opCtx, &userSession, pfcpRules(bearer))
			cancel()
			if err != nil {
				break
			}
			deactivatedInCurrent = true
		}
		unlock()
		if err != nil {
			if deactivatedInCurrent {
				g.reactivateDownlinks(parent, []session.Session{current})
			}
			g.reactivateDownlinks(parent, deactivated)
			g.reject("release-access-bearers", peer, "SGW-U downlink deactivation failed: "+err.Error())
			return failureResponse(gtpv2.MessageReleaseAccessBearersResponse, control.MMEControl.TEID, gtpv2.CauseSystemFailure, 0)
		}
		deactivated = append(deactivated, current)
	}

	for _, current := range deactivated {
		unlock := g.locks.lock(current.ID)
		latest, ok := g.store.Find(current.ID)
		if !ok {
			unlock()
			g.reactivateDownlinks(parent, deactivated)
			return failureResponse(gtpv2.MessageReleaseAccessBearersResponse, control.MMEControl.TEID, gtpv2.CauseSystemFailure, 0)
		}
		_, err := g.store.Update(latest.ID, latest.Revision, func(candidate *session.Session) error {
			candidate.State = session.StateIdle
			for ebi, bearer := range candidate.Bearers {
				bearer.State = session.BearerIdle
				bearer.ENBUser = session.FTEID{}
				candidate.Bearers[ebi] = bearer
			}
			return nil
		})
		unlock()
		if err != nil {
			g.reactivateDownlinks(parent, deactivated)
			g.reject("release-access-bearers", peer, "local multi-PDN state update failed: "+err.Error())
			return failureResponse(gtpv2.MessageReleaseAccessBearersResponse, control.MMEControl.TEID, gtpv2.CauseSystemFailure, 0)
		}
	}
	g.counters.releaseAccepted.Add(1)
	g.emit(Event{Severity: "info", Procedure: "release-access-bearers", Peer: peer, Subscriber: control.SubscriberKey, Message: fmt.Sprintf("access tunnels released for %d PDN context(s); core sessions retained", len(contexts))})
	return successResponse(gtpv2.MessageReleaseAccessBearersResponse, control.MMEControl.TEID, 0)
}

func (g *Gateway) deleteSession(parent context.Context, peer netip.AddrPort, request gtpv2.Message) *gtpv2.Message {
	contexts := g.store.FindAllByS11TEID(request.Header.TEID)
	if len(contexts) == 0 {
		g.reject("delete-session", peer, "unknown S11 TEID")
		return failureResponse(gtpv2.MessageDeleteSessionResponse, 0, gtpv2.CauseContextNotFound, 0)
	}
	control := contexts[len(contexts)-1]
	deleteEBI, hasDeleteEBI, err := parseDeleteSessionEBI(request)
	if err != nil {
		g.reject("delete-session", peer, "invalid linked bearer EBI: "+err.Error())
		return failureResponse(gtpv2.MessageDeleteSessionResponse, control.MMEControl.TEID, gtpv2.CauseMandatoryIEIncorrect, 0)
	}
	unlockSubscriber := g.subscriberLocks.lock(subscriberLockKey(control.SubscriberKey))
	defer unlockSubscriber()
	contexts = g.store.FindAllByS11TEID(request.Header.TEID)
	if len(contexts) == 0 {
		return failureResponse(gtpv2.MessageDeleteSessionResponse, 0, gtpv2.CauseContextNotFound, 0)
	}
	control = contexts[len(contexts)-1]
	current := control
	var ok bool
	if hasDeleteEBI {
		current, ok = g.store.FindByS11TEIDAndEBI(request.Header.TEID, deleteEBI)
		if !ok {
			g.reject("delete-session", peer, "linked bearer does not belong to the S11 context")
			return failureResponse(gtpv2.MessageDeleteSessionResponse, control.MMEControl.TEID, gtpv2.CauseContextNotFound, deleteEBI)
		}
	}
	unlock := g.locks.lock(current.ID)
	defer unlock()
	current, ok = g.store.Find(current.ID)
	if !ok || peer.Addr().Unmap() != current.MMEControl.IP.Unmap() {
		return failureResponse(gtpv2.MessageDeleteSessionResponse, 0, gtpv2.CauseContextNotFound, 0)
	}
	bearer := defaultBearer(current)
	toPGW := request.Clone()
	toPGW.Header = gtpv2.Header{
		Version: gtpv2.Version, HasTEID: true,
		MessageType: gtpv2.MessageDeleteSessionRequest, TEID: current.PGWControl.TEID,
	}
	sgwS5, err := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8SGWGTPC,
		TEID:          current.S5Control.TEID,
		IPv4:          current.S5Control.IP,
	})
	if err != nil {
		g.reject("delete-session", peer, "S5-C F-TEID construction failed: "+err.Error())
		return failureResponse(gtpv2.MessageDeleteSessionResponse, current.MMEControl.TEID, gtpv2.CauseSystemFailure, bearer.EBI)
	}
	// A Delete Session received over S11 can carry the MME's Sender F-TEID in
	// instance zero. It must identify this SGW's S5-C endpoint when the request
	// is relayed to the PGW; forwarding the MME endpoint makes a strict PGW
	// reject the deletion and leaves stale PDN state on both sides.
	toPGW.IEs = gtpv2.UpsertIE(toPGW.IEs, sgwS5)
	g.stampRecovery(&toPGW)
	opCtx, cancel := g.operationContext(parent)
	pgwResponse, err := g.doS5(opCtx, g.pgwControlForAPN(current.APN), toPGW)
	cancel()
	if err != nil {
		g.reject("delete-session", peer, "PGW transaction failed: "+err.Error())
		return failureResponse(gtpv2.MessageDeleteSessionResponse, current.MMEControl.TEID, transportCause(err), bearer.EBI)
	}
	cause, err := messageCause(pgwResponse)
	if err != nil {
		return failureResponse(gtpv2.MessageDeleteSessionResponse, current.MMEControl.TEID, gtpv2.CauseInvalidReplyFromPeer, bearer.EBI)
	}
	// A prior attempt or the peer-restart procedure may already have removed
	// the PGW-C/U half of this bearer. Context Not Found is therefore an
	// idempotent delete result; local SGW-C/U cleanup must still complete.
	downstreamContextMissing := cause == gtpv2.CauseContextNotFound
	if !downstreamContextMissing && pgwResponse.Header.TEID != current.S5Control.TEID {
		return failureResponse(gtpv2.MessageDeleteSessionResponse, current.MMEControl.TEID, gtpv2.CauseInvalidReplyFromPeer, bearer.EBI)
	}
	if cause != gtpv2.CauseRequestAccepted && !downstreamContextMissing {
		g.reject("delete-session", peer, fmt.Sprintf("PGW rejected request with cause %d", cause))
		return relayResponse(pgwResponse, gtpv2.MessageDeleteSessionResponse, current.MMEControl.TEID)
	}
	opCtx, cancel = g.operationContext(parent)
	err = g.up.Delete(opCtx, pfcpSession(current))
	cancel()
	if err != nil {
		g.reject("delete-session", peer, "SGW-U deletion failed after PGW deletion: "+err.Error())
		return failureResponse(gtpv2.MessageDeleteSessionResponse, current.MMEControl.TEID, gtpv2.CauseSystemFailure, bearer.EBI)
	}
	if err := g.store.Delete(current.ID, current.Revision); err != nil {
		g.reject("delete-session", peer, "local deletion failed: "+err.Error())
		return failureResponse(gtpv2.MessageDeleteSessionResponse, current.MMEControl.TEID, gtpv2.CauseSystemFailure, bearer.EBI)
	}
	g.paging.purgeSession(current.ID)
	g.releaseIDs(current)
	if downstreamContextMissing {
		g.counters.deleteContextNotFound.Add(1)
	}
	g.counters.deleteAccepted.Add(1)
	message := "control and user-plane contexts deleted"
	if downstreamContextMissing {
		message = "downstream context already absent; local control and user-plane contexts reconciled"
	}
	g.emit(Event{Severity: "info", Procedure: "delete-session", Peer: peer, Subscriber: current.SubscriberKey, Message: message})
	if downstreamContextMissing {
		return successResponse(gtpv2.MessageDeleteSessionResponse, current.MMEControl.TEID, bearer.EBI)
	}
	return relayResponse(pgwResponse, gtpv2.MessageDeleteSessionResponse, current.MMEControl.TEID)
}

func parseCreateRequest(peer netip.AddrPort, request gtpv2.Message) (createRequest, uint8, error) {
	var out createRequest
	imsiIE, imsiOK := request.Find(gtpv2.IEIMSI, 0)
	apnIE, apnOK := request.Find(gtpv2.IEAPN, 0)
	mmeIE, mmeOK := request.Find(gtpv2.IEFTEID, 0)
	bearerIE, bearerOK := request.Find(gtpv2.IEBearerContext, 0)
	if !imsiOK || !apnOK || !mmeOK || !bearerOK {
		return out, gtpv2.CauseMandatoryIEMissing, gtpv2.ErrMissingIE
	}
	var err error
	out.imsi, err = imsiIE.IMSI()
	if err != nil {
		return out, gtpv2.CauseMandatoryIEIncorrect, err
	}
	out.apn, err = apnIE.APN()
	if err != nil {
		return out, gtpv2.CauseMandatoryIEIncorrect, err
	}
	out.mmeControl, err = mmeIE.FTEID()
	if err != nil || out.mmeControl.InterfaceType != gtpv2.InterfaceS11MMEGTPC || !out.mmeControl.IPv4.Is4() {
		return out, gtpv2.CauseMandatoryIEIncorrect, errors.New("invalid S11 MME F-TEID")
	}
	if out.mmeControl.IPv4.Unmap() != peer.Addr().Unmap() {
		return out, gtpv2.CauseMandatoryIEIncorrect, errors.New("MME F-TEID address does not match packet source")
	}
	children, err := bearerIE.Children()
	if err != nil {
		return out, gtpv2.CauseMandatoryIEIncorrect, err
	}
	ebiIE, ebiOK := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
	qosIE, qosOK := gtpv2.FindIE(children, gtpv2.IEBearerQoS, 0)
	if !ebiOK || !qosOK {
		return out, gtpv2.CauseMandatoryIEMissing, gtpv2.ErrMissingIE
	}
	out.ebi, err = ebiIE.EBI()
	if err != nil {
		return out, gtpv2.CauseMandatoryIEIncorrect, err
	}
	out.qos, err = qosIE.BearerQoSDetails()
	if err != nil {
		return out, gtpv2.CauseMandatoryIEIncorrect, err
	}
	out.uplinkBitrate = out.qos.UplinkMBR
	out.downlinkBitrate = out.qos.DownlinkMBR
	if ambrIE, ok := request.Find(gtpv2.IEAMBR, 0); ok {
		uplinkAMBR, downlinkAMBR, err := ambrIE.AMBR()
		if err != nil {
			return out, gtpv2.CauseMandatoryIEIncorrect, err
		}
		out.uplinkBitrate = effectiveDefaultBearerRate(uplinkAMBR, out.uplinkBitrate)
		out.downlinkBitrate = effectiveDefaultBearerRate(downlinkAMBR, out.downlinkBitrate)
	}
	return out, 0, nil
}

func effectiveDefaultBearerRate(apnAMBR, bearerMBR uint64) uint64 {
	if apnAMBR == 0 {
		return bearerMBR
	}
	if bearerMBR == 0 || apnAMBR < bearerMBR {
		return apnAMBR
	}
	return bearerMBR
}

func parsePGWSessionResponse(response gtpv2.Message, expectedTEID uint32, expectedEBI uint8) (pgwSession, error) {
	if response.Header.TEID != expectedTEID {
		return pgwSession{}, fmt.Errorf("response TEID %d, expected %d", response.Header.TEID, expectedTEID)
	}
	controlIE, ok := response.Find(gtpv2.IEFTEID, 1)
	if !ok {
		return pgwSession{}, gtpv2.ErrMissingIE
	}
	control, err := controlIE.FTEID()
	if err != nil || control.InterfaceType != gtpv2.InterfaceS5S8PGWGTPC || !control.IPv4.Is4() {
		return pgwSession{}, errors.New("invalid PGW S5-C F-TEID")
	}
	bearerIE, ok := response.Find(gtpv2.IEBearerContext, 0)
	if !ok {
		return pgwSession{}, gtpv2.ErrMissingIE
	}
	children, err := bearerIE.Children()
	if err != nil {
		return pgwSession{}, err
	}
	causeIE, causeOK := gtpv2.FindIE(children, gtpv2.IECause, 0)
	ebiIE, ebiOK := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
	userIE, userOK := gtpv2.FindIE(children, gtpv2.IEFTEID, 2)
	if !causeOK || !ebiOK || !userOK {
		return pgwSession{}, gtpv2.ErrMissingIE
	}
	bearerCause, err := causeIE.Cause()
	if err != nil || bearerCause.Value != gtpv2.CauseRequestAccepted {
		return pgwSession{}, errors.New("default bearer was not accepted")
	}
	ebi, err := ebiIE.EBI()
	if err != nil || ebi != expectedEBI {
		return pgwSession{}, errors.New("PGW returned the wrong EBI")
	}
	user, err := userIE.FTEID()
	if err != nil || user.InterfaceType != gtpv2.InterfaceS5S8PGWGTPU || !user.IPv4.Is4() {
		return pgwSession{}, errors.New("invalid PGW S5-U F-TEID")
	}
	return pgwSession{control: control, user: user}, nil
}

func parseModifyBearers(request gtpv2.Message) ([]modifyBearerItem, error) {
	contexts := gtpv2.FindAllIEs(request.IEs, gtpv2.IEBearerContext, 0)
	if len(contexts) == 0 {
		return nil, gtpv2.ErrMissingIE
	}
	// TS 23.401 limits one UE to eleven EPS bearer identities (5 through 15).
	if len(contexts) > 11 {
		return nil, errors.New("too many Bearer Context IEs")
	}
	items := make([]modifyBearerItem, 0, len(contexts))
	seen := make(map[uint8]struct{}, len(contexts))
	for _, grouped := range contexts {
		item, err := parseModifyBearerContext(grouped)
		if err != nil {
			return items, err
		}
		if _, duplicate := seen[item.ebi]; duplicate {
			return append(items, item), fmt.Errorf("duplicate bearer EBI %d", item.ebi)
		}
		seen[item.ebi] = struct{}{}
		items = append(items, item)
	}
	return items, nil
}

func parseModifyBearerContext(grouped gtpv2.IE) (modifyBearerItem, error) {
	item := modifyBearerItem{grouped: grouped.Clone()}
	children, err := grouped.Children()
	if err != nil {
		return item, err
	}
	ebiIE, ebiOK := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
	enodebIE, enodebOK := gtpv2.FindIE(children, gtpv2.IEFTEID, 0)
	if !ebiOK || !enodebOK {
		return item, gtpv2.ErrMissingIE
	}
	item.ebi, err = ebiIE.EBI()
	if err != nil {
		return item, err
	}
	if item.ebi < 5 || item.ebi > 15 {
		return item, fmt.Errorf("invalid bearer EBI %d", item.ebi)
	}
	item.enodeb, err = enodebIE.FTEID()
	if err != nil || item.enodeb.InterfaceType != gtpv2.InterfaceS1UENodeBGTPU || item.enodeb.TEID == 0 ||
		!item.enodeb.IPv4.Is4() || item.enodeb.IPv4.IsUnspecified() || item.enodeb.IPv4.IsMulticast() {
		return item, errors.New("invalid eNodeB S1-U F-TEID")
	}
	item.enodeb.IPv4 = item.enodeb.IPv4.Unmap()
	return item, nil
}

func modifyBearerRequestForPGW(request gtpv2.Message, group modifyBearerGroup) (gtpv2.Message, error) {
	out := request.Clone()
	out.Header = gtpv2.Header{
		Version: gtpv2.Version, HasTEID: true,
		MessageType: gtpv2.MessageModifyBearerRequest, TEID: group.current.PGWControl.TEID,
	}
	out.IEs = gtpv2.RemoveIE(out.IEs, gtpv2.IEBearerContext, 0)
	for _, item := range group.items {
		bearer, exists := group.current.Bearers[item.ebi]
		if !exists {
			return gtpv2.Message{}, fmt.Errorf("bearer EBI %d disappeared", item.ebi)
		}
		sgwCore, err := gtpv2.NewFTEIDIE(1, gtpv2.FTEID{
			InterfaceType: gtpv2.InterfaceS5S8SGWGTPU,
			TEID:          bearer.SGWUCore.TEID,
			IPv4:          bearer.SGWUCore.IP,
		})
		if err != nil {
			return gtpv2.Message{}, err
		}
		children, err := item.grouped.Children()
		if err != nil {
			return gtpv2.Message{}, err
		}
		children = gtpv2.RemoveIE(children, gtpv2.IEFTEID, 0)
		children = gtpv2.UpsertIE(children, sgwCore)
		toPGWGroup, err := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, children...)
		if err != nil {
			return gtpv2.Message{}, err
		}
		out.IEs = append(out.IEs, toPGWGroup)
	}
	return out, nil
}

func modifyBearerResponseCause(response gtpv2.Message, expected []modifyBearerItem) (uint8, error) {
	topCause, err := messageCause(response)
	if err != nil || topCause != gtpv2.CauseRequestAccepted {
		return topCause, err
	}
	expectedEBIs := make(map[uint8]struct{}, len(expected))
	for _, item := range expected {
		expectedEBIs[item.ebi] = struct{}{}
	}
	seen := make(map[uint8]struct{}, len(expected))
	for _, grouped := range gtpv2.FindAllIEs(response.IEs, gtpv2.IEBearerContext, 0) {
		children, childErr := grouped.Children()
		if childErr != nil {
			return 0, childErr
		}
		ebiIE, hasEBI := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
		causeIE, hasCause := gtpv2.FindIE(children, gtpv2.IECause, 0)
		if !hasEBI || !hasCause {
			return 0, gtpv2.ErrMissingIE
		}
		ebi, parseErr := ebiIE.EBI()
		if parseErr != nil {
			return 0, parseErr
		}
		if _, wanted := expectedEBIs[ebi]; !wanted {
			return 0, fmt.Errorf("unexpected bearer EBI %d", ebi)
		}
		if _, duplicate := seen[ebi]; duplicate {
			return 0, fmt.Errorf("duplicate bearer EBI %d", ebi)
		}
		seen[ebi] = struct{}{}
		bearerCause, parseErr := causeIE.Cause()
		if parseErr != nil {
			return 0, parseErr
		}
		if bearerCause.Value != gtpv2.CauseRequestAccepted {
			return bearerCause.Value, nil
		}
	}
	return gtpv2.CauseRequestAccepted, nil
}

func parseDeleteSessionEBI(request gtpv2.Message) (uint8, bool, error) {
	ie, ok := request.Find(gtpv2.IEEBI, 0)
	if !ok {
		return 0, false, nil
	}
	ebi, err := ie.EBI()
	if err != nil {
		return 0, true, err
	}
	return ebi, true, nil
}

func (g *Gateway) createResponseForMME(response gtpv2.Message, current session.Session, ebi uint8) (*gtpv2.Message, error) {
	out := response.Clone()
	out.Header = gtpv2.Header{
		Version: gtpv2.Version, HasTEID: true,
		MessageType: gtpv2.MessageCreateSessionResponse, TEID: current.MMEControl.TEID,
	}
	sgwS11, err := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS11SGWGTPC, TEID: current.S11Control.TEID, IPv4: current.S11Control.IP,
	})
	if err != nil {
		return nil, err
	}
	out.IEs = gtpv2.UpsertIE(out.IEs, sgwS11)
	bearerIE, ok := out.Find(gtpv2.IEBearerContext, 0)
	if !ok {
		return nil, gtpv2.ErrMissingIE
	}
	children, err := bearerIE.Children()
	if err != nil {
		return nil, err
	}
	bearer := current.Bearers[ebi]
	sgwS1, err := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS1USGWGTPU, TEID: bearer.SGWUAccess.TEID, IPv4: bearer.SGWUAccess.IP,
	})
	if err != nil {
		return nil, err
	}
	children = gtpv2.UpsertIE(children, sgwS1)
	grouped, err := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, children...)
	if err != nil {
		return nil, err
	}
	out.IEs = gtpv2.UpsertIE(out.IEs, grouped)
	return &out, nil
}

func messageCause(message gtpv2.Message) (uint8, error) {
	ie, ok := message.Find(gtpv2.IECause, 0)
	if !ok {
		return 0, gtpv2.ErrMissingIE
	}
	cause, err := ie.Cause()
	if err != nil {
		return 0, err
	}
	return cause.Value, nil
}

func successResponse(messageType uint8, teid uint32, ebi uint8) *gtpv2.Message {
	return failureResponse(messageType, teid, gtpv2.CauseRequestAccepted, ebi)
}

func failureResponse(messageType uint8, teid uint32, cause uint8, ebi uint8) *gtpv2.Message {
	ies := []gtpv2.IE{gtpv2.NewCauseIE(cause, 0)}
	if ebi >= 5 && ebi <= 15 && (messageType == gtpv2.MessageCreateSessionResponse || messageType == gtpv2.MessageModifyBearerResponse) {
		ebiIE, _ := gtpv2.NewEBIIE(ebi, 0)
		grouped, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, gtpv2.NewCauseIE(cause, 0))
		ies = append(ies, grouped)
	}
	return &gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: messageType, TEID: teid},
		IEs:    ies,
	}
}

func modifyBearerResponse(teid uint32, cause uint8, items []modifyBearerItem) *gtpv2.Message {
	ies := make([]gtpv2.IE, 0, len(items)+1)
	ies = append(ies, gtpv2.NewCauseIE(cause, 0))
	seen := make(map[uint8]struct{}, len(items))
	for _, item := range items {
		if item.ebi < 5 || item.ebi > 15 {
			continue
		}
		if _, duplicate := seen[item.ebi]; duplicate {
			continue
		}
		seen[item.ebi] = struct{}{}
		ebiIE, err := gtpv2.NewEBIIE(item.ebi, 0)
		if err != nil {
			continue
		}
		grouped, err := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, gtpv2.NewCauseIE(cause, 0))
		if err == nil {
			ies = append(ies, grouped)
		}
	}
	return &gtpv2.Message{
		Header: gtpv2.Header{
			Version: gtpv2.Version, HasTEID: true,
			MessageType: gtpv2.MessageModifyBearerResponse, TEID: teid,
		},
		IEs: ies,
	}
}

func relayResponse(response gtpv2.Message, messageType uint8, teid uint32) *gtpv2.Message {
	out := response.Clone()
	out.Header = gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: messageType, TEID: teid}
	return &out
}

func transportCause(err error) uint8 {
	if errors.Is(err, gtptransport.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
		return gtpv2.CauseRemotePeerNotResponding
	}
	return gtpv2.CauseSystemFailure
}

func (g *Gateway) findOwner(subscriber, apn string) bool {
	_, exists := g.store.FindByOwner(subscriber, apn)
	return exists
}

func (g *Gateway) createResourceFailure(peer netip.AddrPort, parsed createRequest, err error) *gtpv2.Message {
	g.reject("create-session", peer, "identifier allocation failed: "+err.Error())
	return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.mmeControl.TEID, gtpv2.CauseNoResourcesAvailable, parsed.ebi)
}

func (g *Gateway) rollbackDownlink(parent context.Context, userSession *pfcpclient.Session) {
	opCtx, cancel := g.operationContext(parent)
	_ = g.up.DeactivateDownlink(opCtx, userSession)
	cancel()
}

func (g *Gateway) rollbackModifyBearerActivations(parent context.Context, activations []modifyBearerActivation) {
	rollbackParent := context.WithoutCancel(parent)
	for index := len(activations) - 1; index >= 0; index-- {
		activation := activations[index]
		userSession := pfcpSession(activation.current)
		rules := pfcpRules(activation.bearer)
		opCtx, cancel := g.operationContext(rollbackParent)
		var err error
		if activation.bearer.State == session.BearerActive && activation.bearer.ENBUser.TEID != 0 && activation.bearer.ENBUser.IP.Is4() {
			err = g.up.ActivateBearer(opCtx, &userSession, rules, pfcpclient.Tunnel{
				TEID: activation.bearer.ENBUser.TEID,
				IP:   activation.bearer.ENBUser.IP,
			})
		} else {
			err = g.up.DeactivateBearer(opCtx, &userSession, rules)
		}
		cancel()
		if err != nil {
			g.emit(Event{
				Severity: "error", Procedure: "modify-bearer", Subscriber: activation.current.SubscriberKey,
				Message: fmt.Sprintf("rollback could not restore EBI %d: %v", activation.bearer.EBI, err),
			})
		}
	}
}

func (g *Gateway) rollbackModifyBearerState(committed []modifyBearerCommit) {
	for index := len(committed) - 1; index >= 0; index-- {
		commit := committed[index]
		_, err := g.store.Update(commit.updated.ID, commit.updated.Revision, func(candidate *session.Session) error {
			candidate.State = commit.previous.State
			candidate.Bearers = make(map[uint8]session.Bearer, len(commit.previous.Bearers))
			for ebi, bearer := range commit.previous.Bearers {
				candidate.Bearers[ebi] = bearer
			}
			return nil
		})
		if err != nil {
			g.emit(Event{
				Severity: "error", Procedure: "modify-bearer", Subscriber: commit.previous.SubscriberKey,
				Message: "rollback could not restore durable PDN state: " + err.Error(),
			})
		}
	}
}

func (g *Gateway) reactivateDownlinks(parent context.Context, previous []session.Session) {
	for _, prior := range previous {
		userSession := pfcpSession(prior)
		restored := true
		for _, bearer := range prior.Bearers {
			if bearer.ENBUser.TEID == 0 || !bearer.ENBUser.IP.Is4() {
				continue
			}
			opCtx, cancel := g.operationContext(parent)
			err := g.up.ActivateBearer(opCtx, &userSession, pfcpRules(bearer), pfcpclient.Tunnel{TEID: bearer.ENBUser.TEID, IP: bearer.ENBUser.IP})
			cancel()
			if err != nil {
				restored = false
				g.emit(Event{Severity: "error", Procedure: "release-access-bearers", Subscriber: prior.SubscriberKey, Message: "rollback could not reactivate an access tunnel: " + err.Error()})
			}
		}
		if !restored {
			continue
		}
		unlock := g.locks.lock(prior.ID)
		latest, ok := g.store.Find(prior.ID)
		if ok && latest.State != prior.State {
			_, _ = g.store.Update(latest.ID, latest.Revision, func(candidate *session.Session) error {
				candidate.State = prior.State
				for ebi, oldBearer := range prior.Bearers {
					candidate.Bearers[ebi] = oldBearer
				}
				return nil
			})
		}
		unlock()
	}
}

func (g *Gateway) bestEffortDeletePGW(parent context.Context, peer netip.AddrPort, pgwControl gtpv2.FTEID, ebi uint8) {
	ebiIE, _ := gtpv2.NewEBIIE(ebi, 0)
	request := gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteSessionRequest, TEID: pgwControl.TEID},
		IEs:    []gtpv2.IE{ebiIE},
	}
	g.stampRecovery(&request)
	opCtx, cancel := g.operationContext(parent)
	_, _ = g.doS5(opCtx, peer, request)
	cancel()
}

func (g *Gateway) reject(procedure string, peer netip.AddrPort, message string) {
	g.counters.rejected.Add(1)
	switch procedure {
	case "create-session":
		g.counters.createRejected.Add(1)
	case "modify-bearer":
		g.counters.modifyRejected.Add(1)
	case "release-access-bearers":
		g.counters.releaseRejected.Add(1)
	case "delete-session":
		g.counters.deleteRejected.Add(1)
	case "create-bearer":
		g.counters.createBearerRejected.Add(1)
	case "update-bearer":
		g.counters.updateBearerRejected.Add(1)
	case "delete-bearer":
		g.counters.deleteBearerRejected.Add(1)
	}
	g.emit(Event{Severity: "error", Procedure: procedure, Peer: peer, Message: message})
}
