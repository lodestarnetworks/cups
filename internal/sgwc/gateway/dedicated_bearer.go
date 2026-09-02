package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/lodestarnetworks/cups/internal/sgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/sgwc/session"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

type createBearerRequest struct {
	linkedEBI    uint8
	requestedEBI uint8
	contextIE    gtpv2.IE
	pgwUser      gtpv2.FTEID
	qos          gtpv2.BearerQoS
}

func (g *Gateway) createBearer(parent context.Context, peer netip.AddrPort, request gtpv2.Message) *gtpv2.Message {
	current, responseTEID, ok := g.s5Session(request)
	if !ok {
		g.reject("create-bearer", peer, "unknown or malformed S5-C tunnel")
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, responseTEID, gtpv2.CauseContextNotFound, 0)
	}
	parsed, cause, err := parseCreateBearerRequest(request)
	if err != nil {
		g.reject("create-bearer", peer, "invalid PGW request: "+err.Error())
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, responseTEID, cause, parsed.requestedEBI)
	}
	defaultEPSBearer := defaultBearer(current)
	if !defaultEPSBearer.Default || parsed.linkedEBI != defaultEPSBearer.EBI {
		g.reject("create-bearer", peer, "linked EBI does not identify this PDN's default bearer")
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, responseTEID, gtpv2.CauseContextNotFound, parsed.requestedEBI)
	}

	unlockSubscriber := g.subscriberLocks.lock(subscriberLockKey(current.SubscriberKey))
	defer unlockSubscriber()
	unlocks := g.locks.lock(current.ID)
	defer unlocks()
	current, found := g.store.FindByS5TEID(request.Header.TEID)
	if !found {
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, responseTEID, gtpv2.CauseContextNotFound, parsed.requestedEBI)
	}
	if parsed.requestedEBI != 0 {
		if _, exists := current.Bearers[parsed.requestedEBI]; exists || g.ebiUsedOnS11(current.S11Control.TEID, parsed.requestedEBI, current.ID) {
			g.reject("create-bearer", peer, "requested EBI is already in use")
			return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, current.PGWControl.TEID, gtpv2.CauseNoResourcesAvailable, parsed.requestedEBI)
		}
	}

	accessTEID, err := g.ids.allocateTEID()
	if err != nil {
		g.reject("create-bearer", peer, "S1-U TEID allocation failed: "+err.Error())
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, current.PGWControl.TEID, gtpv2.CauseNoResourcesAvailable, parsed.requestedEBI)
	}
	coreTEID, err := g.ids.allocateTEID()
	if err != nil {
		g.ids.releaseTEIDs(accessTEID)
		g.reject("create-bearer", peer, "S5-U TEID allocation failed: "+err.Error())
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, current.PGWControl.TEID, gtpv2.CauseNoResourcesAvailable, parsed.requestedEBI)
	}
	committed := false
	defer func() {
		if !committed {
			g.ids.releaseTEIDs(accessTEID, coreTEID)
		}
	}()

	rules, err := allocateBearerRuleIDs(current)
	if err != nil {
		g.reject("create-bearer", peer, "PFCP rule allocation failed: "+err.Error())
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, current.PGWControl.TEID, gtpv2.CauseNoResourcesAvailable, parsed.requestedEBI)
	}
	userSession := pfcpSession(current)
	plan := pfcpclient.BearerPlan{
		Rules:           rules,
		AccessLocal:     pfcpclient.Tunnel{TEID: accessTEID, IP: g.config.SGWUAccessIP},
		CoreLocal:       pfcpclient.Tunnel{TEID: coreTEID, IP: g.config.SGWUCoreIP},
		CoreRemote:      pfcpclient.Tunnel{TEID: parsed.pgwUser.TEID, IP: parsed.pgwUser.IPv4},
		UplinkBitrate:   parsed.qos.UplinkMBR,
		DownlinkBitrate: parsed.qos.DownlinkMBR,
		QCI:             parsed.qos.QCI, ARP: parsed.qos.Priority,
		PreemptionCapable: parsed.qos.PreemptionCapable, PreemptionVulnerable: parsed.qos.PreemptionVulnerable,
	}
	opCtx, cancel := g.operationContext(parent)
	err = g.up.AddBearer(opCtx, &userSession, plan)
	cancel()
	if err != nil {
		g.reject("create-bearer", peer, "SGW-U rejected provisional bearer rules: "+err.Error())
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, current.PGWControl.TEID, gtpv2.CauseSystemFailure, parsed.requestedEBI)
	}
	provisional := true
	defer func() {
		if provisional {
			g.removeBearerRules(parent, current, rules, "create-bearer rollback")
		}
	}()

	toMME, err := g.createBearerForMME(request, current, parsed.contextIE, accessTEID)
	if err != nil {
		g.reject("create-bearer", peer, "could not build S11 request: "+err.Error())
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, current.PGWControl.TEID, gtpv2.CauseSystemFailure, parsed.requestedEBI)
	}
	g.stampRecovery(&toMME)
	mmePeer := netip.AddrPortFrom(current.MMEControl.IP.Unmap(), gtpControlPort)
	opCtx, cancel = g.operationContext(parent)
	mmeResponse, err := g.s11.Do(opCtx, mmePeer, toMME)
	cancel()
	if err != nil {
		g.reject("create-bearer", peer, "MME transaction failed: "+err.Error())
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, current.PGWControl.TEID, transportCause(err), parsed.requestedEBI)
	}
	if _, err := g.acceptMMEResponseTEID(mmeResponse, current, "create-bearer", mmePeer); err != nil {
		g.reject("create-bearer", peer, err.Error())
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, current.PGWControl.TEID, gtpv2.CauseInvalidReplyFromPeer, parsed.requestedEBI)
	}
	topCause, err := messageCause(mmeResponse)
	if err != nil {
		g.reject("create-bearer", peer, "MME response omitted a valid Cause")
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, current.PGWControl.TEID, gtpv2.CauseInvalidReplyFromPeer, parsed.requestedEBI)
	}
	if topCause != gtpv2.CauseRequestAccepted {
		g.reject("create-bearer", peer, fmt.Sprintf("MME rejected bearer with cause %d", topCause))
		return relayResponse(mmeResponse, gtpv2.MessageCreateBearerResponse, current.PGWControl.TEID)
	}
	assignedEBI, enodeb, err := parseMMECreateBearerResponse(mmeResponse, parsed.requestedEBI)
	if err != nil {
		g.reject("create-bearer", peer, "invalid accepted MME response: "+err.Error())
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, current.PGWControl.TEID, gtpv2.CauseInvalidReplyFromPeer, parsed.requestedEBI)
	}
	if _, exists := current.Bearers[assignedEBI]; exists || g.ebiUsedOnS11(current.S11Control.TEID, assignedEBI, current.ID) {
		g.bestEffortDeleteBearerFromMME(parent, current, assignedEBI)
		g.reject("create-bearer", peer, "MME assigned an EBI already used on this S11 context")
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, current.PGWControl.TEID, gtpv2.CauseNoResourcesAvailable, assignedEBI)
	}

	response, err := createBearerForPGW(mmeResponse, current.PGWControl.TEID, coreTEID, g.config.SGWUCoreIP, parsed.pgwUser)
	if err != nil {
		g.bestEffortDeleteBearerFromMME(parent, current, assignedEBI)
		g.reject("create-bearer", peer, "could not build S5-C response: "+err.Error())
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, current.PGWControl.TEID, gtpv2.CauseSystemFailure, assignedEBI)
	}
	opCtx, cancel = g.operationContext(parent)
	err = g.up.ActivateBearer(opCtx, &userSession, rules, pfcpclient.Tunnel{TEID: enodeb.TEID, IP: enodeb.IPv4})
	cancel()
	if err != nil {
		g.bestEffortDeleteBearerFromMME(parent, current, assignedEBI)
		g.reject("create-bearer", peer, "SGW-U downlink activation failed: "+err.Error())
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, current.PGWControl.TEID, gtpv2.CauseSystemFailure, assignedEBI)
	}

	updated, err := g.store.Update(current.ID, current.Revision, func(candidate *session.Session) error {
		candidate.Bearers[assignedEBI] = session.Bearer{
			EBI: assignedEBI, QCI: parsed.qos.QCI, ARP: parsed.qos.Priority,
			PreemptionCapable: parsed.qos.PreemptionCapable, PreemptionVulnerable: parsed.qos.PreemptionVulnerable,
			UplinkMBR: parsed.qos.UplinkMBR, DownlinkMBR: parsed.qos.DownlinkMBR,
			UplinkGBR: parsed.qos.UplinkGBR, DownlinkGBR: parsed.qos.DownlinkGBR,
			State:      session.BearerActive,
			ENBUser:    session.FTEID{TEID: enodeb.TEID, IP: enodeb.IPv4},
			SGWUAccess: session.FTEID{TEID: accessTEID, IP: g.config.SGWUAccessIP},
			SGWUCore:   session.FTEID{TEID: coreTEID, IP: g.config.SGWUCoreIP},
			PGWUser:    session.FTEID{TEID: parsed.pgwUser.TEID, IP: parsed.pgwUser.IPv4},
			Rules:      sessionRules(rules),
		}
		candidate.State = session.StateActive
		return nil
	})
	if err != nil {
		g.bestEffortDeleteBearerFromMME(parent, current, assignedEBI)
		g.reject("create-bearer", peer, "local bearer commit failed: "+err.Error())
		return bearerFailureResponse(gtpv2.MessageCreateBearerResponse, current.PGWControl.TEID, gtpv2.CauseSystemFailure, assignedEBI)
	}

	committed = true
	provisional = false
	g.counters.createBearerAccepted.Add(1)
	g.emit(Event{Severity: "info", Procedure: "create-bearer", Peer: peer, Subscriber: updated.SubscriberKey, Message: fmt.Sprintf("dedicated bearer EBI %d activated", assignedEBI)})
	return response
}

func (g *Gateway) updateBearer(parent context.Context, peer netip.AddrPort, request gtpv2.Message) *gtpv2.Message {
	current, responseTEID, ok := g.s5Session(request)
	if !ok {
		g.reject("update-bearer", peer, "unknown or malformed S5-C tunnel")
		return bearerFailureResponse(gtpv2.MessageUpdateBearerResponse, responseTEID, gtpv2.CauseContextNotFound, 0)
	}
	ebi, qos, hasQoS, err := parseUpdateBearerRequest(request)
	if err != nil {
		g.reject("update-bearer", peer, "invalid PGW request: "+err.Error())
		return bearerFailureResponse(gtpv2.MessageUpdateBearerResponse, responseTEID, gtpv2.CauseMandatoryIEIncorrect, ebi)
	}
	unlocks := g.subscriberLocks.lock(subscriberLockKey(current.SubscriberKey))
	defer unlocks()
	unlock := g.locks.lock(current.ID)
	defer unlock()
	current, ok = g.store.FindByS5TEID(request.Header.TEID)
	if !ok {
		return bearerFailureResponse(gtpv2.MessageUpdateBearerResponse, responseTEID, gtpv2.CauseContextNotFound, ebi)
	}
	bearer, ok := current.Bearers[ebi]
	if !ok {
		g.reject("update-bearer", peer, "bearer EBI does not exist")
		return bearerFailureResponse(gtpv2.MessageUpdateBearerResponse, current.PGWControl.TEID, gtpv2.CauseContextNotFound, ebi)
	}
	userSession := pfcpSession(current)
	rules := pfcpRules(bearer)
	qosUpdated := false
	if hasQoS {
		opCtx, cancel := g.operationContext(parent)
		err = g.up.UpdateBearerQoS(opCtx, &userSession, rules, qos.QCI, qos.Priority, qos.PreemptionCapable, qos.PreemptionVulnerable, qos.UplinkMBR, qos.DownlinkMBR)
		cancel()
		if err != nil {
			g.reject("update-bearer", peer, "SGW-U QoS update failed: "+err.Error())
			return bearerFailureResponse(gtpv2.MessageUpdateBearerResponse, current.PGWControl.TEID, gtpv2.CauseSystemFailure, ebi)
		}
		qosUpdated = true
	}
	rollbackQoS := func() {
		if !qosUpdated {
			return
		}
		opCtx, cancel := g.operationContext(parent)
		_ = g.up.UpdateBearerQoS(opCtx, &userSession, rules, bearer.QCI, bearer.ARP, bearer.PreemptionCapable, bearer.PreemptionVulnerable, bearer.UplinkMBR, bearer.DownlinkMBR)
		cancel()
	}
	toMME := request.Clone()
	toMME.Header = gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageUpdateBearerRequest, TEID: current.MMEControl.TEID}
	g.stampRecovery(&toMME)
	mmePeer := netip.AddrPortFrom(current.MMEControl.IP.Unmap(), gtpControlPort)
	opCtx, cancel := g.operationContext(parent)
	mmeResponse, err := g.s11.Do(opCtx, mmePeer, toMME)
	cancel()
	if err != nil {
		rollbackQoS()
		g.reject("update-bearer", peer, "MME transaction failed: "+err.Error())
		return bearerFailureResponse(gtpv2.MessageUpdateBearerResponse, current.PGWControl.TEID, transportCause(err), ebi)
	}
	if _, err := g.acceptMMEResponseTEID(mmeResponse, current, "update-bearer", mmePeer); err != nil {
		rollbackQoS()
		g.reject("update-bearer", peer, err.Error())
		return bearerFailureResponse(gtpv2.MessageUpdateBearerResponse, current.PGWControl.TEID, gtpv2.CauseInvalidReplyFromPeer, ebi)
	}
	cause, err := messageCause(mmeResponse)
	if err != nil {
		rollbackQoS()
		return bearerFailureResponse(gtpv2.MessageUpdateBearerResponse, current.PGWControl.TEID, gtpv2.CauseInvalidReplyFromPeer, ebi)
	}
	if cause != gtpv2.CauseRequestAccepted {
		rollbackQoS()
		g.reject("update-bearer", peer, fmt.Sprintf("MME rejected bearer update with cause %d", cause))
		return relayResponse(mmeResponse, gtpv2.MessageUpdateBearerResponse, current.PGWControl.TEID)
	}
	if hasQoS {
		_, err = g.store.Update(current.ID, current.Revision, func(candidate *session.Session) error {
			updatedBearer := candidate.Bearers[ebi]
			updatedBearer.QCI, updatedBearer.ARP = qos.QCI, qos.Priority
			updatedBearer.PreemptionCapable, updatedBearer.PreemptionVulnerable = qos.PreemptionCapable, qos.PreemptionVulnerable
			updatedBearer.UplinkMBR, updatedBearer.DownlinkMBR = qos.UplinkMBR, qos.DownlinkMBR
			updatedBearer.UplinkGBR, updatedBearer.DownlinkGBR = qos.UplinkGBR, qos.DownlinkGBR
			candidate.Bearers[ebi] = updatedBearer
			return nil
		})
		if err != nil {
			rollbackQoS()
			g.reject("update-bearer", peer, "local QoS commit failed: "+err.Error())
			return bearerFailureResponse(gtpv2.MessageUpdateBearerResponse, current.PGWControl.TEID, gtpv2.CauseSystemFailure, ebi)
		}
	}
	g.counters.updateBearerAccepted.Add(1)
	g.emit(Event{Severity: "info", Procedure: "update-bearer", Peer: peer, Subscriber: current.SubscriberKey, Message: fmt.Sprintf("bearer EBI %d updated", ebi)})
	return relayResponse(mmeResponse, gtpv2.MessageUpdateBearerResponse, current.PGWControl.TEID)
}

func (g *Gateway) deleteBearer(parent context.Context, peer netip.AddrPort, request gtpv2.Message) *gtpv2.Message {
	current, responseTEID, ok := g.s5Session(request)
	if !ok {
		g.reject("delete-bearer", peer, "unknown or malformed S5-C tunnel")
		return bearerFailureResponse(gtpv2.MessageDeleteBearerResponse, responseTEID, gtpv2.CauseContextNotFound, 0)
	}
	ebi, dedicated, err := parseDeleteBearerRequest(request)
	if err != nil {
		g.reject("delete-bearer", peer, "invalid PGW request: "+err.Error())
		return bearerFailureResponse(gtpv2.MessageDeleteBearerResponse, responseTEID, gtpv2.CauseMandatoryIEIncorrect, ebi)
	}
	unlockSubscriber := g.subscriberLocks.lock(subscriberLockKey(current.SubscriberKey))
	defer unlockSubscriber()
	unlock := g.locks.lock(current.ID)
	defer unlock()
	current, ok = g.store.FindByS5TEID(request.Header.TEID)
	if !ok {
		return bearerFailureResponse(gtpv2.MessageDeleteBearerResponse, responseTEID, gtpv2.CauseContextNotFound, ebi)
	}
	bearer, ok := current.Bearers[ebi]
	if !ok || dedicated && bearer.Default || !dedicated && !bearer.Default {
		g.reject("delete-bearer", peer, "bearer does not match the requested deletion scope")
		return bearerFailureResponse(gtpv2.MessageDeleteBearerResponse, current.PGWControl.TEID, gtpv2.CauseContextNotFound, ebi)
	}

	userSession := pfcpSession(current)
	rules := pfcpRules(bearer)
	removed := false
	if dedicated {
		opCtx, cancel := g.operationContext(parent)
		err = g.up.RemoveBearer(opCtx, &userSession, rules)
		cancel()
		if err != nil {
			g.reject("delete-bearer", peer, "SGW-U bearer removal failed: "+err.Error())
			return bearerFailureResponse(gtpv2.MessageDeleteBearerResponse, current.PGWControl.TEID, gtpv2.CauseSystemFailure, ebi)
		}
		removed = true
	}
	rollback := func() {
		if removed {
			g.restoreBearerRules(parent, current, bearer)
		}
	}
	toMME := request.Clone()
	toMME.Header = gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteBearerRequest, TEID: current.MMEControl.TEID}
	g.stampRecovery(&toMME)
	mmePeer := netip.AddrPortFrom(current.MMEControl.IP.Unmap(), gtpControlPort)
	opCtx, cancel := g.operationContext(parent)
	mmeResponse, err := g.s11.Do(opCtx, mmePeer, toMME)
	cancel()
	if err != nil {
		rollback()
		g.reject("delete-bearer", peer, "MME transaction failed: "+err.Error())
		return bearerFailureResponse(gtpv2.MessageDeleteBearerResponse, current.PGWControl.TEID, transportCause(err), ebi)
	}
	if _, err := g.acceptMMEResponseTEID(mmeResponse, current, "delete-bearer", mmePeer); err != nil {
		rollback()
		g.reject("delete-bearer", peer, err.Error())
		return bearerFailureResponse(gtpv2.MessageDeleteBearerResponse, current.PGWControl.TEID, gtpv2.CauseInvalidReplyFromPeer, ebi)
	}
	cause, err := messageCause(mmeResponse)
	if err != nil {
		rollback()
		return bearerFailureResponse(gtpv2.MessageDeleteBearerResponse, current.PGWControl.TEID, gtpv2.CauseInvalidReplyFromPeer, ebi)
	}
	if cause != gtpv2.CauseRequestAccepted {
		rollback()
		g.reject("delete-bearer", peer, fmt.Sprintf("MME rejected bearer deletion with cause %d", cause))
		return relayResponse(mmeResponse, gtpv2.MessageDeleteBearerResponse, current.PGWControl.TEID)
	}
	if dedicated {
		_, err = g.store.Update(current.ID, current.Revision, func(candidate *session.Session) error {
			delete(candidate.Bearers, ebi)
			return nil
		})
		if err != nil {
			rollback()
			g.reject("delete-bearer", peer, "local bearer deletion failed: "+err.Error())
			return bearerFailureResponse(gtpv2.MessageDeleteBearerResponse, current.PGWControl.TEID, gtpv2.CauseSystemFailure, ebi)
		}
		g.paging.cancel(current.ID, ebi)
		g.ids.releaseTEIDs(bearer.SGWUAccess.TEID, bearer.SGWUCore.TEID)
	} else {
		opCtx, cancel = g.operationContext(parent)
		err = g.up.Delete(opCtx, userSession)
		cancel()
		if err != nil {
			g.reject("delete-bearer", peer, "SGW-U session deletion failed: "+err.Error())
			return bearerFailureResponse(gtpv2.MessageDeleteBearerResponse, current.PGWControl.TEID, gtpv2.CauseSystemFailure, ebi)
		}
		if err := g.store.Delete(current.ID, current.Revision); err != nil {
			g.reject("delete-bearer", peer, "local PDN deletion failed: "+err.Error())
			return bearerFailureResponse(gtpv2.MessageDeleteBearerResponse, current.PGWControl.TEID, gtpv2.CauseSystemFailure, ebi)
		}
		g.paging.purgeSession(current.ID)
		g.releaseIDs(current)
	}
	g.counters.deleteBearerAccepted.Add(1)
	g.emit(Event{Severity: "info", Procedure: "delete-bearer", Peer: peer, Subscriber: current.SubscriberKey, Message: fmt.Sprintf("bearer EBI %d deleted", ebi)})
	return relayResponse(mmeResponse, gtpv2.MessageDeleteBearerResponse, current.PGWControl.TEID)
}

func parseCreateBearerRequest(request gtpv2.Message) (createBearerRequest, uint8, error) {
	var out createBearerRequest
	linkedIE, ok := request.Find(gtpv2.IEEBI, 0)
	if !ok {
		return out, gtpv2.CauseMandatoryIEMissing, gtpv2.ErrMissingIE
	}
	var err error
	out.linkedEBI, err = linkedIE.EBI()
	if err != nil {
		return out, gtpv2.CauseMandatoryIEIncorrect, err
	}
	contexts := gtpv2.FindAllIEs(request.IEs, gtpv2.IEBearerContext, 0)
	if len(contexts) != 1 {
		return out, gtpv2.CauseServiceNotSupported, fmt.Errorf("exactly one bearer context is supported per transaction, got %d", len(contexts))
	}
	out.contextIE = contexts[0]
	children, err := out.contextIE.Children()
	if err != nil {
		return out, gtpv2.CauseMandatoryIEIncorrect, err
	}
	ebiIE, ebiOK := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
	userIE, userOK := gtpv2.FindIE(children, gtpv2.IEFTEID, 1)
	qosIE, qosOK := gtpv2.FindIE(children, gtpv2.IEBearerQoS, 0)
	tftIE, tftOK := gtpv2.FindIE(children, gtpv2.IEBearerTFT, 0)
	if !ebiOK || !userOK || !qosOK || !tftOK {
		return out, gtpv2.CauseMandatoryIEMissing, gtpv2.ErrMissingIE
	}
	if _, err := tftIE.BearerTFT(); err != nil {
		return out, gtpv2.CauseMandatoryIEIncorrect, fmt.Errorf("invalid Bearer TFT: %w", err)
	}
	out.requestedEBI, err = ebiIE.EBIOrZero()
	if err != nil {
		return out, gtpv2.CauseMandatoryIEIncorrect, err
	}
	out.pgwUser, err = userIE.FTEID()
	if err != nil || out.pgwUser.InterfaceType != gtpv2.InterfaceS5S8PGWGTPU || !out.pgwUser.IPv4.Is4() {
		return out, gtpv2.CauseMandatoryIEIncorrect, errors.New("invalid PGW S5-U F-TEID")
	}
	out.qos, err = qosIE.BearerQoSDetails()
	if err != nil {
		return out, gtpv2.CauseMandatoryIEIncorrect, err
	}
	return out, 0, nil
}

func parseMMECreateBearerResponse(response gtpv2.Message, requestedEBI uint8) (uint8, gtpv2.FTEID, error) {
	contexts := gtpv2.FindAllIEs(response.IEs, gtpv2.IEBearerContext, 0)
	if len(contexts) != 1 {
		return 0, gtpv2.FTEID{}, fmt.Errorf("bearer context count %d", len(contexts))
	}
	children, err := contexts[0].Children()
	if err != nil {
		return 0, gtpv2.FTEID{}, err
	}
	ebiIE, ebiOK := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
	causeIE, causeOK := gtpv2.FindIE(children, gtpv2.IECause, 0)
	enodebIE, enodebOK := gtpv2.FindIE(children, gtpv2.IEFTEID, 0)
	if !ebiOK || !causeOK || !enodebOK {
		return 0, gtpv2.FTEID{}, gtpv2.ErrMissingIE
	}
	ebi, err := ebiIE.EBI()
	if err != nil || requestedEBI != 0 && ebi != requestedEBI {
		return 0, gtpv2.FTEID{}, errors.New("MME returned an invalid EBI")
	}
	cause, err := causeIE.Cause()
	if err != nil || cause.Value != gtpv2.CauseRequestAccepted {
		return 0, gtpv2.FTEID{}, errors.New("MME did not accept the bearer context")
	}
	enodeb, err := enodebIE.FTEID()
	if err != nil || enodeb.InterfaceType != gtpv2.InterfaceS1UENodeBGTPU || !enodeb.IPv4.Is4() {
		return 0, gtpv2.FTEID{}, errors.New("invalid eNodeB S1-U F-TEID")
	}
	return ebi, enodeb, nil
}

func parseUpdateBearerRequest(request gtpv2.Message) (uint8, gtpv2.BearerQoS, bool, error) {
	contexts := gtpv2.FindAllIEs(request.IEs, gtpv2.IEBearerContext, 0)
	if len(contexts) != 1 {
		return 0, gtpv2.BearerQoS{}, false, fmt.Errorf("exactly one bearer context is supported per transaction, got %d", len(contexts))
	}
	children, err := contexts[0].Children()
	if err != nil {
		return 0, gtpv2.BearerQoS{}, false, err
	}
	ebiIE, ok := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
	if !ok {
		return 0, gtpv2.BearerQoS{}, false, gtpv2.ErrMissingIE
	}
	ebi, err := ebiIE.EBI()
	if err != nil {
		return 0, gtpv2.BearerQoS{}, false, err
	}
	qosIE, ok := gtpv2.FindIE(children, gtpv2.IEBearerQoS, 0)
	if !ok {
		return ebi, gtpv2.BearerQoS{}, false, nil
	}
	qos, err := qosIE.BearerQoSDetails()
	return ebi, qos, true, err
}

func parseDeleteBearerRequest(request gtpv2.Message) (uint8, bool, error) {
	linked, hasLinked := request.Find(gtpv2.IEEBI, 0)
	dedicated := gtpv2.FindAllIEs(request.IEs, gtpv2.IEEBI, 1)
	if hasLinked == (len(dedicated) > 0) || len(dedicated) > 1 {
		return 0, false, errors.New("request must identify exactly one default or dedicated bearer")
	}
	if hasLinked {
		ebi, err := linked.EBI()
		return ebi, false, err
	}
	ebi, err := dedicated[0].EBI()
	return ebi, true, err
}

func (g *Gateway) createBearerForMME(request gtpv2.Message, current session.Session, contextIE gtpv2.IE, accessTEID uint32) (gtpv2.Message, error) {
	children, err := contextIE.Children()
	if err != nil {
		return gtpv2.Message{}, err
	}
	sgwAccess, err := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{InterfaceType: gtpv2.InterfaceS1USGWGTPU, TEID: accessTEID, IPv4: g.config.SGWUAccessIP})
	if err != nil {
		return gtpv2.Message{}, err
	}
	children = gtpv2.UpsertIE(children, sgwAccess)
	grouped, err := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, children...)
	if err != nil {
		return gtpv2.Message{}, err
	}
	out := request.Clone()
	out.Header = gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateBearerRequest, TEID: current.MMEControl.TEID}
	out.IEs = gtpv2.RemoveIE(out.IEs, gtpv2.IEFTEID, 0)
	out.IEs = gtpv2.UpsertIE(out.IEs, grouped)
	return out, nil
}

func createBearerForPGW(response gtpv2.Message, pgwControlTEID, coreTEID uint32, coreIP netip.Addr, pgwUser gtpv2.FTEID) (*gtpv2.Message, error) {
	contextIE, ok := response.Find(gtpv2.IEBearerContext, 0)
	if !ok {
		return nil, gtpv2.ErrMissingIE
	}
	children, err := contextIE.Children()
	if err != nil {
		return nil, err
	}
	for instance := uint8(0); instance <= 3; instance++ {
		children = gtpv2.RemoveIE(children, gtpv2.IEFTEID, instance)
	}
	sgwCore, err := gtpv2.NewFTEIDIE(2, gtpv2.FTEID{InterfaceType: gtpv2.InterfaceS5S8SGWGTPU, TEID: coreTEID, IPv4: coreIP})
	if err != nil {
		return nil, err
	}
	pgwCore, err := gtpv2.NewFTEIDIE(3, pgwUser)
	if err != nil {
		return nil, err
	}
	children = append(children, sgwCore, pgwCore)
	grouped, err := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, children...)
	if err != nil {
		return nil, err
	}
	out := response.Clone()
	out.Header = gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateBearerResponse, TEID: pgwControlTEID}
	out.IEs = gtpv2.RemoveIE(out.IEs, gtpv2.IEFTEID, 0)
	out.IEs = gtpv2.UpsertIE(out.IEs, grouped)
	return &out, nil
}

func (g *Gateway) s5Session(request gtpv2.Message) (session.Session, uint32, bool) {
	if !request.Header.HasTEID || request.Header.TEID == 0 {
		return session.Session{}, 0, false
	}
	current, ok := g.store.FindByS5TEID(request.Header.TEID)
	if !ok {
		return session.Session{}, 0, false
	}
	return current, current.PGWControl.TEID, true
}

func allocateBearerRuleIDs(current session.Session) (pfcpclient.RuleIDs, error) {
	usedPDR := make(map[uint16]bool)
	usedFAR := make(map[uint32]bool)
	usedQER := make(map[uint32]bool)
	usedURR := make(map[uint32]bool)
	for _, bearer := range current.Bearers {
		usedPDR[bearer.Rules.UplinkPDR], usedPDR[bearer.Rules.DownlinkPDR] = true, true
		usedFAR[bearer.Rules.UplinkFAR], usedFAR[bearer.Rules.DownlinkFAR] = true, true
		usedQER[bearer.Rules.QER] = true
		usedURR[bearer.Rules.URR] = true
	}
	// LTE permits at most eleven simultaneous EPS bearers, so this bounded scan
	// leaves ample room while keeping IDs deterministic and operator-readable.
	for slot := uint32(1); slot <= 255; slot++ {
		candidate := pfcpclient.RuleIDs{
			UplinkPDR: uint16(slot*2 + 1), DownlinkPDR: uint16(slot*2 + 2),
			UplinkFAR: slot*2 + 1, DownlinkFAR: slot*2 + 2, QER: slot + 1, URR: slot + 1,
		}
		if !usedPDR[candidate.UplinkPDR] && !usedPDR[candidate.DownlinkPDR] &&
			!usedFAR[candidate.UplinkFAR] && !usedFAR[candidate.DownlinkFAR] && !usedQER[candidate.QER] && !usedURR[candidate.URR] {
			return candidate, nil
		}
	}
	return pfcpclient.RuleIDs{}, errors.New("no PFCP bearer rule slot available")
}

func sessionRules(rules pfcpclient.RuleIDs) session.RuleIDs {
	return session.RuleIDs{
		UplinkPDR: rules.UplinkPDR, DownlinkPDR: rules.DownlinkPDR,
		UplinkFAR: rules.UplinkFAR, DownlinkFAR: rules.DownlinkFAR, QER: rules.QER, URR: rules.URR,
	}
}

func pfcpRules(bearer session.Bearer) pfcpclient.RuleIDs {
	rules := pfcpclient.RuleIDs{
		UplinkPDR: bearer.Rules.UplinkPDR, DownlinkPDR: bearer.Rules.DownlinkPDR,
		UplinkFAR: bearer.Rules.UplinkFAR, DownlinkFAR: bearer.Rules.DownlinkFAR, QER: bearer.Rules.QER, URR: bearer.Rules.URR,
	}
	if rules.URR == 0 && rules.QER != 0 {
		// WAL records written before URR support remain replayable. Rule IDs
		// were already bearer-scoped, so using the QER ID is collision-free.
		rules.URR = rules.QER
	}
	if bearer.Default && rules == (pfcpclient.RuleIDs{}) {
		return pfcpclient.DefaultRuleIDs
	}
	return rules
}

func (g *Gateway) ebiUsedOnS11(s11TEID uint32, ebi uint8, exceptSession uint64) bool {
	for _, candidate := range g.store.FindAllByS11TEID(s11TEID) {
		if candidate.ID == exceptSession {
			continue
		}
		if _, exists := candidate.Bearers[ebi]; exists {
			return true
		}
	}
	return false
}

func (g *Gateway) removeBearerRules(parent context.Context, current session.Session, rules pfcpclient.RuleIDs, procedure string) {
	userSession := pfcpSession(current)
	opCtx, cancel := g.operationContext(parent)
	err := g.up.RemoveBearer(opCtx, &userSession, rules)
	cancel()
	if err != nil {
		g.emit(Event{Severity: "error", Procedure: procedure, Subscriber: current.SubscriberKey, Message: "could not remove provisional SGW-U rules: " + err.Error()})
	}
}

func (g *Gateway) restoreBearerRules(parent context.Context, current session.Session, bearer session.Bearer) {
	userSession := pfcpSession(current)
	rules := pfcpRules(bearer)
	plan := pfcpclient.BearerPlan{
		Rules:         rules,
		AccessLocal:   pfcpclient.Tunnel{TEID: bearer.SGWUAccess.TEID, IP: bearer.SGWUAccess.IP},
		CoreLocal:     pfcpclient.Tunnel{TEID: bearer.SGWUCore.TEID, IP: bearer.SGWUCore.IP},
		CoreRemote:    pfcpclient.Tunnel{TEID: bearer.PGWUser.TEID, IP: bearer.PGWUser.IP},
		UplinkBitrate: bearer.UplinkMBR, DownlinkBitrate: bearer.DownlinkMBR,
		QCI: bearer.QCI, ARP: bearer.ARP,
		PreemptionCapable: bearer.PreemptionCapable, PreemptionVulnerable: bearer.PreemptionVulnerable,
	}
	opCtx, cancel := g.operationContext(parent)
	err := g.up.AddBearer(opCtx, &userSession, plan)
	cancel()
	if err == nil && bearer.State == session.BearerActive && bearer.ENBUser.TEID != 0 {
		opCtx, cancel = g.operationContext(parent)
		err = g.up.ActivateBearer(opCtx, &userSession, rules, pfcpclient.Tunnel{TEID: bearer.ENBUser.TEID, IP: bearer.ENBUser.IP})
		cancel()
	} else if err == nil && bearer.State == session.BearerIdle {
		opCtx, cancel = g.operationContext(parent)
		err = g.up.DeactivateBearer(opCtx, &userSession, rules)
		cancel()
	}
	if err != nil {
		g.emit(Event{Severity: "error", Procedure: "delete-bearer-rollback", Subscriber: current.SubscriberKey, Message: "could not restore SGW-U bearer rules: " + err.Error()})
	}
}

func (g *Gateway) bestEffortDeleteBearerFromMME(parent context.Context, current session.Session, ebi uint8) {
	ebiIE, err := gtpv2.NewEBIIE(ebi, 1)
	if err != nil {
		return
	}
	request := gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteBearerRequest, TEID: current.MMEControl.TEID},
		IEs:    []gtpv2.IE{ebiIE},
	}
	g.stampRecovery(&request)
	opCtx, cancel := g.operationContext(parent)
	_, _ = g.s11.Do(opCtx, netip.AddrPortFrom(current.MMEControl.IP.Unmap(), gtpControlPort), request)
	cancel()
}

func bearerFailureResponse(messageType uint8, teid uint32, cause uint8, ebi uint8) *gtpv2.Message {
	contextChildren := []gtpv2.IE{{Type: gtpv2.IEEBI, Value: []byte{ebi & 0x0f}}, gtpv2.NewCauseIE(cause, 0)}
	contextIE, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, contextChildren...)
	return &gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: messageType, TEID: teid},
		IEs:    []gtpv2.IE{gtpv2.NewCauseIE(cause, 0), contextIE},
	}
}
