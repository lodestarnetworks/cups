package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/lodestarnetworks/cups/internal/pgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/pgwc/session"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

type createRequest struct {
	imsi               string
	apn                string
	profile            APNProfile
	sgwControl         gtpv2.FTEID
	sgwUser            gtpv2.FTEID
	ebi                uint8
	qos                gtpv2.BearerQoS
	apnAMBRUplinkBPS   uint64
	apnAMBRDownlinkBPS uint64
	pcoResponse        *gtpv2.IE
}

func (g *Gateway) createSession(parent context.Context, peer netip.AddrPort, request gtpv2.Message) *gtpv2.Message {
	parsed, cause, err := g.parseCreateRequest(peer, request)
	if err != nil {
		g.reject("create-session", peer, "invalid SGW request: "+err.Error())
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.sgwControl.TEID, cause, parsed.ebi)
	}
	if g.config.AllowNewSessions != nil && !g.config.AllowNewSessions() {
		g.counters.rejected.Add(1)
		g.counters.createRejected.Add(1)
		g.counters.createAdmissionRejected.Add(1)
		g.emit(Event{Severity: "warning", Procedure: "create-session", Peer: peer, Message: "new session rejected while PGW-C is draining"})
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.sgwControl.TEID, gtpv2.CauseNoResourcesAvailable, parsed.ebi)
	}
	subscriber := g.subscriberKey(parsed.imsi)
	unlockSubscriber := g.subscriberLocks.lock(subscriberLockKey(subscriber))
	defer unlockSubscriber()
	if err := g.replaceCreateCollision(parent, peer, subscriber, parsed.ebi); err != nil {
		g.reject("create-session", peer, "colliding context cleanup failed: "+err.Error())
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.sgwControl.TEID, gtpv2.CauseSystemFailure, parsed.ebi)
	}
	if _, exists := g.store.FindByOwner(subscriber, parsed.apn); exists {
		g.reject("create-session", peer, "subscriber/APN context already exists")
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.sgwControl.TEID, gtpv2.CauseNoResourcesAvailable, parsed.ebi)
	}

	lease, err := parsed.profile.Pool.Acquire(leaseOwner(subscriber, parsed.apn))
	if err != nil {
		g.reject("create-session", peer, "UE IPv4 pool exhausted: "+err.Error())
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.sgwControl.TEID, gtpv2.CauseNoResourcesAvailable, parsed.ebi)
	}
	allocatedTEIDs := make([]uint32, 0, 2)
	allocateTEID := func() (uint32, error) {
		teid, allocateErr := g.ids.allocateTEID()
		if allocateErr == nil {
			allocatedTEIDs = append(allocatedTEIDs, teid)
		}
		return teid, allocateErr
	}
	controlTEID, err := allocateTEID()
	if err != nil {
		_ = parsed.profile.Pool.Release(lease.Owner, lease.Addr)
		return g.resourceFailure(peer, parsed, err)
	}
	userTEID, err := allocateTEID()
	if err != nil {
		g.ids.release(allocatedTEIDs, 0)
		_ = parsed.profile.Pool.Release(lease.Owner, lease.Addr)
		return g.resourceFailure(peer, parsed, err)
	}
	cpSEID, err := g.ids.allocateSEID()
	if err != nil {
		g.ids.release(allocatedTEIDs, 0)
		_ = parsed.profile.Pool.Release(lease.Owner, lease.Addr)
		return g.resourceFailure(peer, parsed, err)
	}
	committed := false
	defer func() {
		if !committed {
			g.ids.release(allocatedTEIDs, cpSEID)
			_ = parsed.profile.Pool.Release(lease.Owner, lease.Addr)
		}
	}()

	opCtx, cancel := g.operationContext(parent)
	userSession, err := g.up.Establish(opCtx, pfcpclient.Establishment{
		CPSEID: cpSEID, UEIPv4: lease.Addr,
		Local:           pfcpclient.Tunnel{TEID: userTEID, IP: g.config.PGWUUserIP},
		Remote:          pfcpclient.Tunnel{TEID: parsed.sgwUser.TEID, IP: parsed.sgwUser.IPv4},
		UplinkBitrate:   effectiveBitrate(parsed.apnAMBRUplinkBPS, parsed.qos.UplinkMBR),
		DownlinkBitrate: effectiveBitrate(parsed.apnAMBRDownlinkBPS, parsed.qos.DownlinkMBR),
		QCI:             parsed.qos.QCI,
		ARP:             parsed.qos.Priority,
	})
	cancel()
	if err != nil {
		g.reject("create-session", peer, "PGW-U session establishment failed: "+err.Error())
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.sgwControl.TEID, gtpv2.CauseSystemFailure, parsed.ebi)
	}

	stored, err := g.store.Create(session.Session{
		SubscriberKey: subscriber, APN: parsed.apn, State: session.StateActive,
		EBI: parsed.ebi, QCI: parsed.qos.QCI, ARP: parsed.qos.Priority,
		UplinkMBR: parsed.qos.UplinkMBR, DownlinkMBR: parsed.qos.DownlinkMBR,
		UplinkGBR: parsed.qos.UplinkGBR, DownlinkGBR: parsed.qos.DownlinkGBR,
		APNAMBRUplinkBPS: parsed.apnAMBRUplinkBPS, APNAMBRDownlinkBPS: parsed.apnAMBRDownlinkBPS,
		UEIPv4:          lease.Addr,
		SGWControl:      session.FTEID{TEID: parsed.sgwControl.TEID, IP: parsed.sgwControl.IPv4},
		PGWControl:      session.FTEID{TEID: controlTEID, IP: g.config.S5Advertise},
		SGWUser:         session.FTEID{TEID: parsed.sgwUser.TEID, IP: parsed.sgwUser.IPv4},
		PGWUser:         session.FTEID{TEID: userTEID, IP: g.config.PGWUUserIP},
		PFCPControlSEID: cpSEID, PFCPUserSEID: userSession.UPSEID,
		DedicatedBearers: make(map[uint8]session.Bearer),
	})
	if err != nil {
		opCtx, cancel = g.operationContext(parent)
		_ = g.up.Delete(opCtx, userSession)
		cancel()
		g.reject("create-session", peer, "local session commit failed: "+err.Error())
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.sgwControl.TEID, gtpv2.CauseNoResourcesAvailable, parsed.ebi)
	}
	response, err := createSuccessResponse(stored, parsed.pcoResponse)
	if err != nil {
		opCtx, cancel = g.operationContext(parent)
		_ = g.up.Delete(opCtx, userSession)
		cancel()
		_ = g.store.Delete(stored.ID, stored.Revision)
		g.reject("create-session", peer, "response construction failed: "+err.Error())
		return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.sgwControl.TEID, gtpv2.CauseSystemFailure, parsed.ebi)
	}
	committed = true
	g.counters.createAccepted.Add(1)
	g.emit(Event{Severity: "info", Procedure: "create-session", Peer: peer, Subscriber: subscriber, Message: "IPv4 PDN and default bearer created"})
	return response
}

// replaceCreateCollision removes an old PGW-local PDN before accepting a new
// Create Session for the same [IMSI, EBI]. TS 29.274 requires the PGW to treat
// this as a replacement request rather than a resource-exhaustion condition.
func (g *Gateway) replaceCreateCollision(parent context.Context, peer netip.AddrPort, subscriber string, ebi uint8) error {
	current, ok := g.store.FindBySubscriberAndEBI(subscriber, ebi)
	if !ok {
		return nil
	}
	unlock := g.locks.lock(current.ID)
	defer unlock()
	current, ok = g.store.Find(current.ID)
	if !ok || current.SubscriberKey != subscriber || current.EBI != ebi {
		return nil
	}
	opCtx, cancel := g.operationContext(parent)
	err := g.up.Delete(opCtx, userPlaneSession(current))
	cancel()
	if err != nil {
		return fmt.Errorf("delete stale PGW-U PDN: %w", err)
	}
	if err := g.store.Delete(current.ID, current.Revision); err != nil {
		return fmt.Errorf("delete stale PGW-C PDN: %w", err)
	}
	g.releaseResources(current)
	g.counters.createReplacements.Add(1)
	g.emit(Event{Severity: "warning", Procedure: "create-session", Peer: peer, Subscriber: subscriber, Message: fmt.Sprintf("replaced colliding PDN context for EBI %d", ebi)})
	return nil
}

func (g *Gateway) modifyBearer(parent context.Context, peer netip.AddrPort, request gtpv2.Message) *gtpv2.Message {
	current, ok := g.store.FindByControlTEID(request.Header.TEID)
	if !ok {
		g.reject("modify-bearer", peer, "unknown PGW S5-C TEID")
		return failureResponse(gtpv2.MessageModifyBearerResponse, 0, gtpv2.CauseContextNotFound, 0)
	}
	unlock := g.locks.lock(current.ID)
	defer unlock()
	current, ok = g.store.Find(current.ID)
	if !ok || peer.Addr().Unmap() != current.SGWControl.IP.Unmap() {
		g.reject("modify-bearer", peer, "SGW-C does not own session")
		return failureResponse(gtpv2.MessageModifyBearerResponse, 0, gtpv2.CauseContextNotFound, 0)
	}
	ebi, remote, hasRemote, err := parseModifyRequest(request)
	if err != nil || ebi != current.EBI {
		g.reject("modify-bearer", peer, "invalid bearer context")
		return failureResponse(gtpv2.MessageModifyBearerResponse, current.SGWControl.TEID, gtpv2.CauseMandatoryIEIncorrect, current.EBI)
	}
	if hasRemote && (remote.TEID != current.SGWUser.TEID || remote.IPv4.Unmap() != current.SGWUser.IP.Unmap()) {
		userSession := userPlaneSession(current)
		opCtx, cancel := g.operationContext(parent)
		err = g.up.UpdateRemote(opCtx, &userSession, pfcpclient.Tunnel{TEID: remote.TEID, IP: remote.IPv4})
		cancel()
		if err != nil {
			g.reject("modify-bearer", peer, "PGW-U tunnel update failed: "+err.Error())
			return failureResponse(gtpv2.MessageModifyBearerResponse, current.SGWControl.TEID, gtpv2.CauseSystemFailure, current.EBI)
		}
		updated, updateErr := g.store.Update(current.ID, current.Revision, func(candidate *session.Session) error {
			candidate.SGWUser = session.FTEID{TEID: remote.TEID, IP: remote.IPv4}
			return nil
		})
		if updateErr != nil {
			opCtx, cancel = g.operationContext(parent)
			_ = g.up.UpdateRemote(opCtx, &userSession, pfcpclient.Tunnel{TEID: current.SGWUser.TEID, IP: current.SGWUser.IP})
			cancel()
			g.reject("modify-bearer", peer, "local session update failed: "+updateErr.Error())
			return failureResponse(gtpv2.MessageModifyBearerResponse, current.SGWControl.TEID, gtpv2.CauseSystemFailure, current.EBI)
		}
		current = updated
	}
	g.counters.modifyAccepted.Add(1)
	g.emit(Event{Severity: "info", Procedure: "modify-bearer", Peer: peer, Subscriber: current.SubscriberKey, Message: "default bearer confirmed"})
	return successResponse(gtpv2.MessageModifyBearerResponse, current.SGWControl.TEID, current.EBI)
}

func (g *Gateway) deleteSession(parent context.Context, peer netip.AddrPort, request gtpv2.Message) *gtpv2.Message {
	current, ok := g.store.FindByControlTEID(request.Header.TEID)
	if !ok {
		g.reject("delete-session", peer, "unknown PGW S5-C TEID")
		return failureResponse(gtpv2.MessageDeleteSessionResponse, 0, gtpv2.CauseContextNotFound, 0)
	}
	unlockSubscriber := g.subscriberLocks.lock(subscriberLockKey(current.SubscriberKey))
	defer unlockSubscriber()
	unlock := g.locks.lock(current.ID)
	defer unlock()
	current, ok = g.store.Find(current.ID)
	if !ok || peer.Addr().Unmap() != current.SGWControl.IP.Unmap() {
		g.reject("delete-session", peer, "SGW-C does not own session")
		return failureResponse(gtpv2.MessageDeleteSessionResponse, 0, gtpv2.CauseContextNotFound, 0)
	}
	if err := validateDeleteRequest(request, current); err != nil {
		g.reject("delete-session", peer, "invalid delete request: "+err.Error())
		return failureResponse(gtpv2.MessageDeleteSessionResponse, current.SGWControl.TEID, gtpv2.CauseMandatoryIEIncorrect, 0)
	}
	opCtx, cancel := g.operationContext(parent)
	err := g.up.Delete(opCtx, userPlaneSession(current))
	cancel()
	if err != nil {
		g.reject("delete-session", peer, "PGW-U session deletion failed: "+err.Error())
		return failureResponse(gtpv2.MessageDeleteSessionResponse, current.SGWControl.TEID, gtpv2.CauseSystemFailure, 0)
	}
	if err := g.store.Delete(current.ID, current.Revision); err != nil {
		g.reject("delete-session", peer, "local session deletion failed: "+err.Error())
		return failureResponse(gtpv2.MessageDeleteSessionResponse, current.SGWControl.TEID, gtpv2.CauseSystemFailure, 0)
	}
	g.releaseResources(current)
	g.counters.deleteAccepted.Add(1)
	g.emit(Event{Severity: "info", Procedure: "delete-session", Peer: peer, Subscriber: current.SubscriberKey, Message: "PDN session and IPv4 lease released"})
	return successResponse(gtpv2.MessageDeleteSessionResponse, current.SGWControl.TEID, 0)
}

func (g *Gateway) parseCreateRequest(peer netip.AddrPort, request gtpv2.Message) (createRequest, uint8, error) {
	var out createRequest
	if request.Header.TEID != 0 {
		return out, gtpv2.CauseMandatoryIEIncorrect, errors.New("initial Create Session has non-zero TEID")
	}
	imsiIE, imsiOK := request.Find(gtpv2.IEIMSI, 0)
	apnIE, apnOK := request.Find(gtpv2.IEAPN, 0)
	controlIE, controlOK := request.Find(gtpv2.IEFTEID, 0)
	bearerIE, bearerOK := request.Find(gtpv2.IEBearerContext, 0)
	if !imsiOK || !apnOK || !controlOK || !bearerOK {
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
	profile, served := g.profileForRequestedAPN(out.apn)
	if !served {
		return out, gtpv2.CauseMissingOrUnknownAPN, fmt.Errorf("APN %q is not served", out.apn)
	}
	out.apn, out.profile = profile.APN, profile
	out.sgwControl, err = controlIE.FTEID()
	if err != nil || out.sgwControl.InterfaceType != gtpv2.InterfaceS5S8SGWGTPC || !out.sgwControl.IPv4.Is4() || out.sgwControl.IPv4.Unmap() != peer.Addr().Unmap() {
		return out, gtpv2.CauseMandatoryIEIncorrect, errors.New("invalid SGW S5-C F-TEID")
	}
	if pdnIE, ok := request.Find(gtpv2.IEPDNType, 0); ok {
		pdnType, err := pdnIE.PDNType()
		if err != nil || pdnType != gtpv2.PDNTypeIPv4 {
			return out, gtpv2.CauseServiceNotSupported, errors.New("only IPv4 PDN type is supported")
		}
	}
	out.apnAMBRUplinkBPS = profile.APNAMBRUplinkBPS
	out.apnAMBRDownlinkBPS = profile.APNAMBRDownlinkBPS
	if ambrIE, ok := request.Find(gtpv2.IEAMBR, 0); ok {
		requestedUplink, requestedDownlink, err := ambrIE.AMBR()
		if err != nil {
			return out, gtpv2.CauseMandatoryIEIncorrect, err
		}
		out.apnAMBRUplinkBPS = effectiveBitrate(out.apnAMBRUplinkBPS, requestedUplink)
		out.apnAMBRDownlinkBPS = effectiveBitrate(out.apnAMBRDownlinkBPS, requestedDownlink)
	}
	if pcoIE, ok := request.Find(gtpv2.IEPCO, 0); ok {
		uePCO, err := pcoIE.PCO()
		if err != nil {
			return out, gtpv2.CauseMandatoryIEIncorrect, err
		}
		responsePCO, err := gtpv2.BuildPCOResponse(uePCO, gtpv2.PCOResponseProfile{
			DNSIPv4: profile.DNSIPv4, PCSCFIPv4: profile.PCSCFIPv4, IPv4LinkMTU: profile.IPv4LinkMTU,
		})
		if err != nil {
			return out, gtpv2.CauseMandatoryIEIncorrect, err
		}
		responseIE, err := gtpv2.NewPCOIE(0, responsePCO)
		if err != nil {
			return out, gtpv2.CauseMandatoryIEIncorrect, err
		}
		out.pcoResponse = &responseIE
	}
	children, err := bearerIE.Children()
	if err != nil {
		return out, gtpv2.CauseMandatoryIEIncorrect, err
	}
	ebiIE, ebiOK := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
	qosIE, qosOK := gtpv2.FindIE(children, gtpv2.IEBearerQoS, 0)
	userIE, userOK := gtpv2.FindIE(children, gtpv2.IEFTEID, 2)
	if !ebiOK || !qosOK || !userOK {
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
	out.sgwUser, err = userIE.FTEID()
	if err != nil || out.sgwUser.InterfaceType != gtpv2.InterfaceS5S8SGWGTPU || !out.sgwUser.IPv4.Is4() {
		return out, gtpv2.CauseMandatoryIEIncorrect, errors.New("invalid SGW S5-U F-TEID")
	}
	return out, 0, nil
}

func parseModifyRequest(request gtpv2.Message) (ebi uint8, remote gtpv2.FTEID, hasRemote bool, err error) {
	bearerIE, ok := request.Find(gtpv2.IEBearerContext, 0)
	if !ok {
		return 0, gtpv2.FTEID{}, false, gtpv2.ErrMissingIE
	}
	children, err := bearerIE.Children()
	if err != nil {
		return 0, gtpv2.FTEID{}, false, err
	}
	ebiIE, ok := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
	if !ok {
		return 0, gtpv2.FTEID{}, false, gtpv2.ErrMissingIE
	}
	ebi, err = ebiIE.EBI()
	if err != nil {
		return 0, gtpv2.FTEID{}, false, err
	}
	userIE, ok := gtpv2.FindIE(children, gtpv2.IEFTEID, 1)
	if !ok {
		return ebi, gtpv2.FTEID{}, false, nil
	}
	remote, err = userIE.FTEID()
	if err != nil || remote.InterfaceType != gtpv2.InterfaceS5S8SGWGTPU || !remote.IPv4.Is4() {
		return ebi, gtpv2.FTEID{}, true, errors.New("invalid SGW S5-U F-TEID")
	}
	return ebi, remote, true, nil
}

func validateDeleteRequest(request gtpv2.Message, current session.Session) error {
	if ebiIE, ok := request.Find(gtpv2.IEEBI, 0); ok {
		ebi, err := ebiIE.EBI()
		if err != nil || ebi != current.EBI {
			return errors.New("linked bearer EBI does not match session")
		}
	}
	if senderIE, ok := request.Find(gtpv2.IEFTEID, 0); ok {
		sender, err := senderIE.FTEID()
		if err != nil || sender.InterfaceType != gtpv2.InterfaceS5S8SGWGTPC || sender.TEID != current.SGWControl.TEID || sender.IPv4.Unmap() != current.SGWControl.IP.Unmap() {
			return errors.New("Sender F-TEID does not match session owner")
		}
	}
	return nil
}

func createSuccessResponse(current session.Session, pco *gtpv2.IE) (*gtpv2.Message, error) {
	control, err := gtpv2.NewFTEIDIE(1, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8PGWGTPC, TEID: current.PGWControl.TEID, IPv4: current.PGWControl.IP,
	})
	if err != nil {
		return nil, err
	}
	user, err := gtpv2.NewFTEIDIE(2, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8PGWGTPU, TEID: current.PGWUser.TEID, IPv4: current.PGWUser.IP,
	})
	if err != nil {
		return nil, err
	}
	ebi, _ := gtpv2.NewEBIIE(current.EBI, 0)
	bearer, err := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebi, gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), user)
	if err != nil {
		return nil, err
	}
	paa, err := gtpv2.NewPAAIPv4IE(0, current.UEIPv4)
	if err != nil {
		return nil, err
	}
	ambr, err := gtpv2.NewAMBRIE(0, current.APNAMBRUplinkBPS, current.APNAMBRDownlinkBPS)
	if err != nil {
		return nil, err
	}
	ies := []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), control, paa, ambr, bearer}
	if pco != nil {
		ies = append(ies, pco.Clone())
	}
	return &gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateSessionResponse, TEID: current.SGWControl.TEID},
		IEs:    ies,
	}, nil
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
	return &gtpv2.Message{Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: messageType, TEID: teid}, IEs: ies}
}

func matchesAPN(requested, configured string) bool {
	requested = strings.ToLower(strings.TrimSpace(requested))
	configured = strings.ToLower(strings.TrimSpace(configured))
	return requested == configured || strings.HasPrefix(requested, configured+".mnc")
}

func effectiveBitrate(policy, requested uint64) uint64 {
	if policy == 0 {
		return requested
	}
	if requested == 0 || policy < requested {
		return policy
	}
	return requested
}

func (g *Gateway) resourceFailure(peer netip.AddrPort, parsed createRequest, err error) *gtpv2.Message {
	g.reject("create-session", peer, "identifier allocation failed: "+err.Error())
	return failureResponse(gtpv2.MessageCreateSessionResponse, parsed.sgwControl.TEID, gtpv2.CauseNoResourcesAvailable, parsed.ebi)
}

func (g *Gateway) reject(procedure string, peer netip.AddrPort, message string) {
	g.counters.rejected.Add(1)
	switch procedure {
	case "create-session":
		g.counters.createRejected.Add(1)
	case "modify-bearer":
		g.counters.modifyRejected.Add(1)
	case "delete-session":
		g.counters.deleteRejected.Add(1)
	}
	g.emit(Event{Severity: "warning", Procedure: procedure, Peer: peer, Message: message})
}
