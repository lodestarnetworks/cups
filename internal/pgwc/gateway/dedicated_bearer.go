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

var (
	ErrSessionNotFound = errors.New("pgwc: session not found")
	ErrBearerNotFound  = errors.New("pgwc: dedicated bearer not found")
	ErrBearerRejected  = errors.New("pgwc: dedicated bearer procedure rejected")
)

// DedicatedBearerPlan is the policy input for a PGW-initiated Create Bearer
// procedure. EBI zero asks PGW-C to allocate a stable free value before the
// request, avoiding an ambiguous rollback if the response is lost.
type DedicatedBearerPlan struct {
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
	TFT                  gtpv2.TrafficFlowTemplate
}

type DedicatedBearerQoS struct {
	QCI                  uint8
	ARP                  uint8
	PreemptionCapable    bool
	PreemptionVulnerable bool
	UplinkMBR            uint64
	DownlinkMBR          uint64
	UplinkGBR            uint64
	DownlinkGBR          uint64
}

func (g *Gateway) CreateDedicatedBearer(parent context.Context, sessionID uint64, plan DedicatedBearerPlan) (session.Bearer, error) {
	g.counters.createBearerRequests.Add(1)
	accepted := false
	defer func() {
		if !accepted {
			g.counters.createBearerRejected.Add(1)
			g.counters.rejected.Add(1)
		}
	}()
	current, ok := g.store.Find(sessionID)
	if !ok {
		return session.Bearer{}, ErrSessionNotFound
	}
	unlockSubscriber := g.subscriberLocks.lock(subscriberLockKey(current.SubscriberKey))
	defer unlockSubscriber()
	unlock := g.locks.lock(current.ID)
	defer unlock()
	current, ok = g.store.Find(current.ID)
	if !ok {
		return session.Bearer{}, ErrSessionNotFound
	}
	if current.State != session.StateActive || len(current.DedicatedBearers) >= session.MaxDedicatedBearers {
		return session.Bearer{}, fmt.Errorf("%w: session is not active or has no bearer slots", ErrBearerRejected)
	}
	plan.PolicyID = strings.TrimSpace(plan.PolicyID)
	if plan.PolicyID != "" {
		if !session.ValidPolicyID(plan.PolicyID) {
			return session.Bearer{}, fmt.Errorf("%w: invalid policy identity", ErrBearerRejected)
		}
		for _, bearer := range current.DedicatedBearers {
			if bearer.PolicyID == plan.PolicyID {
				return session.Bearer{}, fmt.Errorf("%w: policy identity %q already exists", ErrBearerRejected, plan.PolicyID)
			}
		}
	}
	if g.config.PGWUQCI1UserIP != g.config.PGWUUserIP && len(current.DedicatedBearers) != 0 {
		return session.Bearer{}, fmt.Errorf("%w: this PGW-U supports one QCI 1 dedicated bearer per UE", ErrBearerRejected)
	}
	qos := DedicatedBearerQoS{
		QCI: plan.QCI, ARP: plan.ARP, PreemptionCapable: plan.PreemptionCapable, PreemptionVulnerable: plan.PreemptionVulnerable,
		UplinkMBR: plan.UplinkMBR, DownlinkMBR: plan.DownlinkMBR, UplinkGBR: plan.UplinkGBR, DownlinkGBR: plan.DownlinkGBR,
	}
	if err := validateDedicatedQoS(qos); err != nil {
		return session.Bearer{}, err
	}
	rawTFT, err := gtpv2.MarshalBearerTFT(plan.TFT)
	if err != nil {
		return session.Bearer{}, err
	}
	canonicalTFT, err := gtpv2.ParseBearerTFT(rawTFT)
	if err != nil || canonicalTFT.Operation != gtpv2.TFTOperationCreate {
		return session.Bearer{}, fmt.Errorf("%w: dedicated bearer requires a create TFT", ErrBearerRejected)
	}
	uplinkPDRs, downlinkPDRs, err := directionalPDRCounts(canonicalTFT)
	if err != nil {
		return session.Bearer{}, err
	}
	if uplinkPDRs+downlinkPDRs > 64 {
		return session.Bearer{}, fmt.Errorf("%w: TFT expands beyond 64 PDRs", ErrBearerRejected)
	}
	ebi, err := g.allocateDedicatedEBI(current, plan.EBI)
	if err != nil {
		return session.Bearer{}, err
	}
	rules, err := allocateBearerRuleIDs(current, uplinkPDRs, downlinkPDRs)
	if err != nil {
		return session.Bearer{}, err
	}
	localTEID, err := g.ids.allocateTEID()
	if err != nil {
		return session.Bearer{}, err
	}
	committed := false
	defer func() {
		if !committed {
			g.ids.release([]uint32{localTEID}, 0)
		}
	}()
	localIP, err := g.dedicatedUserIP(qos.QCI)
	if err != nil {
		return session.Bearer{}, err
	}
	local := session.FTEID{TEID: localTEID, IP: localIP}
	request, err := createBearerRequest(current, ebi, local, qos, canonicalTFT)
	if err != nil {
		return session.Bearer{}, err
	}
	response, err := g.doBearerRequest(parent, current, request)
	if err != nil {
		return session.Bearer{}, err
	}
	assignedEBI, remote, err := parseCreateBearerResponse(response, current, ebi, local)
	if err != nil {
		return session.Bearer{}, err
	}
	if assignedEBI != ebi {
		g.bestEffortDeleteSGWBearer(parent, current, assignedEBI)
		return session.Bearer{}, fmt.Errorf("%w: SGW assigned EBI %d, expected %d", ErrBearerRejected, assignedEBI, ebi)
	}
	bearerPlan := pfcpclient.BearerPlan{
		Rules: rules,
		Local: pfcpclient.Tunnel{TEID: local.TEID, IP: local.IP}, Remote: pfcpclient.Tunnel{TEID: remote.TEID, IP: remote.IP},
		UplinkBitrate: qos.UplinkMBR, DownlinkBitrate: qos.DownlinkMBR, QCI: qos.QCI, ARP: qos.ARP, TFT: canonicalTFT,
	}
	userSession := userPlaneSession(current)
	opCtx, cancel := g.operationContext(parent)
	err = g.up.AddBearer(opCtx, &userSession, bearerPlan)
	cancel()
	if err != nil {
		g.bestEffortDeleteSGWBearer(parent, current, ebi)
		return session.Bearer{}, fmt.Errorf("install PGW-U dedicated bearer: %w", err)
	}
	installedPFCP := true
	rollback := func() {
		if installedPFCP {
			opCtx, cancel := g.operationContext(parent)
			_ = g.up.RemoveBearer(opCtx, &userSession, rules)
			cancel()
		}
		g.bestEffortDeleteSGWBearer(parent, current, ebi)
	}
	storedBearer := session.Bearer{
		PolicyID: plan.PolicyID, EBI: ebi, QCI: qos.QCI, ARP: qos.ARP,
		PreemptionCapable: qos.PreemptionCapable, PreemptionVulnerable: qos.PreemptionVulnerable,
		UplinkMBR: qos.UplinkMBR, DownlinkMBR: qos.DownlinkMBR, UplinkGBR: qos.UplinkGBR, DownlinkGBR: qos.DownlinkGBR,
		SGWUser: remote, PGWUser: local, Rules: sessionRuleIDs(rules), TFT: append([]byte(nil), rawTFT...),
	}
	updated, err := g.store.Update(current.ID, current.Revision, func(candidate *session.Session) error {
		if candidate.DedicatedBearers == nil {
			candidate.DedicatedBearers = make(map[uint8]session.Bearer)
		}
		if _, exists := candidate.DedicatedBearers[ebi]; exists {
			return fmt.Errorf("%w: EBI %d already exists", ErrBearerRejected, ebi)
		}
		candidate.DedicatedBearers[ebi] = storedBearer
		return nil
	})
	if err != nil {
		rollback()
		return session.Bearer{}, fmt.Errorf("commit PGW-C dedicated bearer: %w", err)
	}
	installedPFCP = false
	committed = true
	accepted = true
	g.counters.createBearerAccepted.Add(1)
	g.emit(Event{Severity: "info", Procedure: "create-bearer", Peer: bearerPeer(current), Subscriber: current.SubscriberKey, Message: fmt.Sprintf("dedicated bearer EBI %d activated", ebi)})
	return updated.DedicatedBearers[ebi], nil
}

func (g *Gateway) UpdateDedicatedBearer(parent context.Context, sessionID uint64, ebi uint8, qos DedicatedBearerQoS) (session.Bearer, error) {
	g.counters.updateBearerRequests.Add(1)
	accepted := false
	defer func() {
		if !accepted {
			g.counters.updateBearerRejected.Add(1)
			g.counters.rejected.Add(1)
		}
	}()
	if err := validateDedicatedQoS(qos); err != nil {
		return session.Bearer{}, err
	}
	current, ok := g.store.Find(sessionID)
	if !ok {
		return session.Bearer{}, ErrSessionNotFound
	}
	unlockSubscriber := g.subscriberLocks.lock(subscriberLockKey(current.SubscriberKey))
	defer unlockSubscriber()
	unlock := g.locks.lock(current.ID)
	defer unlock()
	current, ok = g.store.Find(current.ID)
	if !ok {
		return session.Bearer{}, ErrSessionNotFound
	}
	bearer, ok := current.DedicatedBearers[ebi]
	if !ok {
		return session.Bearer{}, ErrBearerNotFound
	}
	expectedUserIP, err := g.dedicatedUserIP(qos.QCI)
	if err != nil {
		return session.Bearer{}, err
	}
	if bearer.PGWUser.IP.Unmap() != expectedUserIP {
		return session.Bearer{}, fmt.Errorf("%w: changing QCI would require a new PGW-U F-TEID", ErrBearerRejected)
	}
	rules := pfcpRuleIDs(bearer.Rules)
	userSession := userPlaneSession(current)
	opCtx, cancel := g.operationContext(parent)
	err = g.up.UpdateBearerQoS(opCtx, &userSession, rules, qos.QCI, qos.ARP, qos.UplinkMBR, qos.DownlinkMBR)
	cancel()
	if err != nil {
		return session.Bearer{}, fmt.Errorf("update PGW-U dedicated bearer: %w", err)
	}
	rollbackPFCP := func() {
		opCtx, cancel := g.operationContext(parent)
		_ = g.up.UpdateBearerQoS(opCtx, &userSession, rules, bearer.QCI, bearer.ARP, bearer.UplinkMBR, bearer.DownlinkMBR)
		cancel()
	}
	request, err := updateBearerRequest(current, ebi, qos)
	if err != nil {
		rollbackPFCP()
		return session.Bearer{}, err
	}
	response, err := g.doBearerRequest(parent, current, request)
	if err != nil {
		rollbackPFCP()
		return session.Bearer{}, err
	}
	if err := parseBearerResponse(response, current.PGWControl.TEID, ebi); err != nil {
		rollbackPFCP()
		return session.Bearer{}, err
	}
	updated, err := g.store.Update(current.ID, current.Revision, func(candidate *session.Session) error {
		changed, exists := candidate.DedicatedBearers[ebi]
		if !exists {
			return ErrBearerNotFound
		}
		changed.QCI, changed.ARP = qos.QCI, qos.ARP
		changed.PreemptionCapable, changed.PreemptionVulnerable = qos.PreemptionCapable, qos.PreemptionVulnerable
		changed.UplinkMBR, changed.DownlinkMBR = qos.UplinkMBR, qos.DownlinkMBR
		changed.UplinkGBR, changed.DownlinkGBR = qos.UplinkGBR, qos.DownlinkGBR
		candidate.DedicatedBearers[ebi] = changed
		return nil
	})
	if err != nil {
		rollbackPFCP()
		g.bestEffortUpdateSGWBearer(parent, current, bearer)
		return session.Bearer{}, fmt.Errorf("commit PGW-C bearer QoS: %w", err)
	}
	accepted = true
	g.counters.updateBearerAccepted.Add(1)
	g.emit(Event{Severity: "info", Procedure: "update-bearer", Peer: bearerPeer(current), Subscriber: current.SubscriberKey, Message: fmt.Sprintf("dedicated bearer EBI %d updated", ebi)})
	return updated.DedicatedBearers[ebi], nil
}

func (g *Gateway) dedicatedUserIP(qci uint8) (netip.Addr, error) {
	if g.config.PGWUQCI1UserIP == g.config.PGWUUserIP {
		return g.config.PGWUUserIP, nil
	}
	if qci != 1 {
		return netip.Addr{}, fmt.Errorf("%w: configured dedicated user plane currently supports QCI 1 only", ErrBearerRejected)
	}
	return g.config.PGWUQCI1UserIP, nil
}

func (g *Gateway) DeleteDedicatedBearer(parent context.Context, sessionID uint64, ebi uint8) error {
	g.counters.deleteBearerRequests.Add(1)
	accepted := false
	defer func() {
		if !accepted {
			g.counters.deleteBearerRejected.Add(1)
			g.counters.rejected.Add(1)
		}
	}()
	current, ok := g.store.Find(sessionID)
	if !ok {
		return ErrSessionNotFound
	}
	unlockSubscriber := g.subscriberLocks.lock(subscriberLockKey(current.SubscriberKey))
	defer unlockSubscriber()
	unlock := g.locks.lock(current.ID)
	defer unlock()
	current, ok = g.store.Find(current.ID)
	if !ok {
		return ErrSessionNotFound
	}
	bearer, ok := current.DedicatedBearers[ebi]
	if !ok {
		return ErrBearerNotFound
	}
	rules := pfcpRuleIDs(bearer.Rules)
	userSession := userPlaneSession(current)
	opCtx, cancel := g.operationContext(parent)
	err := g.up.RemoveBearer(opCtx, &userSession, rules)
	cancel()
	if err != nil {
		return fmt.Errorf("remove PGW-U dedicated bearer: %w", err)
	}
	restorePFCP := func() { g.bestEffortRestorePGWUBearer(parent, current, bearer) }
	request, err := deleteBearerRequest(current, ebi)
	if err != nil {
		restorePFCP()
		return err
	}
	response, err := g.doBearerRequest(parent, current, request)
	if err != nil {
		restorePFCP()
		return err
	}
	if err := parseBearerResponse(response, current.PGWControl.TEID, ebi); err != nil {
		restorePFCP()
		return err
	}
	if _, err := g.store.Update(current.ID, current.Revision, func(candidate *session.Session) error {
		if _, exists := candidate.DedicatedBearers[ebi]; !exists {
			return ErrBearerNotFound
		}
		delete(candidate.DedicatedBearers, ebi)
		return nil
	}); err != nil {
		restorePFCP()
		g.bestEffortCreateSGWBearer(parent, current, bearer)
		return fmt.Errorf("commit PGW-C bearer deletion: %w", err)
	}
	g.ids.release([]uint32{bearer.PGWUser.TEID}, 0)
	accepted = true
	g.counters.deleteBearerAccepted.Add(1)
	g.emit(Event{Severity: "info", Procedure: "delete-bearer", Peer: bearerPeer(current), Subscriber: current.SubscriberKey, Message: fmt.Sprintf("dedicated bearer EBI %d deleted", ebi)})
	return nil
}

func validateDedicatedQoS(qos DedicatedBearerQoS) error {
	if qos.QCI == 0 || qos.QCI == 255 || qos.ARP == 0 || qos.ARP > 15 {
		return fmt.Errorf("%w: invalid QCI/ARP", ErrBearerRejected)
	}
	const maxBitrate = uint64(^uint32(0)) * 1000
	for _, rate := range []uint64{qos.UplinkMBR, qos.DownlinkMBR, qos.UplinkGBR, qos.DownlinkGBR} {
		if rate%1000 != 0 || rate > maxBitrate {
			return fmt.Errorf("%w: bitrate must be whole kbps within PFCP's range", ErrBearerRejected)
		}
	}
	if qos.UplinkGBR > qos.UplinkMBR || qos.DownlinkGBR > qos.DownlinkMBR {
		return fmt.Errorf("%w: GBR exceeds MBR", ErrBearerRejected)
	}
	return nil
}

func directionalPDRCounts(tft gtpv2.TrafficFlowTemplate) (int, int, error) {
	plans, err := pfcpclient.SDFPlansFromTFT(tft)
	if err != nil {
		return 0, 0, err
	}
	uplink, downlink := 0, 0
	for _, plan := range plans {
		switch plan.Direction {
		case gtpv2.TFTDirectionUplink:
			uplink++
		case gtpv2.TFTDirectionDownlink:
			downlink++
		case gtpv2.TFTDirectionBidirectional:
			uplink++
			downlink++
		}
	}
	if uplink == 0 || downlink == 0 {
		return 0, 0, fmt.Errorf("%w: TFT must cover uplink and downlink", ErrBearerRejected)
	}
	return uplink, downlink, nil
}

func (g *Gateway) allocateDedicatedEBI(current session.Session, requested uint8) (uint8, error) {
	inUse := func(ebi uint8) bool {
		_, exists := g.store.FindBySubscriberAndEBI(current.SubscriberKey, ebi)
		return exists
	}
	if requested != 0 {
		if requested < 5 || requested > 15 || requested == current.EBI {
			return 0, fmt.Errorf("%w: invalid dedicated EBI %d", ErrBearerRejected, requested)
		}
		if inUse(requested) {
			return 0, fmt.Errorf("%w: EBI %d already exists for this subscriber", ErrBearerRejected, requested)
		}
		return requested, nil
	}
	for ebi := uint8(5); ebi <= 15; ebi++ {
		if !inUse(ebi) {
			return ebi, nil
		}
	}
	return 0, fmt.Errorf("%w: no EBI is available", ErrBearerRejected)
}

func allocateBearerRuleIDs(current session.Session, uplinkCount, downlinkCount int) (pfcpclient.RuleIDs, error) {
	usedPDR := map[uint16]bool{1: true, 2: true}
	usedFAR := map[uint32]bool{1: true, 2: true}
	usedQER := map[uint32]bool{1: true}
	usedURR := map[uint32]bool{1: true}
	for _, bearer := range current.DedicatedBearers {
		for _, id := range append(append([]uint16(nil), bearer.Rules.UplinkPDRs...), bearer.Rules.DownlinkPDRs...) {
			usedPDR[id] = true
		}
		usedFAR[bearer.Rules.UplinkFAR], usedFAR[bearer.Rules.DownlinkFAR] = true, true
		usedQER[bearer.Rules.QER], usedURR[bearer.Rules.URR] = true, true
	}
	pdrs, err := freePDRIDs(usedPDR, uplinkCount+downlinkCount)
	if err != nil {
		return pfcpclient.RuleIDs{}, err
	}
	fars, err := freeUint32IDs(usedFAR, 2)
	if err != nil {
		return pfcpclient.RuleIDs{}, err
	}
	qers, err := freeUint32IDs(usedQER, 1)
	if err != nil {
		return pfcpclient.RuleIDs{}, err
	}
	urrs, err := freeUint32IDs(usedURR, 1)
	if err != nil {
		return pfcpclient.RuleIDs{}, err
	}
	return pfcpclient.RuleIDs{
		UplinkPDRs: pdrs[:uplinkCount], DownlinkPDRs: pdrs[uplinkCount:],
		UplinkFAR: fars[0], DownlinkFAR: fars[1], QER: qers[0], URR: urrs[0],
	}, nil
}

func freePDRIDs(used map[uint16]bool, count int) ([]uint16, error) {
	out := make([]uint16, 0, count)
	for id := uint32(1); id <= uint32(^uint16(0)) && len(out) < count; id++ {
		if !used[uint16(id)] {
			out = append(out, uint16(id))
		}
	}
	if len(out) != count {
		return nil, fmt.Errorf("%w: PDR ID space exhausted", ErrBearerRejected)
	}
	return out, nil
}

func freeUint32IDs(used map[uint32]bool, count int) ([]uint32, error) {
	out := make([]uint32, 0, count)
	for id := uint64(1); id <= uint64(^uint32(0)) && len(out) < count; id++ {
		if !used[uint32(id)] {
			out = append(out, uint32(id))
		}
	}
	if len(out) != count {
		return nil, fmt.Errorf("%w: PFCP rule ID space exhausted", ErrBearerRejected)
	}
	return out, nil
}

func createBearerRequest(current session.Session, ebi uint8, local session.FTEID, qos DedicatedBearerQoS, tft gtpv2.TrafficFlowTemplate) (gtpv2.Message, error) {
	linked, err := gtpv2.NewEBIIE(current.EBI, 0)
	if err != nil {
		return gtpv2.Message{}, err
	}
	ebiIE, err := gtpv2.NewEBIIE(ebi, 0)
	if err != nil {
		return gtpv2.Message{}, err
	}
	tftIE, err := gtpv2.NewBearerTFTIE(0, tft)
	if err != nil {
		return gtpv2.Message{}, err
	}
	user, err := gtpv2.NewFTEIDIE(1, gtpv2.FTEID{InterfaceType: gtpv2.InterfaceS5S8PGWGTPU, TEID: local.TEID, IPv4: local.IP})
	if err != nil {
		return gtpv2.Message{}, err
	}
	qosIE, err := newBearerQoSIE(qos)
	if err != nil {
		return gtpv2.Message{}, err
	}
	contextIE, err := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, tftIE, user, qosIE)
	if err != nil {
		return gtpv2.Message{}, err
	}
	return gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateBearerRequest, TEID: current.SGWControl.TEID},
		IEs:    []gtpv2.IE{linked, contextIE},
	}, nil
}

func updateBearerRequest(current session.Session, ebi uint8, qos DedicatedBearerQoS) (gtpv2.Message, error) {
	ebiIE, err := gtpv2.NewEBIIE(ebi, 0)
	if err != nil {
		return gtpv2.Message{}, err
	}
	qosIE, err := newBearerQoSIE(qos)
	if err != nil {
		return gtpv2.Message{}, err
	}
	contextIE, err := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, qosIE)
	if err != nil {
		return gtpv2.Message{}, err
	}
	return gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageUpdateBearerRequest, TEID: current.SGWControl.TEID},
		IEs:    []gtpv2.IE{contextIE},
	}, nil
}

func deleteBearerRequest(current session.Session, ebi uint8) (gtpv2.Message, error) {
	ebiIE, err := gtpv2.NewEBIIE(ebi, 1)
	if err != nil {
		return gtpv2.Message{}, err
	}
	return gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteBearerRequest, TEID: current.SGWControl.TEID},
		IEs:    []gtpv2.IE{ebiIE},
	}, nil
}

func newBearerQoSIE(qos DedicatedBearerQoS) (gtpv2.IE, error) {
	ie, err := gtpv2.NewBearerQoSIEWithBitrates(0, qos.QCI, qos.ARP, qos.UplinkMBR, qos.DownlinkMBR, qos.UplinkGBR, qos.DownlinkGBR)
	if err != nil {
		return gtpv2.IE{}, err
	}
	if qos.PreemptionCapable {
		ie.Value[0] |= 0x40
	}
	if qos.PreemptionVulnerable {
		ie.Value[0] |= 0x01
	}
	return ie, nil
}

func (g *Gateway) doBearerRequest(parent context.Context, current session.Session, request gtpv2.Message) (gtpv2.Message, error) {
	request.Upsert(gtpv2.NewRecoveryIE(g.config.RecoveryCounter))
	opCtx, cancel := g.operationContext(parent)
	defer cancel()
	response, err := g.s5.Do(opCtx, bearerPeer(current), request)
	if err != nil {
		return gtpv2.Message{}, err
	}
	return response, nil
}

func parseCreateBearerResponse(response gtpv2.Message, current session.Session, expectedEBI uint8, local session.FTEID) (uint8, session.FTEID, error) {
	if err := parseBearerResponse(response, current.PGWControl.TEID, expectedEBI); err != nil {
		return 0, session.FTEID{}, err
	}
	contextIE, _ := response.Find(gtpv2.IEBearerContext, 0)
	children, _ := contextIE.Children()
	remoteIE, ok := gtpv2.FindIE(children, gtpv2.IEFTEID, 2)
	if !ok {
		return 0, session.FTEID{}, fmt.Errorf("%w: Create Bearer response omitted SGW S5-U F-TEID", ErrBearerRejected)
	}
	remote, err := remoteIE.FTEID()
	if err != nil || remote.InterfaceType != gtpv2.InterfaceS5S8SGWGTPU || !remote.IPv4.Is4() || remote.TEID == 0 {
		return 0, session.FTEID{}, fmt.Errorf("%w: invalid SGW S5-U F-TEID", ErrBearerRejected)
	}
	if returnedLocalIE, ok := gtpv2.FindIE(children, gtpv2.IEFTEID, 3); ok {
		returnedLocal, err := returnedLocalIE.FTEID()
		if err != nil || returnedLocal.InterfaceType != gtpv2.InterfaceS5S8PGWGTPU || returnedLocal.TEID != local.TEID || returnedLocal.IPv4.Unmap() != local.IP.Unmap() {
			return 0, session.FTEID{}, fmt.Errorf("%w: SGW returned the wrong PGW S5-U F-TEID", ErrBearerRejected)
		}
	}
	return expectedEBI, session.FTEID{TEID: remote.TEID, IP: remote.IPv4.Unmap()}, nil
}

func parseBearerResponse(response gtpv2.Message, expectedTEID uint32, expectedEBI uint8) error {
	if !response.Header.HasTEID || response.Header.TEID != expectedTEID {
		return fmt.Errorf("%w: response has wrong PGW control TEID", ErrBearerRejected)
	}
	causeIE, ok := response.Find(gtpv2.IECause, 0)
	if !ok {
		return fmt.Errorf("%w: response omitted Cause IE", ErrBearerRejected)
	}
	cause, err := causeIE.Cause()
	if err != nil {
		return fmt.Errorf("%w: invalid response cause", ErrBearerRejected)
	}
	if cause.Value != gtpv2.CauseRequestAccepted {
		return fmt.Errorf("%w: GTP cause %d", ErrBearerRejected, cause.Value)
	}
	contexts := gtpv2.FindAllIEs(response.IEs, gtpv2.IEBearerContext, 0)
	if len(contexts) != 1 {
		return fmt.Errorf("%w: response bearer-context count %d", ErrBearerRejected, len(contexts))
	}
	children, err := contexts[0].Children()
	if err != nil {
		return fmt.Errorf("%w: invalid bearer context", ErrBearerRejected)
	}
	ebiIE, ebiOK := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
	if !ebiOK {
		ebiIE, ebiOK = gtpv2.FindIE(children, gtpv2.IEEBI, 1)
	}
	contextCauseIE, causeOK := gtpv2.FindIE(children, gtpv2.IECause, 0)
	if !ebiOK || !causeOK {
		return fmt.Errorf("%w: bearer context omitted EBI or Cause", ErrBearerRejected)
	}
	ebi, err := ebiIE.EBI()
	if err != nil || ebi != expectedEBI {
		return fmt.Errorf("%w: response EBI does not match %d", ErrBearerRejected, expectedEBI)
	}
	contextCause, err := contextCauseIE.Cause()
	if err != nil || contextCause.Value != gtpv2.CauseRequestAccepted {
		return fmt.Errorf("%w: bearer-context cause is not accepted", ErrBearerRejected)
	}
	return nil
}

func bearerPeer(current session.Session) netip.AddrPort {
	return netip.AddrPortFrom(current.SGWControl.IP.Unmap(), 2123)
}

func (g *Gateway) bestEffortDeleteSGWBearer(parent context.Context, current session.Session, ebi uint8) {
	request, err := deleteBearerRequest(current, ebi)
	if err != nil {
		return
	}
	var response gtpv2.Message
	response, err = g.doBearerRequest(parent, current, request)
	if err == nil {
		err = parseBearerResponse(response, current.PGWControl.TEID, ebi)
	}
	if err != nil {
		g.emit(Event{Severity: "error", Procedure: "create-bearer-rollback", Peer: bearerPeer(current), Subscriber: current.SubscriberKey, Message: "could not remove provisional SGW bearer: " + err.Error()})
	}
}

func (g *Gateway) bestEffortUpdateSGWBearer(parent context.Context, current session.Session, bearer session.Bearer) {
	qos := DedicatedBearerQoS{
		QCI: bearer.QCI, ARP: bearer.ARP, PreemptionCapable: bearer.PreemptionCapable, PreemptionVulnerable: bearer.PreemptionVulnerable,
		UplinkMBR: bearer.UplinkMBR, DownlinkMBR: bearer.DownlinkMBR, UplinkGBR: bearer.UplinkGBR, DownlinkGBR: bearer.DownlinkGBR,
	}
	request, err := updateBearerRequest(current, bearer.EBI, qos)
	if err == nil {
		var response gtpv2.Message
		response, err = g.doBearerRequest(parent, current, request)
		if err == nil {
			err = parseBearerResponse(response, current.PGWControl.TEID, bearer.EBI)
		}
	}
	if err != nil {
		g.emit(Event{Severity: "error", Procedure: "update-bearer-rollback", Peer: bearerPeer(current), Subscriber: current.SubscriberKey, Message: "could not restore SGW bearer QoS: " + err.Error()})
	}
}

func (g *Gateway) bestEffortRestorePGWUBearer(parent context.Context, current session.Session, bearer session.Bearer) {
	tft, err := gtpv2.ParseBearerTFT(bearer.TFT)
	if err == nil {
		userSession := userPlaneSession(current)
		kept := userSession.Bearers[:0]
		for _, installed := range userSession.Bearers {
			if installed.Rules.QER != bearer.Rules.QER {
				kept = append(kept, installed)
			}
		}
		userSession.Bearers = kept
		opCtx, cancel := g.operationContext(parent)
		err = g.up.AddBearer(opCtx, &userSession, pfcpclient.BearerPlan{
			Rules: pfcpRuleIDs(bearer.Rules),
			Local: pfcpclient.Tunnel{TEID: bearer.PGWUser.TEID, IP: bearer.PGWUser.IP}, Remote: pfcpclient.Tunnel{TEID: bearer.SGWUser.TEID, IP: bearer.SGWUser.IP},
			UplinkBitrate: bearer.UplinkMBR, DownlinkBitrate: bearer.DownlinkMBR, QCI: bearer.QCI, ARP: bearer.ARP, TFT: tft,
		})
		cancel()
	}
	if err != nil {
		g.emit(Event{Severity: "error", Procedure: "delete-bearer-rollback", Peer: bearerPeer(current), Subscriber: current.SubscriberKey, Message: "could not restore PGW-U bearer: " + err.Error()})
	}
}

func (g *Gateway) bestEffortCreateSGWBearer(parent context.Context, current session.Session, bearer session.Bearer) {
	tft, err := gtpv2.ParseBearerTFT(bearer.TFT)
	if err != nil {
		return
	}
	qos := DedicatedBearerQoS{
		QCI: bearer.QCI, ARP: bearer.ARP, PreemptionCapable: bearer.PreemptionCapable, PreemptionVulnerable: bearer.PreemptionVulnerable,
		UplinkMBR: bearer.UplinkMBR, DownlinkMBR: bearer.DownlinkMBR, UplinkGBR: bearer.UplinkGBR, DownlinkGBR: bearer.DownlinkGBR,
	}
	request, err := createBearerRequest(current, bearer.EBI, bearer.PGWUser, qos, tft)
	if err == nil {
		var response gtpv2.Message
		response, err = g.doBearerRequest(parent, current, request)
		if err == nil {
			_, _, err = parseCreateBearerResponse(response, current, bearer.EBI, bearer.PGWUser)
		}
	}
	if err != nil {
		g.emit(Event{Severity: "error", Procedure: "delete-bearer-rollback", Peer: bearerPeer(current), Subscriber: current.SubscriberKey, Message: "could not recreate SGW bearer: " + err.Error()})
	}
}
