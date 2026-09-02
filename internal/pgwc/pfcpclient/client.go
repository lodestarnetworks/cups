// Package pfcpclient implements the PGW-C side of the LTE Sxb interface.
package pfcpclient

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	"github.com/lodestarnetworks/cups/internal/pfcp/usagereport"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
	"github.com/lodestarnetworks/cups/pkg/pfcp"
)

var (
	ErrNotAssociated = errors.New("pgwc PFCP: PGW-U is not associated")
	ErrRejected      = errors.New("pgwc PFCP: request rejected")
	ErrPeerRestarted = errors.New("pgwc PFCP: PGW-U recovery timestamp changed")
)

type Config struct {
	Listen                  netip.AddrPort
	Advertise               netip.Addr
	Remote                  netip.AddrPort
	StartedAt               time.Time
	EnterpriseID            uint16
	UsageReportingThreshold uint64
	UsageLedger             usagereport.LedgerConfig
	Transport               pfcptransport.Config
}

type Tunnel struct {
	TEID uint32
	IP   netip.Addr
}

// RuleIDs are PFCP-session scoped. Dedicated bearers can own multiple PDRs in
// either direction because one TS 24.008 TFT filter can expand into multiple
// standards-based SDF filters.
type RuleIDs struct {
	UplinkPDRs   []uint16
	DownlinkPDRs []uint16
	UplinkFAR    uint32
	DownlinkFAR  uint32
	QER          uint32
	URR          uint32
}

type BearerPlan struct {
	Rules           RuleIDs
	Local           Tunnel
	Remote          Tunnel
	UplinkBitrate   uint64
	DownlinkBitrate uint64
	QCI             uint8
	ARP             uint8
	TFT             gtpv2.TrafficFlowTemplate
}

type Bearer struct {
	Rules           RuleIDs
	Local           Tunnel
	Remote          Tunnel
	UplinkBitrate   uint64
	DownlinkBitrate uint64
	QCI             uint8
	ARP             uint8
}

type Establishment struct {
	CPSEID            uint64
	UEIPv4            netip.Addr
	Local             Tunnel
	Remote            Tunnel
	UplinkBitrate     uint64
	DownlinkBitrate   uint64
	QCI               uint8
	ARP               uint8
	AdditionalBearers []BearerPlan
}

type Session struct {
	CPSEID       uint64
	UPSEID       uint64
	UEIPv4       netip.Addr
	Local        Tunnel
	Remote       Tunnel
	DefaultRules RuleIDs
	Bearers      []Bearer
}

type Association struct {
	NodeAddress  netip.Addr
	NodeFQDN     string
	RecoveryTime time.Time
	Established  time.Time
	LastSeen     time.Time
}

type Client struct {
	config   Config
	endpoint *pfcptransport.Endpoint

	mu                        sync.RWMutex
	association               *Association
	lastRecovery              time.Time
	upSEIDByCP                map[uint64]uint64
	usageLedger               *usagereport.Ledger
	usageLedgerRemoveFailures atomic.Uint64
}

func New(config Config) (*Client, error) {
	if !config.Listen.Addr().IsValid() || !config.Advertise.Is4() || !config.Remote.Addr().Is4() || config.Remote.Port() == 0 {
		return nil, errors.New("pgwc PFCP: valid IPv4 listen, advertise, and remote addresses are required")
	}
	if config.EnterpriseID == 10415 {
		return nil, errors.New("pgwc PFCP: enterprise ID 10415 is reserved for 3GPP")
	}
	config.Advertise = config.Advertise.Unmap()
	config.Remote = netip.AddrPortFrom(config.Remote.Addr().Unmap(), config.Remote.Port())
	if config.StartedAt.IsZero() {
		config.StartedAt = time.Now().UTC()
	}
	if config.UsageReportingThreshold == 0 {
		config.UsageReportingThreshold = 1 << 30
	}
	usageLedger, err := usagereport.OpenLedger(config.UsageLedger)
	if err != nil {
		return nil, fmt.Errorf("pgwc PFCP: open usage-report ledger: %w", err)
	}
	client := &Client{config: config, upSEIDByCP: make(map[uint64]uint64), usageLedger: usageLedger}
	endpoint, err := pfcptransport.Listen(config.Listen, client.handle, config.Transport)
	if err != nil {
		return nil, errors.Join(err, usageLedger.Close())
	}
	client.endpoint = endpoint
	return client, nil
}

func (c *Client) Serve(ctx context.Context) error { return c.endpoint.Serve(ctx) }
func (c *Client) Close() error                    { return errors.Join(c.endpoint.Close(), c.usageLedger.Close()) }
func (c *Client) LocalAddr() netip.AddrPort       { return c.endpoint.LocalAddr() }
func (c *Client) TransportCounters() pfcptransport.Counters {
	return c.endpoint.Counters()
}

func (c *Client) UsageLedgerStats() usagereport.LedgerStats { return c.usageLedger.Stats() }

func (c *Client) UsageLedgerRemoveFailures() uint64 { return c.usageLedgerRemoveFailures.Load() }

func (c *Client) Association() (Association, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.association == nil {
		return Association{}, false
	}
	return *c.association, true
}

func (c *Client) Associate(ctx context.Context) error {
	nodeID, _ := pfcp.NewNodeIDIE(c.config.Advertise, "")
	recovery, _ := pfcp.NewRecoveryTimeStampIE(c.config.StartedAt)
	response, err := c.endpoint.Do(ctx, c.config.Remote, pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, MessageType: pfcp.MessageAssociationSetupRequest},
		IEs:    []pfcp.IE{nodeID, recovery},
	})
	if err != nil {
		return fmt.Errorf("associate PGW-U %s: %w", c.config.Remote, err)
	}
	if err := accepted(response); err != nil {
		return fmt.Errorf("associate PGW-U %s: %w", c.config.Remote, err)
	}
	nodeIE, nodeOK := response.Find(pfcp.IENodeID)
	recoveryIE, recoveryOK := response.Find(pfcp.IERecoveryTimeStamp)
	if !nodeOK || !recoveryOK {
		return pfcp.ErrMissingIE
	}
	nodeAddress, nodeFQDN, err := nodeIE.NodeID()
	if err != nil {
		return err
	}
	recoveryTime, err := recoveryIE.RecoveryTimeStamp()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	c.mu.Lock()
	restarted := !c.lastRecovery.IsZero() && !c.lastRecovery.Equal(recoveryTime)
	c.association = &Association{NodeAddress: nodeAddress, NodeFQDN: nodeFQDN, RecoveryTime: recoveryTime, Established: now, LastSeen: now}
	c.lastRecovery = recoveryTime
	c.mu.Unlock()
	if restarted {
		return ErrPeerRestarted
	}
	return nil
}

func (c *Client) Heartbeat(ctx context.Context) error {
	recovery, _ := pfcp.NewRecoveryTimeStampIE(c.config.StartedAt)
	response, err := c.endpoint.Do(ctx, c.config.Remote, pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, MessageType: pfcp.MessageHeartbeatRequest},
		IEs:    []pfcp.IE{recovery},
	})
	if err != nil {
		return err
	}
	remoteRecovery, ok := response.Find(pfcp.IERecoveryTimeStamp)
	if !ok {
		return pfcp.ErrMissingIE
	}
	recoveryTime, err := remoteRecovery.RecoveryTimeStamp()
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.association == nil {
		c.mu.Unlock()
		return ErrNotAssociated
	}
	if !c.lastRecovery.IsZero() && !c.lastRecovery.Equal(recoveryTime) {
		c.association = nil
		c.lastRecovery = recoveryTime
		c.mu.Unlock()
		return ErrPeerRestarted
	}
	c.lastRecovery = recoveryTime
	c.association.LastSeen = time.Now().UTC()
	c.mu.Unlock()
	return nil
}

// CompleteReconciliation tells the PGW-U that every authoritative session has
// been replayed. The PGW-U may then remove any rule set that was not reaffirmed
// and resume accepting new sessions.
func (c *Client) CompleteReconciliation(ctx context.Context) error {
	if _, ok := c.Association(); !ok {
		return ErrNotAssociated
	}
	nodeID, _ := pfcp.NewNodeIDIE(c.config.Advertise, "")
	response, err := c.endpoint.Do(ctx, c.config.Remote, pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, MessageType: pfcp.MessageAssociationUpdateRequest},
		IEs:    []pfcp.IE{nodeID},
	})
	if err != nil {
		return fmt.Errorf("complete PGW-U reconciliation: %w", err)
	}
	if err := accepted(response); err != nil {
		return fmt.Errorf("complete PGW-U reconciliation: %w", err)
	}
	return nil
}

// MarkUnavailable prevents new PFCP session operations while a failed
// association is inside its grace/reconnect path. Existing PGW-U rules are not
// touched.
func (c *Client) MarkUnavailable() {
	c.mu.Lock()
	c.association = nil
	c.mu.Unlock()
}

func (c *Client) Establish(ctx context.Context, plan Establishment) (Session, error) {
	if _, ok := c.Association(); !ok {
		return Session{}, ErrNotAssociated
	}
	if err := validateEstablishment(plan); err != nil {
		return Session{}, err
	}
	ies, err := c.establishmentIEs(plan)
	if err != nil {
		return Session{}, err
	}
	response, err := c.endpoint.Do(ctx, c.config.Remote, pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, HasSEID: true, MessageType: pfcp.MessageSessionEstablishmentRequest},
		IEs:    ies,
	})
	if err != nil {
		return Session{}, fmt.Errorf("establish PGW-U session: %w", err)
	}
	if response.Header.SEID != plan.CPSEID {
		return Session{}, fmt.Errorf("establish PGW-U session: response CP-SEID %d, expected %d", response.Header.SEID, plan.CPSEID)
	}
	if err := accepted(response); err != nil {
		return Session{}, fmt.Errorf("establish PGW-U session: %w", err)
	}
	fseidIE, ok := response.Find(pfcp.IEFSEID)
	if !ok {
		return Session{}, pfcp.ErrMissingIE
	}
	fseid, err := fseidIE.FSEID()
	if err != nil {
		return Session{}, err
	}
	session := Session{
		CPSEID: plan.CPSEID, UPSEID: fseid.SEID, UEIPv4: plan.UEIPv4.Unmap(),
		Local: canonicalTunnel(plan.Local), Remote: canonicalTunnel(plan.Remote), DefaultRules: defaultRuleIDs(),
	}
	for _, bearer := range plan.AdditionalBearers {
		session.Bearers = append(session.Bearers, installedBearer(bearer))
	}
	c.mu.Lock()
	c.upSEIDByCP[session.CPSEID] = session.UPSEID
	c.mu.Unlock()
	return session, nil
}

func (c *Client) UpdateRemote(ctx context.Context, session *Session, remote Tunnel) error {
	if session == nil || session.CPSEID == 0 || session.UPSEID == 0 {
		return errors.New("pgwc PFCP: invalid session")
	}
	if err := validateTunnel(remote); err != nil {
		return err
	}
	downlinkFAR := session.DefaultRules.DownlinkFAR
	if downlinkFAR == 0 {
		downlinkFAR = 2
	}
	farID, _ := pfcp.NewUint32IE(pfcp.IEFARID, downlinkFAR)
	action, _ := pfcp.NewApplyActionIE(pfcp.ApplyForward)
	destination, _ := pfcp.NewInterfaceIE(pfcp.IEDestinationInterface, pfcp.InterfaceAccess)
	outer, _ := pfcp.NewOuterHeaderCreationIE(pfcp.OuterHeader{Description: pfcp.OuterHeaderGTPUUDPIPv4, TEID: remote.TEID, IPv4: remote.IP})
	forwarding, _ := pfcp.NewGroupedIE(pfcp.IEUpdateForwardingParameters, destination, outer)
	update, _ := pfcp.NewGroupedIE(pfcp.IEUpdateFAR, farID, action, forwarding)
	response, err := c.endpoint.Do(ctx, c.config.Remote, pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, HasSEID: true, MessageType: pfcp.MessageSessionModificationRequest, SEID: session.UPSEID},
		IEs:    []pfcp.IE{update},
	})
	if err != nil {
		return fmt.Errorf("update PGW-U remote tunnel: %w", err)
	}
	if response.Header.SEID != session.CPSEID {
		return errors.New("update PGW-U remote tunnel: wrong response SEID")
	}
	if err := accepted(response); err != nil {
		return fmt.Errorf("update PGW-U remote tunnel: %w", err)
	}
	session.Remote = canonicalTunnel(remote)
	return nil
}

// AddBearer atomically installs one TFT-classified dedicated bearer in an
// existing Sxb session.
func (c *Client) AddBearer(ctx context.Context, session *Session, plan BearerPlan) error {
	if err := validateClientSession(session); err != nil {
		return err
	}
	if err := validateBearerPlan(plan); err != nil {
		return err
	}
	if err := ensureRuleIDsAvailable(*session, plan.Rules); err != nil {
		return err
	}
	ies, err := c.bearerCreateIEs(session.UEIPv4, plan)
	if err != nil {
		return err
	}
	if err := c.modifySession(ctx, session, "add PGW-U dedicated bearer", ies); err != nil {
		return err
	}
	session.Bearers = append(session.Bearers, installedBearer(plan))
	return nil
}

// UpdateBearerQoS replaces a dedicated bearer's gates-open QER, MBR, and
// optional Lodestar QCI/ARP metadata while preserving its classifier rules.
func (c *Client) UpdateBearerQoS(ctx context.Context, session *Session, ids RuleIDs, qci, arp uint8, uplinkBps, downlinkBps uint64) error {
	if err := validateClientSession(session); err != nil {
		return err
	}
	index := findBearer(*session, ids)
	if index < 0 {
		return errors.New("pgwc PFCP: dedicated bearer not found")
	}
	if qci == 0 || qci == 255 || arp == 0 || arp > 15 {
		return errors.New("pgwc PFCP: invalid QCI/ARP")
	}
	if err := validateBitrates(uplinkBps, downlinkBps); err != nil {
		return err
	}
	qer, err := createQER(pfcp.IEUpdateQER, ids.QER, uplinkBps, downlinkBps, c.config.EnterpriseID, qci, arp)
	if err != nil {
		return err
	}
	if err := c.modifySession(ctx, session, "update PGW-U dedicated bearer QoS", []pfcp.IE{qer}); err != nil {
		return err
	}
	bearer := &session.Bearers[index]
	bearer.QCI, bearer.ARP = qci, arp
	bearer.UplinkBitrate, bearer.DownlinkBitrate = uplinkBps, downlinkBps
	return nil
}

func (c *Client) UpdateBearerRemote(ctx context.Context, session *Session, ids RuleIDs, remote Tunnel) error {
	if err := validateClientSession(session); err != nil {
		return err
	}
	index := findBearer(*session, ids)
	if index < 0 {
		return errors.New("pgwc PFCP: dedicated bearer not found")
	}
	if err := validateTunnel(remote); err != nil {
		return err
	}
	farID, _ := pfcp.NewUint32IE(pfcp.IEFARID, ids.DownlinkFAR)
	action, _ := pfcp.NewApplyActionIE(pfcp.ApplyForward)
	destination, _ := pfcp.NewInterfaceIE(pfcp.IEDestinationInterface, pfcp.InterfaceAccess)
	outer, _ := pfcp.NewOuterHeaderCreationIE(pfcp.OuterHeader{Description: pfcp.OuterHeaderGTPUUDPIPv4, TEID: remote.TEID, IPv4: remote.IP})
	forwarding, _ := pfcp.NewGroupedIE(pfcp.IEUpdateForwardingParameters, destination, outer)
	update, _ := pfcp.NewGroupedIE(pfcp.IEUpdateFAR, farID, action, forwarding)
	if err := c.modifySession(ctx, session, "update PGW-U dedicated bearer tunnel", []pfcp.IE{update}); err != nil {
		return err
	}
	session.Bearers[index].Remote = canonicalTunnel(remote)
	return nil
}

// RemoveBearer sends every rule ID owned by one dedicated bearer. PGW-U
// rejects partial rule removal, so no half-installed classifier can commit.
func (c *Client) RemoveBearer(ctx context.Context, session *Session, ids RuleIDs) error {
	if err := validateClientSession(session); err != nil {
		return err
	}
	index := findBearer(*session, ids)
	if index < 0 {
		return errors.New("pgwc PFCP: dedicated bearer not found")
	}
	ies := make([]pfcp.IE, 0, len(ids.UplinkPDRs)+len(ids.DownlinkPDRs)+4)
	for _, id := range append(append([]uint16(nil), ids.UplinkPDRs...), ids.DownlinkPDRs...) {
		idIE, _ := pfcp.NewPDRIDIE(id)
		grouped, _ := pfcp.NewGroupedIE(pfcp.IERemovePDR, idIE)
		ies = append(ies, grouped)
	}
	for _, item := range []struct {
		groupType uint16
		idType    uint16
		id        uint32
	}{
		{pfcp.IERemoveFAR, pfcp.IEFARID, ids.UplinkFAR},
		{pfcp.IERemoveFAR, pfcp.IEFARID, ids.DownlinkFAR},
		{pfcp.IERemoveQER, pfcp.IEQERID, ids.QER},
		{pfcp.IERemoveURR, pfcp.IEURRID, ids.URR},
	} {
		idIE, _ := pfcp.NewUint32IE(item.idType, item.id)
		grouped, _ := pfcp.NewGroupedIE(item.groupType, idIE)
		ies = append(ies, grouped)
	}
	if err := c.modifySession(ctx, session, "remove PGW-U dedicated bearer", ies); err != nil {
		return err
	}
	session.Bearers = append(session.Bearers[:index], session.Bearers[index+1:]...)
	return nil
}

func (c *Client) modifySession(ctx context.Context, session *Session, operation string, ies []pfcp.IE) error {
	if _, ok := c.Association(); !ok {
		return ErrNotAssociated
	}
	response, err := c.endpoint.Do(ctx, c.config.Remote, pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, HasSEID: true, MessageType: pfcp.MessageSessionModificationRequest, SEID: session.UPSEID},
		IEs:    ies,
	})
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	if response.Header.SEID != session.CPSEID {
		return fmt.Errorf("%s: wrong response SEID", operation)
	}
	if err := accepted(response); err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return nil
}

func validateClientSession(session *Session) error {
	if session == nil || session.CPSEID == 0 || session.UPSEID == 0 || !session.UEIPv4.Is4() {
		return errors.New("pgwc PFCP: invalid session")
	}
	return nil
}

func ensureRuleIDsAvailable(session Session, ids RuleIDs) error {
	pdrs, fars, qers, urrs := clientSessionRuleIDs(session)
	for _, id := range append(append([]uint16(nil), ids.UplinkPDRs...), ids.DownlinkPDRs...) {
		if pdrs[id] {
			return fmt.Errorf("pgwc PFCP: PDR ID %d already exists", id)
		}
	}
	for _, id := range []uint32{ids.UplinkFAR, ids.DownlinkFAR} {
		if fars[id] {
			return fmt.Errorf("pgwc PFCP: FAR ID %d already exists", id)
		}
	}
	if qers[ids.QER] {
		return fmt.Errorf("pgwc PFCP: QER ID %d already exists", ids.QER)
	}
	if urrs[ids.URR] {
		return fmt.Errorf("pgwc PFCP: URR ID %d already exists", ids.URR)
	}
	return nil
}

func clientSessionRuleIDs(session Session) (map[uint16]bool, map[uint32]bool, map[uint32]bool, map[uint32]bool) {
	pdrs, fars, qers, urrs := make(map[uint16]bool), make(map[uint32]bool), make(map[uint32]bool), make(map[uint32]bool)
	defaultIDs := session.DefaultRules
	if len(defaultIDs.UplinkPDRs) == 0 {
		defaultIDs = defaultRuleIDs()
	}
	for _, id := range append(append([]uint16(nil), defaultIDs.UplinkPDRs...), defaultIDs.DownlinkPDRs...) {
		pdrs[id] = true
	}
	fars[defaultIDs.UplinkFAR], fars[defaultIDs.DownlinkFAR], qers[defaultIDs.QER], urrs[defaultIDs.URR] = true, true, true, true
	for _, bearer := range session.Bearers {
		for _, id := range append(append([]uint16(nil), bearer.Rules.UplinkPDRs...), bearer.Rules.DownlinkPDRs...) {
			pdrs[id] = true
		}
		fars[bearer.Rules.UplinkFAR], fars[bearer.Rules.DownlinkFAR] = true, true
		qers[bearer.Rules.QER], urrs[bearer.Rules.URR] = true, true
	}
	return pdrs, fars, qers, urrs
}

func findBearer(session Session, ids RuleIDs) int {
	for index := range session.Bearers {
		if equalRuleIDs(session.Bearers[index].Rules, ids) {
			return index
		}
	}
	return -1
}

func equalRuleIDs(left, right RuleIDs) bool {
	if left.UplinkFAR != right.UplinkFAR || left.DownlinkFAR != right.DownlinkFAR || left.QER != right.QER || left.URR != right.URR ||
		len(left.UplinkPDRs) != len(right.UplinkPDRs) || len(left.DownlinkPDRs) != len(right.DownlinkPDRs) {
		return false
	}
	for index := range left.UplinkPDRs {
		if left.UplinkPDRs[index] != right.UplinkPDRs[index] {
			return false
		}
	}
	for index := range left.DownlinkPDRs {
		if left.DownlinkPDRs[index] != right.DownlinkPDRs[index] {
			return false
		}
	}
	return true
}

func (c *Client) Delete(ctx context.Context, session Session) error {
	if session.CPSEID == 0 || session.UPSEID == 0 {
		return errors.New("pgwc PFCP: invalid session")
	}
	response, err := c.endpoint.Do(ctx, c.config.Remote, pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, HasSEID: true, MessageType: pfcp.MessageSessionDeletionRequest, SEID: session.UPSEID},
	})
	if err != nil {
		return fmt.Errorf("delete PGW-U session: %w", err)
	}
	causeIE, ok := response.Find(pfcp.IECause)
	if !ok {
		return fmt.Errorf("delete PGW-U session: %w", pfcp.ErrMissingIE)
	}
	cause, err := causeIE.Cause()
	if err != nil {
		return fmt.Errorf("delete PGW-U session: %w", err)
	}
	if cause != pfcp.CauseSessionNotFound {
		if response.Header.SEID != session.CPSEID {
			return errors.New("delete PGW-U session: wrong response SEID")
		}
		if cause != pfcp.CauseRequestAccepted {
			return fmt.Errorf("delete PGW-U session: %w: cause %d", ErrRejected, cause)
		}
	}
	c.mu.Lock()
	delete(c.upSEIDByCP, session.CPSEID)
	c.mu.Unlock()
	if err := c.usageLedger.RemoveSession(session.CPSEID); err != nil {
		c.usageLedgerRemoveFailures.Add(1)
	}
	return nil
}

func (c *Client) handle(_ context.Context, peer netip.AddrPort, request pfcp.Message) (*pfcp.Message, error) {
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	if peer != c.config.Remote {
		return nil, nil
	}
	switch request.Header.MessageType {
	case pfcp.MessageHeartbeatRequest:
		recovery, _ := pfcp.NewRecoveryTimeStampIE(c.config.StartedAt)
		return &pfcp.Message{Header: pfcp.Header{Version: pfcp.Version, MessageType: pfcp.MessageHeartbeatResponse}, IEs: []pfcp.IE{recovery}}, nil
	case pfcp.MessageSessionReportRequest:
		return c.handleSessionReport(request), nil
	default:
		return nil, nil
	}
}

func (c *Client) handleSessionReport(request pfcp.Message) *pfcp.Message {
	cpSEID := request.Header.SEID
	c.mu.RLock()
	upSEID, found := c.upSEIDByCP[cpSEID]
	association := c.association
	c.mu.RUnlock()
	respond := func(cause uint8) *pfcp.Message {
		return &pfcp.Message{
			Header: pfcp.Header{Version: pfcp.Version, HasSEID: true, MessageType: pfcp.MessageSessionReportResponse, SEID: upSEID},
			IEs:    []pfcp.IE{pfcp.NewCauseIE(cause)},
		}
	}
	if association == nil {
		return respond(pfcp.CauseNoAssociation)
	}
	if !request.Header.HasSEID || cpSEID == 0 || !found {
		return respond(pfcp.CauseSessionNotFound)
	}
	reportTypeIE, ok := request.Find(pfcp.IEReportType)
	if !ok {
		return respond(pfcp.CauseMandatoryIEMissing)
	}
	reportType, err := reportTypeIE.ReportType()
	if err != nil || reportType != pfcp.ReportUsage {
		return respond(pfcp.CauseMandatoryIEIncorrect)
	}
	usageIEs := pfcp.FindAllIEs(request.IEs, pfcp.IEUsageReportSessionReport)
	if len(usageIEs) == 0 {
		return respond(pfcp.CauseMandatoryIEMissing)
	}
	reports := make([]usagereport.Report, 0, len(usageIEs))
	for _, grouped := range usageIEs {
		report, err := usagereport.Decode(cpSEID, grouped)
		if err != nil {
			return respond(pfcp.CauseMandatoryIEIncorrect)
		}
		reports = append(reports, report)
	}
	if _, err := c.usageLedger.Accept(association.RecoveryTime, reports); err != nil {
		return respond(pfcp.CauseSystemFailure)
	}
	return respond(pfcp.CauseRequestAccepted)
}

func (c *Client) establishmentIEs(plan Establishment) ([]pfcp.IE, error) {
	nodeID, _ := pfcp.NewNodeIDIE(c.config.Advertise, "")
	cpFSEID, _ := pfcp.NewFSEIDIE(pfcp.FSEID{SEID: plan.CPSEID, IPv4: c.config.Advertise})
	ruleIDs := defaultRuleIDs()
	uplinkPDR, err := createPDR(1, 100, pfcp.InterfaceAccess, plan.UEIPv4, false, &plan.Local, true, nil, ruleIDs.UplinkFAR, ruleIDs.QER, ruleIDs.URR)
	if err != nil {
		return nil, err
	}
	downlinkPDR, err := createPDR(2, 100, pfcp.InterfaceCore, plan.UEIPv4, true, nil, false, nil, ruleIDs.DownlinkFAR, ruleIDs.QER, ruleIDs.URR)
	if err != nil {
		return nil, err
	}
	uplinkFAR, err := createForwardingFAR(1, pfcp.InterfaceCore, nil)
	if err != nil {
		return nil, err
	}
	downlinkFAR, err := createForwardingFAR(2, pfcp.InterfaceAccess, &plan.Remote)
	if err != nil {
		return nil, err
	}
	qer, err := createQER(pfcp.IECreateQER, ruleIDs.QER, plan.UplinkBitrate, plan.DownlinkBitrate, c.config.EnterpriseID, plan.QCI, plan.ARP)
	if err != nil {
		return nil, err
	}
	urr, err := createURR(pfcp.IECreateURR, ruleIDs.URR, c.config.UsageReportingThreshold)
	if err != nil {
		return nil, err
	}
	ies := []pfcp.IE{nodeID, cpFSEID, uplinkPDR, downlinkPDR, uplinkFAR, downlinkFAR, qer, urr, {Type: pfcp.IEPDNType, Value: []byte{1}}}
	for _, bearer := range plan.AdditionalBearers {
		created, err := c.bearerCreateIEs(plan.UEIPv4, bearer)
		if err != nil {
			return nil, err
		}
		ies = append(ies, created...)
	}
	return ies, nil
}

func createPDR(id uint16, precedence uint32, source uint8, ue netip.Addr, destination bool, local *Tunnel, removeOuter bool, sdf *pfcp.SDFFilter, farID, qerID, urrID uint32) (pfcp.IE, error) {
	pdrID, _ := pfcp.NewPDRIDIE(id)
	precedenceIE, _ := pfcp.NewUint32IE(pfcp.IEPrecedence, precedence)
	sourceIE, _ := pfcp.NewInterfaceIE(pfcp.IESourceInterface, source)
	ueIE, err := pfcp.NewUEIPAddressIE(ue, destination)
	if err != nil {
		return pfcp.IE{}, err
	}
	pdiChildren := []pfcp.IE{sourceIE, ueIE}
	if local != nil {
		fteid, err := pfcp.NewFTEIDIE(pfcp.FTEID{TEID: local.TEID, IPv4: local.IP})
		if err != nil {
			return pfcp.IE{}, err
		}
		pdiChildren = append(pdiChildren, fteid)
	}
	if sdf != nil {
		sdfIE, err := pfcp.NewSDFFilterIE(*sdf)
		if err != nil {
			return pfcp.IE{}, err
		}
		pdiChildren = append(pdiChildren, sdfIE)
	}
	pdi, _ := pfcp.NewGroupedIE(pfcp.IEPDI, pdiChildren...)
	far, _ := pfcp.NewUint32IE(pfcp.IEFARID, farID)
	qer, _ := pfcp.NewUint32IE(pfcp.IEQERID, qerID)
	urr, _ := pfcp.NewUint32IE(pfcp.IEURRID, urrID)
	children := []pfcp.IE{pdrID, precedenceIE, pdi, far, qer, urr}
	if removeOuter {
		removal, _ := pfcp.NewOuterHeaderRemovalIE(pfcp.OuterHeaderRemovalGTPUUDPIPv4)
		children = append(children, removal)
	}
	return pfcp.NewGroupedIE(pfcp.IECreatePDR, children...)
}

func createURR(groupType uint16, id uint32, thresholdBytes uint64) (pfcp.IE, error) {
	urrID, err := pfcp.NewUint32IE(pfcp.IEURRID, id)
	if err != nil {
		return pfcp.IE{}, err
	}
	method, err := pfcp.NewMeasurementMethodIE(true, true)
	if err != nil {
		return pfcp.IE{}, err
	}
	triggers, err := pfcp.NewReportingTriggersIE(pfcp.ReportingTriggerVolumeThreshold)
	if err != nil {
		return pfcp.IE{}, err
	}
	threshold, err := pfcp.NewTotalVolumeThresholdIE(thresholdBytes)
	if err != nil {
		return pfcp.IE{}, err
	}
	return pfcp.NewGroupedIE(groupType, urrID, method, triggers, threshold)
}

func createForwardingFAR(id uint32, destination uint8, remote *Tunnel) (pfcp.IE, error) {
	farID, _ := pfcp.NewUint32IE(pfcp.IEFARID, id)
	action, _ := pfcp.NewApplyActionIE(pfcp.ApplyForward)
	destinationIE, _ := pfcp.NewInterfaceIE(pfcp.IEDestinationInterface, destination)
	parameters := []pfcp.IE{destinationIE}
	if remote != nil {
		outer, err := pfcp.NewOuterHeaderCreationIE(pfcp.OuterHeader{Description: pfcp.OuterHeaderGTPUUDPIPv4, TEID: remote.TEID, IPv4: remote.IP})
		if err != nil {
			return pfcp.IE{}, err
		}
		parameters = append(parameters, outer)
	}
	forwarding, _ := pfcp.NewGroupedIE(pfcp.IEForwardingParameters, parameters...)
	return pfcp.NewGroupedIE(pfcp.IECreateFAR, farID, action, forwarding)
}

func createQER(groupType uint16, id uint32, uplinkBps, downlinkBps uint64, enterpriseID uint16, qci, arp uint8) (pfcp.IE, error) {
	qerID, _ := pfcp.NewUint32IE(pfcp.IEQERID, id)
	children := []pfcp.IE{qerID, pfcp.NewGateStatusIE(true, true)}
	if uplinkBps > 0 || downlinkBps > 0 {
		mbr, err := pfcp.NewBitRateIE(pfcp.IEMBR, uplinkBps/1000, downlinkBps/1000)
		if err != nil {
			return pfcp.IE{}, err
		}
		children = append(children, mbr)
	}
	if enterpriseID != 0 && qci != 0 && arp != 0 {
		metadata, err := pfcp.NewVendorBearerQoSIE(pfcp.BearerQoSMetadata{EnterpriseID: enterpriseID, QCI: qci, ARP: arp})
		if err != nil {
			return pfcp.IE{}, err
		}
		children = append(children, metadata)
	}
	return pfcp.NewGroupedIE(groupType, children...)
}

func (c *Client) bearerCreateIEs(ue netip.Addr, plan BearerPlan) ([]pfcp.IE, error) {
	uplinkPlans, downlinkPlans, err := directionalSDFPlans(plan.TFT)
	if err != nil {
		return nil, err
	}
	ies := make([]pfcp.IE, 0, len(uplinkPlans)+len(downlinkPlans)+4)
	for index, sdf := range uplinkPlans {
		pdr, err := createPDR(plan.Rules.UplinkPDRs[index], sdf.Precedence, pfcp.InterfaceAccess, ue, false, &plan.Local, true, &sdf.Filter, plan.Rules.UplinkFAR, plan.Rules.QER, plan.Rules.URR)
		if err != nil {
			return nil, err
		}
		ies = append(ies, pdr)
	}
	for index, sdf := range downlinkPlans {
		pdr, err := createPDR(plan.Rules.DownlinkPDRs[index], sdf.Precedence, pfcp.InterfaceCore, ue, true, nil, false, &sdf.Filter, plan.Rules.DownlinkFAR, plan.Rules.QER, plan.Rules.URR)
		if err != nil {
			return nil, err
		}
		ies = append(ies, pdr)
	}
	uplinkFAR, err := createForwardingFAR(plan.Rules.UplinkFAR, pfcp.InterfaceCore, nil)
	if err != nil {
		return nil, err
	}
	downlinkFAR, err := createForwardingFAR(plan.Rules.DownlinkFAR, pfcp.InterfaceAccess, &plan.Remote)
	if err != nil {
		return nil, err
	}
	qer, err := createQER(pfcp.IECreateQER, plan.Rules.QER, plan.UplinkBitrate, plan.DownlinkBitrate, c.config.EnterpriseID, plan.QCI, plan.ARP)
	if err != nil {
		return nil, err
	}
	urr, err := createURR(pfcp.IECreateURR, plan.Rules.URR, c.config.UsageReportingThreshold)
	if err != nil {
		return nil, err
	}
	return append(ies, uplinkFAR, downlinkFAR, qer, urr), nil
}

func directionalSDFPlans(tft gtpv2.TrafficFlowTemplate) (uplink, downlink []SDFPlan, err error) {
	plans, err := SDFPlansFromTFT(tft)
	if err != nil {
		return nil, nil, err
	}
	for _, plan := range plans {
		switch plan.Direction {
		case gtpv2.TFTDirectionUplink:
			uplink = append(uplink, plan)
		case gtpv2.TFTDirectionDownlink:
			downlink = append(downlink, plan)
		case gtpv2.TFTDirectionBidirectional:
			uplink = append(uplink, plan)
			downlink = append(downlink, plan)
		default:
			return nil, nil, fmt.Errorf("pgwc PFCP: unsupported TFT direction %d", plan.Direction)
		}
	}
	if len(uplink) == 0 || len(downlink) == 0 {
		return nil, nil, errors.New("pgwc PFCP: dedicated bearer TFT must cover uplink and downlink")
	}
	return uplink, downlink, nil
}

func validateEstablishment(plan Establishment) error {
	if plan.CPSEID == 0 || !plan.UEIPv4.Is4() || plan.UEIPv4.IsUnspecified() || plan.UEIPv4.IsMulticast() {
		return errors.New("pgwc PFCP: CP-SEID and valid UE IPv4 address are required")
	}
	if err := validateTunnel(plan.Local); err != nil {
		return fmt.Errorf("local tunnel: %w", err)
	}
	if err := validateTunnel(plan.Remote); err != nil {
		return fmt.Errorf("remote tunnel: %w", err)
	}
	if err := validateBitrates(plan.UplinkBitrate, plan.DownlinkBitrate); err != nil {
		return err
	}
	if (plan.QCI == 0) != (plan.ARP == 0) || plan.ARP > 15 {
		return errors.New("pgwc PFCP: default QCI and ARP must both be omitted or valid")
	}
	if len(plan.AdditionalBearers) > 10 {
		return errors.New("pgwc PFCP: more than 10 dedicated bearers requested")
	}
	pdrs := map[uint16]struct{}{1: {}, 2: {}}
	fars := map[uint32]struct{}{1: {}, 2: {}}
	qers := map[uint32]struct{}{1: {}}
	urrs := map[uint32]struct{}{1: {}}
	for index, bearer := range plan.AdditionalBearers {
		if err := validateBearerPlan(bearer); err != nil {
			return fmt.Errorf("pgwc PFCP: dedicated bearer %d: %w", index, err)
		}
		for _, id := range append(append([]uint16(nil), bearer.Rules.UplinkPDRs...), bearer.Rules.DownlinkPDRs...) {
			if _, duplicate := pdrs[id]; duplicate {
				return fmt.Errorf("pgwc PFCP: duplicate PDR ID %d", id)
			}
			pdrs[id] = struct{}{}
		}
		for _, id := range []uint32{bearer.Rules.UplinkFAR, bearer.Rules.DownlinkFAR} {
			if _, duplicate := fars[id]; duplicate {
				return fmt.Errorf("pgwc PFCP: duplicate FAR ID %d", id)
			}
			fars[id] = struct{}{}
		}
		if _, duplicate := qers[bearer.Rules.QER]; duplicate {
			return fmt.Errorf("pgwc PFCP: duplicate QER ID %d", bearer.Rules.QER)
		}
		if _, duplicate := urrs[bearer.Rules.URR]; duplicate {
			return fmt.Errorf("pgwc PFCP: duplicate URR ID %d", bearer.Rules.URR)
		}
		qers[bearer.Rules.QER], urrs[bearer.Rules.URR] = struct{}{}, struct{}{}
	}
	return nil
}

func validateBearerPlan(plan BearerPlan) error {
	if err := validateTunnel(plan.Local); err != nil {
		return fmt.Errorf("local tunnel: %w", err)
	}
	if err := validateTunnel(plan.Remote); err != nil {
		return fmt.Errorf("remote tunnel: %w", err)
	}
	if plan.QCI == 0 || plan.QCI == 255 || plan.ARP == 0 || plan.ARP > 15 {
		return errors.New("invalid QCI/ARP")
	}
	if err := validateBitrates(plan.UplinkBitrate, plan.DownlinkBitrate); err != nil {
		return err
	}
	if err := validateRuleIDs(plan.Rules); err != nil {
		return err
	}
	uplink, downlink, err := directionalSDFPlans(plan.TFT)
	if err != nil {
		return err
	}
	if len(plan.Rules.UplinkPDRs) != len(uplink) || len(plan.Rules.DownlinkPDRs) != len(downlink) {
		return fmt.Errorf("PDR IDs provide %d uplink/%d downlink entries, TFT requires %d/%d", len(plan.Rules.UplinkPDRs), len(plan.Rules.DownlinkPDRs), len(uplink), len(downlink))
	}
	return nil
}

func validateRuleIDs(ids RuleIDs) error {
	if len(ids.UplinkPDRs) == 0 || len(ids.DownlinkPDRs) == 0 || ids.UplinkFAR == 0 || ids.DownlinkFAR == 0 || ids.UplinkFAR == ids.DownlinkFAR || ids.QER == 0 || ids.URR == 0 {
		return errors.New("invalid dedicated-bearer PFCP rule IDs")
	}
	seen := make(map[uint16]struct{}, len(ids.UplinkPDRs)+len(ids.DownlinkPDRs))
	for _, id := range append(append([]uint16(nil), ids.UplinkPDRs...), ids.DownlinkPDRs...) {
		if id == 0 {
			return errors.New("zero dedicated-bearer PDR ID")
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("duplicate dedicated-bearer PDR ID %d", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func validateBitrates(uplink, downlink uint64) error {
	const max = uint64(^uint32(0)) * 1000
	if uplink%1000 != 0 || downlink%1000 != 0 || uplink > max || downlink > max {
		return errors.New("pgwc PFCP: bitrates must be whole kilobits per second within PFCP's 32-bit range")
	}
	return nil
}

func defaultRuleIDs() RuleIDs {
	return RuleIDs{UplinkPDRs: []uint16{1}, DownlinkPDRs: []uint16{2}, UplinkFAR: 1, DownlinkFAR: 2, QER: 1, URR: 1}
}

// DefaultRuleIDs returns an independent copy of the fixed rule set reserved
// for the default EPS bearer in every PGW-U PFCP session.
func DefaultRuleIDs() RuleIDs { return defaultRuleIDs() }

func installedBearer(plan BearerPlan) Bearer {
	return Bearer{
		Rules: cloneRuleIDs(plan.Rules), Local: canonicalTunnel(plan.Local), Remote: canonicalTunnel(plan.Remote),
		UplinkBitrate: plan.UplinkBitrate, DownlinkBitrate: plan.DownlinkBitrate, QCI: plan.QCI, ARP: plan.ARP,
	}
}

func cloneRuleIDs(ids RuleIDs) RuleIDs {
	ids.UplinkPDRs = append([]uint16(nil), ids.UplinkPDRs...)
	ids.DownlinkPDRs = append([]uint16(nil), ids.DownlinkPDRs...)
	return ids
}

func validateTunnel(tunnel Tunnel) error {
	if tunnel.TEID == 0 || !tunnel.IP.Is4() {
		return errors.New("valid IPv4 F-TEID is required")
	}
	return nil
}

func accepted(response pfcp.Message) error {
	causeIE, ok := response.Find(pfcp.IECause)
	if !ok {
		return pfcp.ErrMissingIE
	}
	cause, err := causeIE.Cause()
	if err != nil {
		return err
	}
	if cause != pfcp.CauseRequestAccepted {
		return fmt.Errorf("%w: cause %d", ErrRejected, cause)
	}
	return nil
}

func canonicalTunnel(tunnel Tunnel) Tunnel {
	tunnel.IP = tunnel.IP.Unmap()
	return tunnel
}
