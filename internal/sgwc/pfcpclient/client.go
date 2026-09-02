// Package pfcpclient implements the SGW-C side of the 3GPP Sxa interface.
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
	"github.com/lodestarnetworks/cups/pkg/pfcp"
)

var (
	ErrNotAssociated = errors.New("sgwc PFCP: SGW-U is not associated")
	ErrRejected      = errors.New("sgwc PFCP: request rejected")
	ErrPeerRestarted = errors.New("sgwc PFCP: SGW-U recovery timestamp changed")
)

type Config struct {
	Listen                    netip.AddrPort
	Advertise                 netip.Addr
	Remote                    netip.AddrPort
	StartedAt                 time.Time
	ReportQueueSize           int
	EnterpriseID              uint16
	DownlinkNotificationDelay time.Duration
	UsageReportingThreshold   uint64
	UsageLedger               usagereport.LedgerConfig
	Transport                 pfcptransport.Config
}

type Tunnel struct {
	TEID uint32
	IP   netip.Addr
}

// RuleIDs identifies the pair of PDRs/FARs and QER owned by one EPS bearer.
// IDs are scoped to a PFCP session.
type RuleIDs struct {
	UplinkPDR   uint16
	DownlinkPDR uint16
	UplinkFAR   uint32
	DownlinkFAR uint32
	QER         uint32
	URR         uint32
}

var DefaultRuleIDs = RuleIDs{
	UplinkPDR: 1, DownlinkPDR: 2, UplinkFAR: 1, DownlinkFAR: 2, QER: 1, URR: 1,
}

type BearerPlan struct {
	Rules                RuleIDs
	AccessLocal          Tunnel
	CoreLocal            Tunnel
	CoreRemote           Tunnel
	AccessRemote         *Tunnel
	UplinkBitrate        uint64
	DownlinkBitrate      uint64
	QCI                  uint8
	ARP                  uint8
	PreemptionCapable    bool
	PreemptionVulnerable bool
}

type Establishment struct {
	CPSEID               uint64
	AccessLocal          Tunnel
	CoreLocal            Tunnel
	CoreRemote           Tunnel
	AccessRemote         *Tunnel
	UplinkBitrate        uint64
	DownlinkBitrate      uint64
	QCI                  uint8
	ARP                  uint8
	PreemptionCapable    bool
	PreemptionVulnerable bool
	AdditionalBearers    []BearerPlan
}

type Session struct {
	CPSEID       uint64
	UPSEID       uint64
	BARID        uint8
	AccessLocal  Tunnel
	CoreLocal    Tunnel
	CoreRemote   Tunnel
	AccessRemote *Tunnel
}

type Association struct {
	NodeAddress  netip.Addr
	NodeFQDN     string
	RecoveryTime time.Time
	Established  time.Time
	LastSeen     time.Time
}

type DownlinkReport struct {
	CPSEID uint64
	PDRID  uint16
}

type Client struct {
	config   Config
	endpoint *pfcptransport.Endpoint

	mu                        sync.RWMutex
	association               *Association
	lastRecovery              time.Time
	upSEIDByCP                map[uint64]uint64
	reports                   chan DownlinkReport
	usageLedger               *usagereport.Ledger
	usageLedgerRemoveFailures atomic.Uint64
}

func New(config Config) (*Client, error) {
	if !config.Listen.Addr().IsValid() || !config.Advertise.IsValid() || !config.Remote.Addr().IsValid() || config.Remote.Port() == 0 {
		return nil, errors.New("sgwc PFCP: listen, advertise, and remote addresses are required")
	}
	if !config.Advertise.Is4() {
		return nil, errors.New("sgwc PFCP: the LTE profile requires an IPv4 advertised address")
	}
	if config.EnterpriseID == 10415 {
		return nil, errors.New("sgwc PFCP: enterprise ID 10415 is reserved for 3GPP")
	}
	if _, err := pfcp.NewDownlinkDataNotificationDelayIE(config.DownlinkNotificationDelay); err != nil {
		return nil, fmt.Errorf("sgwc PFCP: %w", err)
	}
	config.Advertise = config.Advertise.Unmap()
	config.Remote = netip.AddrPortFrom(config.Remote.Addr().Unmap(), config.Remote.Port())
	if config.StartedAt.IsZero() {
		config.StartedAt = time.Now().UTC()
	}
	if config.ReportQueueSize < 0 {
		return nil, errors.New("sgwc PFCP: invalid downlink report queue size")
	}
	if config.ReportQueueSize == 0 {
		config.ReportQueueSize = 1024
	}
	if config.UsageReportingThreshold == 0 {
		config.UsageReportingThreshold = 1 << 30
	}
	usageLedger, err := usagereport.OpenLedger(config.UsageLedger)
	if err != nil {
		return nil, fmt.Errorf("sgwc PFCP: open usage-report ledger: %w", err)
	}
	client := &Client{
		config: config, upSEIDByCP: make(map[uint64]uint64),
		reports: make(chan DownlinkReport, config.ReportQueueSize), usageLedger: usageLedger,
	}
	endpoint, err := pfcptransport.Listen(config.Listen, client.handle, config.Transport)
	if err != nil {
		return nil, errors.Join(err, usageLedger.Close())
	}
	client.endpoint = endpoint
	return client, nil
}

func (c *Client) Serve(ctx context.Context) error {
	return c.endpoint.Serve(ctx)
}

func (c *Client) Close() error {
	return errors.Join(c.endpoint.Close(), c.usageLedger.Close())
}

func (c *Client) LocalAddr() netip.AddrPort {
	return c.endpoint.LocalAddr()
}

func (c *Client) TransportCounters() pfcptransport.Counters {
	return c.endpoint.Counters()
}

func (c *Client) Reports() <-chan DownlinkReport { return c.reports }

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
	nodeID, err := pfcp.NewNodeIDIE(c.config.Advertise, "")
	if err != nil {
		return err
	}
	recovery, err := pfcp.NewRecoveryTimeStampIE(c.config.StartedAt)
	if err != nil {
		return err
	}
	response, err := c.endpoint.Do(ctx, c.config.Remote, pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, MessageType: pfcp.MessageAssociationSetupRequest},
		IEs:    []pfcp.IE{nodeID, recovery},
	})
	if err != nil {
		return fmt.Errorf("associate SGW-U %s: %w", c.config.Remote, err)
	}
	if err := accepted(response); err != nil {
		return fmt.Errorf("associate SGW-U %s: %w", c.config.Remote, err)
	}
	remoteNode, ok := response.Find(pfcp.IENodeID)
	if !ok {
		return fmt.Errorf("associate SGW-U %s: %w", c.config.Remote, pfcp.ErrMissingIE)
	}
	remoteRecovery, ok := response.Find(pfcp.IERecoveryTimeStamp)
	if !ok {
		return fmt.Errorf("associate SGW-U %s: %w", c.config.Remote, pfcp.ErrMissingIE)
	}
	nodeAddress, nodeFQDN, err := remoteNode.NodeID()
	if err != nil {
		return err
	}
	recoveryTime, err := remoteRecovery.RecoveryTimeStamp()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	c.mu.Lock()
	restarted := !c.lastRecovery.IsZero() && !c.lastRecovery.Equal(recoveryTime)
	c.association = &Association{
		NodeAddress: nodeAddress, NodeFQDN: nodeFQDN, RecoveryTime: recoveryTime,
		Established: now, LastSeen: now,
	}
	c.lastRecovery = recoveryTime
	c.mu.Unlock()
	if restarted {
		return ErrPeerRestarted
	}
	return nil
}

func (c *Client) Heartbeat(ctx context.Context) error {
	recovery, err := pfcp.NewRecoveryTimeStampIE(c.config.StartedAt)
	if err != nil {
		return err
	}
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

// MarkUnavailable blocks new PFCP operations while the SGW-U remains in its
// forwarding grace window. Existing control/user-plane mappings are retained
// for authoritative replay.
func (c *Client) MarkUnavailable() {
	c.mu.Lock()
	c.association = nil
	c.mu.Unlock()
}

// CompleteReconciliation tells SGW-U that all authoritative SGW-C sessions
// have been replayed and unreaffirmed user-plane state may be removed.
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
		return fmt.Errorf("complete SGW-U reconciliation: %w", err)
	}
	if err := accepted(response); err != nil {
		return fmt.Errorf("complete SGW-U reconciliation: %w", err)
	}
	return nil
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
		Header: pfcp.Header{
			Version: pfcp.Version, HasSEID: true,
			MessageType: pfcp.MessageSessionEstablishmentRequest,
		},
		IEs: ies,
	})
	if err != nil {
		return Session{}, fmt.Errorf("establish PFCP session: %w", err)
	}
	if response.Header.SEID != plan.CPSEID {
		return Session{}, fmt.Errorf("establish PFCP session: response CP-SEID %d, expected %d", response.Header.SEID, plan.CPSEID)
	}
	if err := accepted(response); err != nil {
		return Session{}, fmt.Errorf("establish PFCP session: %w", err)
	}
	fseidIE, ok := response.Find(pfcp.IEFSEID)
	if !ok {
		return Session{}, fmt.Errorf("establish PFCP session: %w", pfcp.ErrMissingIE)
	}
	fseid, err := fseidIE.FSEID()
	if err != nil {
		return Session{}, err
	}
	session := Session{
		CPSEID: plan.CPSEID, UPSEID: fseid.SEID, BARID: plan.QCI,
		AccessLocal: plan.AccessLocal, CoreLocal: plan.CoreLocal,
		CoreRemote: plan.CoreRemote, AccessRemote: cloneTunnel(plan.AccessRemote),
	}
	c.mu.Lock()
	c.upSEIDByCP[session.CPSEID] = session.UPSEID
	c.mu.Unlock()
	return session, nil
}

func (c *Client) ActivateDownlink(ctx context.Context, session *Session, remote Tunnel) error {
	return c.ActivateBearer(ctx, session, DefaultRuleIDs, remote)
}

// ActivateBearer points one bearer's downlink FAR at the eNodeB after the MME
// has accepted the bearer. The modification is acknowledged before local
// control-plane state is committed.
func (c *Client) ActivateBearer(ctx context.Context, session *Session, rules RuleIDs, remote Tunnel) error {
	if session == nil || session.CPSEID == 0 || session.UPSEID == 0 {
		return errors.New("sgwc PFCP: invalid session")
	}
	if err := validateRuleIDs(rules); err != nil {
		return err
	}
	if err := validateTunnel("access remote", remote); err != nil {
		return err
	}
	farID, _ := pfcp.NewUint32IE(pfcp.IEFARID, rules.DownlinkFAR)
	action, _ := pfcp.NewApplyActionIE(pfcp.ApplyForward)
	destination, _ := pfcp.NewInterfaceIE(pfcp.IEDestinationInterface, pfcp.InterfaceAccess)
	outer, _ := pfcp.NewOuterHeaderCreationIE(pfcp.OuterHeader{
		Description: pfcp.OuterHeaderGTPUUDPIPv4, TEID: remote.TEID, IPv4: remote.IP,
	})
	forwarding, err := pfcp.NewGroupedIE(pfcp.IEUpdateForwardingParameters, destination, outer)
	if err != nil {
		return err
	}
	update, err := pfcp.NewGroupedIE(pfcp.IEUpdateFAR, farID, action, forwarding)
	if err != nil {
		return err
	}
	response, err := c.endpoint.Do(ctx, c.config.Remote, pfcp.Message{
		Header: pfcp.Header{
			Version: pfcp.Version, HasSEID: true,
			MessageType: pfcp.MessageSessionModificationRequest, SEID: session.UPSEID,
		},
		IEs: []pfcp.IE{update},
	})
	if err != nil {
		return fmt.Errorf("activate PFCP downlink: %w", err)
	}
	if response.Header.SEID != session.CPSEID {
		return fmt.Errorf("activate PFCP downlink: response CP-SEID %d, expected %d", response.Header.SEID, session.CPSEID)
	}
	if err := accepted(response); err != nil {
		return fmt.Errorf("activate PFCP downlink: %w", err)
	}
	session.AccessRemote = &remote
	return nil
}

func (c *Client) DeactivateDownlink(ctx context.Context, session *Session) error {
	return c.DeactivateBearer(ctx, session, DefaultRuleIDs)
}

// DeactivateBearer retains the bearer and its core tunnel while buffering the
// first downlink packet and notifying SGW-C for paging.
func (c *Client) DeactivateBearer(ctx context.Context, session *Session, rules RuleIDs) error {
	if session == nil || session.CPSEID == 0 || session.UPSEID == 0 {
		return errors.New("sgwc PFCP: invalid session")
	}
	if err := validateRuleIDs(rules); err != nil {
		return err
	}
	farID, _ := pfcp.NewUint32IE(pfcp.IEFARID, rules.DownlinkFAR)
	action, _ := pfcp.NewApplyActionIE(pfcp.ApplyBuffer | pfcp.ApplyNotifyControlPlane)
	barID, err := pfcp.NewBARIDIE(session.BARID)
	if err != nil {
		return fmt.Errorf("deactivate PFCP downlink: %w", err)
	}
	update, err := pfcp.NewGroupedIE(pfcp.IEUpdateFAR, farID, action, barID)
	if err != nil {
		return err
	}
	response, err := c.endpoint.Do(ctx, c.config.Remote, pfcp.Message{
		Header: pfcp.Header{
			Version: pfcp.Version, HasSEID: true,
			MessageType: pfcp.MessageSessionModificationRequest, SEID: session.UPSEID,
		},
		IEs: []pfcp.IE{update},
	})
	if err != nil {
		return fmt.Errorf("deactivate PFCP downlink: %w", err)
	}
	if response.Header.SEID != session.CPSEID {
		return fmt.Errorf("deactivate PFCP downlink: response CP-SEID %d, expected %d", response.Header.SEID, session.CPSEID)
	}
	if err := accepted(response); err != nil {
		return fmt.Errorf("deactivate PFCP downlink: %w", err)
	}
	session.AccessRemote = nil
	return nil
}

// AddBearer installs an additional pair of S1-U/S5-U rules in an existing
// PFCP session. The downlink starts closed and is activated only after the MME
// returns an eNodeB F-TEID.
func (c *Client) AddBearer(ctx context.Context, session *Session, plan BearerPlan) error {
	if session == nil || session.CPSEID == 0 || session.UPSEID == 0 {
		return errors.New("sgwc PFCP: invalid session")
	}
	if err := validateBearerPlan(plan); err != nil {
		return err
	}
	uplinkPDR, err := createPDR(plan.Rules.UplinkPDR, 100, pfcp.InterfaceAccess, plan.AccessLocal, plan.Rules.UplinkFAR, plan.Rules.QER, plan.Rules.URR)
	if err != nil {
		return err
	}
	downlinkPDR, err := createPDR(plan.Rules.DownlinkPDR, 100, pfcp.InterfaceCore, plan.CoreLocal, plan.Rules.DownlinkFAR, plan.Rules.QER, plan.Rules.URR)
	if err != nil {
		return err
	}
	uplinkFAR, err := createForwardingFAR(plan.Rules.UplinkFAR, pfcp.InterfaceCore, plan.CoreRemote)
	if err != nil {
		return err
	}
	downlinkFAR, err := createDropFAR(plan.Rules.DownlinkFAR)
	if err != nil {
		return err
	}
	qer, err := createQERWithType(pfcp.IECreateQER, plan.Rules.QER, plan.UplinkBitrate, plan.DownlinkBitrate, c.config.EnterpriseID, plan.QCI, plan.ARP, plan.PreemptionCapable, plan.PreemptionVulnerable)
	if err != nil {
		return err
	}
	urr, err := createURRWithType(pfcp.IECreateURR, plan.Rules.URR, c.config.UsageReportingThreshold)
	if err != nil {
		return err
	}
	return c.modifySession(ctx, session, "add PFCP bearer", []pfcp.IE{
		uplinkFAR, downlinkFAR, qer, urr, uplinkPDR, downlinkPDR,
	})
}

// UpdateBearerBitrate atomically replaces the QER gate and MBR values.
func (c *Client) UpdateBearerBitrate(ctx context.Context, session *Session, rules RuleIDs, uplinkBps, downlinkBps uint64) error {
	return c.updateBearerQoS(ctx, session, rules, 0, 0, false, false, uplinkBps, downlinkBps)
}

// UpdateBearerQoS atomically replaces gate, bitrate, and Lodestar LTE bearer
// metadata while preserving the standard QER ID referenced by both PDRs.
func (c *Client) UpdateBearerQoS(ctx context.Context, session *Session, rules RuleIDs, qci, arp uint8, preemptionCapable, preemptionVulnerable bool, uplinkBps, downlinkBps uint64) error {
	if qci == 0 || qci == 255 || arp == 0 || arp > 15 {
		return errors.New("sgwc PFCP: invalid QCI/ARP")
	}
	return c.updateBearerQoS(ctx, session, rules, qci, arp, preemptionCapable, preemptionVulnerable, uplinkBps, downlinkBps)
}

func (c *Client) updateBearerQoS(ctx context.Context, session *Session, rules RuleIDs, qci, arp uint8, preemptionCapable, preemptionVulnerable bool, uplinkBps, downlinkBps uint64) error {
	if session == nil || session.CPSEID == 0 || session.UPSEID == 0 {
		return errors.New("sgwc PFCP: invalid session")
	}
	if err := validateRuleIDs(rules); err != nil {
		return err
	}
	qer, err := createQERWithType(pfcp.IEUpdateQER, rules.QER, uplinkBps, downlinkBps, c.config.EnterpriseID, qci, arp, preemptionCapable, preemptionVulnerable)
	if err != nil {
		return err
	}
	return c.modifySession(ctx, session, "update PFCP bearer QoS", []pfcp.IE{qer})
}

// RemoveBearer removes only one dedicated bearer from a PFCP session. PFCP
// validation makes the five-rule removal atomic at SGW-U.
func (c *Client) RemoveBearer(ctx context.Context, session *Session, rules RuleIDs) error {
	if session == nil || session.CPSEID == 0 || session.UPSEID == 0 {
		return errors.New("sgwc PFCP: invalid session")
	}
	if err := validateRuleIDs(rules); err != nil {
		return err
	}
	uplinkPDR, _ := removePDR(rules.UplinkPDR)
	downlinkPDR, _ := removePDR(rules.DownlinkPDR)
	uplinkFAR, _ := removeUint32Rule(pfcp.IERemoveFAR, pfcp.IEFARID, rules.UplinkFAR)
	downlinkFAR, _ := removeUint32Rule(pfcp.IERemoveFAR, pfcp.IEFARID, rules.DownlinkFAR)
	qer, _ := removeUint32Rule(pfcp.IERemoveQER, pfcp.IEQERID, rules.QER)
	urr, _ := removeUint32Rule(pfcp.IERemoveURR, pfcp.IEURRID, rules.URR)
	return c.modifySession(ctx, session, "remove PFCP bearer", []pfcp.IE{
		uplinkPDR, downlinkPDR, uplinkFAR, downlinkFAR, qer, urr,
	})
}

func (c *Client) modifySession(ctx context.Context, session *Session, operation string, ies []pfcp.IE) error {
	response, err := c.endpoint.Do(ctx, c.config.Remote, pfcp.Message{
		Header: pfcp.Header{
			Version: pfcp.Version, HasSEID: true,
			MessageType: pfcp.MessageSessionModificationRequest, SEID: session.UPSEID,
		},
		IEs: ies,
	})
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	if response.Header.SEID != session.CPSEID {
		return fmt.Errorf("%s: response CP-SEID %d, expected %d", operation, response.Header.SEID, session.CPSEID)
	}
	if err := accepted(response); err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return nil
}

func (c *Client) Delete(ctx context.Context, session Session) error {
	if session.CPSEID == 0 || session.UPSEID == 0 {
		return errors.New("sgwc PFCP: invalid session")
	}
	response, err := c.endpoint.Do(ctx, c.config.Remote, pfcp.Message{
		Header: pfcp.Header{
			Version: pfcp.Version, HasSEID: true,
			MessageType: pfcp.MessageSessionDeletionRequest, SEID: session.UPSEID,
		},
	})
	if err != nil {
		return fmt.Errorf("delete PFCP session: %w", err)
	}
	causeIE, ok := response.Find(pfcp.IECause)
	if !ok {
		return fmt.Errorf("delete PFCP session: %w", pfcp.ErrMissingIE)
	}
	cause, err := causeIE.Cause()
	if err != nil {
		return fmt.Errorf("delete PFCP session: %w", err)
	}
	if cause != pfcp.CauseSessionNotFound {
		if response.Header.SEID != session.CPSEID {
			return fmt.Errorf("delete PFCP session: response CP-SEID %d, expected %d", response.Header.SEID, session.CPSEID)
		}
		if cause != pfcp.CauseRequestAccepted {
			return fmt.Errorf("delete PFCP session: %w: cause %d", ErrRejected, cause)
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

func (c *Client) establishmentIEs(plan Establishment) ([]pfcp.IE, error) {
	nodeID, _ := pfcp.NewNodeIDIE(c.config.Advertise, "")
	cpFSEID, _ := pfcp.NewFSEIDIE(pfcp.FSEID{SEID: plan.CPSEID, IPv4: c.config.Advertise})
	bar, err := createBAR(plan.QCI, c.config.DownlinkNotificationDelay)
	if err != nil {
		return nil, err
	}

	uplinkPDR, err := createPDR(1, 100, pfcp.InterfaceAccess, plan.AccessLocal, 1, 1, 1)
	if err != nil {
		return nil, err
	}
	downlinkPDR, err := createPDR(2, 100, pfcp.InterfaceCore, plan.CoreLocal, 2, 1, 1)
	if err != nil {
		return nil, err
	}
	uplinkFAR, err := createForwardingFAR(1, pfcp.InterfaceCore, plan.CoreRemote)
	if err != nil {
		return nil, err
	}
	var downlinkFAR pfcp.IE
	if plan.AccessRemote == nil {
		downlinkFAR, err = createBufferingFAR(2, plan.QCI)
	} else {
		downlinkFAR, err = createForwardingFAR(2, pfcp.InterfaceAccess, *plan.AccessRemote)
	}
	if err != nil {
		return nil, err
	}
	qer, err := createQER(1, plan.UplinkBitrate, plan.DownlinkBitrate, c.config.EnterpriseID, plan.QCI, plan.ARP, plan.PreemptionCapable, plan.PreemptionVulnerable)
	if err != nil {
		return nil, err
	}
	urr, err := createURRWithType(pfcp.IECreateURR, 1, c.config.UsageReportingThreshold)
	if err != nil {
		return nil, err
	}
	ies := []pfcp.IE{
		nodeID, cpFSEID, bar, uplinkPDR, downlinkPDR, uplinkFAR, downlinkFAR, qer, urr,
		{Type: pfcp.IEPDNType, Value: []byte{1}},
	}
	for _, bearer := range plan.AdditionalBearers {
		if err := validateBearerPlan(bearer); err != nil {
			return nil, err
		}
		uplinkPDR, err := createPDR(bearer.Rules.UplinkPDR, 100, pfcp.InterfaceAccess, bearer.AccessLocal, bearer.Rules.UplinkFAR, bearer.Rules.QER, bearer.Rules.URR)
		if err != nil {
			return nil, err
		}
		downlinkPDR, err := createPDR(bearer.Rules.DownlinkPDR, 100, pfcp.InterfaceCore, bearer.CoreLocal, bearer.Rules.DownlinkFAR, bearer.Rules.QER, bearer.Rules.URR)
		if err != nil {
			return nil, err
		}
		uplinkFAR, err := createForwardingFAR(bearer.Rules.UplinkFAR, pfcp.InterfaceCore, bearer.CoreRemote)
		if err != nil {
			return nil, err
		}
		var downlinkFAR pfcp.IE
		if bearer.AccessRemote == nil {
			downlinkFAR, err = createBufferingFAR(bearer.Rules.DownlinkFAR, plan.QCI)
		} else {
			downlinkFAR, err = createForwardingFAR(bearer.Rules.DownlinkFAR, pfcp.InterfaceAccess, *bearer.AccessRemote)
		}
		if err != nil {
			return nil, err
		}
		qer, err := createQER(bearer.Rules.QER, bearer.UplinkBitrate, bearer.DownlinkBitrate, c.config.EnterpriseID, bearer.QCI, bearer.ARP, bearer.PreemptionCapable, bearer.PreemptionVulnerable)
		if err != nil {
			return nil, err
		}
		urr, err := createURRWithType(pfcp.IECreateURR, bearer.Rules.URR, c.config.UsageReportingThreshold)
		if err != nil {
			return nil, err
		}
		ies = append(ies, uplinkPDR, downlinkPDR, uplinkFAR, downlinkFAR, qer, urr)
	}
	return ies, nil
}

func createPDR(id uint16, precedence uint32, source uint8, local Tunnel, farID, qerID, urrID uint32) (pfcp.IE, error) {
	pdrID, err := pfcp.NewPDRIDIE(id)
	if err != nil {
		return pfcp.IE{}, err
	}
	precedenceIE, _ := pfcp.NewUint32IE(pfcp.IEPrecedence, precedence)
	sourceIE, _ := pfcp.NewInterfaceIE(pfcp.IESourceInterface, source)
	fteid, _ := pfcp.NewFTEIDIE(pfcp.FTEID{TEID: local.TEID, IPv4: local.IP})
	pdi, err := pfcp.NewGroupedIE(pfcp.IEPDI, sourceIE, fteid)
	if err != nil {
		return pfcp.IE{}, err
	}
	removal, _ := pfcp.NewOuterHeaderRemovalIE(pfcp.OuterHeaderRemovalGTPUUDPIPv4)
	far, _ := pfcp.NewUint32IE(pfcp.IEFARID, farID)
	qer, _ := pfcp.NewUint32IE(pfcp.IEQERID, qerID)
	urr, _ := pfcp.NewUint32IE(pfcp.IEURRID, urrID)
	return pfcp.NewGroupedIE(pfcp.IECreatePDR, pdrID, precedenceIE, pdi, removal, far, qer, urr)
}

func createForwardingFAR(id uint32, destination uint8, remote Tunnel) (pfcp.IE, error) {
	farID, _ := pfcp.NewUint32IE(pfcp.IEFARID, id)
	action, _ := pfcp.NewApplyActionIE(pfcp.ApplyForward)
	destinationIE, _ := pfcp.NewInterfaceIE(pfcp.IEDestinationInterface, destination)
	outer, err := pfcp.NewOuterHeaderCreationIE(pfcp.OuterHeader{
		Description: pfcp.OuterHeaderGTPUUDPIPv4, TEID: remote.TEID, IPv4: remote.IP,
	})
	if err != nil {
		return pfcp.IE{}, err
	}
	forwarding, err := pfcp.NewGroupedIE(pfcp.IEForwardingParameters, destinationIE, outer)
	if err != nil {
		return pfcp.IE{}, err
	}
	return pfcp.NewGroupedIE(pfcp.IECreateFAR, farID, action, forwarding)
}

func createDropFAR(id uint32) (pfcp.IE, error) {
	farID, _ := pfcp.NewUint32IE(pfcp.IEFARID, id)
	action, _ := pfcp.NewApplyActionIE(pfcp.ApplyDrop)
	return pfcp.NewGroupedIE(pfcp.IECreateFAR, farID, action)
}

func createBufferingFAR(id uint32, bar uint8) (pfcp.IE, error) {
	farID, _ := pfcp.NewUint32IE(pfcp.IEFARID, id)
	action, _ := pfcp.NewApplyActionIE(pfcp.ApplyBuffer | pfcp.ApplyNotifyControlPlane)
	barID, err := pfcp.NewBARIDIE(bar)
	if err != nil {
		return pfcp.IE{}, err
	}
	return pfcp.NewGroupedIE(pfcp.IECreateFAR, farID, action, barID)
}

func createBAR(id uint8, delay time.Duration) (pfcp.IE, error) {
	barID, err := pfcp.NewBARIDIE(id)
	if err != nil {
		return pfcp.IE{}, err
	}
	delayIE, err := pfcp.NewDownlinkDataNotificationDelayIE(delay)
	if err != nil {
		return pfcp.IE{}, err
	}
	return pfcp.NewGroupedIE(pfcp.IECreateBAR, barID, delayIE)
}

func createQER(id uint32, uplinkBps, downlinkBps uint64, enterpriseID uint16, qci, arp uint8, preemptionCapable, preemptionVulnerable bool) (pfcp.IE, error) {
	return createQERWithType(pfcp.IECreateQER, id, uplinkBps, downlinkBps, enterpriseID, qci, arp, preemptionCapable, preemptionVulnerable)
}

func createQERWithType(groupType uint16, id uint32, uplinkBps, downlinkBps uint64, enterpriseID uint16, qci, arp uint8, preemptionCapable, preemptionVulnerable bool) (pfcp.IE, error) {
	qerID, _ := pfcp.NewUint32IE(pfcp.IEQERID, id)
	children := []pfcp.IE{qerID, pfcp.NewGateStatusIE(true, true)}
	if uplinkBps > 0 || downlinkBps > 0 {
		mbr, err := pfcp.NewBitRateIE(pfcp.IEMBR, uplinkBps/1000, downlinkBps/1000)
		if err != nil {
			return pfcp.IE{}, err
		}
		children = append(children, mbr)
	}
	if enterpriseID != 0 && qci != 0 {
		metadata, err := pfcp.NewVendorBearerQoSIE(pfcp.BearerQoSMetadata{
			EnterpriseID: enterpriseID, QCI: qci, ARP: arp,
			PreemptionCapable: preemptionCapable, PreemptionVulnerable: preemptionVulnerable,
		})
		if err != nil {
			return pfcp.IE{}, err
		}
		children = append(children, metadata)
	}
	return pfcp.NewGroupedIE(groupType, children...)
}

func createURRWithType(groupType uint16, id uint32, thresholdBytes uint64) (pfcp.IE, error) {
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

func removePDR(id uint16) (pfcp.IE, error) {
	pdrID, err := pfcp.NewPDRIDIE(id)
	if err != nil {
		return pfcp.IE{}, err
	}
	return pfcp.NewGroupedIE(pfcp.IERemovePDR, pdrID)
}

func removeUint32Rule(groupType, idType uint16, id uint32) (pfcp.IE, error) {
	idIE, err := pfcp.NewUint32IE(idType, id)
	if err != nil {
		return pfcp.IE{}, err
	}
	return pfcp.NewGroupedIE(groupType, idIE)
}

func validateEstablishment(plan Establishment) error {
	if plan.CPSEID == 0 {
		return errors.New("sgwc PFCP: CP-SEID is required")
	}
	if err := validateBearerQoS(plan.QCI, plan.ARP); err != nil {
		return err
	}
	for name, tunnel := range map[string]Tunnel{
		"access local": plan.AccessLocal, "core local": plan.CoreLocal, "core remote": plan.CoreRemote,
	} {
		if err := validateTunnel(name, tunnel); err != nil {
			return err
		}
	}
	if plan.AccessRemote != nil {
		if err := validateTunnel("access remote", *plan.AccessRemote); err != nil {
			return err
		}
	}
	return nil
}

func validateBearerPlan(plan BearerPlan) error {
	if err := validateRuleIDs(plan.Rules); err != nil {
		return err
	}
	if err := validateBearerQoS(plan.QCI, plan.ARP); err != nil {
		return err
	}
	for name, tunnel := range map[string]Tunnel{
		"access local": plan.AccessLocal, "core local": plan.CoreLocal, "core remote": plan.CoreRemote,
	} {
		if err := validateTunnel(name, tunnel); err != nil {
			return err
		}
	}
	if plan.AccessRemote != nil {
		if err := validateTunnel("access remote", *plan.AccessRemote); err != nil {
			return err
		}
	}
	return nil
}

func validateBearerQoS(qci, arp uint8) error {
	if qci == 0 || qci == 255 || arp == 0 || arp > 15 {
		return errors.New("sgwc PFCP: QCI and ARP priority 1..15 are required")
	}
	return nil
}

func validateRuleIDs(rules RuleIDs) error {
	if rules.UplinkPDR == 0 || rules.DownlinkPDR == 0 || rules.UplinkPDR == rules.DownlinkPDR ||
		rules.UplinkFAR == 0 || rules.DownlinkFAR == 0 || rules.UplinkFAR == rules.DownlinkFAR || rules.QER == 0 || rules.URR == 0 {
		return errors.New("sgwc PFCP: complete distinct bearer rule IDs are required")
	}
	return nil
}

func validateTunnel(name string, tunnel Tunnel) error {
	if tunnel.TEID == 0 || !tunnel.IP.Is4() {
		return fmt.Errorf("sgwc PFCP: %s tunnel requires a non-zero TEID and IPv4 address", name)
	}
	return nil
}

func accepted(message pfcp.Message) error {
	causeIE, ok := message.Find(pfcp.IECause)
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

func cloneTunnel(tunnel *Tunnel) *Tunnel {
	if tunnel == nil {
		return nil
	}
	copy := *tunnel
	return &copy
}

func (c *Client) handle(_ context.Context, peer netip.AddrPort, request pfcp.Message) (*pfcp.Message, error) {
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	if peer != c.config.Remote {
		return nil, nil
	}
	switch request.Header.MessageType {
	case pfcp.MessageHeartbeatRequest:
		recovery, _ := pfcp.NewRecoveryTimeStampIE(c.config.StartedAt)
		return &pfcp.Message{
			Header: pfcp.Header{Version: pfcp.Version, MessageType: pfcp.MessageHeartbeatResponse},
			IEs:    []pfcp.IE{recovery},
		}, nil
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
			Header: pfcp.Header{
				Version: pfcp.Version, HasSEID: true,
				MessageType: pfcp.MessageSessionReportResponse, SEID: upSEID,
			},
			IEs: []pfcp.IE{pfcp.NewCauseIE(cause)},
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
	if err != nil {
		return respond(pfcp.CauseMandatoryIEIncorrect)
	}
	usageIEs := pfcp.FindAllIEs(request.IEs, pfcp.IEUsageReportSessionReport)
	if reportType&pfcp.ReportUsage != 0 {
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
	} else if len(usageIEs) != 0 {
		return respond(pfcp.CauseMandatoryIEIncorrect)
	}
	downlinkIEs := pfcp.FindAllIEs(request.IEs, pfcp.IEDownlinkDataReport)
	if reportType&pfcp.ReportDownlinkData != 0 {
		if len(downlinkIEs) != 1 {
			return respond(pfcp.CauseMandatoryIEMissing)
		}
		children, err := downlinkIEs[0].Children()
		if err != nil {
			return respond(pfcp.CauseMandatoryIEIncorrect)
		}
		pdrIE, ok := pfcp.FindIE(children, pfcp.IEPDRID)
		if !ok {
			return respond(pfcp.CauseMandatoryIEMissing)
		}
		pdrID, err := pdrIE.PDRID()
		if err != nil {
			return respond(pfcp.CauseMandatoryIEIncorrect)
		}
		select {
		case c.reports <- DownlinkReport{CPSEID: cpSEID, PDRID: pdrID}:
		default:
			return respond(pfcp.CauseNoResources)
		}
	} else if len(downlinkIEs) != 0 {
		return respond(pfcp.CauseMandatoryIEIncorrect)
	}
	if reportType&(pfcp.ReportDownlinkData|pfcp.ReportUsage) == 0 {
		return respond(pfcp.CauseMandatoryIEIncorrect)
	}
	return respond(pfcp.CauseRequestAccepted)
}
