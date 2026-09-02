package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lodestarnetworks/cups/internal/kernelgtp"
	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
)

var ErrKernelPolicyUnsupported = errors.New("pgwu kernel dataplane cannot represent PFCP policy")

const (
	defaultQCI1RouteTable   uint32 = 21_521
	defaultQCI1RulePriority uint32 = 10_510
	defaultQCI1FirewallMark uint32 = 0x4c51_0000
	defaultQCI1FirewallMask uint32 = 0xffff_0000
)

type KernelConfig struct {
	S5                netip.AddrPort
	QCI1S5            netip.AddrPort
	AllowedSGWPeers   []netip.Addr
	TunnelName        string
	QCI1TunnelName    string
	OwnershipFile     string
	QCI1OwnershipFile string
	QCI1RouteTable    uint32
	QCI1RulePriority  uint32
	QCI1FirewallMark  uint32
	QCI1FirewallMask  uint32
	UEPoolPrefix      netip.Prefix
	UEGateway         netip.Addr
	UEPools           []UEPool
	HashSize          uint32
	MTU               uint32
	SocketBufferBytes int
	MaxSessions       int
	MaxPolicyFilters  int
	QERBurstDuration  time.Duration
	// AllowUnsupportedPolicy is restricted to synthetic/kernel plumbing tests.
	// Production callers must leave it false so QER/URR policy fails closed.
	AllowUnsupportedPolicy bool
}

// UEPool is one exact SGi-facing IPv4 range and its gateway address. Several
// APNs may share one GTP device, but their address ranges must never overlap.
type UEPool struct {
	Prefix  netip.Prefix
	Gateway netip.Addr
}

type kernelController interface {
	EnsureContext(kernelgtp.Context) (bool, error)
	DeleteContext(uint32, uint32) error
	Reconcile(uint32, []kernelgtp.Context) (kernelgtp.ReconcileReport, error)
	PeerFilterCounters(kernelgtp.Link) (kernelgtp.PeerFilterCounters, error)
	Close() error
}

// KernelForwarder maps committed PGW-U PFCP sessions to Linux GTPv1-U PDP
// contexts. The kernel network device is the SGi-facing interface.
type KernelForwarder struct {
	controller             kernelController
	link                   kernelgtp.Link
	qci1Link               kernelgtp.Link
	s5                     netip.AddrPort
	qci1S5                 netip.AddrPort
	allowed                map[netip.Addr]struct{}
	uePools                []netip.Prefix
	policy                 kernelPolicyBackend
	closed                 chan struct{}
	closeOnce              sync.Once
	closeErr               error
	allowUnsupportedPolicy bool
}

func OpenKernel(config KernelConfig) (*KernelForwarder, error) {
	if !config.S5.Addr().Is4() || config.S5.Port() != kernelgtp.GTPUPort {
		return nil, errors.New("pgwu kernel dataplane: S5-U must be an IPv4 address on UDP 2152")
	}
	if len(config.AllowedSGWPeers) == 0 {
		return nil, errors.New("pgwu kernel dataplane: at least one SGW-U peer is required")
	}
	allowed := make(map[netip.Addr]struct{}, len(config.AllowedSGWPeers))
	for index, peer := range config.AllowedSGWPeers {
		peer = peer.Unmap()
		if !peer.Is4() {
			return nil, fmt.Errorf("pgwu kernel dataplane: peer %d is not IPv4", index)
		}
		allowed[peer] = struct{}{}
	}
	uePools, err := normalizeKernelUEPools(config)
	if err != nil {
		return nil, err
	}
	uePrefixes := make([]netip.Prefix, len(uePools))
	for index := range uePools {
		uePrefixes[index] = uePools[index].Prefix
	}
	controller, err := kernelgtp.Open()
	if err != nil {
		return nil, err
	}
	link, err := controller.CreateLink(kernelgtp.LinkConfig{
		Name: config.TunnelName, OwnershipFile: config.OwnershipFile,
		LocalIPv4: config.S5.Addr(), AllowedPeers: config.AllowedSGWPeers, Role: kernelgtp.RoleGGSN,
		HashSize: config.HashSize, MTU: config.MTU, SocketBufferBytes: config.SocketBufferBytes,
	})
	if err != nil {
		_ = controller.Close()
		return nil, err
	}
	for _, pool := range uePools {
		if err := controller.ConfigureIPv4(link, pool.Gateway, pool.Prefix); err != nil {
			_ = controller.Close()
			return nil, err
		}
	}
	forwarder := &KernelForwarder{
		controller: controller, link: link, s5: config.S5,
		allowed: allowed, uePools: uePrefixes,
		allowUnsupportedPolicy: config.AllowUnsupportedPolicy, closed: make(chan struct{}),
	}
	if config.QCI1S5.IsValid() {
		if config.QCI1RouteTable == 0 {
			config.QCI1RouteTable = defaultQCI1RouteTable
		}
		if config.QCI1RulePriority == 0 {
			config.QCI1RulePriority = defaultQCI1RulePriority
		}
		if config.QCI1FirewallMark == 0 {
			config.QCI1FirewallMark = defaultQCI1FirewallMark
		}
		if config.QCI1FirewallMask == 0 {
			config.QCI1FirewallMask = defaultQCI1FirewallMask
		}
		if !config.QCI1S5.Addr().Is4() || config.QCI1S5.Port() != kernelgtp.GTPUPort || config.QCI1S5.Addr().Unmap() == config.S5.Addr().Unmap() {
			_ = controller.Close()
			return nil, errors.New("pgwu kernel dataplane: QCI 1 S5-U must be a distinct IPv4 address on UDP 2152")
		}
		if config.QCI1TunnelName == "" || config.QCI1OwnershipFile == "" {
			_ = controller.Close()
			return nil, errors.New("pgwu kernel dataplane: QCI 1 tunnel name and ownership file are required")
		}
		qci1Link, createErr := controller.CreateLink(kernelgtp.LinkConfig{
			Name: config.QCI1TunnelName, OwnershipFile: config.QCI1OwnershipFile,
			LocalIPv4: config.QCI1S5.Addr(), AllowedPeers: config.AllowedSGWPeers, Role: kernelgtp.RoleGGSN,
			HashSize: config.HashSize, MTU: config.MTU, SocketBufferBytes: config.SocketBufferBytes,
		})
		if createErr != nil {
			_ = controller.Close()
			return nil, createErr
		}
		routeRecovery, routeErr := controller.ConfigurePolicyIPv4Prefixes(qci1Link, uePrefixes, kernelgtp.PolicyRoutingConfig{
			Table: config.QCI1RouteTable, Priority: config.QCI1RulePriority,
			Mark: config.QCI1FirewallMark, Mask: config.QCI1FirewallMask,
		})
		if routeErr != nil {
			_ = controller.Close()
			return nil, routeErr
		}
		qci1Link.Recovery.PolicyRuleRemoved = qci1Link.Recovery.PolicyRuleRemoved || routeRecovery.PolicyRuleRemoved
		policy, policyErr := openKernelPolicy(kernelPolicyConfig{
			DefaultLink: link, QCI1Link: qci1Link, MaxSessions: config.MaxSessions,
			MaxFilters: config.MaxPolicyFilters, BurstDuration: config.QERBurstDuration,
			PacketSizeBits: uint64(config.MTU) * 8, UEPoolPrefixes: uePrefixes,
			FirewallMark: config.QCI1FirewallMark, FirewallMask: config.QCI1FirewallMask,
		})
		if policyErr != nil {
			_ = controller.Close()
			return nil, policyErr
		}
		forwarder.qci1Link, forwarder.qci1S5, forwarder.policy = qci1Link, config.QCI1S5, policy
	}
	return forwarder, nil
}

func normalizeKernelUEPools(config KernelConfig) ([]UEPool, error) {
	pools := append([]UEPool(nil), config.UEPools...)
	legacyConfigured := config.UEPoolPrefix.IsValid() || config.UEGateway.IsValid()
	if len(pools) == 0 {
		if !config.UEPoolPrefix.IsValid() || !config.UEGateway.IsValid() {
			return nil, errors.New("pgwu kernel dataplane: at least one UE pool and gateway are required")
		}
		pools = []UEPool{{Prefix: config.UEPoolPrefix, Gateway: config.UEGateway}}
	} else if legacyConfigured {
		return nil, errors.New("pgwu kernel dataplane: UE pools cannot be combined with the legacy UE pool fields")
	}
	if len(pools) > 256 {
		return nil, errors.New("pgwu kernel dataplane: at most 256 UE pools are supported")
	}
	prefixes := make([]netip.Prefix, 0, len(pools))
	for index := range pools {
		pools[index].Prefix = pools[index].Prefix.Masked()
		pools[index].Gateway = pools[index].Gateway.Unmap()
		if !pools[index].Gateway.Is4() || !pools[index].Prefix.IsValid() || !pools[index].Prefix.Addr().Is4() ||
			pools[index].Prefix.Bits() < 8 || pools[index].Prefix.Bits() > 30 ||
			!netip.MustParsePrefix("10.0.0.0/8").Contains(pools[index].Prefix.Addr()) ||
			!pools[index].Prefix.Contains(pools[index].Gateway) {
			return nil, fmt.Errorf("pgwu kernel dataplane: UE pool %d has an invalid private IPv4 prefix or gateway", index)
		}
		prefixes = append(prefixes, pools[index].Prefix)
	}
	if _, err := normalizeUEPoolPrefixes(prefixes, netip.Prefix{}); err != nil {
		return nil, fmt.Errorf("pgwu kernel dataplane: %w", err)
	}
	sort.Slice(pools, func(left, right int) bool {
		if pools[left].Prefix.Addr() != pools[right].Prefix.Addr() {
			return pools[left].Prefix.Addr().Less(pools[right].Prefix.Addr())
		}
		return pools[left].Prefix.Bits() < pools[right].Prefix.Bits()
	})
	return pools, nil
}

func (f *KernelForwarder) S5Addr() netip.AddrPort { return f.s5 }
func (f *KernelForwarder) TunnelName() string     { return f.link.Name }
func (f *KernelForwarder) Mode() string {
	if f.policy != nil {
		return "kernel-gtp/netlink+nft-policy-route+tcx-policy"
	}
	return "kernel-gtp/netlink"
}
func (f *KernelForwarder) RecoveryReport() kernelgtp.RecoveryReport {
	return kernelgtp.RecoveryReport{
		LinkRemoved:       f.link.Recovery.LinkRemoved || f.qci1Link.Recovery.LinkRemoved,
		PeerFilterRemoved: f.link.Recovery.PeerFilterRemoved || f.qci1Link.Recovery.PeerFilterRemoved,
		PolicyRuleRemoved: f.link.Recovery.PolicyRuleRemoved || f.qci1Link.Recovery.PolicyRuleRemoved,
	}
}

func (f *KernelForwarder) Capabilities() []Capability {
	policyEnabled := f.policy != nil
	directionalDetail := "closed PFCP gate currently removes both directions"
	bitrateDetail := "TC QER shaper is not implemented"
	dedicatedDetail := "per-class devices and transactional TFT routing are not implemented"
	usageDetail := "kernel device and peer-filter counters are aggregate"
	if policyEnabled {
		directionalDetail = "TCX policy enforces independent default and QCI 1 uplink/downlink gates"
		bitrateDetail = "TCX token buckets enforce per-bearer, per-direction MBR in bits per second"
		dedicatedDetail = "separate default/QCI 1 GTP devices, nftables verdict-map TFT routing, and TCX fail-closed bearer verification"
		usageDetail = "per-CPU, per-bearer telemetry-only URR counters"
	}
	return []Capability{
		{Name: CapabilityGTPv1U, Supported: true, Detail: "Linux kernel GTPv1-U PDP contexts"},
		{Name: CapabilityOuterPeerFilter, Supported: true, Detail: "pre-GTP nftables outer-source allowlist"},
		{Name: CapabilityDirectionalGating, Supported: policyEnabled, Detail: directionalDetail},
		{Name: CapabilityMaxBitrateQER, Supported: policyEnabled, Detail: bitrateDetail},
		{Name: CapabilityDedicatedBearer, Supported: policyEnabled, Detail: dedicatedDetail},
		{Name: CapabilityPerSessionUsage, Supported: policyEnabled, Detail: usageDetail},
		{Name: CapabilityRestartReconcile, Supported: true, Detail: "durable WAL replay plus ownership-fenced stale kernel-resource recovery"},
	}
}

func (f *KernelForwarder) Serve(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case <-f.closed:
		return nil
	}
}

func (f *KernelForwarder) Close() error {
	f.closeOnce.Do(func() {
		close(f.closed)
		if f.policy != nil {
			f.closeErr = f.policy.Close()
		}
		f.closeErr = errors.Join(f.closeErr, f.controller.Close())
	})
	return f.closeErr
}

// Apply implements rules.Applier. A closed gate is represented
// conservatively by removing the PDP context, which blocks both directions.
// Directional gating and bitrate enforcement remain explicit production gates
// for the TC policy layer rather than being silently approximated.
func (f *KernelForwarder) Apply(previous, next *rules.Session) error {
	select {
	case <-f.closed:
		return errors.New("pgwu kernel dataplane is closed")
	default:
	}
	if previous != nil {
		if err := f.validateSession(previous); err != nil {
			return err
		}
	}
	if next != nil {
		if err := f.validateSession(next); err != nil {
			return err
		}
	}
	if f.policy != nil {
		previousDedicated := previous != nil && len(previous.DedicatedBearers) == 1
		nextDedicated := next != nil && len(next.DedicatedBearers) == 1
		routingChanged := !sameDedicatedRouting(previous, next)
		if previousDedicated && routingChanged {
			// Remove the route selector first. Until the replacement is active,
			// dedicated packets fall toward the default device and its TCX guard
			// drops them as wrong-bearer traffic; they can never leak on the default
			// TEID during a transaction.
			if err := f.policy.ApplyRouting(previous, nil); err != nil {
				return err
			}
		}
		restorePreviousRouting := func() error {
			if !previousDedicated || !routingChanged {
				return nil
			}
			return f.policy.ApplyRouting(nil, previous)
		}
		if err := f.policy.Apply(previous, next); err != nil {
			return errors.Join(err, restorePreviousRouting())
		}
		if err := f.applyPolicyContexts(previous, next); err != nil {
			rollbackErr := f.policy.Apply(next, previous)
			if rollbackErr == nil {
				rollbackErr = restorePreviousRouting()
			}
			return errors.Join(err, rollbackErr)
		}
		if nextDedicated && routingChanged {
			if err := f.policy.ApplyRouting(nil, next); err != nil {
				contextRollback := f.applyPolicyContexts(next, previous)
				policyRollback := f.policy.Apply(next, previous)
				var routeRollback error
				if contextRollback == nil && policyRollback == nil {
					routeRollback = restorePreviousRouting()
				}
				return errors.Join(err, contextRollback, policyRollback, routeRollback)
			}
		}
		return nil
	}
	previousForwarding := sessionForwarding(previous)
	nextForwarding := sessionForwarding(next)
	switch {
	case previousForwarding && !nextForwarding:
		return f.controller.DeleteContext(f.link.Index, previous.Local.TEID)
	case !previousForwarding && nextForwarding:
		_, err := f.controller.EnsureContext(f.context(*next))
		return err
	case previousForwarding && nextForwarding:
		if previous.UEIPv4 != next.UEIPv4 || previous.Local.TEID != next.Local.TEID {
			return fmt.Errorf("%w: UE and incoming TEID are immutable", ErrKernelPolicyUnsupported)
		}
		_, err := f.controller.EnsureContext(f.context(*next))
		return err
	default:
		return nil
	}
}

func (f *KernelForwarder) applyPolicyContexts(previous, next *rules.Session) error {
	type contextState struct {
		present bool
		value   kernelgtp.Context
	}
	defaultState := func(session *rules.Session) contextState {
		if session == nil {
			return contextState{}
		}
		return contextState{present: true, value: f.context(*session)}
	}
	qci1State := func(session *rules.Session) contextState {
		if session == nil || len(session.DedicatedBearers) == 0 {
			return contextState{}
		}
		bearer := session.DedicatedBearers[0]
		return contextState{present: true, value: kernelgtp.Context{
			LinkIndex: f.qci1Link.Index, UEIPv4: session.UEIPv4, PeerIPv4: bearer.Remote.IP,
			IncomingTEID: bearer.Local.TEID, OutgoingTEID: bearer.Remote.TEID,
		}}
	}
	transitions := [][2]contextState{
		{defaultState(previous), defaultState(next)},
		{qci1State(previous), qci1State(next)},
	}
	undos := make([]func() error, 0, 4)
	rollback := func(cause error) error {
		result := cause
		for index := len(undos) - 1; index >= 0; index-- {
			result = errors.Join(result, undos[index]())
		}
		return result
	}
	for _, transition := range transitions {
		before, after := transition[0], transition[1]
		switch {
		case !before.present && !after.present:
			continue
		case before.present && !after.present:
			if err := f.controller.DeleteContext(before.value.LinkIndex, before.value.IncomingTEID); err != nil {
				return rollback(err)
			}
			old := before.value
			undos = append(undos, func() error { _, err := f.controller.EnsureContext(old); return err })
		case !before.present && after.present:
			if _, err := f.controller.EnsureContext(after.value); err != nil {
				return rollback(err)
			}
			created := after.value
			undos = append(undos, func() error { return f.controller.DeleteContext(created.LinkIndex, created.IncomingTEID) })
		case before.value.LinkIndex == after.value.LinkIndex && before.value.UEIPv4 == after.value.UEIPv4 && before.value.IncomingTEID == after.value.IncomingTEID:
			if _, err := f.controller.EnsureContext(after.value); err != nil {
				return rollback(err)
			}
			old := before.value
			undos = append(undos, func() error { _, err := f.controller.EnsureContext(old); return err })
		default:
			if err := f.controller.DeleteContext(before.value.LinkIndex, before.value.IncomingTEID); err != nil {
				return rollback(err)
			}
			old := before.value
			undos = append(undos, func() error { _, err := f.controller.EnsureContext(old); return err })
			if _, err := f.controller.EnsureContext(after.value); err != nil {
				return rollback(err)
			}
			created := after.value
			undos = append(undos, func() error { return f.controller.DeleteContext(created.LinkIndex, created.IncomingTEID) })
		}
	}
	return nil
}

// ReconcileSessions implements rules.Reconciler for durable startup. It makes
// the kernel PDP table authoritative to the recovered WAL snapshot, including
// deletion of stale contexts.
func (f *KernelForwarder) ReconcileSessions(sessions []rules.Session) error {
	select {
	case <-f.closed:
		return errors.New("pgwu kernel dataplane is closed")
	default:
	}
	desired := make([]kernelgtp.Context, 0, len(sessions))
	qci1Desired := make([]kernelgtp.Context, 0)
	for index := range sessions {
		if err := f.validateSession(&sessions[index]); err != nil {
			return fmt.Errorf("reconcile session %d: %w", index, err)
		}
		if f.policy != nil || sessionForwarding(&sessions[index]) {
			desired = append(desired, f.context(sessions[index]))
		}
		if f.policy != nil && len(sessions[index].DedicatedBearers) == 1 {
			bearer := sessions[index].DedicatedBearers[0]
			qci1Desired = append(qci1Desired, kernelgtp.Context{
				LinkIndex: f.qci1Link.Index, UEIPv4: sessions[index].UEIPv4, PeerIPv4: bearer.Remote.IP,
				IncomingTEID: bearer.Local.TEID, OutgoingTEID: bearer.Remote.TEID,
			})
		}
	}
	if f.policy != nil {
		if err := f.policy.ReconcileRouting(nil); err != nil {
			return err
		}
		if err := f.policy.ReconcileSessions(sessions); err != nil {
			return err
		}
	}
	if _, err := f.controller.Reconcile(f.link.Index, desired); err != nil {
		if f.policy != nil {
			_ = f.policy.ReconcileSessions(nil)
		}
		return err
	}
	if f.policy != nil {
		if _, err := f.controller.Reconcile(f.qci1Link.Index, qci1Desired); err != nil {
			_, rollbackErr := f.controller.Reconcile(f.link.Index, nil)
			policyErr := f.policy.ReconcileSessions(nil)
			return errors.Join(err, rollbackErr, policyErr)
		}
		if err := f.policy.ReconcileRouting(sessions); err != nil {
			_, qciRollbackErr := f.controller.Reconcile(f.qci1Link.Index, nil)
			_, defaultRollbackErr := f.controller.Reconcile(f.link.Index, nil)
			policyErr := f.policy.ReconcileSessions(nil)
			routingErr := f.policy.ReconcileRouting(nil)
			return errors.Join(err, qciRollbackErr, defaultRollbackErr, policyErr, routingErr)
		}
	}
	return nil
}

func (f *KernelForwarder) validateSession(session *rules.Session) error {
	served := false
	for _, prefix := range f.uePools {
		if prefix.Contains(session.UEIPv4.Unmap()) {
			served = true
			break
		}
	}
	if !session.UEIPv4.Is4() || !served {
		return fmt.Errorf("%w: UE address %s is outside every served pool", ErrKernelPolicyUnsupported, session.UEIPv4)
	}
	if f.policy == nil && len(session.DedicatedBearers) != 0 {
		return fmt.Errorf("%w: kernel backend cannot safely install dedicated bearer TFTs; use the portable backend", ErrKernelPolicyUnsupported)
	}
	if session.Local.IP.Unmap() != f.s5.Addr().Unmap() {
		return fmt.Errorf("%w: local F-TEID %s does not match S5-U %s", ErrKernelPolicyUnsupported, session.Local.IP, f.s5.Addr())
	}
	if _, ok := f.allowed[session.Remote.IP.Unmap()]; !ok {
		return fmt.Errorf("%w: SGW-U peer %s is not allowlisted", ErrKernelPolicyUnsupported, session.Remote.IP)
	}
	if f.policy != nil {
		if len(session.DedicatedBearers) > 1 {
			return fmt.Errorf("%w: kernel policy supports at most one QCI 1 bearer per UE", ErrKernelPolicyUnsupported)
		}
		if len(session.DedicatedBearers) == 1 {
			bearer := session.DedicatedBearers[0]
			if bearer.QCI != 1 || bearer.Local.IP.Unmap() != f.qci1S5.Addr().Unmap() {
				return fmt.Errorf("%w: dedicated bearer must be QCI 1 on %s", ErrKernelPolicyUnsupported, f.qci1S5.Addr())
			}
			if _, ok := f.allowed[bearer.Remote.IP.Unmap()]; !ok {
				return fmt.Errorf("%w: dedicated SGW-U peer %s is not allowlisted", ErrKernelPolicyUnsupported, bearer.Remote.IP)
			}
		}
		return nil
	}
	if !f.allowUnsupportedPolicy && (session.MaxUplinkBitsPerSecond != 0 || session.MaxDownlinkBitsPerSecond != 0 || session.URRID != 0) {
		return fmt.Errorf("%w: kernel backend cannot enforce QER bitrate or per-session URR; use the portable policy path until TC policy support lands", ErrKernelPolicyUnsupported)
	}
	return nil
}

func (f *KernelForwarder) context(session rules.Session) kernelgtp.Context {
	return kernelgtp.Context{
		LinkIndex: f.link.Index, UEIPv4: session.UEIPv4, PeerIPv4: session.Remote.IP,
		IncomingTEID: session.Local.TEID, OutgoingTEID: session.Remote.TEID,
	}
}

func sessionForwarding(session *rules.Session) bool {
	return session != nil && session.UplinkGateOpen && session.DownlinkGateOpen
}

func sameDedicatedRouting(previous, next *rules.Session) bool {
	if previous == nil || next == nil || len(previous.DedicatedBearers) != 1 || len(next.DedicatedBearers) != 1 {
		return previous == nil && next == nil ||
			previous != nil && next != nil && len(previous.DedicatedBearers) == 0 && len(next.DedicatedBearers) == 0
	}
	return previous.UEIPv4 == next.UEIPv4 && previous.DedicatedBearers[0].QCI == next.DedicatedBearers[0].QCI &&
		reflect.DeepEqual(previous.DedicatedBearers[0].Filters, next.DedicatedBearers[0].Filters)
}

func (f *KernelForwarder) Counters() Counters {
	type linkCounters struct {
		rxPackets, txPackets, rxBytes, txBytes, rxDrops, txDrops, rxErrors, txErrors uint64
		peerFilter                                                                   kernelgtp.PeerFilterCounters
	}
	readLink := func(link kernelgtp.Link) linkCounters {
		if link.Index == 0 {
			return linkCounters{}
		}
		base := filepath.Join("/sys/class/net", link.Name, "statistics")
		peerFilter, _ := f.controller.PeerFilterCounters(link)
		return linkCounters{
			rxPackets: readKernelCounter(base, "rx_packets"), txPackets: readKernelCounter(base, "tx_packets"),
			rxBytes: readKernelCounter(base, "rx_bytes"), txBytes: readKernelCounter(base, "tx_bytes"),
			rxDrops: readKernelCounter(base, "rx_dropped"), txDrops: readKernelCounter(base, "tx_dropped"),
			rxErrors: readKernelCounter(base, "rx_errors"), txErrors: readKernelCounter(base, "tx_errors"),
			peerFilter: peerFilter,
		}
	}
	defaultCounters, qci1Counters := readLink(f.link), readLink(f.qci1Link)
	rxPackets := defaultCounters.rxPackets + qci1Counters.rxPackets
	txPackets := defaultCounters.txPackets + qci1Counters.txPackets
	rxBytes := defaultCounters.rxBytes + qci1Counters.rxBytes
	txBytes := defaultCounters.txBytes + qci1Counters.txBytes
	rxDrops := defaultCounters.rxDrops + qci1Counters.rxDrops
	txDrops := defaultCounters.txDrops + qci1Counters.txDrops
	rxErrors := defaultCounters.rxErrors + qci1Counters.rxErrors
	txErrors := defaultCounters.txErrors + qci1Counters.txErrors
	unauthorized := defaultCounters.peerFilter.DroppedPackets + qci1Counters.peerFilter.DroppedPackets
	recoveredLinks, recoveredFirewalls, recoveredPolicyRules := uint64(0), uint64(0), uint64(0)
	for _, link := range []kernelgtp.Link{f.link, f.qci1Link} {
		if link.Recovery.LinkRemoved {
			recoveredLinks++
		}
		if link.Recovery.PeerFilterRemoved {
			recoveredFirewalls++
		}
		if link.Recovery.PolicyRuleRemoved {
			recoveredPolicyRules++
		}
	}
	result := Counters{
		UplinkPackets: rxPackets, DownlinkPackets: txPackets,
		ForwardedPackets: rxPackets + txPackets, ForwardedBytes: rxBytes + txBytes,
		UplinkBytes: rxBytes, DownlinkBytes: txBytes,
		DroppedPackets:    rxDrops + txDrops + rxErrors + txErrors + unauthorized,
		UnauthorizedPeers: unauthorized,
		WriteErrors:       txErrors,
		RecoveredGTPLinks: recoveredLinks, RecoveredFirewalls: recoveredFirewalls, RecoveredPolicyRules: recoveredPolicyRules,
	}
	if f.policy != nil {
		policy := f.policy.Counters()
		result.DefaultUplinkPackets, result.DefaultUplinkBytes = policy.DefaultUplinkPackets, policy.DefaultUplinkBytes
		result.DefaultDownlinkPackets, result.DefaultDownlinkBytes = policy.DefaultDownlinkPackets, policy.DefaultDownlinkBytes
		result.QCI1UplinkPackets, result.QCI1UplinkBytes = policy.QCI1UplinkPackets, policy.QCI1UplinkBytes
		result.QCI1DownlinkPackets, result.QCI1DownlinkBytes = policy.QCI1DownlinkPackets, policy.QCI1DownlinkBytes
		result.QCI1RoutePackets = policy.QCI1RoutePackets
		result.ActiveTFTFilters, result.ActiveQCI1Sessions, result.ActiveQCI1Contexts, result.TFTSyncErrors =
			policy.ActiveTFTFilters, policy.ActiveQCI1Sessions, policy.ActiveQCI1Contexts, policy.TFTSyncErrors
		result.UplinkPackets = policy.DefaultUplinkPackets + policy.QCI1UplinkPackets
		result.DownlinkPackets = policy.DefaultDownlinkPackets + policy.QCI1DownlinkPackets
		result.UplinkBytes = policy.DefaultUplinkBytes + policy.QCI1UplinkBytes
		result.DownlinkBytes = policy.DefaultDownlinkBytes + policy.QCI1DownlinkBytes
		result.ForwardedPackets = result.UplinkPackets + result.DownlinkPackets
		result.ForwardedBytes = result.UplinkBytes + result.DownlinkBytes
		result.TFTUnmatched = policy.TFTWrongBearerDrops + policy.TFTUnmatchedDrops
		result.FragmentDrops = policy.FragmentDrops
		result.ClosedGates = policy.GateDrops
		result.QERGateDrops = policy.GateDrops
		result.QERRateDrops = policy.RateDrops
		result.URRMeteredPackets = policy.UsagePackets
		result.URRMeteredBytes = policy.UsageBytes
		result.URRActiveMeters = policy.ActiveUsageMeters
		for _, usage := range f.policy.Usage() {
			result.URRThresholdEvents += usage.ThresholdEvents
		}
		policyDrops := policy.GateDrops + policy.RateDrops + policy.TFTWrongBearerDrops + policy.TFTUnmatchedDrops +
			policy.MissingPolicyDrops + policy.StalePolicyDrops + policy.MissingRateDrops + policy.PolicyMapErrors + policy.MalformedPackets + policy.FragmentDrops
		result.DroppedPackets += policyDrops
		result.MalformedIP += policy.MalformedPackets
	}
	return result
}

func (f *KernelForwarder) Usage() []UsageMeasurement {
	if f.policy == nil {
		return nil
	}
	return f.policy.Usage()
}

func readKernelCounter(base, name string) uint64 {
	contents, err := os.ReadFile(filepath.Join(base, name))
	if err != nil {
		return 0
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(contents)), 10, 64)
	if err != nil {
		return 0
	}
	return value
}
