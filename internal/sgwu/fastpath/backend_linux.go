//go:build linux

package fastpath

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/lodestarnetworks/cups/internal/sgwu/dataplane"
	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
)

const (
	sideAccess uint32 = iota
	sideCore
)

const (
	counterAccessPackets uint32 = iota
	counterCorePackets
	counterForwardedPackets
	counterForwardedBytes
	counterUplinkBytes
	counterDownlinkBytes
	counterUnauthorized
	counterRewriteErrors
	counterFallbackPackets
)

const maxFastPathURRsPerRule = 4

type endpoint struct {
	ifindex   uint32
	localIP   uint32
	remoteIP  uint32
	localMAC  [6]byte
	remoteMAC [6]byte
}

type resolvedSide struct {
	ifindex    int
	localIP    uint32
	localMAC   [6]byte
	neighbours map[netip.Addr]endpoint
}

type installedSession struct {
	revision uint64
	tunnels  map[bpfTunnelKey]struct{}
	rules    []bpfRuleKey
	usage    map[bpfUsageKey]rules.URR
}

type usageTracker struct {
	rule               rules.URR
	thresholdEvents    uint64
	nextThreshold      uint64
	rawUplinkPackets   uint64
	rawDownlinkPackets uint64
	rawUplinkBytes     uint64
	rawDownlinkBytes   uint64
	uplinkPackets      uint64
	downlinkPackets    uint64
	uplinkBytes        uint64
	downlinkBytes      uint64
	firstPacket        time.Time
	lastPacket         time.Time
}

type usageTotals struct {
	packets         uint64
	bytes           uint64
	thresholdEvents uint64
}

// Backend owns TCX links and revisioned eBPF maps. Map misses deliberately
// return packets to the portable path; an update first deactivates the session
// so a failed map write cannot leave stale forwarding active.
type Backend struct {
	store   *rules.Store
	objects bpfObjects
	links   []link.Link

	mu                sync.Mutex
	closed            bool
	access            resolvedSide
	core              resolvedSide
	installed         map[uint64]installedSession
	usage             map[bpfUsageKey]*usageTracker
	retiredUsage      usageTotals
	cachedActiveUsage usageTotals

	syncFailures atomic.Uint64
}

func Open(config Config, store *rules.Store) (*Backend, error) {
	if store == nil {
		return nil, errors.New("sgwu fastpath: nil rule store")
	}
	if config.MaxSessions <= 0 {
		config.MaxSessions = store.Capacity()
	}
	if config.MaxSessions <= 0 || uint64(config.MaxSessions) > math.MaxUint32 {
		return nil, errors.New("sgwu fastpath: invalid session capacity")
	}
	if config.MaxRules < 4 || config.MaxRules > 8_000_000 || uint64(config.MaxRules)*2 > math.MaxUint32 {
		return nil, errors.New("sgwu fastpath: max rules must be between 4 and 8000000")
	}
	access, err := resolveSide(config.Access)
	if err != nil {
		return nil, fmt.Errorf("sgwu fastpath access: %w", err)
	}
	core, err := resolveSide(config.Core)
	if err != nil {
		return nil, fmt.Errorf("sgwu fastpath core: %w", err)
	}
	if access.ifindex == core.ifindex {
		return nil, errors.New("sgwu fastpath: access and core interfaces must differ")
	}

	spec, err := loadBpf()
	if err != nil {
		return nil, err
	}
	spec.Maps[bpfMapAllowedPeers].MaxEntries = uint32(len(config.Access.Neighbours) + len(config.Core.Neighbours))
	spec.Maps[bpfMapTunnelSessions].MaxEntries = uint32(config.MaxRules)
	spec.Maps[bpfMapActiveRevisions].MaxEntries = uint32(config.MaxSessions)
	spec.Maps[bpfMapPacketRules].MaxEntries = uint32(config.MaxRules * 2)
	spec.Maps[bpfMapUsageCounters].MaxEntries = uint32(config.MaxRules)
	for _, name := range []string{bpfMapTunnelSessions, bpfMapActiveRevisions, bpfMapPacketRules, bpfMapUsageCounters} {
		spec.Maps[name].Flags |= unix.BPF_F_NO_PREALLOC
	}
	var objects bpfObjects
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("sgwu fastpath load eBPF objects: %w", err)
	}
	backend := &Backend{
		store: store, objects: objects, access: access, core: core,
		installed: make(map[uint64]installedSession), usage: make(map[bpfUsageKey]*usageTracker),
	}
	if err := backend.configureMaps(config); err != nil {
		_ = backend.Close()
		return nil, err
	}
	if err := backend.reconcile(); err != nil {
		_ = backend.Close()
		return nil, err
	}
	accessLink, err := link.AttachTCX(link.TCXOptions{
		Interface: access.ifindex, Program: objects.SgwuAccessIngress,
		Attach: ebpf.AttachTCXIngress,
	})
	if err != nil {
		_ = backend.Close()
		return nil, fmt.Errorf("sgwu fastpath attach access TCX: %w", err)
	}
	backend.links = append(backend.links, accessLink)
	coreLink, err := link.AttachTCX(link.TCXOptions{
		Interface: core.ifindex, Program: objects.SgwuCoreIngress,
		Attach: ebpf.AttachTCXIngress,
	})
	if err != nil {
		_ = backend.Close()
		return nil, fmt.Errorf("sgwu fastpath attach core TCX: %w", err)
	}
	backend.links = append(backend.links, coreLink)
	return backend, nil
}

func (b *Backend) Mode() string { return "ebpf-tcx/ipv4" }

func (b *Backend) SessionChanged(upSEID uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	if err := b.syncSessionLocked(upSEID); err != nil {
		b.syncFailures.Add(1)
	}
}

func (b *Backend) SessionDeleted(upSEID uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	if err := b.deleteSessionLocked(upSEID); err != nil {
		b.syncFailures.Add(1)
	}
}

func (b *Backend) Counters() dataplane.FastPathCounters {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return dataplane.FastPathCounters{SyncFailures: b.syncFailures.Load()}
	}
	access := b.counter(counterAccessPackets)
	core := b.counter(counterCorePackets)
	unauthorized := b.counter(counterUnauthorized)
	rewriteErrors := b.counter(counterRewriteErrors)
	usage := usageTotals{
		packets:         saturatingAdd(b.retiredUsage.packets, b.cachedActiveUsage.packets),
		bytes:           saturatingAdd(b.retiredUsage.bytes, b.cachedActiveUsage.bytes),
		thresholdEvents: saturatingAdd(b.retiredUsage.thresholdEvents, b.cachedActiveUsage.thresholdEvents),
	}
	return dataplane.FastPathCounters{
		AccessPackets: access, CorePackets: core,
		ForwardedPackets: b.counter(counterForwardedPackets),
		ForwardedBytes:   b.counter(counterForwardedBytes),
		UplinkBytes:      b.counter(counterUplinkBytes), DownlinkBytes: b.counter(counterDownlinkBytes),
		DroppedPackets: unauthorized + rewriteErrors, UnauthorizedPeers: unauthorized,
		FallbackPackets: b.counter(counterFallbackPackets), RewriteErrors: rewriteErrors,
		SyncFailures: b.syncFailures.Load(), P95LatencyMicros: b.p95LatencyMicros(),
		URRMeteredPackets: usage.packets, URRMeteredBytes: usage.bytes,
		URRThresholdEvents: usage.thresholdEvents, URRActiveMeters: uint64(len(b.usage)),
	}
}

func (b *Backend) Usage() []dataplane.UsageMeasurement {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	measurements, err := b.usageSnapshotLocked(time.Now().UTC())
	if err != nil {
		b.syncFailures.Add(1)
	}
	return measurements
}

var latencyBucketUpperMicros = [...]uint64{1, 2, 5, 10, 20, 50, 100, 250, 500, 1_000, 2_000, 5_000, 5_000}

func (b *Backend) p95LatencyMicros() uint64 {
	counts := make([]uint64, len(latencyBucketUpperMicros))
	var total uint64
	for index := range counts {
		counts[index] = b.mapCounter(b.objects.LatencyBuckets, uint32(index))
		total += counts[index]
	}
	if total == 0 {
		return 0
	}
	target := (total*95 + 99) / 100
	var cumulative uint64
	for index, count := range counts {
		cumulative += count
		if cumulative >= target {
			return latencyBucketUpperMicros[index]
		}
	}
	return latencyBucketUpperMicros[len(latencyBucketUpperMicros)-1]
}

func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	var result error
	for index := len(b.links) - 1; index >= 0; index-- {
		result = errors.Join(result, b.links[index].Close())
	}
	b.links = nil
	return errors.Join(result, b.objects.Close())
}

func (b *Backend) configureMaps(config Config) error {
	for source, value := range map[uint32]resolvedSide{sideAccess: b.access, sideCore: b.core} {
		entry := bpfSideConfiguration{LocalIp: value.localIP}
		if err := b.objects.SideConfigurations.Update(&source, &entry, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("sgwu fastpath configure side %d: %w", source, err)
		}
	}
	allowed := uint8(1)
	for source, values := range map[uint32][]Neighbour{sideAccess: config.Access.Neighbours, sideCore: config.Core.Neighbours} {
		for _, neighbour := range values {
			key := bpfPeerKey{Source: source, Ip: ipv4Native(neighbour.IP)}
			if err := b.objects.AllowedPeers.Update(&key, &allowed, ebpf.UpdateNoExist); err != nil {
				return fmt.Errorf("sgwu fastpath allow peer %s: %w", neighbour.IP, err)
			}
		}
	}
	return nil
}

func (b *Backend) reconcile() error {
	sessions := b.store.Snapshot()
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].UPSEID < sessions[j].UPSEID })
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, session := range sessions {
		if err := b.syncSessionValueLocked(session); err != nil {
			return fmt.Errorf("sgwu fastpath reconcile UP-SEID %d: %w", session.UPSEID, err)
		}
	}
	return nil
}

func (b *Backend) syncSessionLocked(upSEID uint64) error {
	session, exists := b.store.FindByUPSEID(upSEID)
	if !exists {
		return b.deleteSessionLocked(upSEID)
	}
	return b.syncSessionValueLocked(session)
}

func (b *Backend) syncSessionValueLocked(session rules.Session) error {
	if previous, exists := b.installed[session.UPSEID]; exists && previous.revision == session.Revision {
		return nil
	}
	entries, err := b.buildEntries(session)
	if err != nil {
		_ = b.deactivateLocked(session.UPSEID)
		return err
	}
	if err := b.deactivateLocked(session.UPSEID); err != nil {
		return err
	}
	previous := b.installed[session.UPSEID]
	usage := usageRules(entries)
	if err := b.prepareUsageLocked(usage); err != nil {
		b.purgeEntriesLocked(session.UPSEID, previous, nil, nil, usage)
		return fmt.Errorf("stage usage counters: %w", err)
	}
	stagedRules := make([]bpfRuleKey, 0, len(entries))
	stagedTunnels := make(map[bpfTunnelKey]struct{}, len(entries))
	for _, entry := range entries {
		if err := b.objects.PacketRules.Update(&entry.ruleKey, &entry.value, ebpf.UpdateAny); err != nil {
			b.purgeEntriesLocked(session.UPSEID, previous, stagedTunnels, stagedRules, usage)
			return fmt.Errorf("stage packet rule: %w", err)
		}
		stagedRules = append(stagedRules, entry.ruleKey)
		owner := session.UPSEID
		if err := b.objects.TunnelSessions.Update(&entry.tunnelKey, &owner, ebpf.UpdateAny); err != nil {
			b.purgeEntriesLocked(session.UPSEID, previous, stagedTunnels, stagedRules, usage)
			return fmt.Errorf("stage tunnel index: %w", err)
		}
		stagedTunnels[entry.tunnelKey] = struct{}{}
	}
	revision := session.Revision
	if err := b.objects.ActiveRevisions.Update(&session.UPSEID, &revision, ebpf.UpdateAny); err != nil {
		b.purgeEntriesLocked(session.UPSEID, previous, stagedTunnels, stagedRules, usage)
		return fmt.Errorf("activate revision: %w", err)
	}
	current := installedSession{revision: revision, tunnels: stagedTunnels, rules: stagedRules, usage: usage}
	b.installed[session.UPSEID] = current
	if err := b.cleanupSupersededLocked(previous, current); err != nil {
		return fmt.Errorf("cleanup superseded revision: %w", err)
	}
	return nil
}

type mapEntry struct {
	tunnelKey bpfTunnelKey
	ruleKey   bpfRuleKey
	value     bpfRuleValue
	usage     []rules.URR
}

func (b *Backend) buildEntries(session rules.Session) ([]mapEntry, error) {
	ids := make([]int, 0, len(session.PDRs))
	for id := range session.PDRs {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	type candidate struct {
		pdr         rules.PDR
		destination endpoint
		source      uint32
		usage       []rules.URR
	}
	candidates := make(map[uint16]candidate, len(ids))
	portableURRs := make(map[uint32]struct{})
	for _, rawID := range ids {
		pdr := session.PDRs[uint16(rawID)]
		usage, usageOK := pdrUsageRules(session, pdr)
		far, exists := session.FARs[pdr.FARID]
		eligible := usageOK && exists && far.ApplyAction&rules.ActionForward != 0 &&
			far.ApplyAction&(rules.ActionDrop|rules.ActionBuffer) == 0 && far.OuterHeader != nil &&
			gatesOpen(session, pdr) && !requiresPortablePolicy(session, pdr, usage) &&
			pdr.LocalFTEID.IP.Is4() && far.OuterHeader.IP.Is4()
		if !eligible {
			markPortableURRs(portableURRs, usage)
			continue
		}
		source, err := sourceID(pdr.SourceInterface)
		if err != nil {
			return nil, err
		}
		destination, err := b.destination(far.DestinationInterface, far.OuterHeader.IP)
		if err != nil {
			// A missing neighbour is a safe portable-path fallback, not a
			// reason to reject the already committed PFCP session.
			markPortableURRs(portableURRs, usage)
			continue
		}
		candidates[pdr.ID] = candidate{pdr: pdr, destination: destination, source: source, usage: usage}
	}
	// An URR must be wholly kernel- or portable-accounted. Propagate fallback
	// across PDRs sharing multiple URRs so threshold events cannot be split.
	for changed := true; changed; {
		changed = false
		for _, current := range candidates {
			if !hasPortableURR(portableURRs, current.usage) {
				continue
			}
			for _, urr := range current.usage {
				if _, exists := portableURRs[urr.ID]; !exists {
					portableURRs[urr.ID] = struct{}{}
					changed = true
				}
			}
		}
	}
	entries := make([]mapEntry, 0, len(candidates))
	for _, rawID := range ids {
		current, exists := candidates[uint16(rawID)]
		if !exists || hasPortableURR(portableURRs, current.usage) {
			continue
		}
		pdr := current.pdr
		far := session.FARs[pdr.FARID]
		tunnelKey := bpfTunnelKey{Source: current.source, Teid: pdr.LocalFTEID.TEID}
		ruleKey := bpfRuleKey{UpSeid: session.UPSEID, Revision: session.Revision, Source: current.source, Teid: pdr.LocalFTEID.TEID}
		value := bpfRuleValue{
			EgressIfindex: current.destination.ifindex, SourceIp: current.destination.localIP,
			DestinationIp: current.destination.remoteIP, Teid: far.OuterHeader.TEID,
			SourceMac: current.destination.localMAC, DestinationMac: current.destination.remoteMAC,
			UrrCount: uint32(len(current.usage)),
		}
		for index, urr := range current.usage {
			value.UrrIds[index] = urr.ID
		}
		entries = append(entries, mapEntry{tunnelKey: tunnelKey, ruleKey: ruleKey, value: value, usage: current.usage})
	}
	return entries, nil
}

func pdrUsageRules(session rules.Session, pdr rules.PDR) ([]rules.URR, bool) {
	unique := make(map[uint32]rules.URR, len(pdr.URRIDs))
	for _, id := range pdr.URRIDs {
		urr, exists := session.URRs[id]
		if !exists {
			return nil, false
		}
		unique[id] = urr
	}
	out := make([]rules.URR, 0, len(unique))
	for _, urr := range unique {
		out = append(out, urr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, true
}

func markPortableURRs(target map[uint32]struct{}, usage []rules.URR) {
	for _, urr := range usage {
		target[urr.ID] = struct{}{}
	}
}

func hasPortableURR(portable map[uint32]struct{}, usage []rules.URR) bool {
	for _, urr := range usage {
		if _, exists := portable[urr.ID]; exists {
			return true
		}
	}
	return false
}

func usageRules(entries []mapEntry) map[bpfUsageKey]rules.URR {
	out := make(map[bpfUsageKey]rules.URR)
	for _, entry := range entries {
		for _, urr := range entry.usage {
			key := bpfUsageKey{UpSeid: entry.ruleKey.UpSeid, UrrId: urr.ID}
			out[key] = urr
		}
	}
	return out
}

func sortedUsageKeys(values map[bpfUsageKey]rules.URR) []bpfUsageKey {
	keys := make([]bpfUsageKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].UpSeid == keys[j].UpSeid {
			return keys[i].UrrId < keys[j].UrrId
		}
		return keys[i].UpSeid < keys[j].UpSeid
	})
	return keys
}

func (b *Backend) prepareUsageLocked(values map[bpfUsageKey]rules.URR) error {
	if b.usage == nil {
		b.usage = make(map[bpfUsageKey]*usageTracker)
	}
	now := time.Now().UTC()
	for _, key := range sortedUsageKeys(values) {
		rule := values[key]
		if tracker := b.usage[key]; tracker != nil {
			if err := b.refreshUsageKeyLocked(key, tracker, now); err != nil {
				return err
			}
			if tracker.rule.ReportingThreshold != rule.ReportingThreshold {
				tracker.nextThreshold = nextUsageThreshold(saturatingAdd(tracker.uplinkBytes, tracker.downlinkBytes), rule.ReportingThreshold)
			}
			tracker.rule = rule
			continue
		}
		zero := bpfUsageValue{}
		if err := b.objects.UsageCounters.Update(&key, &zero, ebpf.UpdateNoExist); err != nil {
			if !errors.Is(err, ebpf.ErrKeyExist) {
				return err
			}
		}
		b.usage[key] = &usageTracker{rule: rule, nextThreshold: rule.ReportingThreshold}
	}
	return nil
}

func (b *Backend) usageSnapshotLocked(now time.Time) ([]dataplane.UsageMeasurement, error) {
	keys := make([]bpfUsageKey, 0, len(b.usage))
	for key := range b.usage {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].UpSeid == keys[j].UpSeid {
			return keys[i].UrrId < keys[j].UrrId
		}
		return keys[i].UpSeid < keys[j].UpSeid
	})
	result := b.refreshAllUsageLocked(keys, now)
	out := make([]dataplane.UsageMeasurement, 0, len(keys))
	for _, key := range keys {
		tracker := b.usage[key]
		out = append(out, dataplane.UsageMeasurement{
			UPSEID: key.UpSeid, URRID: key.UrrId,
			UplinkPackets: tracker.uplinkPackets, DownlinkPackets: tracker.downlinkPackets,
			UplinkBytes: tracker.uplinkBytes, DownlinkBytes: tracker.downlinkBytes,
			ThresholdEvents: tracker.thresholdEvents,
			FirstPacket:     tracker.firstPacket, LastPacket: tracker.lastPacket,
		})
	}
	return out, result
}

func (b *Backend) refreshAllUsageLocked(keys []bpfUsageKey, now time.Time) error {
	if len(keys) <= 128 {
		return b.refreshUsageKeysIndividuallyLocked(keys, now)
	}
	const batchSize = 4096
	batchKeys := make([]bpfUsageKey, batchSize)
	batchValues := make([]bpfUsageValue, batchSize)
	cursor := &ebpf.MapBatchCursor{}
	seen := 0
	for {
		count, err := b.objects.UsageCounters.BatchLookup(cursor, batchKeys, batchValues, nil)
		for index := 0; index < count; index++ {
			if tracker := b.usage[batchKeys[index]]; tracker != nil {
				b.applyUsageValueLocked(tracker, batchValues[index], now)
				seen++
			}
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			if seen == len(keys) {
				return nil
			}
			return b.refreshUsageKeysIndividuallyLocked(keys, now)
		}
		if err != nil {
			// Older kernels and unusually dense hash buckets can reject batch
			// lookup. The bounded per-key path preserves correctness in that
			// case while newer production kernels keep the low-syscall path.
			return b.refreshUsageKeysIndividuallyLocked(keys, now)
		}
		if count == 0 {
			// A successful batch lookup must advance the cursor. Guard against a
			// kernel or library edge case returning no entries without EOF so a
			// telemetry scrape can never hold the dataplane mutex forever.
			return b.refreshUsageKeysIndividuallyLocked(keys, now)
		}
	}
}

func (b *Backend) refreshUsageKeysIndividuallyLocked(keys []bpfUsageKey, now time.Time) error {
	var result error
	for _, key := range keys {
		if err := b.refreshUsageKeyLocked(key, b.usage[key], now); err != nil {
			result = errors.Join(result, fmt.Errorf("read usage UP-SEID %d URR %d: %w", key.UpSeid, key.UrrId, err))
		}
	}
	return result
}

func (b *Backend) refreshUsageKeyLocked(key bpfUsageKey, tracker *usageTracker, now time.Time) error {
	var current bpfUsageValue
	if err := b.objects.UsageCounters.Lookup(&key, &current); err != nil {
		return err
	}
	b.applyUsageValueLocked(tracker, current, now)
	return nil
}

func (b *Backend) applyUsageValueLocked(tracker *usageTracker, current bpfUsageValue, now time.Time) {
	previous := trackerTotals(tracker)
	uplinkPacketDelta := monotonicDelta(current.UplinkPackets, tracker.rawUplinkPackets)
	downlinkPacketDelta := monotonicDelta(current.DownlinkPackets, tracker.rawDownlinkPackets)
	uplinkByteDelta := monotonicDelta(current.UplinkBytes, tracker.rawUplinkBytes)
	downlinkByteDelta := monotonicDelta(current.DownlinkBytes, tracker.rawDownlinkBytes)
	tracker.rawUplinkPackets = current.UplinkPackets
	tracker.rawDownlinkPackets = current.DownlinkPackets
	tracker.rawUplinkBytes = current.UplinkBytes
	tracker.rawDownlinkBytes = current.DownlinkBytes
	tracker.uplinkPackets = saturatingAdd(tracker.uplinkPackets, uplinkPacketDelta)
	tracker.downlinkPackets = saturatingAdd(tracker.downlinkPackets, downlinkPacketDelta)
	if tracker.rule.MeasureVolume {
		tracker.uplinkBytes = saturatingAdd(tracker.uplinkBytes, uplinkByteDelta)
		tracker.downlinkBytes = saturatingAdd(tracker.downlinkBytes, downlinkByteDelta)
	}
	if uplinkPacketDelta != 0 || downlinkPacketDelta != 0 {
		if tracker.firstPacket.IsZero() {
			tracker.firstPacket = now
		}
		tracker.lastPacket = now
	}
	total := saturatingAdd(tracker.uplinkBytes, tracker.downlinkBytes)
	if threshold := tracker.rule.ReportingThreshold; tracker.rule.MeasureVolume && threshold != 0 && tracker.nextThreshold != 0 && total >= tracker.nextThreshold {
		crossed := (total-tracker.nextThreshold)/threshold + 1
		tracker.thresholdEvents = saturatingAdd(tracker.thresholdEvents, crossed)
		tracker.nextThreshold = saturatingAdd(tracker.nextThreshold, saturatingMultiply(crossed, threshold))
	}
	b.replaceCachedUsageLocked(previous, trackerTotals(tracker))
}

func trackerTotals(tracker *usageTracker) usageTotals {
	return usageTotals{
		packets:         saturatingAdd(tracker.uplinkPackets, tracker.downlinkPackets),
		bytes:           saturatingAdd(tracker.uplinkBytes, tracker.downlinkBytes),
		thresholdEvents: tracker.thresholdEvents,
	}
}

func (b *Backend) replaceCachedUsageLocked(previous, current usageTotals) {
	b.cachedActiveUsage.packets = replaceMonotonicTotal(b.cachedActiveUsage.packets, previous.packets, current.packets)
	b.cachedActiveUsage.bytes = replaceMonotonicTotal(b.cachedActiveUsage.bytes, previous.bytes, current.bytes)
	b.cachedActiveUsage.thresholdEvents = replaceMonotonicTotal(b.cachedActiveUsage.thresholdEvents, previous.thresholdEvents, current.thresholdEvents)
}

func replaceMonotonicTotal(total, previous, current uint64) uint64 {
	if previous > total {
		total = 0
	} else {
		total -= previous
	}
	return saturatingAdd(total, current)
}

func monotonicDelta(current, previous uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	return current
}

func nextUsageThreshold(total, threshold uint64) uint64 {
	if threshold == 0 {
		return 0
	}
	completed := total / threshold
	if completed == math.MaxUint64 {
		return math.MaxUint64
	}
	return saturatingMultiply(completed+1, threshold)
}

func saturatingAdd(left, right uint64) uint64 {
	if right > math.MaxUint64-left {
		return math.MaxUint64
	}
	return left + right
}

func saturatingMultiply(left, right uint64) uint64 {
	if left != 0 && right > math.MaxUint64/left {
		return math.MaxUint64
	}
	return left * right
}

func gatesOpen(session rules.Session, pdr rules.PDR) bool {
	for _, id := range pdr.QERIDs {
		qer, exists := session.QERs[id]
		if !exists || (pdr.SourceInterface == rules.SourceAccess && !qer.UplinkGateOpen) || (pdr.SourceInterface == rules.SourceCore && !qer.DownlinkGateOpen) {
			return false
		}
	}
	return true
}

func requiresPortablePolicy(session rules.Session, pdr rules.PDR, usage []rules.URR) bool {
	if len(usage) > maxFastPathURRsPerRule {
		return true
	}
	for _, id := range pdr.QERIDs {
		qer, exists := session.QERs[id]
		if !exists || qer.MaxUplinkBitsPerSecond != 0 || qer.MaxDownlinkBitsPerSecond != 0 || qer.QCI == 1 {
			return true
		}
	}
	return false
}

func (b *Backend) destination(side rules.DestinationInterface, address netip.Addr) (endpoint, error) {
	address = address.Unmap()
	var values map[netip.Addr]endpoint
	switch side {
	case rules.DestinationAccess:
		values = b.access.neighbours
	case rules.DestinationCore:
		values = b.core.neighbours
	default:
		return endpoint{}, errors.New("unsupported destination interface")
	}
	value, exists := values[address]
	if !exists {
		return endpoint{}, fmt.Errorf("no neighbour for %s", address)
	}
	return value, nil
}

func (b *Backend) deleteSessionLocked(upSEID uint64) error {
	if err := b.deactivateLocked(upSEID); err != nil {
		return err
	}
	previous, exists := b.installed[upSEID]
	if !exists {
		return nil
	}
	delete(b.installed, upSEID)
	var result error
	for key := range previous.tunnels {
		result = errors.Join(result, deleteMapKey(b.objects.TunnelSessions, &key))
	}
	for _, key := range previous.rules {
		result = errors.Join(result, deleteMapKey(b.objects.PacketRules, &key))
	}
	for key := range previous.usage {
		result = errors.Join(result, b.retireUsageKeyLocked(key))
	}
	return result
}

func (b *Backend) deactivateLocked(upSEID uint64) error {
	err := b.objects.ActiveRevisions.Delete(&upSEID)
	if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	var disabled uint64
	if updateErr := b.objects.ActiveRevisions.Update(&upSEID, &disabled, ebpf.UpdateAny); updateErr != nil {
		return errors.Join(fmt.Errorf("delete active revision: %w", err), fmt.Errorf("zero active revision: %w", updateErr))
	}
	return nil
}

func (b *Backend) purgeEntriesLocked(upSEID uint64, previous installedSession, tunnels map[bpfTunnelKey]struct{}, ruleKeys []bpfRuleKey, usage map[bpfUsageKey]rules.URR) {
	_ = b.deactivateLocked(upSEID)
	for key := range tunnels {
		_ = deleteMapKey(b.objects.TunnelSessions, &key)
	}
	for key := range previous.tunnels {
		_ = deleteMapKey(b.objects.TunnelSessions, &key)
	}
	for _, key := range ruleKeys {
		_ = deleteMapKey(b.objects.PacketRules, &key)
	}
	for _, key := range previous.rules {
		_ = deleteMapKey(b.objects.PacketRules, &key)
	}
	allUsage := make(map[bpfUsageKey]struct{}, len(previous.usage)+len(usage))
	for key := range previous.usage {
		allUsage[key] = struct{}{}
	}
	for key := range usage {
		allUsage[key] = struct{}{}
	}
	for key := range allUsage {
		_ = b.retireUsageKeyLocked(key)
	}
	delete(b.installed, upSEID)
}

func (b *Backend) cleanupSupersededLocked(previous, current installedSession) error {
	var result error
	for key := range previous.tunnels {
		if _, retained := current.tunnels[key]; !retained {
			result = errors.Join(result, deleteMapKey(b.objects.TunnelSessions, &key))
		}
	}
	for _, key := range previous.rules {
		result = errors.Join(result, deleteMapKey(b.objects.PacketRules, &key))
	}
	for key := range previous.usage {
		if _, retained := current.usage[key]; !retained {
			result = errors.Join(result, b.retireUsageKeyLocked(key))
		}
	}
	return result
}

func (b *Backend) retireUsageKeyLocked(key bpfUsageKey) error {
	tracker := b.usage[key]
	var result error
	if tracker != nil {
		if err := b.refreshUsageKeyLocked(key, tracker, time.Now().UTC()); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			result = errors.Join(result, err)
		}
		totals := trackerTotals(tracker)
		b.replaceCachedUsageLocked(totals, usageTotals{})
		b.retiredUsage.packets = saturatingAdd(b.retiredUsage.packets, totals.packets)
		b.retiredUsage.bytes = saturatingAdd(b.retiredUsage.bytes, totals.bytes)
		b.retiredUsage.thresholdEvents = saturatingAdd(b.retiredUsage.thresholdEvents, totals.thresholdEvents)
		delete(b.usage, key)
	}
	result = errors.Join(result, deleteMapKey(b.objects.UsageCounters, &key))
	return result
}

func deleteMapKey(value *ebpf.Map, key any) error {
	err := value.Delete(key)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (b *Backend) counter(index uint32) uint64 {
	return b.mapCounter(b.objects.Counters, index)
}

func (b *Backend) mapCounter(valueMap *ebpf.Map, index uint32) uint64 {
	values := make([]uint64, 0)
	if err := valueMap.Lookup(&index, &values); err != nil {
		return 0
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	return total
}

func resolveSide(config Side) (resolvedSide, error) {
	if config.Interface == "" || !config.LocalIP.Is4() || len(config.Neighbours) == 0 {
		return resolvedSide{}, errors.New("interface, IPv4 local address, and neighbours are required")
	}
	device, err := net.InterfaceByName(config.Interface)
	if err != nil {
		return resolvedSide{}, err
	}
	if len(device.HardwareAddr) != 6 || device.HardwareAddr[0]&1 != 0 {
		return resolvedSide{}, errors.New("interface requires a unicast 6-byte Ethernet address")
	}
	if !interfaceHasAddress(device, config.LocalIP) {
		return resolvedSide{}, fmt.Errorf("interface %s does not own %s", config.Interface, config.LocalIP)
	}
	value := resolvedSide{
		ifindex: device.Index, localIP: ipv4Native(config.LocalIP),
		neighbours: make(map[netip.Addr]endpoint, len(config.Neighbours)),
	}
	copy(value.localMAC[:], device.HardwareAddr)
	for _, neighbour := range config.Neighbours {
		ip := neighbour.IP.Unmap()
		if !ip.Is4() || len(neighbour.MAC) != 6 || neighbour.MAC[0]&1 != 0 {
			return resolvedSide{}, fmt.Errorf("invalid neighbour %s", neighbour.IP)
		}
		if _, exists := value.neighbours[ip]; exists {
			return resolvedSide{}, fmt.Errorf("duplicate neighbour %s", ip)
		}
		current := endpoint{ifindex: uint32(device.Index), localIP: value.localIP, remoteIP: ipv4Native(ip), localMAC: value.localMAC}
		copy(current.remoteMAC[:], neighbour.MAC)
		value.neighbours[ip] = current
	}
	return value, nil
}

func interfaceHasAddress(device *net.Interface, wanted netip.Addr) bool {
	addresses, err := device.Addrs()
	if err != nil {
		return false
	}
	wanted = wanted.Unmap()
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Unmap() == wanted {
			return true
		}
	}
	return false
}

func sourceID(value rules.SourceInterface) (uint32, error) {
	switch value {
	case rules.SourceAccess:
		return sideAccess, nil
	case rules.SourceCore:
		return sideCore, nil
	default:
		return 0, errors.New("unsupported source interface")
	}
}

func ipv4Native(value netip.Addr) uint32 {
	bytes := value.Unmap().As4()
	return binary.NativeEndian.Uint32(bytes[:])
}
