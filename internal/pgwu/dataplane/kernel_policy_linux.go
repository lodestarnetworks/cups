//go:build linux

package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

const (
	kernelPolicyDirectionUplink uint8 = iota
	kernelPolicyDirectionDownlink
)

const (
	kernelPolicyBearerDefault uint8 = iota
	kernelPolicyBearerQCI1
)

const (
	kernelPolicyFilterLocalAddress uint8 = 1 << iota
	kernelPolicyFilterRemoteAddress
	kernelPolicyFilterProtocol
	kernelPolicyFilterLocalPort
	kernelPolicyFilterRemotePort
	kernelPolicyFilterTOS
)

const (
	kernelPolicyGateDefaultUplink uint8 = 1 << iota
	kernelPolicyGateDefaultDownlink
	kernelPolicyGateQCI1Uplink
	kernelPolicyGateQCI1Downlink
)

const (
	kernelPolicyCounterDefaultUplink uint32 = iota
	kernelPolicyCounterDefaultUplinkBytes
	kernelPolicyCounterDefaultDownlink
	kernelPolicyCounterDefaultDownlinkBytes
	kernelPolicyCounterQCI1Uplink
	kernelPolicyCounterQCI1UplinkBytes
	kernelPolicyCounterQCI1Downlink
	kernelPolicyCounterQCI1DownlinkBytes
	kernelPolicyCounterQCI1RoutePackets
	kernelPolicyCounterGateDrops
	kernelPolicyCounterRateDrops
	kernelPolicyCounterTFTWrongBearer
	kernelPolicyCounterTFTUnmatched
	kernelPolicyCounterMissingPolicy
	kernelPolicyCounterStalePolicy
	kernelPolicyCounterMissingRate
	kernelPolicyCounterMapErrors
	kernelPolicyCounterMalformed
	kernelPolicyCounterFragmentDrops
	kernelPolicyCounterUsagePackets
	kernelPolicyCounterUsageBytes
	kernelPolicyCounterCount
)

type kernelPolicyFilterEntry struct {
	key   pgwupolicyFilterKey
	value pgwupolicyFilterValue
}

type kernelPolicyRateEntry struct {
	key   pgwupolicyRateKey
	value pgwupolicyRateValue
}

type kernelPolicyUsageEntry struct {
	key       pgwupolicyUsageKey
	qci       uint8
	arp       uint8
	threshold uint64
	default_  bool
}

type installedKernelPolicy struct {
	upSEID   uint64
	revision uint64
	ueIP     uint32
	policy   pgwupolicyPolicyValue
	filters  []kernelPolicyFilterEntry
	rates    []kernelPolicyRateEntry
	usage    []kernelPolicyUsageEntry
}

type kernelPolicy struct {
	objects    pgwupolicyObjects
	links      []link.Link
	classifier *kernelTFTClassifier

	mu             sync.Mutex
	closed         bool
	maxFilters     int
	burst          time.Duration
	packetSizeBits uint64
	possibleCPUs   int
	installed      map[uint64]installedKernelPolicy
	syncErrors     uint64
}

func openKernelPolicy(config kernelPolicyConfig) (kernelPolicyBackend, error) {
	if config.DefaultLink.Index == 0 || config.QCI1Link.Index == 0 || config.DefaultLink.Index == config.QCI1Link.Index {
		return nil, errors.New("pgwu kernel policy: distinct default and QCI 1 GTP links are required")
	}
	if config.MaxSessions <= 0 || uint64(config.MaxSessions) > math.MaxUint32/4 {
		return nil, errors.New("pgwu kernel policy: invalid session capacity")
	}
	if config.MaxFilters <= 0 || config.MaxFilters > 8_000_000 {
		return nil, errors.New("pgwu kernel policy: filter capacity must be between 1 and 8000000")
	}
	if config.BurstDuration <= 0 || config.BurstDuration > time.Second {
		return nil, errors.New("pgwu kernel policy: QER burst duration must be between 1ns and 1s")
	}
	if config.PacketSizeBits == 0 {
		return nil, errors.New("pgwu kernel policy: packet-size burst floor is required")
	}
	if err := requireKernelPolicyRPFilterDisabled(config.DefaultLink.Name, config.QCI1Link.Name); err != nil {
		return nil, err
	}
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("pgwu kernel policy: resolve possible CPUs: %w", err)
	}
	spec, err := loadPgwupolicy()
	if err != nil {
		return nil, fmt.Errorf("pgwu kernel policy: load embedded eBPF: %w", err)
	}
	spec.Maps[pgwupolicyMapPolicies].MaxEntries = uint32(config.MaxSessions)
	spec.Maps[pgwupolicyMapActiveRevisions].MaxEntries = uint32(config.MaxSessions)
	spec.Maps[pgwupolicyMapTftFilters].MaxEntries = uint32(config.MaxFilters)
	spec.Maps[pgwupolicyMapRateStates].MaxEntries = uint32(config.MaxSessions * 4)
	spec.Maps[pgwupolicyMapUsageCounters].MaxEntries = uint32(config.MaxSessions * 2)
	fragmentEntries := config.MaxSessions
	if fragmentEntries < 4_096 {
		fragmentEntries = 4_096
	}
	if fragmentEntries > 262_144 {
		fragmentEntries = 262_144
	}
	spec.Maps[pgwupolicyMapFragmentDecisions].MaxEntries = uint32(fragmentEntries)
	for _, name := range []string{
		pgwupolicyMapPolicies, pgwupolicyMapActiveRevisions, pgwupolicyMapTftFilters,
		pgwupolicyMapRateStates, pgwupolicyMapUsageCounters,
	} {
		spec.Maps[name].Flags |= unix.BPF_F_NO_PREALLOC
	}
	var objects pgwupolicyObjects
	// Some LTS kernels return EFAULT rather than ENOSPC when the verifier log
	// exceeds cilium/ebpf's 64 KiB default. Starting with a larger buffer avoids
	// that kernel failure mode while retaining the library's bounded growth and
	// complete verifier diagnostics on genuine program rejection.
	loadOptions := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20},
	}
	if err := spec.LoadAndAssign(&objects, loadOptions); err != nil {
		return nil, fmt.Errorf("pgwu kernel policy: load eBPF objects: %w", err)
	}
	classifier, err := openKernelTFTClassifier(config)
	if err != nil {
		_ = objects.Close()
		return nil, err
	}
	policy := &kernelPolicy{
		objects: objects, classifier: classifier,
		maxFilters: config.MaxFilters, burst: config.BurstDuration,
		packetSizeBits: config.PacketSizeBits, possibleCPUs: possibleCPUs,
		installed: make(map[uint64]installedKernelPolicy),
	}
	defaultIngress, err := link.AttachTCX(link.TCXOptions{
		Interface: int(config.DefaultLink.Index), Program: objects.PgwuDefaultIngress, Attach: ebpf.AttachTCXIngress,
	})
	if err != nil {
		_ = policy.Close()
		return nil, fmt.Errorf("pgwu kernel policy: attach default ingress: %w", err)
	}
	policy.links = append(policy.links, defaultIngress)
	defaultEgress, err := link.AttachTCX(link.TCXOptions{
		Interface: int(config.DefaultLink.Index), Program: objects.PgwuDefaultEgress, Attach: ebpf.AttachTCXEgress,
	})
	if err != nil {
		_ = policy.Close()
		return nil, fmt.Errorf("pgwu kernel policy: attach default egress: %w", err)
	}
	policy.links = append(policy.links, defaultEgress)
	qci1Ingress, err := link.AttachTCX(link.TCXOptions{
		Interface: int(config.QCI1Link.Index), Program: objects.PgwuQci1Ingress, Attach: ebpf.AttachTCXIngress,
	})
	if err != nil {
		_ = policy.Close()
		return nil, fmt.Errorf("pgwu kernel policy: attach QCI 1 ingress: %w", err)
	}
	policy.links = append(policy.links, qci1Ingress)
	qci1Egress, err := link.AttachTCX(link.TCXOptions{
		Interface: int(config.QCI1Link.Index), Program: objects.PgwuQci1Egress, Attach: ebpf.AttachTCXEgress,
	})
	if err != nil {
		_ = policy.Close()
		return nil, fmt.Errorf("pgwu kernel policy: attach QCI 1 egress: %w", err)
	}
	policy.links = append(policy.links, qci1Egress)
	return policy, nil
}

func requireKernelPolicyRPFilterDisabled(linkNames ...string) error {
	names := append([]string{"all"}, linkNames...)
	for _, name := range names {
		path := filepath.Join("/proc/sys/net/ipv4/conf", name, "rp_filter")
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("pgwu kernel policy: read net.ipv4.conf.%s.rp_filter: %w", name, err)
		}
		value, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 8)
		if err != nil {
			return fmt.Errorf("pgwu kernel policy: parse net.ipv4.conf.%s.rp_filter: %w", name, err)
		}
		if value != 0 {
			return fmt.Errorf("pgwu kernel policy: net.ipv4.conf.%s.rp_filter=%d; asymmetric default/QCI1 GTP paths require reverse-path filtering disabled", name, value)
		}
	}
	return nil
}

func (p *kernelPolicy) Apply(previous, next *rules.Session) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("pgwu kernel policy is closed")
	}
	if previous != nil && next != nil && previous.UPSEID != next.UPSEID {
		return errors.New("pgwu kernel policy: session identity changed")
	}
	switch {
	case next == nil && previous == nil:
		return nil
	case next == nil:
		return p.deleteLocked(previous.UPSEID)
	default:
		built, err := p.build(*next)
		if err != nil {
			return err
		}
		return p.replaceLocked(built)
	}
}

func (p *kernelPolicy) ApplyRouting(previous, next *rules.Session) error {
	return p.classifier.Apply(previous, next)
}

func (p *kernelPolicy) ReconcileSessions(sessions []rules.Session) error {
	built := make([]installedKernelPolicy, len(sessions))
	seen := make(map[uint64]struct{}, len(sessions))
	for index := range sessions {
		entry, err := p.build(sessions[index])
		if err != nil {
			return fmt.Errorf("pgwu kernel policy reconcile session %d: %w", index, err)
		}
		if _, exists := seen[entry.upSEID]; exists {
			return fmt.Errorf("pgwu kernel policy reconcile: duplicate UP-SEID %d", entry.upSEID)
		}
		seen[entry.upSEID] = struct{}{}
		built[index] = entry
	}
	sort.Slice(built, func(i, j int) bool { return built[i].upSEID < built[j].upSEID })

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("pgwu kernel policy is closed")
	}
	for upSEID := range p.installed {
		if err := p.deleteLocked(upSEID); err != nil {
			return err
		}
	}
	staged := make([]uint64, 0, len(built))
	for _, entry := range built {
		if err := p.installLocked(entry); err != nil {
			result := err
			for index := len(staged) - 1; index >= 0; index-- {
				result = errors.Join(result, p.deleteLocked(staged[index]))
			}
			return result
		}
		p.installed[entry.upSEID] = entry
		staged = append(staged, entry.upSEID)
	}
	return nil
}

func (p *kernelPolicy) ReconcileRouting(sessions []rules.Session) error {
	return p.classifier.Reconcile(sessions)
}

func (p *kernelPolicy) replaceLocked(next installedKernelPolicy) error {
	previous, hadPrevious := p.installed[next.upSEID]
	if hadPrevious && previous.revision == next.revision {
		return nil
	}
	if err := p.deactivateLocked(next.upSEID); err != nil {
		return err
	}
	if err := p.installMapsLocked(next); err != nil {
		cleanupErr := p.removeMapsLocked(next, installedKernelPolicy{})
		var restoreErr error
		if hadPrevious {
			restoreErr = p.installLocked(previous)
		}
		p.syncErrors++
		return errors.Join(err, cleanupErr, restoreErr)
	}
	if err := p.activateLocked(next.upSEID, next.revision); err != nil {
		cleanupErr := p.removeMapsLocked(next, installedKernelPolicy{})
		var restoreErr error
		if hadPrevious {
			restoreErr = p.installLocked(previous)
		}
		p.syncErrors++
		return errors.Join(err, cleanupErr, restoreErr)
	}
	if hadPrevious {
		if err := p.removeMapsLocked(previous, next); err != nil {
			_ = p.deactivateLocked(next.upSEID)
			_ = p.removeMapsLocked(next, installedKernelPolicy{})
			restoreErr := p.installLocked(previous)
			p.syncErrors++
			return errors.Join(err, restoreErr)
		}
	}
	p.installed[next.upSEID] = next
	return nil
}

func (p *kernelPolicy) installLocked(entry installedKernelPolicy) error {
	if err := p.deactivateLocked(entry.upSEID); err != nil {
		return err
	}
	if err := p.installMapsLocked(entry); err != nil {
		return err
	}
	return p.activateLocked(entry.upSEID, entry.revision)
}

func (p *kernelPolicy) installMapsLocked(entry installedKernelPolicy) error {
	if err := p.objects.Policies.Update(&entry.ueIP, &entry.policy, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("install PGW-U policy: %w", err)
	}
	for _, filter := range entry.filters {
		if err := p.objects.TftFilters.Update(&filter.key, &filter.value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("install PGW-U TFT filter: %w", err)
		}
	}
	for _, rate := range entry.rates {
		if err := p.objects.RateStates.Update(&rate.key, &rate.value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("install PGW-U rate state: %w", err)
		}
	}
	zero := make([]pgwupolicyUsageValue, p.possibleCPUs)
	for _, usage := range entry.usage {
		if err := p.objects.UsageCounters.Update(&usage.key, zero, ebpf.UpdateNoExist); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("install PGW-U usage counter: %w", err)
		}
	}
	return nil
}

func (p *kernelPolicy) activateLocked(upSEID, revision uint64) error {
	if err := p.objects.ActiveRevisions.Update(&upSEID, &revision, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("activate PGW-U policy revision: %w", err)
	}
	return nil
}

func (p *kernelPolicy) deactivateLocked(upSEID uint64) error {
	err := p.objects.ActiveRevisions.Delete(&upSEID)
	if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return fmt.Errorf("deactivate PGW-U policy revision: %w", err)
}

func (p *kernelPolicy) deleteLocked(upSEID uint64) error {
	entry, exists := p.installed[upSEID]
	if !exists {
		return p.deactivateLocked(upSEID)
	}
	result := p.deactivateLocked(upSEID)
	result = errors.Join(result, p.removeMapsLocked(entry, installedKernelPolicy{}))
	if result == nil {
		delete(p.installed, upSEID)
	}
	return result
}

func (p *kernelPolicy) removeMapsLocked(remove, retain installedKernelPolicy) error {
	retainedFilters := make(map[pgwupolicyFilterKey]struct{}, len(retain.filters))
	for _, entry := range retain.filters {
		retainedFilters[entry.key] = struct{}{}
	}
	retainedRates := make(map[pgwupolicyRateKey]struct{}, len(retain.rates))
	for _, entry := range retain.rates {
		retainedRates[entry.key] = struct{}{}
	}
	retainedUsage := make(map[pgwupolicyUsageKey]struct{}, len(retain.usage))
	for _, entry := range retain.usage {
		retainedUsage[entry.key] = struct{}{}
	}
	var result error
	if remove.ueIP != 0 && remove.ueIP != retain.ueIP {
		result = errors.Join(result, deleteKernelPolicyMapKey(p.objects.Policies, &remove.ueIP))
	}
	for _, entry := range remove.filters {
		if _, keep := retainedFilters[entry.key]; !keep {
			result = errors.Join(result, deleteKernelPolicyMapKey(p.objects.TftFilters, &entry.key))
		}
	}
	for _, entry := range remove.rates {
		if _, keep := retainedRates[entry.key]; !keep {
			result = errors.Join(result, deleteKernelPolicyMapKey(p.objects.RateStates, &entry.key))
		}
	}
	for _, entry := range remove.usage {
		if _, keep := retainedUsage[entry.key]; !keep {
			result = errors.Join(result, deleteKernelPolicyMapKey(p.objects.UsageCounters, &entry.key))
		}
	}
	return result
}

func (p *kernelPolicy) build(session rules.Session) (installedKernelPolicy, error) {
	if session.UPSEID == 0 || session.Revision == 0 || !session.UEIPv4.Is4() {
		return installedKernelPolicy{}, errors.New("pgwu kernel policy: invalid session identity")
	}
	entry := installedKernelPolicy{
		upSEID: session.UPSEID, revision: session.Revision, ueIP: kernelPolicyIPv4(session.UEIPv4),
		policy: pgwupolicyPolicyValue{
			UpSeid: session.UPSEID, Revision: session.Revision, BurstNs: uint64(p.burst),
			QerIds: [2]uint32{session.QERID, 0}, UrrIds: [2]uint32{session.URRID, 0},
		},
	}
	if session.UplinkGateOpen {
		entry.policy.GateFlags |= kernelPolicyGateDefaultUplink
	}
	if session.DownlinkGateOpen {
		entry.policy.GateFlags |= kernelPolicyGateDefaultDownlink
	}
	entry.policy.Rates[0], entry.policy.Rates[1] = session.MaxUplinkBitsPerSecond, session.MaxDownlinkBitsPerSecond
	entry.policy.Capacities[0] = kernelPolicyCapacity(entry.policy.Rates[0], p.burst, p.packetSizeBits)
	entry.policy.Capacities[1] = kernelPolicyCapacity(entry.policy.Rates[1], p.burst, p.packetSizeBits)

	if len(session.DedicatedBearers) > 1 {
		return installedKernelPolicy{}, errors.New("pgwu kernel policy: only one QCI 1 bearer per UE is supported")
	}
	if len(session.DedicatedBearers) == 1 {
		bearer := session.DedicatedBearers[0]
		if bearer.QCI != 1 {
			return installedKernelPolicy{}, fmt.Errorf("pgwu kernel policy: dedicated QCI %d is unsupported", bearer.QCI)
		}
		entry.policy.HasQci1 = 1
		entry.policy.QerIds[1], entry.policy.UrrIds[1] = bearer.QERID, bearer.URRID
		entry.policy.Rates[2], entry.policy.Rates[3] = bearer.MaxUplinkBitsPerSecond, bearer.MaxDownlinkBitsPerSecond
		entry.policy.Capacities[2] = kernelPolicyCapacity(entry.policy.Rates[2], p.burst, p.packetSizeBits)
		entry.policy.Capacities[3] = kernelPolicyCapacity(entry.policy.Rates[3], p.burst, p.packetSizeBits)
		if bearer.UplinkGateOpen {
			entry.policy.GateFlags |= kernelPolicyGateQCI1Uplink
		}
		if bearer.DownlinkGateOpen {
			entry.policy.GateFlags |= kernelPolicyGateQCI1Downlink
		}
		if err := p.addFilters(&entry, bearer.Filters); err != nil {
			return installedKernelPolicy{}, err
		}
	}

	p.addRateEntries(&entry)
	if session.URRID != 0 {
		entry.usage = append(entry.usage, kernelPolicyUsageEntry{
			key:      pgwupolicyUsageKey{UpSeid: session.UPSEID, QerId: session.QERID, UrrId: session.URRID},
			default_: true, threshold: session.UsageReportingThreshold,
		})
	}
	if len(session.DedicatedBearers) == 1 && session.DedicatedBearers[0].URRID != 0 {
		bearer := session.DedicatedBearers[0]
		entry.usage = append(entry.usage, kernelPolicyUsageEntry{
			key: pgwupolicyUsageKey{UpSeid: session.UPSEID, QerId: bearer.QERID, UrrId: bearer.URRID},
			qci: bearer.QCI, arp: bearer.ARP, threshold: bearer.UsageReportingThreshold,
		})
	}
	return entry, nil
}

func (p *kernelPolicy) addFilters(entry *installedKernelPolicy, filters []rules.FlowFilter) error {
	uplink := make([]rules.FlowFilter, 0, len(filters))
	downlink := make([]rules.FlowFilter, 0, len(filters))
	for _, filter := range filters {
		if filter.Direction != filter.Filter.Direction {
			return errors.New("pgwu kernel policy: inconsistent TFT direction metadata")
		}
		if filter.Filter.AppliesTo(gtpv2.TFTDirectionUplink) {
			uplink = append(uplink, filter)
		}
		if filter.Filter.AppliesTo(gtpv2.TFTDirectionDownlink) {
			downlink = append(downlink, filter)
		}
	}
	if len(uplink) == 0 || len(downlink) == 0 || len(uplink) > rules.MaxFiltersPerBearer || len(downlink) > rules.MaxFiltersPerBearer {
		return errors.New("pgwu kernel policy: QCI 1 TFT must contain 1-64 filters in each direction")
	}
	sortFilters := func(values []rules.FlowFilter) {
		sort.SliceStable(values, func(i, j int) bool {
			if values[i].Precedence != values[j].Precedence {
				return values[i].Precedence < values[j].Precedence
			}
			return values[i].PDRID < values[j].PDRID
		})
	}
	sortFilters(uplink)
	sortFilters(downlink)
	if len(uplink)+len(downlink) > p.maxFilters {
		return errors.New("pgwu kernel policy: session TFT exceeds configured filter capacity")
	}
	for direction, values := range map[uint8][]rules.FlowFilter{
		kernelPolicyDirectionUplink: uplink, kernelPolicyDirectionDownlink: downlink,
	} {
		for index, filter := range values {
			entry.filters = append(entry.filters, kernelPolicyFilterEntry{
				key:   pgwupolicyFilterKey{UeIp: entry.ueIP, Index: uint16(index), Direction: direction},
				value: kernelPolicyFilterValue(filter),
			})
		}
	}
	entry.policy.UplinkFilterCount = uint16(len(uplink))
	entry.policy.DownlinkFilterCount = uint16(len(downlink))
	return nil
}

func (p *kernelPolicy) addRateEntries(entry *installedKernelPolicy) {
	for bearer := uint8(0); bearer <= kernelPolicyBearerQCI1; bearer++ {
		if bearer == kernelPolicyBearerQCI1 && entry.policy.HasQci1 == 0 {
			continue
		}
		for direction := uint8(0); direction <= kernelPolicyDirectionDownlink; direction++ {
			slot := int(bearer)*2 + int(direction)
			rate := entry.policy.Rates[slot]
			if rate == 0 {
				continue
			}
			capacity := entry.policy.Capacities[slot]
			entry.rates = append(entry.rates, kernelPolicyRateEntry{
				key: pgwupolicyRateKey{UeIp: entry.ueIP, Bearer: bearer, Direction: direction},
				value: pgwupolicyRateValue{
					Revision: entry.revision, QerId: uint64(entry.policy.QerIds[bearer]),
					Rate: rate, Capacity: capacity, Tokens: capacity,
				},
			})
		}
	}
}

func kernelPolicyFilterValue(filter rules.FlowFilter) pgwupolicyFilterValue {
	value := pgwupolicyFilterValue{Precedence: filter.Precedence, PdrId: filter.PDRID}
	typed := filter.Filter
	if typed.HasLocalAddress {
		value.Flags |= kernelPolicyFilterLocalAddress
		value.LocalAddress, value.LocalMask = kernelPolicyIPv4(typed.LocalAddress), kernelPolicyIPv4(typed.LocalAddressMask)
	}
	if typed.HasRemoteAddress {
		value.Flags |= kernelPolicyFilterRemoteAddress
		value.RemoteAddress, value.RemoteMask = kernelPolicyIPv4(typed.RemoteAddress), kernelPolicyIPv4(typed.RemoteAddressMask)
	}
	if typed.HasProtocol {
		value.Flags |= kernelPolicyFilterProtocol
		value.Protocol = typed.Protocol
	}
	if typed.HasLocalPort {
		value.Flags |= kernelPolicyFilterLocalPort
		value.LocalPortLow, value.LocalPortHigh = typed.LocalPortLow, typed.LocalPortHigh
	}
	if typed.HasRemotePort {
		value.Flags |= kernelPolicyFilterRemotePort
		value.RemotePortLow, value.RemotePortHigh = typed.RemotePortLow, typed.RemotePortHigh
	}
	if typed.HasTypeOfService {
		value.Flags |= kernelPolicyFilterTOS
		value.Tos, value.TosMask = typed.TypeOfService, typed.TypeOfServiceMask
	}
	return value
}

func kernelPolicyCapacity(rate uint64, burst time.Duration, packetFloor uint64) uint64 {
	if rate == 0 {
		return 0
	}
	seconds := uint64(burst / time.Second)
	remainder := uint64(burst % time.Second)
	capacity := kernelPolicySaturatingMultiply(rate, seconds)
	fraction := kernelPolicySaturatingMultiply(rate, remainder) / uint64(time.Second)
	capacity = kernelPolicySaturatingAdd(capacity, fraction)
	if capacity < packetFloor {
		capacity = packetFloor
	}
	return capacity
}

func kernelPolicySaturatingMultiply(left, right uint64) uint64 {
	if left != 0 && right > math.MaxUint64/left {
		return math.MaxUint64
	}
	return left * right
}

func kernelPolicySaturatingAdd(left, right uint64) uint64 {
	if math.MaxUint64-left < right {
		return math.MaxUint64
	}
	return left + right
}

func kernelPolicyIPv4(value netip.Addr) uint32 {
	raw := value.Unmap().As4()
	return binary.NativeEndian.Uint32(raw[:])
}

func deleteKernelPolicyMapKey(value *ebpf.Map, key any) error {
	err := value.Delete(key)
	if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (p *kernelPolicy) Counters() kernelPolicyCounters {
	p.mu.Lock()
	activeMeters := uint64(0)
	activeQCI1Contexts := uint64(0)
	for _, entry := range p.installed {
		activeMeters += uint64(len(entry.usage))
		if entry.policy.HasQci1 != 0 {
			activeQCI1Contexts++
		}
	}
	syncErrors := p.syncErrors
	p.mu.Unlock()
	read := func(index uint32) uint64 {
		values := make([]uint64, p.possibleCPUs)
		if err := p.objects.Counters.Lookup(&index, &values); err != nil {
			return 0
		}
		var total uint64
		for _, value := range values {
			total = kernelPolicySaturatingAdd(total, value)
		}
		return total
	}
	classifier := p.classifier.Snapshot()
	return kernelPolicyCounters{
		DefaultUplinkPackets: read(kernelPolicyCounterDefaultUplink), DefaultUplinkBytes: read(kernelPolicyCounterDefaultUplinkBytes),
		DefaultDownlinkPackets: read(kernelPolicyCounterDefaultDownlink), DefaultDownlinkBytes: read(kernelPolicyCounterDefaultDownlinkBytes),
		QCI1UplinkPackets: read(kernelPolicyCounterQCI1Uplink), QCI1UplinkBytes: read(kernelPolicyCounterQCI1UplinkBytes),
		QCI1DownlinkPackets: read(kernelPolicyCounterQCI1Downlink), QCI1DownlinkBytes: read(kernelPolicyCounterQCI1DownlinkBytes),
		QCI1RoutePackets: read(kernelPolicyCounterQCI1RoutePackets), GateDrops: read(kernelPolicyCounterGateDrops),
		ActiveTFTFilters: classifier.Rules, ActiveQCI1Sessions: classifier.Sessions, TFTSyncErrors: classifier.Errors,
		ActiveQCI1Contexts: activeQCI1Contexts,
		RateDrops:          read(kernelPolicyCounterRateDrops), TFTWrongBearerDrops: read(kernelPolicyCounterTFTWrongBearer),
		TFTUnmatchedDrops: read(kernelPolicyCounterTFTUnmatched), MissingPolicyDrops: read(kernelPolicyCounterMissingPolicy),
		StalePolicyDrops: read(kernelPolicyCounterStalePolicy), MissingRateDrops: read(kernelPolicyCounterMissingRate),
		PolicyMapErrors:  kernelPolicySaturatingAdd(read(kernelPolicyCounterMapErrors), syncErrors),
		MalformedPackets: read(kernelPolicyCounterMalformed), FragmentDrops: read(kernelPolicyCounterFragmentDrops),
		UsagePackets: read(kernelPolicyCounterUsagePackets),
		UsageBytes:   read(kernelPolicyCounterUsageBytes), ActiveUsageMeters: activeMeters,
	}
}

func (p *kernelPolicy) Usage() []UsageMeasurement {
	p.mu.Lock()
	metadata := make(map[pgwupolicyUsageKey]kernelPolicyUsageEntry)
	for _, session := range p.installed {
		for _, usage := range session.usage {
			metadata[usage.key] = usage
		}
	}
	p.mu.Unlock()
	out := make([]UsageMeasurement, 0, len(metadata))
	iterator := p.objects.UsageCounters.Iterate()
	var key pgwupolicyUsageKey
	values := make([]pgwupolicyUsageValue, p.possibleCPUs)
	for iterator.Next(&key, &values) {
		meta, active := metadata[key]
		if !active {
			continue
		}
		measurement := UsageMeasurement{
			UPSEID: key.UpSeid, QERID: key.QerId, URRID: key.UrrId,
			QCI: meta.qci, ARP: meta.arp, DefaultBearer: meta.default_,
		}
		for _, value := range values {
			measurement.UplinkPackets = kernelPolicySaturatingAdd(measurement.UplinkPackets, value.UplinkPackets)
			measurement.UplinkBytes = kernelPolicySaturatingAdd(measurement.UplinkBytes, value.UplinkBytes)
			measurement.DownlinkPackets = kernelPolicySaturatingAdd(measurement.DownlinkPackets, value.DownlinkPackets)
			measurement.DownlinkBytes = kernelPolicySaturatingAdd(measurement.DownlinkBytes, value.DownlinkBytes)
		}
		total := kernelPolicySaturatingAdd(measurement.UplinkBytes, measurement.DownlinkBytes)
		if meta.threshold != 0 {
			measurement.ThresholdEvents = total / meta.threshold
		}
		out = append(out, measurement)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UPSEID != out[j].UPSEID {
			return out[i].UPSEID < out[j].UPSEID
		}
		return out[i].QERID < out[j].QERID
	})
	return out
}

func (p *kernelPolicy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	var result error
	if p.classifier != nil {
		result = errors.Join(result, p.classifier.Close())
	}
	for index := len(p.links) - 1; index >= 0; index-- {
		result = errors.Join(result, p.links[index].Close())
	}
	p.links = nil
	return errors.Join(result, p.objects.Close())
}
