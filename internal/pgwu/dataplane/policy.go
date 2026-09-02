package dataplane

import (
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
)

const pgwPolicyShardCount = 256

type policyDecision uint8

const (
	policyAllow policyDecision = iota
	policyGateClosed
	policyRateExceeded
)

type rateKey struct {
	upSEID uint64
	qerID  uint32
	uplink bool
}

type tokenBucket struct {
	rate     uint64
	capacity uint64
	tokens   uint64
	last     time.Time
}

type usageKey struct {
	upSEID uint64
	urrID  uint32
}

type usageState struct {
	revision        uint64
	qerID           uint32
	qci             uint8
	arp             uint8
	defaultBearer   bool
	measureVolume   bool
	threshold       uint64
	uplinkPackets   uint64
	downlinkPackets uint64
	uplinkBytes     uint64
	downlinkBytes   uint64
	thresholdEvents uint64
	nextThreshold   uint64
	firstPacket     time.Time
	lastPacket      time.Time
}

type usagePolicy struct {
	revision      uint64
	qerID         uint32
	urrID         uint32
	qci           uint8
	arp           uint8
	defaultBearer bool
	measureVolume bool
	threshold     uint64
}

type policyShard struct {
	mu    sync.Mutex
	rates map[rateKey]tokenBucket
	usage map[usageKey]usageState
}

type policyEngine struct {
	burst  time.Duration
	shards [pgwPolicyShardCount]policyShard

	qerGateDrops       atomic.Uint64
	qerRateDrops       atomic.Uint64
	urrMeteredPackets  atomic.Uint64
	urrMeteredBytes    atomic.Uint64
	urrThresholdEvents atomic.Uint64
	urrActiveMeters    atomic.Uint64
}

type policyCounterSnapshot struct {
	QERGateDrops       uint64
	QERRateDrops       uint64
	URRMeteredPackets  uint64
	URRMeteredBytes    uint64
	URRThresholdEvents uint64
	URRActiveMeters    uint64
}

// UsageMeasurement is a telemetry-only per-bearer URR snapshot. Thresholds
// never gate user traffic and are not charging quotas.
type UsageMeasurement struct {
	UPSEID          uint64
	QERID           uint32
	URRID           uint32
	QCI             uint8
	ARP             uint8
	DefaultBearer   bool
	UplinkPackets   uint64
	DownlinkPackets uint64
	UplinkBytes     uint64
	DownlinkBytes   uint64
	ThresholdEvents uint64
	FirstPacket     time.Time
	LastPacket      time.Time
}

func newPolicyEngine(burst time.Duration) *policyEngine {
	if burst <= 0 {
		burst = 100 * time.Millisecond
	}
	engine := &policyEngine{burst: burst}
	for index := range engine.shards {
		engine.shards[index].rates = make(map[rateKey]tokenBucket)
		engine.shards[index].usage = make(map[usageKey]usageState)
	}
	return engine
}

func (p *policyEngine) authorize(matched rules.PacketRule, uplink bool, payloadBytes int, now time.Time) policyDecision {
	if uplink && !matched.UplinkGateOpen || !uplink && !matched.DownlinkGateOpen {
		p.qerGateDrops.Add(1)
		return policyGateClosed
	}
	if payloadBytes <= 0 {
		return policyAllow
	}
	rate := matched.MaxDownlinkBitsPerSecond
	if uplink {
		rate = matched.MaxUplinkBitsPerSecond
	}
	if rate == 0 {
		return policyAllow
	}
	packetBits := uint64(payloadBytes) * 8
	capacity := pgwRateForDuration(rate, p.burst)
	if capacity < packetBits {
		capacity = packetBits
	}
	key := rateKey{upSEID: matched.UPSEID, qerID: matched.QERID, uplink: uplink}
	shard := p.shard(matched.UPSEID)
	shard.mu.Lock()
	bucket, exists := shard.rates[key]
	if !exists || bucket.rate != rate || bucket.capacity != capacity {
		bucket = tokenBucket{rate: rate, capacity: capacity, tokens: capacity, last: now}
	} else {
		pgwRefill(&bucket, now, p.burst)
	}
	if bucket.tokens < packetBits {
		shard.rates[key] = bucket
		shard.mu.Unlock()
		p.qerRateDrops.Add(1)
		return policyRateExceeded
	}
	bucket.tokens -= packetBits
	shard.rates[key] = bucket
	shard.mu.Unlock()
	return policyAllow
}

func (p *policyEngine) recordUsage(matched rules.PacketRule, uplink bool, payloadBytes int, now time.Time) {
	if matched.URRID == 0 || payloadBytes < 0 {
		return
	}
	key := usageKey{upSEID: matched.UPSEID, urrID: matched.URRID}
	shard := p.shard(matched.UPSEID)
	shard.mu.Lock()
	state, exists := shard.usage[key]
	// Reconciliation installs every valid meter before its packet generation is
	// activated. Rejecting absent or stale state prevents an in-flight packet
	// from recreating a bearer meter after update/delete.
	if !exists || state.revision != matched.Revision || state.qerID != matched.QERID {
		shard.mu.Unlock()
		return
	}
	if state.firstPacket.IsZero() {
		state.firstPacket = now
	}
	state.lastPacket = now
	bytes := uint64(payloadBytes)
	if uplink {
		state.uplinkPackets++
		if state.measureVolume {
			state.uplinkBytes = pgwSaturatingAdd(state.uplinkBytes, bytes)
		}
	} else {
		state.downlinkPackets++
		if state.measureVolume {
			state.downlinkBytes = pgwSaturatingAdd(state.downlinkBytes, bytes)
		}
	}
	p.urrMeteredPackets.Add(1)
	if state.measureVolume {
		p.urrMeteredBytes.Add(bytes)
		total := pgwSaturatingAdd(state.uplinkBytes, state.downlinkBytes)
		if state.threshold != 0 && state.nextThreshold != 0 && total >= state.nextThreshold {
			crossed := (total-state.nextThreshold)/state.threshold + 1
			state.thresholdEvents = pgwSaturatingAdd(state.thresholdEvents, crossed)
			p.urrThresholdEvents.Add(crossed)
			state.nextThreshold = pgwSaturatingAdd(state.nextThreshold, pgwSaturatingMultiply(crossed, state.threshold))
		}
	}
	shard.usage[key] = state
	shard.mu.Unlock()
}

func (p *policyEngine) reconcileSession(session rules.Session) {
	desired := make(map[usageKey]usagePolicy, 1+len(session.DedicatedBearers))
	add := func(urrID, qerID uint32, qci, arp uint8, defaultBearer, measureVolume bool, threshold uint64) {
		if urrID == 0 {
			return
		}
		key := usageKey{upSEID: session.UPSEID, urrID: urrID}
		desired[key] = usagePolicy{
			revision: session.Revision, qerID: qerID, urrID: urrID, qci: qci, arp: arp,
			defaultBearer: defaultBearer, measureVolume: measureVolume, threshold: threshold,
		}
	}
	add(session.URRID, session.QERID, 0, 0, true, session.MeasureVolume, session.UsageReportingThreshold)
	for _, bearer := range session.DedicatedBearers {
		add(bearer.URRID, bearer.QERID, bearer.QCI, bearer.ARP, false, bearer.MeasureVolume, bearer.UsageReportingThreshold)
	}

	shard := p.shard(session.UPSEID)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	for key := range shard.rates {
		if key.upSEID == session.UPSEID {
			delete(shard.rates, key)
		}
	}
	for key := range shard.usage {
		if key.upSEID != session.UPSEID {
			continue
		}
		if _, exists := desired[key]; !exists {
			delete(shard.usage, key)
			p.urrActiveMeters.Add(^uint64(0))
		}
	}
	for key, policy := range desired {
		state, exists := shard.usage[key]
		if !exists {
			state.nextThreshold = policy.threshold
			p.urrActiveMeters.Add(1)
		} else if state.threshold != policy.threshold {
			total := pgwSaturatingAdd(state.uplinkBytes, state.downlinkBytes)
			state.nextThreshold = pgwNextThreshold(total, policy.threshold)
		}
		state.revision = policy.revision
		state.qerID = policy.qerID
		state.qci = policy.qci
		state.arp = policy.arp
		state.defaultBearer = policy.defaultBearer
		state.measureVolume = policy.measureVolume
		state.threshold = policy.threshold
		shard.usage[key] = state
	}
}

func (p *policyEngine) deleteSession(upSEID uint64) {
	shard := p.shard(upSEID)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	for key := range shard.rates {
		if key.upSEID == upSEID {
			delete(shard.rates, key)
		}
	}
	for key := range shard.usage {
		if key.upSEID == upSEID {
			delete(shard.usage, key)
			p.urrActiveMeters.Add(^uint64(0))
		}
	}
}

func (p *policyEngine) counters() policyCounterSnapshot {
	return policyCounterSnapshot{
		QERGateDrops: p.qerGateDrops.Load(), QERRateDrops: p.qerRateDrops.Load(),
		URRMeteredPackets: p.urrMeteredPackets.Load(), URRMeteredBytes: p.urrMeteredBytes.Load(),
		URRThresholdEvents: p.urrThresholdEvents.Load(), URRActiveMeters: p.urrActiveMeters.Load(),
	}
}

func (p *policyEngine) usageSnapshot() []UsageMeasurement {
	out := make([]UsageMeasurement, 0, int(p.urrActiveMeters.Load()))
	for index := range p.shards {
		shard := &p.shards[index]
		shard.mu.Lock()
		for key, state := range shard.usage {
			out = append(out, UsageMeasurement{
				UPSEID: key.upSEID, QERID: state.qerID, URRID: key.urrID, QCI: state.qci, ARP: state.arp,
				DefaultBearer: state.defaultBearer,
				UplinkPackets: state.uplinkPackets, DownlinkPackets: state.downlinkPackets,
				UplinkBytes: state.uplinkBytes, DownlinkBytes: state.downlinkBytes,
				ThresholdEvents: state.thresholdEvents, FirstPacket: state.firstPacket, LastPacket: state.lastPacket,
			})
		}
		shard.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UPSEID != out[j].UPSEID {
			return out[i].UPSEID < out[j].UPSEID
		}
		if out[i].QERID != out[j].QERID {
			return out[i].QERID < out[j].QERID
		}
		return out[i].URRID < out[j].URRID
	})
	return out
}

func (p *policyEngine) shard(upSEID uint64) *policyShard {
	return &p.shards[byte(upSEID^(upSEID>>16)^(upSEID>>32)^(upSEID>>48))]
}

func pgwRefill(bucket *tokenBucket, now time.Time, burst time.Duration) {
	if now.Before(bucket.last) {
		bucket.last = now
		return
	}
	elapsed := now.Sub(bucket.last)
	if elapsed <= 0 {
		return
	}
	if elapsed >= burst {
		bucket.tokens = bucket.capacity
		bucket.last = now
		return
	}
	added := pgwRateForDuration(bucket.rate, elapsed)
	if added >= bucket.capacity-bucket.tokens {
		bucket.tokens = bucket.capacity
	} else {
		bucket.tokens += added
	}
	bucket.last = now
}

func pgwRateForDuration(rate uint64, duration time.Duration) uint64 {
	if rate == 0 || duration <= 0 {
		return 0
	}
	seconds := uint64(duration / time.Second)
	nanoseconds := uint64(duration % time.Second)
	if seconds != 0 && rate > math.MaxUint64/seconds {
		return math.MaxUint64
	}
	whole := rate * seconds
	partial := (rate/uint64(time.Second))*nanoseconds + (rate%uint64(time.Second))*nanoseconds/uint64(time.Second)
	if partial > math.MaxUint64-whole {
		return math.MaxUint64
	}
	return whole + partial
}

func pgwNextThreshold(total, threshold uint64) uint64 {
	if threshold == 0 {
		return 0
	}
	completed := total / threshold
	if completed == math.MaxUint64 {
		return math.MaxUint64
	}
	return pgwSaturatingMultiply(completed+1, threshold)
}

func pgwSaturatingAdd(left, right uint64) uint64 {
	if right > math.MaxUint64-left {
		return math.MaxUint64
	}
	return left + right
}

func pgwSaturatingMultiply(left, right uint64) uint64 {
	if left != 0 && right > math.MaxUint64/left {
		return math.MaxUint64
	}
	return left * right
}
