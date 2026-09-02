package dataplane

import (
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
)

const policyShardCount = 256

type policyDecision uint8

const (
	policyAllow policyDecision = iota
	policyGateClosed
	policyRateExceeded
	policyRuleInactive
)

type rateKey struct {
	upSEID uint64
	qerID  uint32
	source rules.SourceInterface
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
	rule            rules.URR
	uplinkPackets   uint64
	downlinkPackets uint64
	uplinkBytes     uint64
	downlinkBytes   uint64
	thresholdEvents uint64
	nextThreshold   uint64
	firstPacket     time.Time
	lastPacket      time.Time
}

type policyShard struct {
	mu    sync.Mutex
	rates map[rateKey]tokenBucket
	usage map[usageKey]usageState
}

type policyEngine struct {
	burst  time.Duration
	shards [policyShardCount]policyShard

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

// UsageMeasurement is a telemetry-only PFCP URR snapshot. It never carries a
// quota or a forwarding decision: Lodestar mobile data remains unmetered and
// usage is collected solely for operations and capacity planning.
type UsageMeasurement struct {
	UPSEID          uint64
	URRID           uint32
	UplinkPackets   uint64
	DownlinkPackets uint64
	UplinkBytes     uint64
	DownlinkBytes   uint64
	ThresholdEvents uint64
	FirstPacket     time.Time
	LastPacket      time.Time
}

func newPolicyEngine(burst time.Duration) *policyEngine {
	engine := &policyEngine{burst: burst}
	for index := range engine.shards {
		engine.shards[index].rates = make(map[rateKey]tokenBucket)
		engine.shards[index].usage = make(map[usageKey]usageState)
	}
	return engine
}

func (p *policyEngine) authorize(matched rules.PacketRule, source rules.SourceInterface, payloadBytes int, now time.Time) policyDecision {
	if !matched.Active() {
		return policyRuleInactive
	}
	if decision := p.checkGates(matched, source); decision != policyAllow {
		return decision
	}
	return p.allowRate(matched, source, payloadBytes, now)
}

func (p *policyEngine) checkGates(matched rules.PacketRule, source rules.SourceInterface) policyDecision {
	for _, qer := range matched.QERs {
		if source == rules.SourceAccess && !qer.UplinkGateOpen || source == rules.SourceCore && !qer.DownlinkGateOpen {
			p.qerGateDrops.Add(1)
			return policyGateClosed
		}
	}
	return policyAllow
}

func (p *policyEngine) allowRate(matched rules.PacketRule, source rules.SourceInterface, payloadBytes int, now time.Time) policyDecision {
	if payloadBytes <= 0 {
		return policyAllow
	}
	packetBits := uint64(payloadBytes) * 8
	limited := false
	for _, qer := range matched.QERs {
		if qerRate(qer, source) != 0 {
			limited = true
			break
		}
	}
	if !limited {
		return policyAllow
	}

	shard := p.shard(matched.UPSEID)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if !matched.Active() {
		return policyRuleInactive
	}
	for _, qer := range matched.QERs {
		rate := qerRate(qer, source)
		if rate == 0 {
			continue
		}
		key := rateKey{upSEID: matched.UPSEID, qerID: qer.ID, source: source}
		bucket, exists := shard.rates[key]
		capacity := rateForDuration(rate, p.burst)
		if capacity < packetBits {
			capacity = packetBits
		}
		if !exists || bucket.rate != rate || bucket.capacity != capacity {
			bucket = tokenBucket{rate: rate, capacity: capacity, tokens: capacity, last: now}
		} else {
			refill(&bucket, now, p.burst)
		}
		shard.rates[key] = bucket
		if bucket.tokens < packetBits {
			p.qerRateDrops.Add(1)
			return policyRateExceeded
		}
	}
	// All QERs have enough credit. Consume only after the complete rule chain
	// has passed so a restrictive second QER cannot drain an earlier bucket.
	for _, qer := range matched.QERs {
		if qerRate(qer, source) == 0 {
			continue
		}
		key := rateKey{upSEID: matched.UPSEID, qerID: qer.ID, source: source}
		bucket := shard.rates[key]
		bucket.tokens -= packetBits
		shard.rates[key] = bucket
	}
	return policyAllow
}

func qerRate(qer rules.QER, source rules.SourceInterface) uint64 {
	if source == rules.SourceAccess {
		return qer.MaxUplinkBitsPerSecond
	}
	return qer.MaxDownlinkBitsPerSecond
}

func refill(bucket *tokenBucket, now time.Time, burst time.Duration) {
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
	added := rateForDuration(bucket.rate, elapsed)
	if added >= bucket.capacity-bucket.tokens {
		bucket.tokens = bucket.capacity
	} else {
		bucket.tokens += added
	}
	bucket.last = now
}

func rateForDuration(rate uint64, duration time.Duration) uint64 {
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

func (p *policyEngine) recordUsage(matched rules.PacketRule, source rules.SourceInterface, payloadBytes int, now time.Time) {
	if payloadBytes < 0 || len(matched.URRs) == 0 {
		return
	}
	shard := p.shard(matched.UPSEID)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	// A packet worker may have resolved this immutable rule immediately before
	// PFCP deleted or replaced its session. The observer cleanup runs after the
	// generation is invalidated; refusing stale generations while holding the
	// same policy shard prevents that worker from recreating an orphan meter.
	if !matched.Active() {
		p.recordStaleUsageTotals(matched, payloadBytes)
		return
	}
	for _, urr := range matched.URRs {
		key := usageKey{upSEID: matched.UPSEID, urrID: urr.ID}
		state, exists := shard.usage[key]
		if !exists {
			state = usageState{rule: urr, nextThreshold: urr.ReportingThreshold}
			p.urrActiveMeters.Add(1)
		}
		if state.firstPacket.IsZero() {
			state.firstPacket = now
		}
		state.lastPacket = now
		bytes := uint64(payloadBytes)
		if source == rules.SourceAccess {
			state.uplinkPackets++
			if urr.MeasureVolume {
				state.uplinkBytes = saturatingAdd(state.uplinkBytes, bytes)
			}
		} else {
			state.downlinkPackets++
			if urr.MeasureVolume {
				state.downlinkBytes = saturatingAdd(state.downlinkBytes, bytes)
			}
		}
		p.urrMeteredPackets.Add(1)
		if urr.MeasureVolume {
			p.urrMeteredBytes.Add(bytes)
			total := saturatingAdd(state.uplinkBytes, state.downlinkBytes)
			if urr.ReportingThreshold != 0 && state.nextThreshold != 0 && total >= state.nextThreshold {
				crossed := (total-state.nextThreshold)/urr.ReportingThreshold + 1
				state.thresholdEvents = saturatingAdd(state.thresholdEvents, crossed)
				p.urrThresholdEvents.Add(crossed)
				increment := saturatingMultiply(crossed, urr.ReportingThreshold)
				state.nextThreshold = saturatingAdd(state.nextThreshold, increment)
			}
		}
		state.rule = urr
		shard.usage[key] = state
	}
}

// recordStaleUsageTotals preserves process-lifetime traffic counters for a
// packet that was successfully sent just before its PFCP generation was
// removed. It deliberately does not recreate per-session state or threshold
// scheduling after teardown.
func (p *policyEngine) recordStaleUsageTotals(matched rules.PacketRule, payloadBytes int) {
	bytes := uint64(payloadBytes)
	for _, urr := range matched.URRs {
		p.urrMeteredPackets.Add(1)
		if urr.MeasureVolume {
			p.urrMeteredBytes.Add(bytes)
		}
	}
}

func (p *policyEngine) reconcileSession(session rules.Session) {
	shard := p.shard(session.UPSEID)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	for key := range shard.rates {
		if key.upSEID == session.UPSEID {
			if _, exists := session.QERs[key.qerID]; !exists {
				delete(shard.rates, key)
			}
		}
	}
	for key, state := range shard.usage {
		if key.upSEID != session.UPSEID {
			continue
		}
		urr, exists := session.URRs[key.urrID]
		if !exists {
			delete(shard.usage, key)
			p.urrActiveMeters.Add(^uint64(0))
			continue
		}
		if state.rule.ReportingThreshold != urr.ReportingThreshold {
			total := saturatingAdd(state.uplinkBytes, state.downlinkBytes)
			state.nextThreshold = nextThreshold(total, urr.ReportingThreshold)
		}
		state.rule = urr
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

func (p *policyEngine) usageSnapshot() []UsageMeasurement {
	out := make([]UsageMeasurement, 0, int(p.urrActiveMeters.Load()))
	for index := range p.shards {
		shard := &p.shards[index]
		shard.mu.Lock()
		for key, state := range shard.usage {
			out = append(out, UsageMeasurement{
				UPSEID: key.upSEID, URRID: key.urrID,
				UplinkPackets: state.uplinkPackets, DownlinkPackets: state.downlinkPackets,
				UplinkBytes: state.uplinkBytes, DownlinkBytes: state.downlinkBytes,
				ThresholdEvents: state.thresholdEvents,
				FirstPacket:     state.firstPacket, LastPacket: state.lastPacket,
			})
		}
		shard.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UPSEID == out[j].UPSEID {
			return out[i].URRID < out[j].URRID
		}
		return out[i].UPSEID < out[j].UPSEID
	})
	return out
}

func (p *policyEngine) counters() policyCounterSnapshot {
	return policyCounterSnapshot{
		QERGateDrops: p.qerGateDrops.Load(), QERRateDrops: p.qerRateDrops.Load(),
		URRMeteredPackets: p.urrMeteredPackets.Load(), URRMeteredBytes: p.urrMeteredBytes.Load(),
		URRThresholdEvents: p.urrThresholdEvents.Load(), URRActiveMeters: p.urrActiveMeters.Load(),
	}
}

func (p *policyEngine) shard(upSEID uint64) *policyShard {
	return &p.shards[(upSEID^(upSEID>>32))&(policyShardCount-1)]
}

func nextThreshold(total, threshold uint64) uint64 {
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
