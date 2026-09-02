package live

import (
	"context"
	"time"

	pfcpassociation "github.com/lodestarnetworks/cups/internal/pfcp/association"
	"github.com/lodestarnetworks/cups/internal/runtimeobs"
	"github.com/lodestarnetworks/cups/internal/sgwu/dataplane"
	"github.com/lodestarnetworks/cups/internal/sgwu/pfcpserver"
	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
	"github.com/lodestarnetworks/cups/internal/telemetry"
)

type UserProvider struct {
	started     time.Time
	server      *pfcpserver.Server
	rules       *rules.Store
	forwarder   *dataplane.Forwarder
	events      *EventLog
	store       *telemetry.Store
	previous    dataplane.Counters
	last        time.Time
	lastTraffic time.Time
	runtime     *runtimeobs.Sampler
}

func NewUserProvider(started time.Time, server *pfcpserver.Server, ruleStore *rules.Store, forwarder *dataplane.Forwarder, events *EventLog, runtimeSamplers ...*runtimeobs.Sampler) *UserProvider {
	if events == nil {
		events = NewEventLog(200)
	}
	runtimeSampler := runtimeobs.NewSampler()
	if len(runtimeSamplers) != 0 && runtimeSamplers[0] != nil {
		runtimeSampler = runtimeSamplers[0]
	}
	provider := &UserProvider{
		started: started.UTC(), server: server, rules: ruleStore,
		forwarder: forwarder, events: events, runtime: runtimeSampler,
	}
	provider.store = telemetry.NewStore(telemetry.Snapshot{Mode: "live-sgwu"})
	provider.sample(time.Now().UTC())
	return provider
}

func (p *UserProvider) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			p.runtime.Sample()
			p.sample(now.UTC())
		case <-ctx.Done():
			return
		}
	}
}

func (p *UserProvider) Snapshot() telemetry.Snapshot { return p.store.Snapshot() }

func (p *UserProvider) sample(now time.Time) {
	sessions := p.rules.Snapshot()
	pdrs, fars, qers, urrs := 0, 0, 0, 0
	for _, current := range sessions {
		pdrs += len(current.PDRs)
		fars += len(current.FARs)
		qers += len(current.QERs)
		urrs += len(current.URRs)
	}
	counters := p.forwarder.Counters()
	elapsed := now.Sub(p.last).Seconds()
	var uplinkBPS, downlinkBPS, packetsPS uint64
	if !p.last.IsZero() && elapsed > 0 {
		uplinkBPS = rate(counterDelta(counters.UplinkBytes, p.previous.UplinkBytes), elapsed) * 8
		downlinkBPS = rate(counterDelta(counters.DownlinkBytes, p.previous.DownlinkBytes), elapsed) * 8
		packetsPS = rate(counterDelta(counters.ForwardedPackets, p.previous.ForwardedPackets), elapsed)
		p.lastTraffic = latestTrafficAt(p.lastTraffic, p.previous.ForwardedPackets, counters.ForwardedPackets, now)
	}
	p.previous = counters
	p.last = now
	var lastTrafficAt *time.Time
	if !p.lastTraffic.IsZero() {
		value := p.lastTraffic
		lastTrafficAt = &value
	}
	dropPercent := float64(0)
	total := counters.ForwardedPackets + counters.DroppedPackets
	if total > 0 {
		dropPercent = float64(counters.DroppedPackets) / float64(total) * 100
	}
	associationState := telemetry.StateStarting
	state := telemetry.StateDegraded
	associationPhase := pfcpassociation.StateUnavailable
	graceRemaining := time.Duration(0)
	associations := p.server.Associations()
	if len(associations) > 0 {
		associationPhase = associations[0].State
		graceRemaining = p.server.GraceRemaining(associations[0].Peer)
	}
	if associationPhase == pfcpassociation.StateAssociated {
		associationState = telemetry.StateHealthy
		state = telemetry.StateHealthy
	} else if associationPhase == pfcpassociation.StateGrace || associationPhase == pfcpassociation.StateReconciling {
		associationState = telemetry.StateDegraded
	}
	pfcpCounters := p.server.Counters()
	bufferClasses := make([]telemetry.BufferUsage, 0, len(counters.BufferClasses))
	for _, class := range counters.BufferClasses {
		bufferClasses = append(bufferClasses, telemetry.BufferUsage{
			QCI: class.QCI, CurrentPackets: class.CurrentPackets, CurrentBytes: class.CurrentBytes,
			Enqueued: class.Enqueued, Flushed: class.Flushed, Expired: class.Expired,
			OverflowDrops: class.OverflowDrops, Purged: class.Purged,
		})
	}
	pfcpTransport := p.server.TransportCounters()
	lifecycle := p.rules.LifecycleCounters()
	runtimeSnapshot := p.runtime.Snapshot()
	previous := p.store.Snapshot()
	history := append(previous.History, telemetry.TrafficPoint{
		At: now, UplinkBitsPerSecond: uplinkBPS,
		DownlinkBitsPerSecond: downlinkBPS, PacketsPerSecond: packetsPS,
	})
	if len(history) > 60 {
		history = history[len(history)-60:]
	}
	p.store.Replace(telemetry.Snapshot{
		GeneratedAt: now, Mode: "live-sgwu",
		SGWC: telemetry.SGWC{State: telemetry.StateStarting},
		SGWU: telemetry.SGWU{
			State: state, UptimeSeconds: uptime(p.started, now),
			PFCPAssociationState: associationState, PFCPAssociationPhase: string(associationPhase),
			PFCPGraceSecondsRemaining: graceRemaining.Seconds(), PFCPGraceEntries: pfcpCounters.GraceEntries,
			PFCPGraceExpirations: pfcpCounters.GraceExpirations, PFCPReconciliations: pfcpCounters.Reconciliations,
			PFCPSocketDrops: pfcpTransport.SocketDrops,
			PFCPMessagesRX:  pfcpTransport.Received, PFCPMessagesTX: pfcpTransport.Sent,
			PFCPErrors:             pfcpTransport.Malformed + pfcpTransport.TimedOut + pfcpTransport.WorkerDrops + pfcpTransport.SocketDrops,
			PFCPSessions:           uint64(len(sessions)),
			SessionsInstalledTotal: lifecycle.Installed, SessionsRemovedTotal: lifecycle.Removed,
			PDRs: uint64(pdrs), FARs: uint64(fars), QERs: uint64(qers), URRs: uint64(urrs),
			DataplaneMode: p.forwarder.Mode(), UplinkBitsPerSecond: uplinkBPS,
			DownlinkBitsPerSecond: downlinkBPS, PacketsPerSecond: packetsPS,
			ForwardedPackets: counters.ForwardedPackets, ForwardedBytes: counters.ForwardedBytes,
			LastTrafficAt:  lastTrafficAt,
			DroppedPackets: counters.DroppedPackets, DropPercent: dropPercent,
			UplinkRXPackets: counters.UplinkRXPackets, UplinkRXBytes: counters.UplinkRXBytes,
			UplinkTXPackets: counters.UplinkTXPackets, UplinkTXBytes: counters.UplinkTXBytes,
			DownlinkRXPackets: counters.DownlinkRXPackets, DownlinkRXBytes: counters.DownlinkRXBytes,
			DownlinkTXPackets: counters.DownlinkTXPackets, DownlinkTXBytes: counters.DownlinkTXBytes,
			AccessSocketDrops: counters.AccessSocketDrops,
			CoreSocketDrops:   counters.CoreSocketDrops,
			UnknownTEIDs:      counters.UnknownTEIDs,
			MalformedPackets:  counters.MalformedPackets,
			QueueFullDrops:    counters.QueueFullDrops,
			UnauthorizedPeers: counters.UnauthorizedPeers,
			DownlinkReports:   counters.DownlinkReports,
			BufferedPackets:   counters.BufferedPackets, BufferedBytes: counters.BufferedBytes,
			BufferEnqueued: counters.BufferEnqueued, BufferFlushed: counters.BufferFlushed,
			BufferExpired: counters.BufferExpired, BufferOverflowDrops: counters.BufferOverflowDrops,
			BufferPurged: counters.BufferPurged, BufferClasses: bufferClasses,
			FastPathFallbacks: counters.FastPathFallbacks, FastPathForwardedPackets: counters.FastPathForwardedPackets,
			FastPathForwardedBytes: counters.FastPathForwardedBytes, FastPathSyncFailures: counters.FastPathSyncFailures,
			FastPathRewriteErrors:    counters.FastPathRewriteErrors,
			FastPathP95LatencyMillis: float64(counters.FastPathP95Micros) / 1_000,
			P50LatencyMillis:         float64(counters.P50LatencyMicros) / 1_000,
			P95LatencyMillis:         float64(counters.P95LatencyMicros) / 1_000,
			P99LatencyMillis:         float64(counters.P99LatencyMicros) / 1_000,
			P999LatencyMillis:        float64(counters.P999LatencyMicros) / 1_000,
			MaxLatencyMillis:         float64(counters.MaxLatencyMicros) / 1_000,
			LatencyHistogram:         latencyHistogram(counters.LatencyBuckets),
			RuntimeHeapObjectsBytes:  runtimeSnapshot.HeapObjectsBytes, RuntimeGoroutines: runtimeSnapshot.Goroutines,
			RuntimeGCPauseCount:     runtimeSnapshot.GCPauseCount,
			RuntimeGCPauseP99Millis: runtimeSnapshot.GCPauseP99Seconds * 1_000,
			RuntimeGCPauseMaxMillis: runtimeSnapshot.GCPauseMaxSeconds * 1_000,
			RuntimeGCPauseHistogram: runtimeHistogram(runtimeSnapshot.GCPauseBuckets),
			QERGateDrops:            counters.QERGateDrops, QERRateDrops: counters.QERRateDrops,
			URRMeteredPackets: counters.URRMeteredPackets, URRMeteredBytes: counters.URRMeteredBytes,
			URRThresholdEvents: counters.URRThresholdEvents, URRActiveMeters: counters.URRActiveMeters,
			UsageReportsGenerated: pfcpCounters.UsageReportsGenerated,
			UsageReportsSent:      pfcpCounters.UsageReportsSent, UsageReportsRetried: pfcpCounters.UsageReportsRetried,
			UsageReportsFailed: pfcpCounters.UsageReportsFailed, UsageReportsPending: pfcpCounters.UsageReportsPending,
			UsageReportQueueFull: pfcpCounters.UsageReportQueueFull, UsageCounterResets: pfcpCounters.UsageCounterResets,
			UsageTrackedURRs: pfcpCounters.UsageTrackedURRs,
		},
		History: history, Events: p.events.Snapshot(),
	})
}

func latencyHistogram(values []dataplane.LatencyBucket) []telemetry.HistogramBucket {
	out := make([]telemetry.HistogramBucket, 0, len(values))
	var cumulative uint64
	for _, value := range values {
		cumulative += value.Count
		out = append(out, telemetry.HistogramBucket{UpperBoundSeconds: float64(value.UpperBoundMicros) / 1_000_000, Count: cumulative})
	}
	return out
}

func runtimeHistogram(values []runtimeobs.Bucket) []telemetry.HistogramBucket {
	out := make([]telemetry.HistogramBucket, 0, len(values))
	for _, value := range values {
		out = append(out, telemetry.HistogramBucket{UpperBoundSeconds: value.UpperBoundSeconds, Count: value.Count})
	}
	return out
}

func rate(delta uint64, seconds float64) uint64 {
	return uint64(float64(delta) / seconds)
}

func counterDelta(current, previous uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}

func latestTrafficAt(last time.Time, previous, current uint64, sampledAt time.Time) time.Time {
	if current > previous {
		return sampledAt
	}
	return last
}

func uptime(started, now time.Time) uint64 {
	if now.Before(started) {
		return 0
	}
	return uint64(now.Sub(started).Seconds())
}
