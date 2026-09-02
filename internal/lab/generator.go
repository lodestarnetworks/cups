package lab

import (
	"context"
	"math"
	"time"

	"github.com/lodestarnetworks/cups/internal/telemetry"
)

const historyLimit = 24

type Generator struct {
	store   *telemetry.Store
	started time.Time
	step    uint64
	eventID uint64
}

func NewGenerator(store *telemetry.Store, now time.Time) *Generator {
	return &Generator{store: store, started: now, eventID: 4}
}

func InitialSnapshot(now time.Time) telemetry.Snapshot {
	history := make([]telemetry.TrafficPoint, 0, historyLimit)
	for i := historyLimit - 1; i >= 0; i-- {
		at := now.Add(-time.Duration(i) * 40 * time.Second)
		history = append(history, trafficPoint(at, uint64(historyLimit-i)))
	}

	return telemetry.Snapshot{
		GeneratedAt: now,
		Mode:        "simulated-lab",
		SGWC: telemetry.SGWC{
			State:                 telemetry.StateHealthy,
			ActiveSessions:        48_216,
			ActiveBearers:         52_904,
			ActiveTransactions:    37,
			Retransmissions:       126,
			TransactionCollisions: 3,
			RecoveryCounter:       9,
			Peers: []telemetry.Peer{
				{Name: "MME London", Interface: "S11 / GTP-C", Address: "10.90.0.12:2123", State: telemetry.StateHealthy, RTTMillis: 1.8},
				{Name: "PGW Core", Interface: "S5-C / GTP-C", Address: "10.90.0.21:2123", State: telemetry.StateHealthy, RTTMillis: 2.4},
				{Name: "SGW-U alpha", Interface: "Sxa / PFCP", Address: "10.90.0.31:8805", State: telemetry.StateHealthy, RTTMillis: 0.7},
			},
			Procedures: []telemetry.Procedure{
				{Name: "Create Session", Requests: 44_807, Successes: 44_799, Failures: 8, Active: 12, P95DurationMillis: 18.4},
				{Name: "Modify Bearer", Requests: 91_228, Successes: 91_216, Failures: 12, Active: 19, P95DurationMillis: 11.7},
				{Name: "Delete Session", Requests: 42_111, Successes: 42_109, Failures: 2, Active: 6, P95DurationMillis: 14.1},
			},
		},
		SGWU: telemetry.SGWU{
			State:                 telemetry.StateHealthy,
			PFCPAssociationState:  telemetry.StateHealthy,
			PFCPSessions:          48_216,
			PDRs:                  105_808,
			FARs:                  105_808,
			QERs:                  52_904,
			URRs:                  52_904,
			DataplaneMode:         "go-lab",
			UplinkBitsPerSecond:   318_000_000,
			DownlinkBitsPerSecond: 424_000_000,
			PacketsPerSecond:      1_210_000,
			DroppedPackets:        49,
			DropPercent:           0.004,
			UnknownTEIDs:          14,
			P95LatencyMillis:      2.7,
			QCI: []telemetry.QCIUsage{
				{QCI: 9, Label: "Default data", Bearers: 35_975},
				{QCI: 5, Label: "IMS signalling", Bearers: 8_994},
				{QCI: 1, Label: "Voice", Bearers: 4_761},
				{QCI: 0, Label: "Other", Bearers: 3_174},
			},
		},
		History: history,
		Events: []telemetry.Event{
			{ID: 4, At: now.Add(-12 * time.Second), Component: "sgw-c", Severity: telemetry.SeverityInfo, Kind: "session", Summary: "Create Session completed", Context: map[string]string{"subscriber": "IMSI •••• 4921"}},
			{ID: 3, At: now.Add(-26 * time.Second), Component: "sgw-c", Severity: telemetry.SeverityInfo, Kind: "bearer", Summary: "Dedicated bearer activated · QCI 1", Context: map[string]string{"ebi": "6", "apn": "ims"}},
			{ID: 2, At: now.Add(-41 * time.Second), Component: "sgw-u", Severity: telemetry.SeverityWarning, Kind: "path", Summary: "GTP-U echo latency above baseline", Context: map[string]string{"peer": "PGW Core", "rtt": "8.2 ms"}},
			{ID: 1, At: now.Add(-68 * time.Second), Component: "sgw-c", Severity: telemetry.SeverityInfo, Kind: "session", Summary: "Release Access Bearers completed", Context: map[string]string{"subscriber": "IMSI •••• 7734"}},
		},
	}
}

func (g *Generator) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			g.advance(now)
		}
	}
}

func (g *Generator) advance(now time.Time) {
	g.step++
	snapshot := g.store.Snapshot()
	snapshot.GeneratedAt = now
	snapshot.SGWC.UptimeSeconds = uint64(now.Sub(g.started).Seconds())
	snapshot.SGWU.UptimeSeconds = snapshot.SGWC.UptimeSeconds
	snapshot.SGWC.ActiveTransactions = 28 + g.step%19
	snapshot.SGWC.Retransmissions += g.step % 3

	point := trafficPoint(now, g.step+historyLimit)
	snapshot.SGWU.UplinkBitsPerSecond = point.UplinkBitsPerSecond
	snapshot.SGWU.DownlinkBitsPerSecond = point.DownlinkBitsPerSecond
	snapshot.SGWU.PacketsPerSecond = point.PacketsPerSecond
	snapshot.History = append(snapshot.History, point)
	if len(snapshot.History) > historyLimit {
		snapshot.History = append([]telemetry.TrafficPoint(nil), snapshot.History[len(snapshot.History)-historyLimit:]...)
	}

	if g.step%8 == 0 {
		g.eventID++
		event := telemetry.Event{
			ID:        g.eventID,
			At:        now,
			Component: "sgw-c",
			Severity:  telemetry.SeverityInfo,
			Kind:      "session",
			Summary:   "Modify Bearer completed",
			Context:   map[string]string{"ebi": "5", "result": "accepted"},
		}
		snapshot.Events = append([]telemetry.Event{event}, snapshot.Events...)
		if len(snapshot.Events) > 20 {
			snapshot.Events = snapshot.Events[:20]
		}
	}
	g.store.Replace(snapshot)
}

func trafficPoint(at time.Time, step uint64) telemetry.TrafficPoint {
	wave := math.Sin(float64(step) / 3.2)
	fine := math.Sin(float64(step) / 1.35)
	downlink := uint64(390_000_000 + wave*52_000_000 + fine*12_000_000)
	uplink := uint64(292_000_000 + wave*36_000_000 - fine*8_000_000)
	return telemetry.TrafficPoint{
		At:                    at,
		UplinkBitsPerSecond:   uplink,
		DownlinkBitsPerSecond: downlink,
		PacketsPerSecond:      (uplink + downlink) / 610,
	}
}
