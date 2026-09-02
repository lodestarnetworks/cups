package live

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lodestarnetworks/cups/internal/admission"
	"github.com/lodestarnetworks/cups/internal/sgwc/gateway"
	"github.com/lodestarnetworks/cups/internal/sgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/sgwc/session"
	"github.com/lodestarnetworks/cups/internal/telemetry"
)

type ControlConfig struct {
	Started           time.Time
	Recovery          uint8
	MMEAddresses      []string
	PGWAddress        string
	SGWUAddress       string
	SGWUMetricsURL    string
	DurableState      bool
	RecoveredSessions uint64
	StateStats        func() session.WALStats
	AdmissionStats    func() admission.Stats
}

type ControlProvider struct {
	config  ControlConfig
	gateway *gateway.Gateway
	pfcp    *pfcpclient.Client
	events  *EventLog
	store   *telemetry.Store
	http    *http.Client
}

func NewControlProvider(config ControlConfig, control *gateway.Gateway, pfcpClient *pfcpclient.Client, events *EventLog) *ControlProvider {
	if events == nil {
		events = NewEventLog(200)
	}
	provider := &ControlProvider{
		config: config, gateway: control, pfcp: pfcpClient, events: events,
		http: &http.Client{Timeout: 750 * time.Millisecond},
	}
	provider.store = telemetry.NewStore(telemetry.Snapshot{
		Mode: "live-lte", SGWC: telemetry.SGWC{State: telemetry.StateStarting},
		SGWU: telemetry.SGWU{State: telemetry.StateStarting, PFCPAssociationState: telemetry.StateStarting},
	})
	provider.sample(context.Background(), time.Now().UTC())
	return provider
}

func (p *ControlProvider) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			p.sample(ctx, now.UTC())
		case <-ctx.Done():
			return
		}
	}
}

func (p *ControlProvider) Snapshot() telemetry.Snapshot { return p.store.Snapshot() }

func (p *ControlProvider) sample(ctx context.Context, now time.Time) {
	previous := p.store.Snapshot()
	remote, remoteErr := p.fetchUser(ctx)
	if remoteErr == nil {
		previous.SGWU = remote.SGWU
		previous.History = remote.History
	}
	sessions := p.gateway.Sessions()
	activeBearers := 0
	for _, current := range sessions {
		for _, bearer := range current.Bearers {
			if bearer.State == session.BearerActive {
				activeBearers++
			}
		}
	}
	counters := p.gateway.Counters()
	pagingHistograms, pendingPaging := p.gateway.PagingLatencyHistograms()
	ddnPaging := make([]telemetry.DDNPagingHistogram, 0, len(pagingHistograms))
	for _, histogram := range pagingHistograms {
		buckets := make([]telemetry.HistogramBucket, len(histogram.Buckets))
		for index, bucket := range histogram.Buckets {
			buckets[index] = telemetry.HistogramBucket{
				UpperBoundSeconds: bucket.UpperBoundSeconds,
				Count:             bucket.Count,
			}
		}
		ddnPaging = append(ddnPaging, telemetry.DDNPagingHistogram{
			QCI: histogram.QCI, ENB: histogram.ENB, Count: histogram.Count,
			SumSeconds: histogram.SumSeconds, Buckets: buckets,
		})
	}
	s11, s5 := p.gateway.TransportCounters()
	pfcpTransport := p.pfcp.TransportCounters()
	usage := p.pfcp.UsageLedgerStats()
	usageRemoveFailures := p.pfcp.UsageLedgerRemoveFailures()
	stateStats := session.WALStats{}
	if p.config.StateStats != nil {
		stateStats = p.config.StateStats()
	}
	admissionStats := admission.Stats{}
	if p.config.AdmissionStats != nil {
		admissionStats = p.config.AdmissionStats()
	}
	_, associated := p.pfcp.Association()
	state := telemetry.StateHealthy
	if !associated || remoteErr != nil || previous.SGWU.State == telemetry.StateDown {
		state = telemetry.StateDegraded
	}
	peerState := telemetry.StateStarting
	if counters.CreateRequests > 0 {
		peerState = telemetry.StateHealthy
	}
	if counters.CreateRejected > 0 && counters.CreateAccepted == 0 {
		peerState = telemetry.StateDegraded
	}
	peers := make([]telemetry.Peer, 0, len(p.config.MMEAddresses)+2)
	for index, address := range p.config.MMEAddresses {
		name := "MME"
		if len(p.config.MMEAddresses) > 1 {
			name += " " + string(rune('A'+index))
		}
		peers = append(peers, telemetry.Peer{Name: name, Interface: "S11 / GTPv2-C", Address: address, State: peerState})
	}
	peers = append(peers,
		telemetry.Peer{Name: "PGW", Interface: "S5-C / GTPv2-C", Address: p.config.PGWAddress, State: peerState},
		telemetry.Peer{Name: "SGW-U", Interface: "Sxa / PFCP", Address: p.config.SGWUAddress, State: boolState(associated)},
	)
	procedures := []telemetry.Procedure{
		procedure("Create Session", counters.CreateRequests, counters.CreateAccepted, counters.CreateRejected),
		procedure("Modify Bearer", counters.ModifyRequests, counters.ModifyAccepted, counters.ModifyRejected),
		procedure("Release Access Bearers", counters.ReleaseRequests, counters.ReleaseAccepted, counters.ReleaseRejected),
		procedure("Downlink Data Notification", counters.DDNRequests, counters.DDNAccepted, counters.DDNRejected),
		procedure("Create Dedicated Bearer", counters.CreateBearerRequests, counters.CreateBearerAccepted, counters.CreateBearerRejected),
		procedure("Update Bearer QoS", counters.UpdateBearerRequests, counters.UpdateBearerAccepted, counters.UpdateBearerRejected),
		procedure("Delete Dedicated Bearer", counters.DeleteBearerRequests, counters.DeleteBearerAccepted, counters.DeleteBearerRejected),
		procedure("Delete Session", counters.DeleteRequests, counters.DeleteAccepted, counters.DeleteRejected),
	}
	events := p.events.Snapshot()
	if remoteErr != nil {
		previous.SGWU.State = telemetry.StateDegraded
		previous.SGWU.PFCPAssociationState = boolState(associated)
	}
	p.store.Replace(telemetry.Snapshot{
		GeneratedAt: now, Mode: "live-lte",
		SGWC: telemetry.SGWC{
			State: state, UptimeSeconds: uptime(p.config.Started, now),
			ActiveSessions: uint64(len(sessions)), ActiveBearers: uint64(activeBearers),
			ActiveTransactions:       s11.ActiveTransactions + s5.ActiveTransactions,
			Retransmissions:          s11.Retransmitted + s5.Retransmitted,
			ControlSocketDrops:       s11.SocketDrops + s5.SocketDrops + pfcpTransport.SocketDrops,
			TransactionCollisions:    s11.TransactionCollisions + s5.TransactionCollisions,
			PeerRestarts:             counters.PeerRestarts,
			PeerRestartPurgeFailures: counters.PeerRestartPurgeFailures,
			RecoveryCounter:          p.config.Recovery, DurableStateEnabled: p.config.DurableState,
			StateWALBytes: uint64(stateStats.Bytes), StateWALRecords: stateStats.DataRecords,
			StateStarts: stateStats.Starts, StateCompactions: stateStats.Compactions,
			RecoveredSessions:  p.config.RecoveredSessions,
			StateTailRecovered: stateStats.RecoveredTail,
			AdmissionDraining:  admissionStats.Draining, AdmissionTransitions: admissionStats.Transitions,
			AdmissionCheckErrors: admissionStats.CheckErrors, AdmissionRejected: counters.CreateAdmissionRejected,
			DeleteContextNotFound: counters.DeleteContextNotFound,
			PFCPUsageDurable:      usage.Durable, PFCPUsageCheckpoints: usage.ActiveCheckpoints,
			PFCPUsageAccepted: usage.ReportsAccepted, PFCPUsageDuplicates: usage.ReportsDuplicate,
			PFCPUsageSequenceGaps: usage.SequenceGaps, PFCPUsageConflicts: usage.SequenceConflicts,
			PFCPUsageUplinkPackets: usage.UplinkPackets, PFCPUsageDownlinkPackets: usage.DownlinkPackets,
			PFCPUsageUplinkBytes: usage.UplinkBytes, PFCPUsageDownlinkBytes: usage.DownlinkBytes,
			PFCPUsageWALBytes: usage.WALBytes, PFCPUsageWALRecords: usage.WALRecords,
			PFCPUsageWALCompactions: usage.WALCompactions, PFCPUsageWALTailRecovered: usage.WALRecoveredTail,
			PFCPUsageRemoveFailures: usageRemoveFailures, PendingPaging: pendingPaging,
			DDNPagingHistograms: ddnPaging, Peers: peers, Procedures: procedures,
		},
		SGWU: previous.SGWU, History: previous.History, Events: events,
	})
}

func (p *ControlProvider) fetchUser(ctx context.Context) (telemetry.Snapshot, error) {
	base := strings.TrimRight(strings.TrimSpace(p.config.SGWUMetricsURL), "/")
	if base == "" {
		return telemetry.Snapshot{}, errors.New("SGW-U metrics URL is empty")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/dashboard", nil)
	if err != nil {
		return telemetry.Snapshot{}, err
	}
	response, err := p.http.Do(request)
	if err != nil {
		return telemetry.Snapshot{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return telemetry.Snapshot{}, errors.New("SGW-U metrics endpoint is unavailable")
	}
	var snapshot telemetry.Snapshot
	if err := json.NewDecoder(response.Body).Decode(&snapshot); err != nil {
		return telemetry.Snapshot{}, err
	}
	return snapshot, nil
}

func procedure(name string, requests, successes, failures uint64) telemetry.Procedure {
	return telemetry.Procedure{Name: name, Requests: requests, Successes: successes, Failures: failures}
}

func boolState(value bool) telemetry.State {
	if value {
		return telemetry.StateHealthy
	}
	return telemetry.StateDegraded
}
