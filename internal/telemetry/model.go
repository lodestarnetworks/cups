package telemetry

import "time"

type State string

const (
	StateHealthy  State = "healthy"
	StateDegraded State = "degraded"
	StateDown     State = "down"
	StateStarting State = "starting"
)

type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

type Peer struct {
	Name         string  `json:"name"`
	Interface    string  `json:"interface"`
	Address      string  `json:"address"`
	State        State   `json:"state"`
	RTTMillis    float64 `json:"rttMillis"`
	MissedEchoes uint64  `json:"missedEchoes"`
}

type Procedure struct {
	Name              string  `json:"name"`
	Requests          uint64  `json:"requests"`
	Successes         uint64  `json:"successes"`
	Failures          uint64  `json:"failures"`
	Active            uint64  `json:"active"`
	P95DurationMillis float64 `json:"p95DurationMillis"`
}

type HistogramBucket struct {
	UpperBoundSeconds float64 `json:"upperBoundSeconds"`
	Count             uint64  `json:"count"`
}

type DDNPagingHistogram struct {
	QCI        uint8             `json:"qci"`
	ENB        string            `json:"enb"`
	Count      uint64            `json:"count"`
	SumSeconds float64           `json:"sumSeconds"`
	Buckets    []HistogramBucket `json:"buckets"`
}

type SGWC struct {
	State                     State                `json:"state"`
	UptimeSeconds             uint64               `json:"uptimeSeconds"`
	ActiveSessions            uint64               `json:"activeSessions"`
	ActiveBearers             uint64               `json:"activeBearers"`
	ActiveTransactions        uint64               `json:"activeTransactions"`
	Retransmissions           uint64               `json:"retransmissions"`
	ControlSocketDrops        uint64               `json:"controlSocketDrops"`
	TransactionCollisions     uint64               `json:"transactionCollisions"`
	PeerRestarts              uint64               `json:"peerRestarts"`
	PeerRestartPurgeFailures  uint64               `json:"peerRestartPurgeFailures"`
	RecoveryCounter           uint8                `json:"recoveryCounter"`
	DurableStateEnabled       bool                 `json:"durableStateEnabled"`
	StateWALBytes             uint64               `json:"stateWalBytes"`
	StateWALRecords           uint64               `json:"stateWalRecords"`
	StateStarts               uint64               `json:"stateStarts"`
	StateCompactions          uint64               `json:"stateCompactions"`
	RecoveredSessions         uint64               `json:"recoveredSessions"`
	StateTailRecovered        bool                 `json:"stateTailRecovered"`
	AdmissionDraining         bool                 `json:"admissionDraining"`
	AdmissionTransitions      uint64               `json:"admissionTransitions"`
	AdmissionCheckErrors      uint64               `json:"admissionCheckErrors"`
	AdmissionRejected         uint64               `json:"admissionRejected"`
	DeleteContextNotFound     uint64               `json:"deleteContextNotFoundReconciled"`
	PFCPUsageDurable          bool                 `json:"pfcpUsageDurable"`
	PFCPUsageCheckpoints      uint64               `json:"pfcpUsageCheckpoints"`
	PFCPUsageAccepted         uint64               `json:"pfcpUsageAccepted"`
	PFCPUsageDuplicates       uint64               `json:"pfcpUsageDuplicates"`
	PFCPUsageSequenceGaps     uint64               `json:"pfcpUsageSequenceGaps"`
	PFCPUsageConflicts        uint64               `json:"pfcpUsageConflicts"`
	PFCPUsageUplinkPackets    uint64               `json:"pfcpUsageUplinkPackets"`
	PFCPUsageDownlinkPackets  uint64               `json:"pfcpUsageDownlinkPackets"`
	PFCPUsageUplinkBytes      uint64               `json:"pfcpUsageUplinkBytes"`
	PFCPUsageDownlinkBytes    uint64               `json:"pfcpUsageDownlinkBytes"`
	PFCPUsageWALBytes         int64                `json:"pfcpUsageWalBytes"`
	PFCPUsageWALRecords       uint64               `json:"pfcpUsageWalRecords"`
	PFCPUsageWALCompactions   uint64               `json:"pfcpUsageWalCompactions"`
	PFCPUsageWALTailRecovered bool                 `json:"pfcpUsageWalTailRecovered"`
	PFCPUsageRemoveFailures   uint64               `json:"pfcpUsageRemoveFailures"`
	PendingPaging             uint64               `json:"pendingPaging"`
	DDNPagingHistograms       []DDNPagingHistogram `json:"ddnPagingHistograms"`
	Peers                     []Peer               `json:"peers"`
	Procedures                []Procedure          `json:"procedures"`
}

type QCIUsage struct {
	QCI     uint8  `json:"qci"`
	Label   string `json:"label"`
	Bearers uint64 `json:"bearers"`
}

type BufferUsage struct {
	QCI            uint8  `json:"qci"`
	CurrentPackets uint64 `json:"currentPackets"`
	CurrentBytes   uint64 `json:"currentBytes"`
	Enqueued       uint64 `json:"enqueued"`
	Flushed        uint64 `json:"flushed"`
	Expired        uint64 `json:"expired"`
	OverflowDrops  uint64 `json:"overflowDrops"`
	Purged         uint64 `json:"purged"`
}

type SGWU struct {
	State                     State             `json:"state"`
	UptimeSeconds             uint64            `json:"uptimeSeconds"`
	PFCPAssociationState      State             `json:"pfcpAssociationState"`
	PFCPAssociationPhase      string            `json:"pfcpAssociationPhase"`
	PFCPGraceSecondsRemaining float64           `json:"pfcpGraceSecondsRemaining"`
	PFCPGraceEntries          uint64            `json:"pfcpGraceEntries"`
	PFCPGraceExpirations      uint64            `json:"pfcpGraceExpirations"`
	PFCPReconciliations       uint64            `json:"pfcpReconciliations"`
	PFCPSocketDrops           uint64            `json:"pfcpSocketDrops"`
	PFCPMessagesRX            uint64            `json:"pfcpMessagesRx"`
	PFCPMessagesTX            uint64            `json:"pfcpMessagesTx"`
	PFCPErrors                uint64            `json:"pfcpErrors"`
	PFCPSessions              uint64            `json:"pfcpSessions"`
	SessionsInstalledTotal    uint64            `json:"sessionsInstalledTotal"`
	SessionsRemovedTotal      uint64            `json:"sessionsRemovedTotal"`
	PDRs                      uint64            `json:"pdrs"`
	FARs                      uint64            `json:"fars"`
	QERs                      uint64            `json:"qers"`
	URRs                      uint64            `json:"urrs"`
	DataplaneMode             string            `json:"dataplaneMode"`
	UplinkBitsPerSecond       uint64            `json:"uplinkBitsPerSecond"`
	DownlinkBitsPerSecond     uint64            `json:"downlinkBitsPerSecond"`
	PacketsPerSecond          uint64            `json:"packetsPerSecond"`
	ForwardedPackets          uint64            `json:"forwardedPackets"`
	ForwardedBytes            uint64            `json:"forwardedBytes"`
	LastTrafficAt             *time.Time        `json:"lastTrafficAt,omitempty"`
	DroppedPackets            uint64            `json:"droppedPackets"`
	UplinkRXPackets           uint64            `json:"uplinkRxPackets"`
	UplinkRXBytes             uint64            `json:"uplinkRxBytes"`
	UplinkTXPackets           uint64            `json:"uplinkTxPackets"`
	UplinkTXBytes             uint64            `json:"uplinkTxBytes"`
	DownlinkRXPackets         uint64            `json:"downlinkRxPackets"`
	DownlinkRXBytes           uint64            `json:"downlinkRxBytes"`
	DownlinkTXPackets         uint64            `json:"downlinkTxPackets"`
	DownlinkTXBytes           uint64            `json:"downlinkTxBytes"`
	AccessSocketDrops         uint64            `json:"accessSocketDrops"`
	CoreSocketDrops           uint64            `json:"coreSocketDrops"`
	DropPercent               float64           `json:"dropPercent"`
	UnknownTEIDs              uint64            `json:"unknownTeids"`
	MalformedPackets          uint64            `json:"malformedPackets"`
	QueueFullDrops            uint64            `json:"queueFullDrops"`
	UnauthorizedPeers         uint64            `json:"unauthorizedPeers"`
	DownlinkReports           uint64            `json:"downlinkReports"`
	BufferedPackets           uint64            `json:"bufferedPackets"`
	BufferedBytes             uint64            `json:"bufferedBytes"`
	BufferEnqueued            uint64            `json:"bufferEnqueued"`
	BufferFlushed             uint64            `json:"bufferFlushed"`
	BufferExpired             uint64            `json:"bufferExpired"`
	BufferOverflowDrops       uint64            `json:"bufferOverflowDrops"`
	BufferPurged              uint64            `json:"bufferPurged"`
	BufferClasses             []BufferUsage     `json:"bufferClasses"`
	FastPathFallbacks         uint64            `json:"fastPathFallbacks"`
	FastPathForwardedPackets  uint64            `json:"fastPathForwardedPackets"`
	FastPathForwardedBytes    uint64            `json:"fastPathForwardedBytes"`
	FastPathSyncFailures      uint64            `json:"fastPathSyncFailures"`
	FastPathRewriteErrors     uint64            `json:"fastPathRewriteErrors"`
	FastPathP95LatencyMillis  float64           `json:"fastPathP95LatencyMillis"`
	P95LatencyMillis          float64           `json:"p95LatencyMillis"`
	P50LatencyMillis          float64           `json:"p50LatencyMillis"`
	P99LatencyMillis          float64           `json:"p99LatencyMillis"`
	P999LatencyMillis         float64           `json:"p999LatencyMillis"`
	MaxLatencyMillis          float64           `json:"maxLatencyMillis"`
	LatencyHistogram          []HistogramBucket `json:"latencyHistogram"`
	RuntimeHeapObjectsBytes   uint64            `json:"runtimeHeapObjectsBytes"`
	RuntimeGoroutines         uint64            `json:"runtimeGoroutines"`
	RuntimeGCPauseCount       uint64            `json:"runtimeGcPauseCount"`
	RuntimeGCPauseP99Millis   float64           `json:"runtimeGcPauseP99Millis"`
	RuntimeGCPauseMaxMillis   float64           `json:"runtimeGcPauseMaxMillis"`
	RuntimeGCPauseHistogram   []HistogramBucket `json:"runtimeGcPauseHistogram"`
	QERGateDrops              uint64            `json:"qerGateDrops"`
	QERRateDrops              uint64            `json:"qerRateDrops"`
	URRMeteredPackets         uint64            `json:"urrMeteredPackets"`
	URRMeteredBytes           uint64            `json:"urrMeteredBytes"`
	URRThresholdEvents        uint64            `json:"urrThresholdEvents"`
	URRActiveMeters           uint64            `json:"urrActiveMeters"`
	UsageReportsGenerated     uint64            `json:"usageReportsGenerated"`
	UsageReportsSent          uint64            `json:"usageReportsSent"`
	UsageReportsRetried       uint64            `json:"usageReportsRetried"`
	UsageReportsFailed        uint64            `json:"usageReportsFailed"`
	UsageReportsPending       uint64            `json:"usageReportsPending"`
	UsageReportQueueFull      uint64            `json:"usageReportQueueFull"`
	UsageCounterResets        uint64            `json:"usageCounterResets"`
	UsageTrackedURRs          uint64            `json:"usageTrackedUrrs"`
	QCI                       []QCIUsage        `json:"qci"`
}

type TrafficPoint struct {
	At                    time.Time `json:"at"`
	UplinkBitsPerSecond   uint64    `json:"uplinkBitsPerSecond"`
	DownlinkBitsPerSecond uint64    `json:"downlinkBitsPerSecond"`
	PacketsPerSecond      uint64    `json:"packetsPerSecond"`
}

type Event struct {
	ID        uint64            `json:"id"`
	At        time.Time         `json:"at"`
	Component string            `json:"component"`
	Severity  Severity          `json:"severity"`
	Kind      string            `json:"kind"`
	Summary   string            `json:"summary"`
	Context   map[string]string `json:"context,omitempty"`
}

type Snapshot struct {
	GeneratedAt time.Time      `json:"generatedAt"`
	Mode        string         `json:"mode"`
	SGWC        SGWC           `json:"sgwc"`
	SGWU        SGWU           `json:"sgwu"`
	History     []TrafficPoint `json:"history"`
	Events      []Event        `json:"events"`
}
