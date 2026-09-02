package dataplane

import (
	"context"
	"net/netip"
)

const (
	CapabilityGTPv1U            = "gtp_v1u"
	CapabilityOuterPeerFilter   = "outer_peer_filter"
	CapabilityDirectionalGating = "directional_gating"
	CapabilityMaxBitrateQER     = "maximum_bitrate_qer"
	CapabilityDedicatedBearer   = "dedicated_bearer_tft"
	CapabilityPerSessionUsage   = "per_session_usage"
	CapabilityRestartReconcile  = "restart_reconciliation"
)

// Capability makes backend limitations machine-visible. Unsupported features
// are explicit because silently approximating PFCP policy is unsafe.
type Capability struct {
	Name      string
	Supported bool
	Detail    string
}

// Backend is the stable PGW-U runtime contract shared by the portable
// correctness path and production-oriented kernel datapaths.
type Backend interface {
	Serve(context.Context) error
	Close() error
	Counters() Counters
	Usage() []UsageMeasurement
	S5Addr() netip.AddrPort
	TunnelName() string
	Mode() string
	Capabilities() []Capability
}

func (f *Forwarder) Mode() string { return "portable-go/tun" }

func (f *Forwarder) Capabilities() []Capability {
	return []Capability{
		{Name: CapabilityGTPv1U, Supported: true, Detail: "GTPv1-U encapsulation and decapsulation"},
		{Name: CapabilityOuterPeerFilter, Supported: true, Detail: "userspace outer-source allowlist"},
		{Name: CapabilityDirectionalGating, Supported: true, Detail: "independent uplink and downlink gate checks"},
		{Name: CapabilityMaxBitrateQER, Supported: true, Detail: "sharded per-session, per-direction token buckets in bits per second"},
		{Name: CapabilityDedicatedBearer, Supported: true, Detail: "per-bearer TEIDs, precedence-ordered TFT/SDF classification, QER policing, and URR metering"},
		{Name: CapabilityPerSessionUsage, Supported: true, Detail: "telemetry-only PFCP URR volume and duration meters"},
		{Name: CapabilityRestartReconcile, Supported: true, Detail: "PFCP rules recover from the durable WAL and policy state is reconciled"},
	}
}
