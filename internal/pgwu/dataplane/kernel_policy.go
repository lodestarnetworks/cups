package dataplane

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/lodestarnetworks/cups/internal/kernelgtp"
	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
)

var errKernelPolicyPlatformUnsupported = errors.New("PGW-U kernel policy requires Linux TCX/eBPF")

type kernelPolicyConfig struct {
	DefaultLink    kernelgtp.Link
	QCI1Link       kernelgtp.Link
	MaxSessions    int
	MaxFilters     int
	BurstDuration  time.Duration
	PacketSizeBits uint64
	UEPoolPrefix   netip.Prefix
	UEPoolPrefixes []netip.Prefix
	FirewallMark   uint32
	FirewallMask   uint32
}

func normalizeUEPoolPrefixes(configured []netip.Prefix, legacy netip.Prefix) ([]netip.Prefix, error) {
	prefixes := append([]netip.Prefix(nil), configured...)
	if len(prefixes) == 0 && legacy.IsValid() {
		prefixes = []netip.Prefix{legacy}
	} else if len(prefixes) != 0 && legacy.IsValid() {
		return nil, errors.New("pgwu: UE pool prefixes cannot be combined with the legacy UE pool prefix")
	}
	if len(prefixes) == 0 || len(prefixes) > 256 {
		return nil, errors.New("pgwu: between 1 and 256 UE IPv4 pools are required")
	}
	out := make([]netip.Prefix, 0, len(prefixes))
	for index, prefix := range prefixes {
		prefix = prefix.Masked()
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() < 8 || prefix.Bits() > 30 ||
			!netip.MustParsePrefix("10.0.0.0/8").Contains(prefix.Addr()) {
			return nil, fmt.Errorf("pgwu: UE pool %d must be an IPv4 /8../30 inside 10.0.0.0/8", index)
		}
		for otherIndex, other := range out {
			if prefix.Contains(other.Addr()) || other.Contains(prefix.Addr()) {
				return nil, fmt.Errorf("pgwu: UE pool %d overlaps pool %d", index, otherIndex)
			}
		}
		out = append(out, prefix)
	}
	sort.Slice(out, func(left, right int) bool {
		if out[left].Addr() != out[right].Addr() {
			return out[left].Addr().Less(out[right].Addr())
		}
		return out[left].Bits() < out[right].Bits()
	})
	return out, nil
}

type kernelPolicyCounters struct {
	DefaultUplinkPackets   uint64
	DefaultUplinkBytes     uint64
	DefaultDownlinkPackets uint64
	DefaultDownlinkBytes   uint64
	QCI1UplinkPackets      uint64
	QCI1UplinkBytes        uint64
	QCI1DownlinkPackets    uint64
	QCI1DownlinkBytes      uint64
	QCI1RoutePackets       uint64
	ActiveTFTFilters       uint64
	ActiveQCI1Sessions     uint64
	ActiveQCI1Contexts     uint64
	TFTSyncErrors          uint64
	GateDrops              uint64
	RateDrops              uint64
	TFTWrongBearerDrops    uint64
	TFTUnmatchedDrops      uint64
	MissingPolicyDrops     uint64
	StalePolicyDrops       uint64
	MissingRateDrops       uint64
	PolicyMapErrors        uint64
	MalformedPackets       uint64
	FragmentDrops          uint64
	UsagePackets           uint64
	UsageBytes             uint64
	ActiveUsageMeters      uint64
}

type kernelPolicyBackend interface {
	Apply(previous, next *rules.Session) error
	ApplyRouting(previous, next *rules.Session) error
	ReconcileSessions([]rules.Session) error
	ReconcileRouting([]rules.Session) error
	Counters() kernelPolicyCounters
	Usage() []UsageMeasurement
	Close() error
}
