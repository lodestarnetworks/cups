package dataplane

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
)

func TestKernelPolicyFailsClosedUnlessSyntheticBypassIsExplicit(t *testing.T) {
	local := netip.MustParseAddr("10.200.0.20")
	remote := netip.MustParseAddr("10.200.0.10")
	session := rules.Session{
		UEIPv4: netip.MustParseAddr("10.201.0.7"),
		Local:  rules.Tunnel{TEID: 1, IP: local}, Remote: rules.Tunnel{TEID: 2, IP: remote},
		MaxDownlinkBitsPerSecond: 1_000_000, URRID: 1, MeasureVolume: true,
	}
	forwarder := &KernelForwarder{
		s5: netip.AddrPortFrom(local, 2152), allowed: map[netip.Addr]struct{}{remote: {}},
		uePools: []netip.Prefix{netip.MustParsePrefix("10.201.0.0/16")},
	}
	if err := forwarder.validateSession(&session); !errors.Is(err, ErrKernelPolicyUnsupported) {
		t.Fatalf("unsupported policy error = %v", err)
	}
	forwarder.allowUnsupportedPolicy = true
	if err := forwarder.validateSession(&session); err != nil {
		t.Fatalf("explicit synthetic bypass error = %v", err)
	}
}

func TestSameDedicatedRoutingIgnoresQEROnlyChanges(t *testing.T) {
	previous := kernelPolicyTestSession(
		netip.MustParseAddr("10.200.0.20"), netip.MustParseAddr("10.200.0.21"),
		netip.MustParseAddr("10.200.0.10"), netip.MustParseAddr("10.201.0.7"),
	)
	next := previous
	next.DedicatedBearers = append([]rules.Bearer(nil), previous.DedicatedBearers...)
	next.DedicatedBearers[0].MaxDownlinkBitsPerSecond++
	next.DedicatedBearers[0].DownlinkGateOpen = !next.DedicatedBearers[0].DownlinkGateOpen
	if !sameDedicatedRouting(&previous, &next) {
		t.Fatal("QER-only update unnecessarily changes nftables routing")
	}
	next.DedicatedBearers[0].Filters = append([]rules.FlowFilter(nil), previous.DedicatedBearers[0].Filters...)
	next.DedicatedBearers[0].Filters[0].Filter.LocalPortLow++
	if sameDedicatedRouting(&previous, &next) {
		t.Fatal("TFT change was treated as routing-equivalent")
	}
}
