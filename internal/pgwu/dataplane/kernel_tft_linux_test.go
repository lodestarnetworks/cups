//go:build linux

package dataplane

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/google/nftables/expr"

	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

func TestKernelTFTMarkConstantsUseHostByteOrder(t *testing.T) {
	classifier := &kernelTFTClassifier{mark: 0x4c51_0000, mask: 0xffff_0000}
	filter := gtpv2.IPv4PacketFilter{
		Direction:   gtpv2.TFTDirectionDownlink,
		HasProtocol: true, Protocol: 17,
		HasLocalPort: true, LocalPortLow: 5_060, LocalPortHigh: 5_060,
	}
	sets := classifier.filterExpressions(netip.MustParseAddr("10.251.0.7"), filter)
	if len(sets) != 1 {
		t.Fatalf("expanded rule count = %d", len(sets))
	}
	var found bool
	for _, expression := range sets[0] {
		bitwise, ok := expression.(*expr.Bitwise)
		if !ok || bitwise.Len != 4 || len(bitwise.Xor) != 4 || binary.NativeEndian.Uint32(bitwise.Xor) == 0 {
			continue
		}
		found = true
		if got := binary.NativeEndian.Uint32(bitwise.Mask); got != ^classifier.mask {
			t.Fatalf("mark mask = %#x, want %#x", got, ^classifier.mask)
		}
		if got := binary.NativeEndian.Uint32(bitwise.Xor); got != classifier.mark {
			t.Fatalf("mark xor = %#x, want %#x", got, classifier.mark)
		}
	}
	if !found {
		t.Fatal("mark-setting expression not found")
	}

	clear := kernelTFTClearMarkExpressions(netip.MustParsePrefix("10.251.0.0/16"), classifier.mask)
	clearBitwise, ok := clear[4].(*expr.Bitwise)
	if !ok || binary.NativeEndian.Uint32(clearBitwise.Mask) != ^classifier.mask {
		t.Fatalf("clear-mark expression = %#v", clear[4])
	}
}

func TestKernelTFTPortWildcardExpandsSafeTransportProtocols(t *testing.T) {
	classifier := &kernelTFTClassifier{mark: 0x4c51_0000, mask: 0xffff_0000}
	filter := gtpv2.IPv4PacketFilter{
		Direction:     gtpv2.TFTDirectionDownlink,
		HasRemotePort: true, RemotePortLow: 16_384, RemotePortHigh: 32_767,
		HasLocalPort: true, LocalPortLow: 4_000, LocalPortHigh: 4_100,
	}
	if expanded := classifier.filterExpressions(netip.MustParseAddr("10.251.0.7"), filter); len(expanded) != 3 {
		t.Fatalf("protocol-wildcard port filter expanded to %d rules, want TCP/UDP/SCTP", len(expanded))
	}
}
