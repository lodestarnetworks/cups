//go:build linux

package kernelgtp

import (
	"net/netip"
	"testing"
)

func TestNormalizePolicyRoutingPrefixesUsesExactDisjointRoutes(t *testing.T) {
	config := PolicyRoutingConfig{Table: 21_521, Priority: 10_510, Mark: 0x4c51_0000, Mask: 0xffff_0000}
	pools, normalized, err := normalizePolicyRoutingPrefixes([]netip.Prefix{
		netip.MustParsePrefix("10.46.0.0/16"),
		netip.MustParsePrefix("10.45.0.0/16"),
	}, config)
	if err != nil {
		t.Fatal(err)
	}
	if normalized != config || len(pools) != 2 || pools[0] != netip.MustParsePrefix("10.45.0.0/16") ||
		pools[1] != netip.MustParsePrefix("10.46.0.0/16") {
		t.Fatalf("normalized policy routes = %v, %#v", pools, normalized)
	}
	if _, _, err := normalizePolicyRoutingPrefixes([]netip.Prefix{
		netip.MustParsePrefix("10.45.0.0/16"),
		netip.MustParsePrefix("10.45.1.0/24"),
	}, config); err == nil {
		t.Fatal("overlapping policy routes were accepted")
	}
}
