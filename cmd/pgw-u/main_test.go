package main

import (
	"net/netip"
	"testing"

	"github.com/lodestarnetworks/cups/internal/config"
)

func TestBuildUEPoolsPreservesEveryAPNRange(t *testing.T) {
	value := config.PGWU{UEPools: []config.PGWUUEPool{
		{APN: "internet", UEPoolPrefix: "10.45.0.0/16", UEGateway: "10.45.0.1"},
		{APN: "ims", UEPoolPrefix: "10.46.0.0/16", UEGateway: "10.46.0.1"},
	}}
	pools, err := buildUEPools(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(pools) != 2 || pools[0].Prefix != netip.MustParsePrefix("10.45.0.0/16") ||
		pools[1].Prefix != netip.MustParsePrefix("10.46.0.0/16") || pools[1].Gateway != netip.MustParseAddr("10.46.0.1") {
		t.Fatalf("built UE pools = %#v", pools)
	}
}

func TestBuildUEPoolsRejectsMalformedAddressing(t *testing.T) {
	value := config.PGWU{UEPools: []config.PGWUUEPool{{
		APN: "internet", UEPoolPrefix: "not-a-prefix", UEGateway: "10.45.0.1",
	}}}
	if _, err := buildUEPools(value); err == nil {
		t.Fatal("malformed UE pool was accepted")
	}
}
