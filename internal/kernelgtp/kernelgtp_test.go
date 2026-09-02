package kernelgtp

import (
	"errors"
	"net/netip"
	"testing"
)

func TestNormalizeLinkConfig(t *testing.T) {
	config, err := normalizeLinkConfig(LinkConfig{
		Name: "lod-pgwu0", OwnershipFile: "/run/sgw-next/lod-pgwu0.owner", LocalIPv4: netip.MustParseAddr("10.20.30.40"),
		AllowedPeers: []netip.Addr{netip.MustParseAddr("10.20.30.41")}, Role: RoleGGSN,
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.HashSize != DefaultHashSize || config.MTU != DefaultMTU || config.SocketBufferBytes != DefaultSocketBufferBytes {
		t.Fatalf("defaults not applied: %+v", config)
	}
}

func TestNormalizeLinkConfigRejectsUnsafeValues(t *testing.T) {
	tests := []LinkConfig{
		{Name: "", OwnershipFile: "/run/sgw-next/x.owner", LocalIPv4: netip.MustParseAddr("10.1.1.1"), AllowedPeers: []netip.Addr{netip.MustParseAddr("10.1.1.2")}},
		{Name: "name/with/slash", OwnershipFile: "/run/sgw-next/x.owner", LocalIPv4: netip.MustParseAddr("10.1.1.1"), AllowedPeers: []netip.Addr{netip.MustParseAddr("10.1.1.2")}},
		{Name: "lod-pgwu0", OwnershipFile: "relative.owner", LocalIPv4: netip.MustParseAddr("10.1.1.1"), AllowedPeers: []netip.Addr{netip.MustParseAddr("10.1.1.2")}},
		{Name: "lod-pgwu0", OwnershipFile: "/run/sgw-next/x.owner", LocalIPv4: netip.MustParseAddr("192.0.2.1"), AllowedPeers: []netip.Addr{netip.MustParseAddr("10.1.1.2")}},
		{Name: "lod-pgwu0", OwnershipFile: "/run/sgw-next/x.owner", LocalIPv4: netip.MustParseAddr("10.1.1.1")},
		{Name: "lod-pgwu0", OwnershipFile: "/run/sgw-next/x.owner", LocalIPv4: netip.MustParseAddr("10.1.1.1"), AllowedPeers: []netip.Addr{netip.MustParseAddr("10.1.1.2")}, Role: Role(9)},
		{Name: "lod-pgwu0", OwnershipFile: "/run/sgw-next/x.owner", LocalIPv4: netip.MustParseAddr("10.1.1.1"), AllowedPeers: []netip.Addr{netip.MustParseAddr("10.1.1.2")}, HashSize: 12},
		{Name: "lod-pgwu0", OwnershipFile: "/run/sgw-next/x.owner", LocalIPv4: netip.MustParseAddr("10.1.1.1"), AllowedPeers: []netip.Addr{netip.MustParseAddr("10.1.1.2")}, MTU: 1_500},
	}
	for index, test := range tests {
		if _, err := normalizeLinkConfig(test); !errors.Is(err, ErrInvalid) {
			t.Fatalf("case %d: expected ErrInvalid, got %v", index, err)
		}
	}
}

func TestNormalizeContext(t *testing.T) {
	want := Context{
		LinkIndex: 7, UEIPv4: netip.MustParseAddr("10.200.0.7"), PeerIPv4: netip.MustParseAddr("10.90.0.31"),
		IncomingTEID: 1001, OutgoingTEID: 2001,
	}
	got, err := normalizeContext(want)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("context changed: got %+v want %+v", got, want)
	}
}

func TestNormalizeContextRejectsInvalidIdentity(t *testing.T) {
	base := Context{
		LinkIndex: 1, UEIPv4: netip.MustParseAddr("10.200.0.1"), PeerIPv4: netip.MustParseAddr("10.90.0.1"),
		IncomingTEID: 1, OutgoingTEID: 2,
	}
	tests := []Context{base, base, base, base, base}
	tests[0].LinkIndex = 0
	tests[1].UEIPv4 = netip.MustParseAddr("2001:db8::1")
	tests[2].PeerIPv4 = netip.MustParseAddr("198.51.100.1")
	tests[3].IncomingTEID = 0
	tests[4].OutgoingTEID = 0
	for index, test := range tests {
		if _, err := normalizeContext(test); !errors.Is(err, ErrInvalid) {
			t.Fatalf("case %d: expected ErrInvalid, got %v", index, err)
		}
	}
}

func TestNormalizeIPv4Network(t *testing.T) {
	gateway := netip.MustParseAddr("10.251.0.1")
	pool := netip.MustParsePrefix("10.251.0.99/16")
	gotGateway, gotPool, err := normalizeIPv4Network(gateway, pool)
	if err != nil {
		t.Fatal(err)
	}
	if gotGateway != gateway || gotPool != netip.MustParsePrefix("10.251.0.0/16") {
		t.Fatalf("normalised network = %s, %s", gotGateway, gotPool)
	}
	if _, _, err := normalizeIPv4Network(netip.MustParseAddr("10.252.0.1"), pool); !errors.Is(err, ErrInvalid) {
		t.Fatalf("gateway outside pool error = %v", err)
	}
}
