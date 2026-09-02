package main

import (
	"bytes"
	"testing"

	"github.com/lodestarnetworks/cups/internal/config"
)

func TestSGWCStateIdentityIncludesCanonicalPGWRoutes(t *testing.T) {
	base := config.SGWC{
		S11Listen: "10.200.10.1:2123", S11Advertise: "10.200.10.1", AllowedMME: []string{"10.200.10.2"},
		S5Listen: "10.200.20.1:2123", S5Advertise: "10.200.20.1", PGWControl: "10.200.20.2:2123",
		PFCPListen: "10.200.30.1:8805", PFCPAdvertise: "10.200.30.1", PFCPRemote: "10.200.30.2:8805",
		SGWUAccessIP: "10.200.40.1", SGWUCoreIP: "10.200.50.1", SubscriberSalt: "test-secret",
	}
	withoutRoutes, err := sgwcStateIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	base.PGWRoutes = []config.SGWCPGWRoute{
		{APN: "xcap", Address: "10.200.20.4:2123"},
		{APN: "ims", Address: "10.200.20.3:2123"},
	}
	withRoutes, err := sgwcStateIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(withoutRoutes, withRoutes) {
		t.Fatal("PGW routes did not change durable-state identity")
	}
	base.PGWRoutes[0], base.PGWRoutes[1] = base.PGWRoutes[1], base.PGWRoutes[0]
	reordered, err := sgwcStateIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(withRoutes, reordered) {
		t.Fatal("equivalent PGW route ordering changed durable-state identity")
	}
}
