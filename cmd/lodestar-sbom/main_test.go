package main

import (
	"strings"
	"testing"
)

func TestDeterministicUUID(t *testing.T) {
	first := deterministicUUID("release material")
	if first != deterministicUUID("release material") || first == deterministicUUID("different") {
		t.Fatal("SBOM serial number is not deterministic and content-bound")
	}
	if !strings.HasPrefix(first, "urn:uuid:") || len(first) != len("urn:uuid:00000000-0000-0000-0000-000000000000") {
		t.Fatalf("invalid UUID %q", first)
	}
}

func TestUniqueSortedReferences(t *testing.T) {
	got := unique([]string{"a", "a", "b", "b", "c"})
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("unique references = %v", got)
	}
}
