package main

import (
	"testing"

	gtptransport "github.com/lodestarnetworks/cups/internal/gtpv2/transport"
	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
)

func TestFaultAwareTransportHealth(t *testing.T) {
	clean := transportSnapshot{}
	if !cleanTransports(clean) || !resilientTransports(clean) || transportFaultsObserved(clean) {
		t.Fatal("zeroed transport counters must be clean with no observed fault")
	}

	recovered := transportSnapshot{
		MMEGTP:   gtptransport.Counters{Retransmitted: 2},
		SGWCS11:  gtptransport.Counters{CacheHits: 1},
		SGWCPFCP: pfcptransport.Counters{Retransmitted: 3},
		SGWUPFCP: pfcptransport.Counters{CacheHits: 2},
	}
	if cleanTransports(recovered) {
		t.Fatal("a fault-recovery run must not be reported as a no-fault run")
	}
	if !resilientTransports(recovered) || !transportFaultsObserved(recovered) {
		t.Fatal("retransmissions and duplicate-cache hits should be accepted and observed in a resilience run")
	}

	timedOut := recovered
	timedOut.PGWCS5.TimedOut = 1
	if resilientTransports(timedOut) {
		t.Fatal("an exhausted GTP transaction must fail the resilience gate")
	}

	dropped := recovered
	dropped.PGWUPFCP.WorkerDrops = 1
	if resilientTransports(dropped) {
		t.Fatal("a PFCP worker drop must fail the resilience gate")
	}
}
