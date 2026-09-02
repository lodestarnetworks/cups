package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	gtptransport "github.com/lodestarnetworks/cups/internal/gtpv2/transport"
	"github.com/lodestarnetworks/cups/internal/pgwc/ipam"
	"github.com/lodestarnetworks/cups/internal/pgwc/session"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

func TestSGWRecoveryPurgesPGWCAndPGWUStateBeforeAcknowledgement(t *testing.T) {
	peer := netip.MustParseAddrPort("127.121.0.1:2123")
	var commits []string
	gateway, userPlane, pool := newPGWRecoveryGateway(t, peer, func(config *Config) {
		config.CommitPeerRecovery = func(key string, counter uint8) error {
			commits = append(commits, key+"="+fmt.Sprint(counter))
			return nil
		}
	})
	if response, err := gateway.handleS5(context.Background(), peer, recoveryEcho(30)); err != nil || response == nil {
		t.Fatalf("baseline Echo response=%+v error=%v", response, err)
	}
	createPGWRecoverySession(t, gateway, peer)
	if len(gateway.Sessions()) != 1 || pool.Used() != 1 {
		t.Fatalf("recovery setup sessions=%d leases=%d", len(gateway.Sessions()), pool.Used())
	}
	response, err := gateway.handleS5(context.Background(), peer, recoveryEcho(31))
	if err != nil || response == nil || response.Header.MessageType != gtpv2.MessageEchoResponse {
		t.Fatalf("restart Echo response=%+v error=%v", response, err)
	}
	_, _, deleted := userPlane.counts()
	if len(gateway.Sessions()) != 0 || pool.Used() != 0 || deleted != 1 {
		t.Fatalf("restart cleanup sessions=%d leases=%d PGW-U deletes=%d", len(gateway.Sessions()), pool.Used(), deleted)
	}
	if got, want := fmt.Sprint(commits), "[s5|127.121.0.1:2123=30 s5|127.121.0.1:2123=31]"; got != want {
		t.Fatalf("durable recovery commits=%s, want %s", got, want)
	}
	if counters := gateway.Counters(); counters.PeerRestarts != 1 || counters.PeerRestartPurgeFailures != 0 {
		t.Fatalf("unexpected recovery counters: %#v", counters)
	}
}

func TestSGWRecoveryPGWUFailureWithholdsAndRetries(t *testing.T) {
	peer := netip.MustParseAddrPort("127.122.0.1:2123")
	gateway, userPlane, pool := newPGWRecoveryGateway(t, peer, nil)
	if response, err := gateway.handleS5(context.Background(), peer, recoveryEcho(40)); err != nil || response == nil {
		t.Fatalf("baseline Echo response=%+v error=%v", response, err)
	}
	createPGWRecoverySession(t, gateway, peer)
	userPlane.setDeleteError(errors.New("synthetic PGW-U timeout"))
	response, err := gateway.handleS5(context.Background(), peer, recoveryEcho(41))
	if err != nil {
		t.Fatal(err)
	}
	if response != nil || len(gateway.Sessions()) != 1 || pool.Used() != 1 || userPlane.deleteAttempts() != 1 {
		t.Fatalf("failed purge response=%+v sessions=%d leases=%d delete_attempts=%d", response, len(gateway.Sessions()), pool.Used(), userPlane.deleteAttempts())
	}
	if counters := gateway.Counters(); counters.PeerRestarts != 0 || counters.PeerRestartPurgeFailures != 1 {
		t.Fatalf("unexpected failed-purge counters: %#v", counters)
	}
	userPlane.setDeleteError(nil)
	response, err = gateway.handleS5(context.Background(), peer, recoveryEcho(41))
	if err != nil || response == nil {
		t.Fatalf("retried Echo response=%+v error=%v", response, err)
	}
	if len(gateway.Sessions()) != 0 || pool.Used() != 0 || userPlane.deleteAttempts() != 2 {
		t.Fatalf("retried purge sessions=%d leases=%d delete_attempts=%d", len(gateway.Sessions()), pool.Used(), userPlane.deleteAttempts())
	}
	if counters := gateway.Counters(); counters.PeerRestarts != 1 || counters.PeerRestartPurgeFailures != 1 {
		t.Fatalf("unexpected retried-purge counters: %#v", counters)
	}
}

func TestSGWRecoveryPersistenceFailureWithholdsFirstContact(t *testing.T) {
	peer := netip.MustParseAddrPort("127.123.0.1:2123")
	persistErr := errors.New("synthetic peer-recovery persistence failure")
	fail := true
	gateway, _, _ := newPGWRecoveryGateway(t, peer, func(config *Config) {
		config.CommitPeerRecovery = func(string, uint8) error {
			if fail {
				return persistErr
			}
			return nil
		}
	})
	response, err := gateway.handleS5(context.Background(), peer, recoveryEcho(50))
	if err != nil {
		t.Fatal(err)
	}
	if response != nil || len(gateway.recovery) != 0 || gateway.Counters().PeerRestartPurgeFailures != 1 {
		t.Fatalf("failed persistence response=%+v recovery=%+v counters=%#v", response, gateway.recovery, gateway.Counters())
	}
	fail = false
	response, err = gateway.handleS5(context.Background(), peer, recoveryEcho(50))
	if err != nil || response == nil || len(gateway.recovery) != 1 {
		t.Fatalf("retried persistence response=%+v recovery=%+v error=%v", response, gateway.recovery, err)
	}
}

func TestPGWPeerRecoveryKeyRoundTrip(t *testing.T) {
	peer := netip.MustParseAddrPort("10.250.20.1:2123")
	key := peerRecoveryKey(peer)
	parsed, err := parsePeerRecoveryKey(key)
	if err != nil || parsed != peer {
		t.Fatalf("peer recovery key %q parsed as %s, error=%v", key, parsed, err)
	}
	for _, raw := range []string{"", "s11|10.250.20.1:2123", "s5|10.250.20.1", "s5|[::1]:2123"} {
		if _, err := parsePeerRecoveryKey(raw); err == nil {
			t.Fatalf("invalid peer recovery key %q accepted", raw)
		}
	}
}

func newPGWRecoveryGateway(t *testing.T, peer netip.AddrPort, configure func(*Config)) (*Gateway, *fakeUserPlane, *ipam.Pool) {
	t.Helper()
	pool, err := ipam.New(netip.MustParsePrefix("10.93.0.0/24"), netip.MustParseAddr("10.93.0.1"), 100)
	if err != nil {
		t.Fatal(err)
	}
	transport := gtptransport.DefaultConfig()
	transport.RetransmitTimeout = 50 * time.Millisecond
	transport.MaxRetransmits = 1
	config := Config{
		S5Listen: netip.MustParseAddrPort("127.0.0.1:0"), S5Advertise: netip.MustParseAddr("10.200.0.20"),
		PGWUUserIP: netip.MustParseAddr("10.200.0.21"), AllowedSGW: []netip.Addr{peer.Addr()},
		APN: "lodestartest", RecoveryCounter: 7, ProcedureTimeout: time.Second,
		SubscriberSalt: []byte("recovery-test-salt"), Transport: transport,
	}
	if configure != nil {
		configure(&config)
	}
	userPlane := &fakeUserPlane{}
	gateway, err := New(config, session.NewStoreWithLimit(100), pool, userPlane)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Close() })
	return gateway, userPlane, pool
}

func createPGWRecoverySession(t *testing.T, gateway *Gateway, peer netip.AddrPort) {
	t.Helper()
	response, err := gateway.handleS5(context.Background(), peer, makeCreateRequest(t, peer.Addr()))
	if err != nil || response == nil || responseCause(t, *response) != gtpv2.CauseRequestAccepted {
		t.Fatalf("Create Session response=%+v error=%v", response, err)
	}
}

func recoveryEcho(counter uint8) gtpv2.Message {
	return gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, MessageType: gtpv2.MessageEchoRequest},
		IEs:    []gtpv2.IE{gtpv2.NewRecoveryIE(counter)},
	}
}
