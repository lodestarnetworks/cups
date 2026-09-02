package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/internal/sgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/sgwc/session"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

func TestRecoveryIdentityIncludesPeerPort(t *testing.T) {
	gateway := &Gateway{
		store:    session.NewStore(),
		recovery: make(map[peerKey]uint8),
	}
	echo := func(counter uint8) gtpv2.Message {
		return gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, MessageType: gtpv2.MessageEchoRequest},
			IEs:    []gtpv2.IE{gtpv2.NewRecoveryIE(counter)},
		}
	}
	peerIP := netip.MustParseAddr("10.200.0.10")

	// A diagnostic probe can legitimately use the MME's source address with an
	// ephemeral port. It is not the same GTP-C peer as the MME listening on 2123
	// and must not make a later MME Echo look like a restart.
	if err := gateway.observeRecovery(context.Background(), 0, netip.AddrPortFrom(peerIP, 49152), echo(8)); err != nil {
		t.Fatal(err)
	}
	if err := gateway.observeRecovery(context.Background(), 0, netip.AddrPortFrom(peerIP, 2123), echo(9)); err != nil {
		t.Fatal(err)
	}

	if got := gateway.Counters().PeerRestarts; got != 0 {
		t.Fatalf("peer restarts=%d, want 0 for different source ports", got)
	}
	if got := len(gateway.recovery); got != 2 {
		t.Fatalf("recovery identities=%d, want 2", got)
	}

	if err := gateway.observeRecovery(context.Background(), 0, netip.AddrPortFrom(peerIP, 2123), echo(10)); err != nil {
		t.Fatal(err)
	}
	if got := gateway.Counters().PeerRestarts; got != 1 {
		t.Fatalf("peer restarts=%d, want 1 for a changed counter on the same endpoint", got)
	}
}

type recoveryUserPlane struct {
	deleteErr error
	deletes   int
}

func (*recoveryUserPlane) Establish(context.Context, pfcpclient.Establishment) (pfcpclient.Session, error) {
	return pfcpclient.Session{}, nil
}
func (*recoveryUserPlane) ActivateDownlink(context.Context, *pfcpclient.Session, pfcpclient.Tunnel) error {
	return nil
}
func (*recoveryUserPlane) DeactivateDownlink(context.Context, *pfcpclient.Session) error {
	return nil
}
func (*recoveryUserPlane) AddBearer(context.Context, *pfcpclient.Session, pfcpclient.BearerPlan) error {
	return nil
}
func (*recoveryUserPlane) ActivateBearer(context.Context, *pfcpclient.Session, pfcpclient.RuleIDs, pfcpclient.Tunnel) error {
	return nil
}
func (*recoveryUserPlane) DeactivateBearer(context.Context, *pfcpclient.Session, pfcpclient.RuleIDs) error {
	return nil
}
func (*recoveryUserPlane) UpdateBearerQoS(context.Context, *pfcpclient.Session, pfcpclient.RuleIDs, uint8, uint8, bool, bool, uint64, uint64) error {
	return nil
}
func (*recoveryUserPlane) RemoveBearer(context.Context, *pfcpclient.Session, pfcpclient.RuleIDs) error {
	return nil
}
func (p *recoveryUserPlane) Delete(context.Context, pfcpclient.Session) error {
	p.deletes++
	return p.deleteErr
}

type recoveryS5Transactions struct {
	deleteErr   error
	causes      []uint8
	deletes     int
	lastPeer    netip.AddrPort
	lastRequest gtpv2.Message
}

func (s *recoveryS5Transactions) Do(_ context.Context, peer netip.AddrPort, request gtpv2.Message) (gtpv2.Message, error) {
	if request.Header.MessageType != gtpv2.MessageDeleteSessionRequest {
		return gtpv2.Message{}, fmt.Errorf("unexpected S5 request type %d", request.Header.MessageType)
	}
	s.deletes++
	s.lastPeer = peer
	s.lastRequest = request.Clone()
	if s.deleteErr != nil {
		return gtpv2.Message{}, s.deleteErr
	}
	cause := uint8(gtpv2.CauseRequestAccepted)
	if len(s.causes) > 0 {
		index := s.deletes - 1
		if index >= len(s.causes) {
			index = len(s.causes) - 1
		}
		cause = s.causes[index]
	}
	teid := uint32(0)
	if cause != gtpv2.CauseContextNotFound {
		senderIE, ok := request.Find(gtpv2.IEFTEID, 0)
		if !ok {
			return gtpv2.Message{}, errors.New("recovery S5 delete omitted Sender F-TEID")
		}
		sender, err := senderIE.FTEID()
		if err != nil {
			return gtpv2.Message{}, err
		}
		teid = sender.TEID
	}
	return gtpv2.Message{
		Header: gtpv2.Header{
			Version: gtpv2.Version, HasTEID: teid != 0,
			MessageType: gtpv2.MessageDeleteSessionResponse, TEID: teid,
		},
		IEs: []gtpv2.IE{gtpv2.NewCauseIE(cause, 0)},
	}, nil
}

func TestRecoveryOnCreateSessionPurgesStaleStateBeforeDispatch(t *testing.T) {
	peer := netip.MustParseAddrPort("10.250.10.2:2123")
	userPlane := &recoveryUserPlane{}
	gateway, s5 := recoveryGateway(t, peer.Addr(), userPlane)
	var commits []string
	gateway.config.CommitPeerRecovery = func(key string, counter uint8) error {
		commits = append(commits, key+"="+fmt.Sprint(counter))
		return nil
	}
	request := func(counter uint8) gtpv2.Message {
		return gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, MessageType: gtpv2.MessageCreateSessionRequest},
			IEs:    []gtpv2.IE{gtpv2.NewRecoveryIE(counter)},
		}
	}
	if _, err := gateway.handleS11(context.Background(), peer, request(9)); err != nil {
		t.Fatal(err)
	}
	createRecoverySession(t, gateway.store, peer.Addr())
	if _, err := gateway.handleS11(context.Background(), peer, request(10)); err != nil {
		t.Fatal(err)
	}
	if got := len(gateway.store.Snapshot()); got != 0 {
		t.Fatalf("stale sessions after MME restart = %d, want 0", got)
	}
	if s5.deletes != 1 || userPlane.deletes != 1 || gateway.Counters().PeerRestarts != 1 {
		t.Fatalf("restart cleanup PGW deletes=%d SGW-U deletes=%d counters=%+v", s5.deletes, userPlane.deletes, gateway.Counters())
	}
	if s5.lastPeer != netip.MustParseAddrPort("10.250.20.2:2123") || s5.lastRequest.Header.TEID != 400 {
		t.Fatalf("restart cleanup targeted peer=%s TEID=%d", s5.lastPeer, s5.lastRequest.Header.TEID)
	}
	if got, want := fmt.Sprint(commits), "[s11|10.250.10.2:2123=9 s11|10.250.10.2:2123=10]"; got != want {
		t.Fatalf("durable recovery commits = %s, want %s", got, want)
	}
}

func TestRecoveryPersistenceFailureWithholdsAndRetriesFirstContact(t *testing.T) {
	peer := netip.MustParseAddrPort("10.250.10.2:2123")
	gateway, _ := recoveryGateway(t, peer.Addr(), &recoveryUserPlane{})
	persistErr := errors.New("synthetic durable recovery failure")
	gateway.config.CommitPeerRecovery = func(string, uint8) error { return persistErr }
	request := gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, MessageType: gtpv2.MessageEchoRequest},
		IEs:    []gtpv2.IE{gtpv2.NewRecoveryIE(30)},
	}
	response, err := gateway.handleS11(context.Background(), peer, request)
	if err != nil {
		t.Fatal(err)
	}
	if response != nil || len(gateway.recovery) != 0 || gateway.Counters().PeerRestartPurgeFailures != 1 {
		t.Fatalf("failed persistence response=%+v state=%+v counters=%+v", response, gateway.recovery, gateway.Counters())
	}
	gateway.config.CommitPeerRecovery = func(string, uint8) error { return nil }
	response, err = gateway.handleS11(context.Background(), peer, request)
	if err != nil || response == nil || len(gateway.recovery) != 1 {
		t.Fatalf("retried persistence response=%+v state=%+v err=%v", response, gateway.recovery, err)
	}
}

func TestPeerRecoveryKeyRoundTrip(t *testing.T) {
	for _, raw := range []string{"s11|10.250.10.2:2123", "s5|10.250.20.2:2123"} {
		key, err := parsePeerRecoveryKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := peerRecoveryKey(key.side, key.peer); got != raw {
			t.Fatalf("peer recovery key round trip = %q, want %q", got, raw)
		}
	}
	for _, raw := range []string{"", "s1|10.0.0.1:2123", "s11|10.0.0.1", "s11|[::1]:2123"} {
		if _, err := parsePeerRecoveryKey(raw); err == nil {
			t.Fatalf("invalid peer recovery key %q accepted", raw)
		}
	}
}

func TestRecoveryPurgeFailureWithholdsRequestAndRetries(t *testing.T) {
	peer := netip.MustParseAddrPort("10.250.10.2:2123")
	purgeFailure := errors.New("synthetic PFCP delete failure")
	userPlane := &recoveryUserPlane{deleteErr: purgeFailure}
	gateway, s5 := recoveryGateway(t, peer.Addr(), userPlane)
	s5.causes = []uint8{gtpv2.CauseRequestAccepted, gtpv2.CauseContextNotFound}
	echo := func(counter uint8) gtpv2.Message {
		return gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, MessageType: gtpv2.MessageEchoRequest},
			IEs:    []gtpv2.IE{gtpv2.NewRecoveryIE(counter)},
		}
	}
	if err := gateway.observeRecovery(context.Background(), 0, peer, echo(20)); err != nil {
		t.Fatal(err)
	}
	createRecoverySession(t, gateway.store, peer.Addr())
	response, err := gateway.handleS11(context.Background(), peer, echo(21))
	if err != nil {
		t.Fatal(err)
	}
	if response != nil || len(gateway.store.Snapshot()) != 1 {
		t.Fatalf("failed purge response=%+v sessions=%d", response, len(gateway.store.Snapshot()))
	}
	if got := gateway.Counters().PeerRestartPurgeFailures; got != 1 {
		t.Fatalf("purge failures = %d, want 1", got)
	}
	userPlane.deleteErr = nil
	response, err = gateway.handleS11(context.Background(), peer, echo(21))
	if err != nil {
		t.Fatal(err)
	}
	if response == nil || len(gateway.store.Snapshot()) != 0 {
		t.Fatalf("retried purge response=%+v sessions=%d", response, len(gateway.store.Snapshot()))
	}
	if s5.deletes != 2 || userPlane.deletes != 2 {
		t.Fatalf("retried cleanup PGW deletes=%d SGW-U deletes=%d", s5.deletes, userPlane.deletes)
	}
}

func TestRecoveryPGWFailureWithholdsLocalAndSGWUCleanup(t *testing.T) {
	peer := netip.MustParseAddrPort("10.250.10.2:2123")
	userPlane := &recoveryUserPlane{}
	gateway, s5 := recoveryGateway(t, peer.Addr(), userPlane)
	echo := func(counter uint8) gtpv2.Message {
		return gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, MessageType: gtpv2.MessageEchoRequest},
			IEs:    []gtpv2.IE{gtpv2.NewRecoveryIE(counter)},
		}
	}
	if err := gateway.observeRecovery(context.Background(), 0, peer, echo(20)); err != nil {
		t.Fatal(err)
	}
	createRecoverySession(t, gateway.store, peer.Addr())
	s5.deleteErr = errors.New("synthetic PGW timeout")
	response, err := gateway.handleS11(context.Background(), peer, echo(21))
	if err != nil {
		t.Fatal(err)
	}
	if response != nil || len(gateway.store.Snapshot()) != 1 || userPlane.deletes != 0 {
		t.Fatalf("failed PGW cleanup response=%+v sessions=%d SGW-U deletes=%d", response, len(gateway.store.Snapshot()), userPlane.deletes)
	}
	s5.deleteErr = nil
	response, err = gateway.handleS11(context.Background(), peer, echo(21))
	if err != nil {
		t.Fatal(err)
	}
	if response == nil || len(gateway.store.Snapshot()) != 0 || s5.deletes != 2 || userPlane.deletes != 1 {
		t.Fatalf("retried PGW cleanup response=%+v sessions=%d PGW deletes=%d SGW-U deletes=%d", response, len(gateway.store.Snapshot()), s5.deletes, userPlane.deletes)
	}
}

func TestDeleteSessionTreatsDownstreamContextNotFoundAsIdempotentSuccess(t *testing.T) {
	peer := netip.MustParseAddrPort("10.250.10.2:2123")
	userPlane := &recoveryUserPlane{}
	gateway, s5 := recoveryGateway(t, peer.Addr(), userPlane)
	s5.causes = []uint8{gtpv2.CauseContextNotFound}
	createRecoverySession(t, gateway.store, peer.Addr())

	ebi, err := gtpv2.NewEBIIE(6, 0)
	if err != nil {
		t.Fatal(err)
	}
	response := gateway.deleteSession(context.Background(), peer, gtpv2.Message{
		Header: gtpv2.Header{
			Version: gtpv2.Version, HasTEID: true,
			MessageType: gtpv2.MessageDeleteSessionRequest, TEID: 200,
		},
		IEs: []gtpv2.IE{ebi},
	})
	cause, err := messageCause(*response)
	if err != nil || cause != gtpv2.CauseRequestAccepted {
		t.Fatalf("Delete Session response cause=%d error=%v", cause, err)
	}
	if response.Header.TEID != 100 {
		t.Fatalf("Delete Session response TEID=%d, want MME TEID 100", response.Header.TEID)
	}
	if gateway.store.Count() != 0 || userPlane.deletes != 1 || s5.deletes != 1 {
		t.Fatalf("idempotent cleanup sessions=%d SGW-U deletes=%d PGW deletes=%d", gateway.store.Count(), userPlane.deletes, s5.deletes)
	}
	counters := gateway.Counters()
	if counters.DeleteAccepted != 1 || counters.DeleteRejected != 0 || counters.DeleteContextNotFound != 1 {
		t.Fatalf("idempotent Delete Session counters=%+v", counters)
	}
}

func recoveryGateway(t *testing.T, mme netip.Addr, userPlane *recoveryUserPlane) (*Gateway, *recoveryS5Transactions) {
	t.Helper()
	s5 := &recoveryS5Transactions{}
	return &Gateway{
		config: Config{
			AllowedMME: []netip.Addr{mme}, ProcedureTimeout: time.Second,
			PGWControl: netip.MustParseAddrPort("10.250.20.2:2123"),
		},
		store: session.NewStore(), up: userPlane, ids: newIDAllocator(),
		recovery: make(map[peerKey]uint8), paging: newPagingTracker(), s5Tx: s5,
	}, s5
}

func createRecoverySession(t *testing.T, store *session.Store, mme netip.Addr) {
	t.Helper()
	_, err := store.Create(session.Session{
		SubscriberKey: "recovery-test-subscriber", APN: "ims", State: session.StateActive,
		MMEControl:      session.FTEID{TEID: 100, IP: mme},
		S11Control:      session.FTEID{TEID: 200, IP: netip.MustParseAddr("10.250.10.1")},
		S5Control:       session.FTEID{TEID: 300, IP: netip.MustParseAddr("10.250.20.1")},
		PGWControl:      session.FTEID{TEID: 400, IP: netip.MustParseAddr("10.250.20.2")},
		PFCPControlSEID: 500, PFCPUserSEID: 600,
		Bearers: map[uint8]session.Bearer{6: {
			EBI: 6, QCI: 5, Default: true, State: session.BearerActive,
			SGWUAccess: session.FTEID{TEID: 700, IP: netip.MustParseAddr("10.250.40.248")},
			SGWUCore:   session.FTEID{TEID: 800, IP: netip.MustParseAddr("10.250.50.4")},
			PGWUser:    session.FTEID{TEID: 900, IP: netip.MustParseAddr("10.250.50.2")},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
}
