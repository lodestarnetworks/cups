package gateway

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gtptransport "github.com/lodestarnetworks/cups/internal/gtpv2/transport"
	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	"github.com/lodestarnetworks/cups/internal/pgwc/ipam"
	"github.com/lodestarnetworks/cups/internal/pgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/pgwc/session"
	pgwupfcp "github.com/lodestarnetworks/cups/internal/pgwu/pfcpserver"
	pgwurules "github.com/lodestarnetworks/cups/internal/pgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

type fakeUserPlane struct {
	mu          sync.Mutex
	established []pfcpclient.Establishment
	updated     []pfcpclient.Tunnel
	deleted     []pfcpclient.Session
	added       []pfcpclient.BearerPlan
	qosUpdated  []pfcpclient.RuleIDs
	removed     []pfcpclient.RuleIDs
	addErr      error
	qosErr      error
	removeErr   error
	deleteErr   error
	deleteCalls int
}

type fakeSGWBearerPeer struct {
	mu               sync.Mutex
	pgwControlTEID   uint32
	userIP           netip.Addr
	created          int
	updated          int
	deleted          int
	validateRecovery bool
	expectedRecovery uint8
}

type failAtPersister struct {
	mu      sync.Mutex
	commits int
	failAt  int
}

func (p *failAtPersister) Commit(_, _ *session.Session) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.commits++
	if p.commits == p.failAt {
		return fmt.Errorf("injected durable commit failure")
	}
	return nil
}

func (p *fakeSGWBearerPeer) setPGWControlTEID(teid uint32) {
	p.mu.Lock()
	p.pgwControlTEID = teid
	p.mu.Unlock()
}

func (p *fakeSGWBearerPeer) counts() (int, int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.created, p.updated, p.deleted
}

func (p *fakeSGWBearerPeer) handle(_ context.Context, _ netip.AddrPort, request gtpv2.Message) (*gtpv2.Message, error) {
	p.mu.Lock()
	pgwControlTEID := p.pgwControlTEID
	p.mu.Unlock()
	if pgwControlTEID == 0 || request.Header.TEID != 0x2001 {
		return nil, fmt.Errorf("fake SGW: invalid control tunnel")
	}
	if p.validateRecovery {
		recoveryIE, ok := request.Find(gtpv2.IERecovery, 0)
		if !ok {
			return nil, fmt.Errorf("fake SGW: request omitted PGW recovery counter")
		}
		counter, err := recoveryIE.Recovery()
		if err != nil || counter != p.expectedRecovery {
			return nil, fmt.Errorf("fake SGW: recovery counter=%d error=%v, want %d", counter, err, p.expectedRecovery)
		}
	}
	switch request.Header.MessageType {
	case gtpv2.MessageCreateBearerRequest:
		linked, ok := request.Find(gtpv2.IEEBI, 0)
		if !ok {
			return nil, fmt.Errorf("fake SGW: missing linked EBI")
		}
		if ebi, err := linked.EBI(); err != nil || ebi != 5 {
			return nil, fmt.Errorf("fake SGW: invalid linked EBI")
		}
		contextIE, ok := request.Find(gtpv2.IEBearerContext, 0)
		if !ok {
			return nil, fmt.Errorf("fake SGW: missing bearer context")
		}
		children, err := contextIE.Children()
		if err != nil {
			return nil, err
		}
		ebiIE, ebiOK := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
		tftIE, tftOK := gtpv2.FindIE(children, gtpv2.IEBearerTFT, 0)
		pgwUserIE, userOK := gtpv2.FindIE(children, gtpv2.IEFTEID, 1)
		if !ebiOK || !tftOK || !userOK {
			return nil, fmt.Errorf("fake SGW: incomplete Create Bearer context")
		}
		ebi, err := ebiIE.EBI()
		if err != nil {
			return nil, err
		}
		if _, err := tftIE.BearerTFT(); err != nil {
			return nil, err
		}
		pgwUser, err := pgwUserIE.FTEID()
		if err != nil || pgwUser.InterfaceType != gtpv2.InterfaceS5S8PGWGTPU {
			return nil, fmt.Errorf("fake SGW: invalid PGW S5-U F-TEID")
		}
		userIP := p.userIP
		if !userIP.IsValid() {
			userIP = netip.MustParseAddr("10.200.0.11")
		}
		remote, _ := gtpv2.NewFTEIDIE(2, gtpv2.FTEID{
			InterfaceType: gtpv2.InterfaceS5S8SGWGTPU, TEID: 0x3300 + uint32(ebi), IPv4: userIP,
		})
		returnedLocal, _ := gtpv2.NewFTEIDIE(3, pgwUser)
		contextResponse, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), remote, returnedLocal)
		p.mu.Lock()
		p.created++
		p.mu.Unlock()
		return &gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateBearerResponse, TEID: pgwControlTEID},
			IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), contextResponse},
		}, nil
	case gtpv2.MessageUpdateBearerRequest:
		contextIE, ok := request.Find(gtpv2.IEBearerContext, 0)
		if !ok {
			return nil, fmt.Errorf("fake SGW: update omitted context")
		}
		children, err := contextIE.Children()
		if err != nil {
			return nil, err
		}
		ebiIE, ebiOK := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
		qosIE, qosOK := gtpv2.FindIE(children, gtpv2.IEBearerQoS, 0)
		if !ebiOK || !qosOK {
			return nil, fmt.Errorf("fake SGW: update omitted EBI or QoS")
		}
		if qos, err := qosIE.BearerQoSDetails(); err != nil || qos.UplinkMBR != 10_000_000 || qos.DownlinkMBR != 14_000_000 {
			return nil, fmt.Errorf("fake SGW: wrong updated QoS")
		}
		contextResponse, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0))
		p.mu.Lock()
		p.updated++
		p.mu.Unlock()
		return &gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageUpdateBearerResponse, TEID: pgwControlTEID},
			IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), contextResponse},
		}, nil
	case gtpv2.MessageDeleteBearerRequest:
		ebiIE, ok := request.Find(gtpv2.IEEBI, 1)
		if !ok {
			return nil, fmt.Errorf("fake SGW: delete omitted dedicated EBI")
		}
		contextResponse, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0))
		p.mu.Lock()
		p.deleted++
		p.mu.Unlock()
		return &gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteBearerResponse, TEID: pgwControlTEID},
			IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), contextResponse},
		}, nil
	default:
		return nil, fmt.Errorf("fake SGW: unsupported message %d", request.Header.MessageType)
	}
}

func (f *fakeUserPlane) Establish(_ context.Context, plan pfcpclient.Establishment) (pfcpclient.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.established = append(f.established, plan)
	return pfcpclient.Session{
		CPSEID: plan.CPSEID, UPSEID: plan.CPSEID + 1, UEIPv4: plan.UEIPv4,
		Local: plan.Local, Remote: plan.Remote,
	}, nil
}

func (f *fakeUserPlane) UpdateRemote(_ context.Context, current *pfcpclient.Session, remote pfcpclient.Tunnel) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updated = append(f.updated, remote)
	current.Remote = remote
	return nil
}

func (f *fakeUserPlane) AddBearer(_ context.Context, current *pfcpclient.Session, plan pfcpclient.BearerPlan) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addErr != nil {
		return f.addErr
	}
	f.added = append(f.added, plan)
	current.Bearers = append(current.Bearers, pfcpclient.Bearer{
		Rules: plan.Rules, Local: plan.Local, Remote: plan.Remote,
		UplinkBitrate: plan.UplinkBitrate, DownlinkBitrate: plan.DownlinkBitrate, QCI: plan.QCI, ARP: plan.ARP,
	})
	return nil
}

func (f *fakeUserPlane) UpdateBearerQoS(_ context.Context, current *pfcpclient.Session, ids pfcpclient.RuleIDs, qci, arp uint8, uplink, downlink uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.qosErr != nil {
		return f.qosErr
	}
	f.qosUpdated = append(f.qosUpdated, ids)
	for index := range current.Bearers {
		if current.Bearers[index].Rules.QER == ids.QER {
			current.Bearers[index].QCI, current.Bearers[index].ARP = qci, arp
			current.Bearers[index].UplinkBitrate, current.Bearers[index].DownlinkBitrate = uplink, downlink
		}
	}
	return nil
}

func (f *fakeUserPlane) RemoveBearer(_ context.Context, current *pfcpclient.Session, ids pfcpclient.RuleIDs) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.removeErr != nil {
		return f.removeErr
	}
	f.removed = append(f.removed, ids)
	for index := range current.Bearers {
		if current.Bearers[index].Rules.QER == ids.QER {
			current.Bearers = append(current.Bearers[:index], current.Bearers[index+1:]...)
			break
		}
	}
	return nil
}

func (f *fakeUserPlane) Delete(_ context.Context, current pfcpclient.Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteCalls++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, current)
	return nil
}

func (f *fakeUserPlane) counts() (established, updated, deleted int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.established), len(f.updated), len(f.deleted)
}

func (f *fakeUserPlane) lastEstablishment() pfcpclient.Establishment {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.established) == 0 {
		return pfcpclient.Establishment{}
	}
	return f.established[len(f.established)-1]
}

func (f *fakeUserPlane) setBearerErrors(add, qos, remove error) {
	f.mu.Lock()
	f.addErr, f.qosErr, f.removeErr = add, qos, remove
	f.mu.Unlock()
}

func (f *fakeUserPlane) setDeleteError(err error) {
	f.mu.Lock()
	f.deleteErr = err
	f.mu.Unlock()
}

func (f *fakeUserPlane) deleteAttempts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deleteCalls
}

func TestS5SessionLifecycle(t *testing.T) {
	transport := gtptransport.DefaultConfig()
	transport.RetransmitTimeout = 50 * time.Millisecond
	transport.MaxRetransmits = 1
	pool, err := ipam.New(netip.MustParsePrefix("10.90.0.0/24"), netip.MustParseAddr("10.90.0.1"), 100)
	if err != nil {
		t.Fatal(err)
	}
	userPlane := &fakeUserPlane{}
	gateway, err := New(Config{
		S5Listen: netip.MustParseAddrPort("127.0.0.1:0"), S5Advertise: netip.MustParseAddr("10.200.0.20"),
		PGWUUserIP: netip.MustParseAddr("10.200.0.21"), AllowedSGW: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		APN: "lodestartest", RecoveryCounter: 7, ProcedureTimeout: time.Second,
		SubscriberSalt: []byte("test-salt"),
		DNSIPv4:        []netip.Addr{netip.MustParseAddr("10.250.70.1"), netip.MustParseAddr("10.250.70.2")}, IPv4LinkMTU: 1400,
		APNAMBRUplinkBPS: 1_000_000_000, APNAMBRDownlinkBPS: 2_000_000_000,
		Transport: transport,
	}, session.NewStoreWithLimit(100), pool, userPlane)
	if err != nil {
		t.Fatal(err)
	}
	client, err := gtptransport.Listen(netip.MustParseAddrPort("127.0.0.1:0"), nil, transport)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer gateway.Close()
	defer client.Close()
	go func() { _ = gateway.Serve(ctx) }()
	go func() { _ = client.Serve(ctx) }()

	operation, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	create := makeCreateRequest(t, client.LocalAddr().Addr())
	response, err := client.Do(operation, gateway.S5Addr(), create)
	if err != nil {
		t.Fatal(err)
	}
	if got := responseCause(t, response); got != gtpv2.CauseRequestAccepted {
		t.Fatalf("create cause = %d", got)
	}
	paaIE, ok := response.Find(gtpv2.IEPAA, 0)
	if !ok {
		t.Fatal("create response omitted PAA")
	}
	ueIPv4, err := paaIE.PAAIPv4()
	if err != nil || ueIPv4.String() != "10.90.0.2" {
		t.Fatalf("PAA = %s, %v", ueIPv4, err)
	}
	ambrIE, ok := response.Find(gtpv2.IEAMBR, 0)
	if !ok {
		t.Fatal("create response omitted APN-AMBR")
	}
	uplinkAMBR, downlinkAMBR, err := ambrIE.AMBR()
	if err != nil || uplinkAMBR != 900_000_000 || downlinkAMBR != 1_800_000_000 {
		t.Fatalf("response APN-AMBR = %d/%d bps, %v", uplinkAMBR, downlinkAMBR, err)
	}
	pcoIE, ok := response.Find(gtpv2.IEPCO, 0)
	if !ok {
		t.Fatal("create response omitted requested PCO")
	}
	pco, err := pcoIE.PCO()
	if err != nil || len(pco.Containers) != 4 {
		t.Fatalf("response PCO = %#v, %v", pco, err)
	}
	if got := netip.AddrFrom4([4]byte(pco.Containers[1].Contents)); got.String() != "10.250.70.1" {
		t.Fatalf("primary DNS = %s", got)
	}
	if got := netip.AddrFrom4([4]byte(pco.Containers[2].Contents)); got.String() != "10.250.70.2" {
		t.Fatalf("secondary DNS = %s", got)
	}
	controlIE, ok := response.Find(gtpv2.IEFTEID, 1)
	if !ok {
		t.Fatal("create response omitted PGW control F-TEID")
	}
	control, err := controlIE.FTEID()
	if err != nil || control.InterfaceType != gtpv2.InterfaceS5S8PGWGTPC {
		t.Fatalf("control F-TEID = %#v, %v", control, err)
	}
	established, _, _ := userPlane.counts()
	if len(gateway.Sessions()) != 1 || pool.Used() != 1 || established != 1 {
		t.Fatalf("create did not commit all state: sessions=%d leases=%d PFCP=%d", len(gateway.Sessions()), pool.Used(), established)
	}
	plan := userPlane.lastEstablishment()
	if plan.UplinkBitrate != 800_000_000 || plan.DownlinkBitrate != 1_800_000_000 {
		t.Fatalf("PFCP MBR = %d/%d bps", plan.UplinkBitrate, plan.DownlinkBitrate)
	}

	ebi, _ := gtpv2.NewEBIIE(5, 0)
	newSGWUser, _ := gtpv2.NewFTEIDIE(1, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8SGWGTPU, TEID: 0x3002, IPv4: netip.MustParseAddr("10.200.0.12"),
	})
	bearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebi, newSGWUser)
	modifyResponse, err := client.Do(operation, gateway.S5Addr(), gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageModifyBearerRequest, TEID: control.TEID},
		IEs:    []gtpv2.IE{bearer},
	})
	_, updated, _ := userPlane.counts()
	if err != nil || responseCause(t, modifyResponse) != gtpv2.CauseRequestAccepted || updated != 1 {
		t.Fatalf("modify response=%#v err=%v updates=%d", modifyResponse, err, updated)
	}

	stored := gateway.Sessions()[0]
	sender, _ := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8SGWGTPC, TEID: stored.SGWControl.TEID, IPv4: stored.SGWControl.IP,
	})
	deleteResponse, err := client.Do(operation, gateway.S5Addr(), gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteSessionRequest, TEID: control.TEID},
		IEs:    []gtpv2.IE{ebi, sender},
	})
	if err != nil || responseCause(t, deleteResponse) != gtpv2.CauseRequestAccepted {
		t.Fatalf("delete response=%#v err=%v", deleteResponse, err)
	}
	_, _, deleted := userPlane.counts()
	if len(gateway.Sessions()) != 0 || pool.Used() != 0 || deleted != 1 {
		t.Fatalf("delete leaked state: sessions=%d leases=%d PFCP=%d", len(gateway.Sessions()), pool.Used(), deleted)
	}
	counters := gateway.Counters()
	if counters.CreateAccepted != 1 || counters.ModifyAccepted != 1 || counters.DeleteAccepted != 1 || counters.Rejected != 0 {
		t.Fatalf("unexpected counters: %#v", counters)
	}
}

func TestPGWInitiatedDedicatedBearerLifecycleAndReplay(t *testing.T) {
	transport := gtptransport.DefaultConfig()
	transport.RetransmitTimeout = 50 * time.Millisecond
	transport.MaxRetransmits = 1
	peerAddress := netip.MustParseAddr("127.90.0.2")
	peerHarness := &fakeSGWBearerPeer{validateRecovery: true, expectedRecovery: 7}
	peer, err := gtptransport.Listen(netip.AddrPortFrom(peerAddress, 2123), peerHarness.handle, transport)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := ipam.New(netip.MustParsePrefix("10.90.0.0/24"), netip.MustParseAddr("10.90.0.1"), 100)
	if err != nil {
		t.Fatal(err)
	}
	userPlane := &fakeUserPlane{}
	gateway, err := New(Config{
		S5Listen: netip.MustParseAddrPort("127.90.0.1:0"), S5Advertise: netip.MustParseAddr("10.200.0.20"),
		PGWUUserIP: netip.MustParseAddr("10.200.0.21"), PGWUQCI1UserIP: netip.MustParseAddr("10.200.0.22"), AllowedSGW: []netip.Addr{peerAddress},
		APN: "lodestartest", RecoveryCounter: 7, ProcedureTimeout: time.Second,
		SubscriberSalt: []byte("test-salt"), Transport: transport,
	}, session.NewStoreWithLimit(100), pool, userPlane)
	if err != nil {
		_ = peer.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = gateway.Close(); _ = peer.Close() })
	go func() { _ = gateway.Serve(ctx) }()
	go func() { _ = peer.Serve(ctx) }()
	operation, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()

	createResponse, err := peer.Do(operation, gateway.S5Addr(), makeCreateRequest(t, peerAddress))
	if err != nil || responseCause(t, createResponse) != gtpv2.CauseRequestAccepted {
		t.Fatalf("Create Session response=%#v error=%v", createResponse, err)
	}
	controlIE, ok := createResponse.Find(gtpv2.IEFTEID, 1)
	if !ok {
		t.Fatal("Create Session response omitted PGW control F-TEID")
	}
	control, err := controlIE.FTEID()
	if err != nil {
		t.Fatal(err)
	}
	peerHarness.setPGWControlTEID(control.TEID)
	current := gateway.Sessions()[0]
	tft := gtpv2.TrafficFlowTemplate{
		Operation: gtpv2.TFTOperationCreate,
		Filters: []gtpv2.PacketFilter{{
			ID: 1, Direction: gtpv2.TFTDirectionBidirectional, Precedence: 10,
			Components: []gtpv2.PacketFilterComponent{
				{Type: gtpv2.TFTComponentProtocol, Value: []byte{17}},
				{Type: gtpv2.TFTComponentSingleLocalPort, Value: []byte{0x13, 0xc4}},
				{Type: gtpv2.TFTComponentSingleRemotePort, Value: []byte{0x13, 0xc5}},
			},
		}},
	}
	created, err := gateway.CreateDedicatedBearer(operation, current.ID, DedicatedBearerPlan{
		PolicyID: "ims-voice", EBI: 6, QCI: 1, ARP: 2, PreemptionCapable: true,
		UplinkMBR: 8_000_000, DownlinkMBR: 12_000_000, UplinkGBR: 3_000_000, DownlinkGBR: 4_000_000,
		TFT: tft,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.PolicyID != "ims-voice" || created.EBI != 6 || created.SGWUser.TEID != 0x3306 || created.PGWUser.TEID == 0 || created.PGWUser.IP != netip.MustParseAddr("10.200.0.22") || len(created.Rules.UplinkPDRs) != 1 || len(created.Rules.DownlinkPDRs) != 1 {
		t.Fatalf("created dedicated bearer = %#v", created)
	}
	if reconciled, err := gateway.ReconcileAll(operation); err != nil || reconciled != 1 {
		t.Fatalf("reconcile dedicated session = %d, %v", reconciled, err)
	}
	replayed := userPlane.lastEstablishment()
	if len(replayed.AdditionalBearers) != 1 || replayed.AdditionalBearers[0].Rules.QER != created.Rules.QER || replayed.AdditionalBearers[0].TFT.Operation != gtpv2.TFTOperationCreate {
		t.Fatalf("replayed PFCP plan = %#v", replayed)
	}
	updated, err := gateway.UpdateDedicatedBearer(operation, current.ID, created.EBI, DedicatedBearerQoS{
		QCI: 1, ARP: 3, PreemptionVulnerable: true,
		UplinkMBR: 10_000_000, DownlinkMBR: 14_000_000, UplinkGBR: 3_000_000, DownlinkGBR: 4_000_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.PolicyID != created.PolicyID || updated.QCI != 1 || updated.ARP != 3 || updated.UplinkMBR != 10_000_000 || updated.DownlinkMBR != 14_000_000 {
		t.Fatalf("updated dedicated bearer = %#v", updated)
	}
	if err := gateway.DeleteDedicatedBearer(operation, current.ID, created.EBI); err != nil {
		t.Fatal(err)
	}
	remaining := gateway.Sessions()[0]
	if len(remaining.DedicatedBearers) != 0 {
		t.Fatalf("dedicated bearer remains: %#v", remaining.DedicatedBearers)
	}
	createdCount, updatedCount, deletedCount := peerHarness.counts()
	if createdCount != 1 || updatedCount != 1 || deletedCount != 1 {
		t.Fatalf("SGW bearer procedures = %d/%d/%d", createdCount, updatedCount, deletedCount)
	}
	userPlane.mu.Lock()
	added, qosUpdated, removed := len(userPlane.added), len(userPlane.qosUpdated), len(userPlane.removed)
	userPlane.mu.Unlock()
	if added != 1 || qosUpdated != 1 || removed != 1 {
		t.Fatalf("PGW-U bearer procedures = %d/%d/%d", added, qosUpdated, removed)
	}
	counters := gateway.Counters()
	if counters.CreateBearerAccepted != 1 || counters.UpdateBearerAccepted != 1 || counters.DeleteBearerAccepted != 1 ||
		counters.CreateBearerRejected != 0 || counters.UpdateBearerRejected != 0 || counters.DeleteBearerRejected != 0 {
		t.Fatalf("dedicated bearer counters = %#v", counters)
	}
}

func TestDedicatedBearerPFCPFailuresLeaveControlAndSGWStateAtomic(t *testing.T) {
	transport := gtptransport.DefaultConfig()
	transport.RetransmitTimeout = 50 * time.Millisecond
	transport.MaxRetransmits = 1
	peerAddress := netip.MustParseAddr("127.92.0.2")
	peerHarness := &fakeSGWBearerPeer{}
	peer, err := gtptransport.Listen(netip.AddrPortFrom(peerAddress, 2123), peerHarness.handle, transport)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := ipam.New(netip.MustParsePrefix("10.90.0.0/24"), netip.MustParseAddr("10.90.0.1"), 100)
	if err != nil {
		t.Fatal(err)
	}
	userPlane := &fakeUserPlane{}
	control, err := New(Config{
		S5Listen: netip.MustParseAddrPort("127.92.0.1:0"), S5Advertise: netip.MustParseAddr("10.200.0.20"),
		PGWUUserIP: netip.MustParseAddr("10.200.0.21"), AllowedSGW: []netip.Addr{peerAddress},
		APN: "lodestartest", ProcedureTimeout: time.Second, SubscriberSalt: []byte("test-salt"), Transport: transport,
	}, session.NewStoreWithLimit(100), pool, userPlane)
	if err != nil {
		_ = peer.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = control.Close(); _ = peer.Close() })
	go func() { _ = control.Serve(ctx) }()
	go func() { _ = peer.Serve(ctx) }()
	operation, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	createResponse, err := peer.Do(operation, control.S5Addr(), makeCreateRequest(t, peerAddress))
	if err != nil || responseCause(t, createResponse) != gtpv2.CauseRequestAccepted {
		t.Fatalf("Create Session response=%#v error=%v", createResponse, err)
	}
	controlIE, _ := createResponse.Find(gtpv2.IEFTEID, 1)
	pgwControl, _ := controlIE.FTEID()
	peerHarness.setPGWControlTEID(pgwControl.TEID)
	current := control.Sessions()[0]
	plan := dedicatedBearerTestPlan()
	injected := fmt.Errorf("injected PFCP failure")

	userPlane.setBearerErrors(injected, nil, nil)
	if _, err := control.CreateDedicatedBearer(operation, current.ID, plan); err == nil {
		t.Fatal("PFCP-rejected Create Bearer was reported as successful")
	}
	if len(control.Sessions()[0].DedicatedBearers) != 0 {
		t.Fatal("PFCP-rejected Create Bearer changed PGW-C state")
	}
	created, updated, deleted := peerHarness.counts()
	if created != 1 || updated != 0 || deleted != 1 {
		t.Fatalf("Create Bearer rollback SGW procedures = %d/%d/%d", created, updated, deleted)
	}

	userPlane.setBearerErrors(nil, nil, nil)
	dedicated, err := control.CreateDedicatedBearer(operation, current.ID, plan)
	if err != nil {
		t.Fatal(err)
	}
	userPlane.setBearerErrors(nil, injected, nil)
	if _, err := control.UpdateDedicatedBearer(operation, current.ID, dedicated.EBI, DedicatedBearerQoS{
		QCI: 2, ARP: 3, UplinkMBR: 10_000_000, DownlinkMBR: 14_000_000,
		UplinkGBR: 3_000_000, DownlinkGBR: 4_000_000,
	}); err == nil {
		t.Fatal("PFCP-rejected Update Bearer was reported as successful")
	}
	stable := control.Sessions()[0].DedicatedBearers[dedicated.EBI]
	if stable.QCI != 1 || stable.UplinkMBR != 8_000_000 || stable.DownlinkMBR != 12_000_000 {
		t.Fatalf("PFCP-rejected update changed PGW-C state: %#v", stable)
	}
	_, updated, deleted = peerHarness.counts()
	if updated != 0 {
		t.Fatal("PGW-C contacted the SGW after PGW-U rejected the QoS update")
	}

	userPlane.setBearerErrors(nil, nil, injected)
	if err := control.DeleteDedicatedBearer(operation, current.ID, dedicated.EBI); err == nil {
		t.Fatal("PFCP-rejected Delete Bearer was reported as successful")
	}
	if len(control.Sessions()[0].DedicatedBearers) != 1 {
		t.Fatal("PFCP-rejected delete changed PGW-C state")
	}
	_, _, afterDelete := peerHarness.counts()
	if afterDelete != deleted {
		t.Fatal("PGW-C contacted the SGW after PGW-U rejected bearer removal")
	}
	counters := control.Counters()
	if counters.CreateBearerAccepted != 1 || counters.CreateBearerRejected != 1 ||
		counters.UpdateBearerRejected != 1 || counters.DeleteBearerRejected != 1 {
		t.Fatalf("PFCP failure counters = %#v", counters)
	}
}

func dedicatedBearerTestPlan() DedicatedBearerPlan {
	return DedicatedBearerPlan{
		EBI: 6, QCI: 1, ARP: 2, UplinkMBR: 8_000_000, DownlinkMBR: 12_000_000,
		UplinkGBR: 3_000_000, DownlinkGBR: 4_000_000,
		TFT: gtpv2.TrafficFlowTemplate{
			Operation: gtpv2.TFTOperationCreate,
			Filters: []gtpv2.PacketFilter{{
				ID: 1, Direction: gtpv2.TFTDirectionBidirectional, Precedence: 10,
				Components: []gtpv2.PacketFilterComponent{
					{Type: gtpv2.TFTComponentProtocol, Value: []byte{17}},
					{Type: gtpv2.TFTComponentSingleLocalPort, Value: []byte{0x13, 0xc4}},
					{Type: gtpv2.TFTComponentSingleRemotePort, Value: []byte{0x13, 0xc5}},
				},
			}},
		},
	}
}

func TestDedicatedBearerDurableCommitFailureCompensatesBothUserAndSGWPlanes(t *testing.T) {
	transport := gtptransport.DefaultConfig()
	transport.RetransmitTimeout = 50 * time.Millisecond
	transport.MaxRetransmits = 1
	peerAddress := netip.MustParseAddr("127.93.0.2")
	peerHarness := &fakeSGWBearerPeer{}
	peer, err := gtptransport.Listen(netip.AddrPortFrom(peerAddress, 2123), peerHarness.handle, transport)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := ipam.New(netip.MustParsePrefix("10.90.0.0/24"), netip.MustParseAddr("10.90.0.1"), 100)
	if err != nil {
		t.Fatal(err)
	}
	userPlane := &fakeUserPlane{}
	persister := &failAtPersister{failAt: 2}
	control, err := New(Config{
		S5Listen: netip.MustParseAddrPort("127.93.0.1:0"), S5Advertise: netip.MustParseAddr("10.200.0.20"),
		PGWUUserIP: netip.MustParseAddr("10.200.0.21"), AllowedSGW: []netip.Addr{peerAddress},
		APN: "lodestartest", ProcedureTimeout: time.Second, SubscriberSalt: []byte("test-salt"), Transport: transport,
	}, session.NewStoreWithPersister(100, persister), pool, userPlane)
	if err != nil {
		_ = peer.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = control.Close(); _ = peer.Close() })
	go func() { _ = control.Serve(ctx) }()
	go func() { _ = peer.Serve(ctx) }()
	operation, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	createResponse, err := peer.Do(operation, control.S5Addr(), makeCreateRequest(t, peerAddress))
	if err != nil || responseCause(t, createResponse) != gtpv2.CauseRequestAccepted {
		t.Fatalf("Create Session response=%#v error=%v", createResponse, err)
	}
	controlIE, _ := createResponse.Find(gtpv2.IEFTEID, 1)
	pgwControl, _ := controlIE.FTEID()
	peerHarness.setPGWControlTEID(pgwControl.TEID)
	current := control.Sessions()[0]
	if _, err := control.CreateDedicatedBearer(operation, current.ID, dedicatedBearerTestPlan()); err == nil {
		t.Fatal("failed durable Create Bearer commit was reported as successful")
	}
	stable := control.Sessions()
	if len(stable) != 1 || len(stable[0].DedicatedBearers) != 0 || pool.Used() != 1 {
		t.Fatalf("durable failure changed committed ownership: sessions=%#v leases=%d", stable, pool.Used())
	}
	created, updated, deleted := peerHarness.counts()
	if created != 1 || updated != 0 || deleted != 1 {
		t.Fatalf("durable rollback SGW procedures = %d/%d/%d", created, updated, deleted)
	}
	userPlane.mu.Lock()
	added, removed := len(userPlane.added), len(userPlane.removed)
	userPlane.mu.Unlock()
	if added != 1 || removed != 1 {
		t.Fatalf("durable rollback PGW-U procedures = add %d remove %d", added, removed)
	}
	if counters := control.Counters(); counters.CreateBearerAccepted != 0 || counters.CreateBearerRejected != 1 {
		t.Fatalf("durable failure counters = %#v", counters)
	}
}

func TestDedicatedBearerGTPTimeoutRollsBackPGWUQoS(t *testing.T) {
	transport := gtptransport.DefaultConfig()
	transport.RetransmitTimeout = 50 * time.Millisecond
	transport.MaxRetransmits = 1
	peerAddress := netip.MustParseAddr("127.94.0.2")
	peerHarness := &fakeSGWBearerPeer{}
	peer, err := gtptransport.Listen(netip.AddrPortFrom(peerAddress, 2123), peerHarness.handle, transport)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := ipam.New(netip.MustParsePrefix("10.90.0.0/24"), netip.MustParseAddr("10.90.0.1"), 100)
	if err != nil {
		t.Fatal(err)
	}
	userPlane := &fakeUserPlane{}
	control, err := New(Config{
		S5Listen: netip.MustParseAddrPort("127.94.0.1:0"), S5Advertise: netip.MustParseAddr("10.200.0.20"),
		PGWUUserIP: netip.MustParseAddr("10.200.0.21"), AllowedSGW: []netip.Addr{peerAddress},
		APN: "lodestartest", ProcedureTimeout: 300 * time.Millisecond,
		SubscriberSalt: []byte("test-salt"), Transport: transport,
	}, session.NewStoreWithLimit(100), pool, userPlane)
	if err != nil {
		_ = peer.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = control.Close(); _ = peer.Close() })
	go func() { _ = control.Serve(ctx) }()
	go func() { _ = peer.Serve(ctx) }()
	operation, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	createResponse, err := peer.Do(operation, control.S5Addr(), makeCreateRequest(t, peerAddress))
	if err != nil || responseCause(t, createResponse) != gtpv2.CauseRequestAccepted {
		t.Fatalf("Create Session response=%#v error=%v", createResponse, err)
	}
	controlIE, _ := createResponse.Find(gtpv2.IEFTEID, 1)
	pgwControl, _ := controlIE.FTEID()
	peerHarness.setPGWControlTEID(pgwControl.TEID)
	current := control.Sessions()[0]
	dedicated, err := control.CreateDedicatedBearer(operation, current.ID, dedicatedBearerTestPlan())
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := control.UpdateDedicatedBearer(operation, current.ID, dedicated.EBI, DedicatedBearerQoS{
		QCI: 2, ARP: 3, UplinkMBR: 10_000_000, DownlinkMBR: 14_000_000,
		UplinkGBR: 3_000_000, DownlinkGBR: 4_000_000,
	}); err == nil {
		t.Fatal("timed-out Update Bearer was reported as successful")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Update Bearer timeout was not bounded: %s", elapsed)
	}
	stable := control.Sessions()[0].DedicatedBearers[dedicated.EBI]
	if stable.QCI != 1 || stable.UplinkMBR != 8_000_000 || stable.DownlinkMBR != 12_000_000 {
		t.Fatalf("timed-out update changed PGW-C state: %#v", stable)
	}
	userPlane.mu.Lock()
	qosUpdates := len(userPlane.qosUpdated)
	userPlane.mu.Unlock()
	if qosUpdates != 2 {
		t.Fatalf("timed-out update did not apply and compensate PGW-U QoS: calls=%d", qosUpdates)
	}
	if counters := control.Counters(); counters.UpdateBearerAccepted != 0 || counters.UpdateBearerRejected != 1 {
		t.Fatalf("timeout counters = %#v", counters)
	}
}

func TestPGWCDurableRestartReconcilesDedicatedBearerWithPGWU(t *testing.T) {
	const enterpriseID uint16 = 65000
	gtpConfig := gtptransport.DefaultConfig()
	gtpConfig.RetransmitTimeout = 50 * time.Millisecond
	gtpConfig.MaxRetransmits = 2
	pfcpConfig := pfcptransport.DefaultConfig()
	pfcpConfig.RetransmitTimeout = 50 * time.Millisecond
	pfcpConfig.MaxRetransmits = 2

	ctx, cancel := context.WithCancel(context.Background())
	var control *Gateway
	var userPlane *pfcpclient.Client
	var stateWAL *session.WAL
	t.Cleanup(func() {
		cancel()
		if control != nil {
			_ = control.Close()
		}
		if userPlane != nil {
			_ = userPlane.Close()
		}
		if stateWAL != nil {
			_ = stateWAL.Close()
		}
	})
	startPFCP := func(client *pfcpclient.Client) { go func() { _ = client.Serve(ctx) }() }
	startGateway := func(current *Gateway) { go func() { _ = current.Serve(ctx) }() }

	pgwcPFCPAddress := netip.MustParseAddr("127.124.0.1")
	pgwuPFCPAddress := netip.MustParseAddr("127.124.0.2")
	pgwuUserAddress := netip.MustParseAddr("10.200.0.21")
	pgwuQCI1Address := netip.MustParseAddr("10.200.0.22")
	pgwuStore := pgwurules.NewStoreWithLimit(100)
	pgwuServer, err := pgwupfcp.New(pgwupfcp.Config{
		Listen: netip.AddrPortFrom(pgwuPFCPAddress, 0), Advertise: pgwuPFCPAddress,
		UserIP: pgwuUserAddress, DedicatedUserIP: pgwuQCI1Address, AllowedCP: []netip.Addr{pgwcPFCPAddress},
		EnterpriseID: enterpriseID, Transport: pfcpConfig,
	}, pgwuStore)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pgwuServer.Close() })
	go func() { _ = pgwuServer.Serve(ctx) }()
	started := time.Now().UTC().Add(-10 * time.Second)
	userPlane, err = pfcpclient.New(pfcpclient.Config{
		Listen: netip.AddrPortFrom(pgwcPFCPAddress, 0), Advertise: pgwcPFCPAddress,
		Remote: pgwuServer.LocalAddr(), StartedAt: started, EnterpriseID: enterpriseID, Transport: pfcpConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	pfcpListen := userPlane.LocalAddr()
	startPFCP(userPlane)
	operation, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	if err := userPlane.Associate(operation); err != nil {
		t.Fatal(err)
	}

	sgwAddress := netip.MustParseAddr("127.125.0.2")
	pgwcS5Address := netip.MustParseAddr("127.125.0.1")
	peerHarness := &fakeSGWBearerPeer{}
	peer, err := gtptransport.Listen(netip.AddrPortFrom(sgwAddress, 2123), peerHarness.handle, gtpConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	go func() { _ = peer.Serve(ctx) }()

	walPath := filepath.Join(t.TempDir(), "pgwc-restart.wal")
	identity := []byte("pgwc-restart-dedicated-v1")
	stateWAL, recovered, err := session.OpenWAL(walPath, 1<<20, identity, 50)
	if err != nil {
		t.Fatal(err)
	}
	if err := stateWAL.Start(); err != nil {
		t.Fatal(err)
	}
	controlStore := session.NewStoreWithPersister(100, stateWAL)
	pool, err := ipam.New(netip.MustParsePrefix("10.90.0.0/24"), netip.MustParseAddr("10.90.0.1"), 100)
	if err != nil {
		t.Fatal(err)
	}
	control, err = New(Config{
		S5Listen: netip.AddrPortFrom(pgwcS5Address, 0), S5Advertise: pgwcS5Address,
		PGWUUserIP: pgwuUserAddress, PGWUQCI1UserIP: pgwuQCI1Address, AllowedSGW: []netip.Addr{sgwAddress}, APN: "lodestartest",
		APNAMBRUplinkBPS: 1_000_000_000, APNAMBRDownlinkBPS: 1_000_000_000,
		ProcedureTimeout: time.Second, SubscriberSalt: []byte("restart-test"), Transport: gtpConfig,
	}, controlStore, pool, userPlane)
	if err != nil {
		t.Fatal(err)
	}
	s5Listen := control.S5Addr()
	startGateway(control)
	createResponse, err := peer.Do(operation, control.S5Addr(), makeCreateRequest(t, sgwAddress))
	if err != nil || responseCause(t, createResponse) != gtpv2.CauseRequestAccepted {
		t.Fatalf("Create Session response=%#v error=%v", createResponse, err)
	}
	controlIE, ok := createResponse.Find(gtpv2.IEFTEID, 1)
	if !ok {
		t.Fatal("Create Session response omitted PGW control F-TEID")
	}
	pgwControl, err := controlIE.FTEID()
	if err != nil {
		t.Fatal(err)
	}
	peerHarness.setPGWControlTEID(pgwControl.TEID)
	beforeRestart := control.Sessions()[0]
	tft := gtpv2.TrafficFlowTemplate{
		Operation: gtpv2.TFTOperationCreate,
		Filters: []gtpv2.PacketFilter{{
			ID: 1, Direction: gtpv2.TFTDirectionBidirectional, Precedence: 10,
			Components: []gtpv2.PacketFilterComponent{
				{Type: gtpv2.TFTComponentProtocol, Value: []byte{17}},
				{Type: gtpv2.TFTComponentSingleLocalPort, Value: []byte{0x13, 0xc4}},
				{Type: gtpv2.TFTComponentSingleRemotePort, Value: []byte{0x13, 0xc5}},
			},
		}},
	}
	dedicated, err := control.CreateDedicatedBearer(operation, beforeRestart.ID, DedicatedBearerPlan{
		EBI: 6, QCI: 1, ARP: 2, UplinkMBR: 8_000_000, DownlinkMBR: 12_000_000,
		UplinkGBR: 3_000_000, DownlinkGBR: 4_000_000, TFT: tft,
	})
	if err != nil {
		t.Fatal(err)
	}
	beforeRestart = control.Sessions()[0]
	oldUPSEID := beforeRestart.PFCPUserSEID
	if len(beforeRestart.DedicatedBearers) != 1 || beforeRestart.DedicatedBearers[dedicated.EBI].PGWUser.IP != pgwuQCI1Address ||
		len(pgwuStore.Snapshot()[0].DedicatedBearers) != 1 || pgwuStore.Snapshot()[0].DedicatedBearers[0].Local.IP != pgwuQCI1Address {
		t.Fatal("dedicated bearer was not durable before PGW-C restart")
	}

	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	if err := userPlane.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stateWAL.Close(); err != nil {
		t.Fatal(err)
	}
	control, userPlane, stateWAL = nil, nil, nil

	stateWAL, recovered, err = session.OpenWAL(walPath, 1<<20, identity, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 1 || len(recovered[0].DedicatedBearers) != 1 {
		t.Fatalf("PGW-C restart recovered %#v", recovered)
	}
	controlStore = session.NewStoreWithPersister(100, stateWAL)
	if err := controlStore.Restore(recovered); err != nil {
		t.Fatal(err)
	}
	pool, err = ipam.New(netip.MustParsePrefix("10.90.0.0/24"), netip.MustParseAddr("10.90.0.1"), 100)
	if err != nil {
		t.Fatal(err)
	}
	leases := make([]ipam.Lease, 0, len(recovered))
	for _, current := range recovered {
		leases = append(leases, ipam.Lease{Owner: leaseOwner(current.SubscriberKey, strings.ToLower(current.APN)), Addr: current.UEIPv4})
	}
	if err := pool.Restore(leases); err != nil {
		t.Fatal(err)
	}
	if err := stateWAL.Start(); err != nil {
		t.Fatal(err)
	}
	userPlane, err = pfcpclient.New(pfcpclient.Config{
		Listen: pfcpListen, Advertise: pgwcPFCPAddress, Remote: pgwuServer.LocalAddr(),
		StartedAt: started.Add(5 * time.Second), EnterpriseID: enterpriseID, Transport: pfcpConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	startPFCP(userPlane)
	if err := userPlane.Associate(operation); err != nil {
		t.Fatal(err)
	}
	control, err = New(Config{
		S5Listen: s5Listen, S5Advertise: pgwcS5Address,
		PGWUUserIP: pgwuUserAddress, PGWUQCI1UserIP: pgwuQCI1Address, AllowedSGW: []netip.Addr{sgwAddress}, APN: "lodestartest",
		APNAMBRUplinkBPS: 1_000_000_000, APNAMBRDownlinkBPS: 1_000_000_000,
		ProcedureTimeout: time.Second, SubscriberSalt: []byte("restart-test"), Transport: gtpConfig,
	}, controlStore, pool, userPlane)
	if err != nil {
		t.Fatal(err)
	}
	startGateway(control)
	if reconciled, err := control.ReconcileAll(operation); err != nil || reconciled != 1 {
		t.Fatalf("PGW-C restart reconciliation = %d, %v", reconciled, err)
	}
	if err := userPlane.CompleteReconciliation(operation); err != nil {
		t.Fatal(err)
	}
	afterRestart := control.Sessions()[0]
	if afterRestart.ID != beforeRestart.ID || afterRestart.UEIPv4 != beforeRestart.UEIPv4 ||
		afterRestart.PGWControl != beforeRestart.PGWControl || afterRestart.PGWUser != beforeRestart.PGWUser ||
		afterRestart.PFCPUserSEID != oldUPSEID || len(afterRestart.DedicatedBearers) != 1 {
		t.Fatalf("PGW-C restart changed stable session identity: before=%#v after=%#v", beforeRestart, afterRestart)
	}
	pgwuRecovered := pgwuStore.Snapshot()
	if len(pgwuRecovered) != 1 || pgwuRecovered[0].UPSEID != oldUPSEID || len(pgwuRecovered[0].DedicatedBearers) != 1 ||
		pgwuRecovered[0].DedicatedBearers[0].QERID != dedicated.Rules.QER {
		t.Fatalf("PGW-U state after PGW-C replay = %#v", pgwuRecovered)
	}
	if _, err := control.UpdateDedicatedBearer(operation, afterRestart.ID, dedicated.EBI, DedicatedBearerQoS{
		QCI: 1, ARP: 3, UplinkMBR: 10_000_000, DownlinkMBR: 14_000_000,
		UplinkGBR: 3_000_000, DownlinkGBR: 4_000_000,
	}); err != nil {
		t.Fatalf("post-restart Update Bearer: %v", err)
	}
	if err := control.DeleteDedicatedBearer(operation, afterRestart.ID, dedicated.EBI); err != nil {
		t.Fatalf("post-restart Delete Bearer: %v", err)
	}
	ebiIE, _ := gtpv2.NewEBIIE(afterRestart.EBI, 0)
	sender, _ := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8SGWGTPC, TEID: afterRestart.SGWControl.TEID, IPv4: afterRestart.SGWControl.IP,
	})
	deleteResponse, err := peer.Do(operation, control.S5Addr(), gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteSessionRequest, TEID: afterRestart.PGWControl.TEID},
		IEs:    []gtpv2.IE{ebiIE, sender},
	})
	if err != nil || responseCause(t, deleteResponse) != gtpv2.CauseRequestAccepted {
		t.Fatalf("post-restart Delete Session response=%#v error=%v", deleteResponse, err)
	}
	if len(control.Sessions()) != 0 || pool.Used() != 0 || pgwuStore.Count() != 0 {
		t.Fatal("post-restart teardown leaked PGW-C, IPAM, or PGW-U state")
	}
}

func TestUnknownAPNRejectedWithoutAllocating(t *testing.T) {
	transport := gtptransport.DefaultConfig()
	pool, _ := ipam.New(netip.MustParsePrefix("10.90.0.0/24"), netip.MustParseAddr("10.90.0.1"), 10)
	gateway, err := New(Config{
		S5Listen: netip.MustParseAddrPort("127.0.0.1:0"), S5Advertise: netip.MustParseAddr("10.200.0.20"),
		PGWUUserIP: netip.MustParseAddr("10.200.0.21"), AllowedSGW: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		APN: "lodestartest", ProcedureTimeout: time.Second, Transport: transport,
	}, session.NewStore(), pool, &fakeUserPlane{})
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	request := makeCreateRequest(t, netip.MustParseAddr("127.0.0.1"))
	wrongAPN, _ := gtpv2.NewAPNIE("internet")
	request.IEs = gtpv2.UpsertIE(request.IEs, wrongAPN)
	response := gateway.createSession(context.Background(), netip.MustParseAddrPort("127.0.0.1:2123"), request)
	if responseCause(t, *response) != gtpv2.CauseMissingOrUnknownAPN || pool.Used() != 0 {
		t.Fatalf("unknown APN response=%#v leases=%d", response, pool.Used())
	}
}

func TestAdmissionDrainRejectsOnlyNewPGWSessions(t *testing.T) {
	transport := gtptransport.DefaultConfig()
	pool, _ := ipam.New(netip.MustParsePrefix("10.90.0.0/24"), netip.MustParseAddr("10.90.0.1"), 10)
	draining := true
	userPlane := &fakeUserPlane{}
	control, err := New(Config{
		S5Listen: netip.MustParseAddrPort("127.0.0.1:0"), S5Advertise: netip.MustParseAddr("10.200.0.20"),
		PGWUUserIP: netip.MustParseAddr("10.200.0.21"), AllowedSGW: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		APN: "lodestartest", ProcedureTimeout: time.Second, Transport: transport,
		AllowNewSessions: func() bool { return !draining },
	}, session.NewStore(), pool, userPlane)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	peer := netip.MustParseAddrPort("127.0.0.1:2123")
	request := makeCreateRequest(t, peer.Addr())
	response := control.createSession(context.Background(), peer, request)
	if responseCause(t, *response) != gtpv2.CauseNoResourcesAvailable || pool.Used() != 0 || len(userPlane.established) != 0 {
		t.Fatalf("drained create response=%#v leases=%d established=%d", response, pool.Used(), len(userPlane.established))
	}
	draining = false
	response = control.createSession(context.Background(), peer, request)
	if responseCause(t, *response) != gtpv2.CauseRequestAccepted || pool.Used() != 1 || len(control.Sessions()) != 1 {
		t.Fatalf("ready create response=%#v leases=%d sessions=%d", response, pool.Used(), len(control.Sessions()))
	}
	draining = true
	second := makeCreateRequest(t, peer.Addr())
	secondIMSI, _ := gtpv2.NewIMSIIE("001010123456780")
	second.IEs = gtpv2.UpsertIE(second.IEs, secondIMSI)
	response = control.createSession(context.Background(), peer, second)
	if responseCause(t, *response) != gtpv2.CauseNoResourcesAvailable || pool.Used() != 1 || len(control.Sessions()) != 1 {
		t.Fatalf("second drained create changed existing state: response=%#v leases=%d sessions=%d", response, pool.Used(), len(control.Sessions()))
	}
	counters := control.Counters()
	if counters.CreateAccepted != 1 || counters.CreateAdmissionRejected != 2 || counters.CreateRejected != 2 {
		t.Fatalf("admission counters = %#v", counters)
	}
}

func TestMultiAPNProfilesAllocateIndependentPoolsAndPCO(t *testing.T) {
	transport := gtptransport.DefaultConfig()
	internetPool, err := ipam.New(netip.MustParsePrefix("10.45.0.0/24"), netip.MustParseAddr("10.45.0.1"), 10)
	if err != nil {
		t.Fatal(err)
	}
	imsPool, err := ipam.New(netip.MustParsePrefix("10.46.0.0/24"), netip.MustParseAddr("10.46.0.1"), 10)
	if err != nil {
		t.Fatal(err)
	}
	userPlane := &fakeUserPlane{}
	gateway, err := New(Config{
		S5Listen: netip.MustParseAddrPort("127.0.0.1:0"), S5Advertise: netip.MustParseAddr("10.200.0.20"),
		PGWUUserIP: netip.MustParseAddr("10.200.0.21"), AllowedSGW: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		APNProfiles: []APNProfile{
			{
				APN: "internet", Pool: internetPool,
				DNSIPv4:     []netip.Addr{netip.MustParseAddr("10.250.70.1"), netip.MustParseAddr("10.250.70.2")},
				IPv4LinkMTU: 1400, APNAMBRUplinkBPS: 1_000_000_000, APNAMBRDownlinkBPS: 2_000_000_000,
			},
			{
				APN: "ims", Pool: imsPool,
				DNSIPv4:     []netip.Addr{netip.MustParseAddr("10.250.70.1"), netip.MustParseAddr("10.250.70.2")},
				PCSCFIPv4:   []netip.Addr{netip.MustParseAddr("10.250.70.3")},
				IPv4LinkMTU: 1400, APNAMBRUplinkBPS: 100_000_000, APNAMBRDownlinkBPS: 100_000_000,
			},
		},
		ProcedureTimeout: time.Second, SubscriberSalt: []byte("test-salt"), Transport: transport,
	}, session.NewStoreWithLimit(100), nil, userPlane)
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	peer := netip.MustParseAddrPort("127.0.0.1:2123")

	internetResponse := gateway.createSession(context.Background(), peer,
		makeCreateRequestForAPN(t, peer.Addr(), "internet.mnc074.mcc901.gprs", 5, 0x2001, 0x3001))
	if responseCause(t, *internetResponse) != gtpv2.CauseRequestAccepted {
		t.Fatalf("internet Create Session response = %#v", internetResponse)
	}
	if got := responsePAA(t, *internetResponse); !internetPool.Prefix().Contains(got) {
		t.Fatalf("internet PAA %s is outside %s", got, internetPool.Prefix())
	}
	if values := responsePCOIPv4(t, *internetResponse, gtpv2.PCOContainerPCSCFIPv4); len(values) != 0 {
		t.Fatalf("internet APN leaked IMS P-CSCF addresses: %v", values)
	}

	imsResponse := gateway.createSession(context.Background(), peer,
		makeCreateRequestForAPN(t, peer.Addr(), "ims.mnc074.mcc901.gprs", 6, 0x2002, 0x3002))
	if responseCause(t, *imsResponse) != gtpv2.CauseRequestAccepted {
		t.Fatalf("IMS Create Session response = %#v", imsResponse)
	}
	if got := responsePAA(t, *imsResponse); !imsPool.Prefix().Contains(got) {
		t.Fatalf("IMS PAA %s is outside %s", got, imsPool.Prefix())
	}
	if values := responsePCOIPv4(t, *imsResponse, gtpv2.PCOContainerPCSCFIPv4); len(values) != 1 || values[0] != netip.MustParseAddr("10.250.70.3") {
		t.Fatalf("IMS P-CSCF response = %v", values)
	}
	sessions := gateway.Sessions()
	if len(sessions) != 2 || sessions[0].APN == sessions[1].APN {
		t.Fatalf("independent internet and IMS sessions were not retained: %#v", sessions)
	}
	var internetSession session.Session
	for _, current := range sessions {
		if current.APN == "internet" {
			internetSession = current
		}
	}
	if allocated, err := gateway.allocateDedicatedEBI(internetSession, 0); err != nil || allocated != 7 {
		t.Fatalf("dedicated EBI with internet/IMS defaults = %d, %v; want 7", allocated, err)
	}
	if _, err := gateway.allocateDedicatedEBI(internetSession, 6); err == nil {
		t.Fatal("dedicated bearer reused IMS default EBI 6")
	}
	if internetPool.Used() != 1 || imsPool.Used() != 1 {
		t.Fatalf("multi-APN lease usage internet=%d IMS=%d", internetPool.Used(), imsPool.Used())
	}
	if established, _, _ := userPlane.counts(); established != 2 {
		t.Fatalf("PGW-U establishment count = %d, want 2", established)
	}

	unknownResponse := gateway.createSession(context.Background(), peer,
		makeCreateRequestForAPN(t, peer.Addr(), "unknown.mnc074.mcc901.gprs", 7, 0x2003, 0x3003))
	if responseCause(t, *unknownResponse) != gtpv2.CauseMissingOrUnknownAPN || internetPool.Used() != 1 || imsPool.Used() != 1 {
		t.Fatalf("unknown APN response=%#v internet leases=%d IMS leases=%d", unknownResponse, internetPool.Used(), imsPool.Used())
	}
}

func TestCreateSessionReplacesCollidingPDN(t *testing.T) {
	transport := gtptransport.DefaultConfig()
	pool, err := ipam.New(netip.MustParsePrefix("10.90.0.0/24"), netip.MustParseAddr("10.90.0.1"), 10)
	if err != nil {
		t.Fatal(err)
	}
	userPlane := &fakeUserPlane{}
	gateway, err := New(Config{
		S5Listen: netip.MustParseAddrPort("127.0.0.1:0"), S5Advertise: netip.MustParseAddr("10.200.0.20"),
		PGWUUserIP: netip.MustParseAddr("10.200.0.21"), AllowedSGW: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		APN: "lodestartest", ProcedureTimeout: time.Second, SubscriberSalt: []byte("test-salt"), Transport: transport,
	}, session.NewStore(), pool, userPlane)
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	peer := netip.MustParseAddrPort("127.0.0.1:2123")

	first := makeCreateRequest(t, peer.Addr())
	firstResponse := gateway.createSession(context.Background(), peer, first)
	if responseCause(t, *firstResponse) != gtpv2.CauseRequestAccepted {
		t.Fatalf("first create response = %#v", firstResponse)
	}
	firstSession := gateway.Sessions()[0]

	replacement := makeCreateRequest(t, peer.Addr())
	replacementControl, _ := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8SGWGTPC, TEID: 0x2011, IPv4: peer.Addr(),
	})
	replacement.IEs = gtpv2.UpsertIE(replacement.IEs, replacementControl)
	bearerIE, _ := replacement.Find(gtpv2.IEBearerContext, 0)
	children, _ := bearerIE.Children()
	replacementUser, _ := gtpv2.NewFTEIDIE(2, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8SGWGTPU, TEID: 0x3011, IPv4: netip.MustParseAddr("10.200.0.11"),
	})
	children = gtpv2.UpsertIE(children, replacementUser)
	replacementBearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, children...)
	replacement.IEs = gtpv2.UpsertIE(replacement.IEs, replacementBearer)

	replacementResponse := gateway.createSession(context.Background(), peer, replacement)
	if responseCause(t, *replacementResponse) != gtpv2.CauseRequestAccepted {
		t.Fatalf("replacement create response = %#v", replacementResponse)
	}
	sessions := gateway.Sessions()
	established, _, deleted := userPlane.counts()
	if len(sessions) != 1 || sessions[0].ID == firstSession.ID || sessions[0].SGWControl.TEID != 0x2011 || sessions[0].SGWUser.TEID != 0x3011 {
		t.Fatalf("stale PGW-C session was not replaced: %#v", sessions)
	}
	if pool.Used() != 1 || established != 2 || deleted != 1 {
		t.Fatalf("replacement leaked state: leases=%d established=%d deleted=%d", pool.Used(), established, deleted)
	}
	if counters := gateway.Counters(); counters.CreateAccepted != 2 || counters.CreateReplacements != 1 || counters.CreateRejected != 0 {
		t.Fatalf("unexpected replacement counters: %#v", counters)
	}
}

func makeCreateRequest(t *testing.T, controlIP netip.Addr) gtpv2.Message {
	t.Helper()
	imsi, _ := gtpv2.NewIMSIIE("001010123456789")
	apn, _ := gtpv2.NewAPNIE("lodestartest.mnc074.mcc901.gprs")
	pdnType, _ := gtpv2.NewPDNTypeIE(0, gtpv2.PDNTypeIPv4)
	control, _ := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8SGWGTPC, TEID: 0x2001, IPv4: controlIP,
	})
	ebi, _ := gtpv2.NewEBIIE(5, 0)
	qos, _ := gtpv2.NewBearerQoSIEWithBitrates(0, 9, 8, 800_000_000, 1_900_000_000, 0, 0)
	user, _ := gtpv2.NewFTEIDIE(2, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8SGWGTPU, TEID: 0x3001, IPv4: netip.MustParseAddr("10.200.0.11"),
	})
	bearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebi, qos, user)
	ambr, _ := gtpv2.NewAMBRIE(0, 900_000_000, 1_800_000_000)
	ipcp := []byte{
		gtpv2.IPCPConfigureRequest, 0x37, 0, 16,
		gtpv2.IPCPOptionPrimaryDNS, 6, 0, 0, 0, 0,
		gtpv2.IPCPOptionSecondDNS, 6, 0, 0, 0, 0,
	}
	pco, _ := gtpv2.NewPCOIE(0, gtpv2.PCO{Extension: true, Containers: []gtpv2.PCOContainer{
		{ID: gtpv2.PCOContainerIPCP, Contents: ipcp},
		{ID: gtpv2.PCOContainerDNSServerIPv4},
		{ID: gtpv2.PCOContainerIPv4LinkMTU},
	}})
	return gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateSessionRequest},
		IEs:    []gtpv2.IE{imsi, apn, pdnType, control, ambr, pco, bearer},
	}
}

func makeCreateRequestForAPN(t *testing.T, controlIP netip.Addr, apn string, ebi uint8, controlTEID, userTEID uint32) gtpv2.Message {
	t.Helper()
	request := makeCreateRequest(t, controlIP)
	apnIE, _ := gtpv2.NewAPNIE(apn)
	controlIE, _ := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8SGWGTPC, TEID: controlTEID, IPv4: controlIP,
	})
	request.IEs = gtpv2.UpsertIE(request.IEs, apnIE)
	request.IEs = gtpv2.UpsertIE(request.IEs, controlIE)
	bearerIE, _ := request.Find(gtpv2.IEBearerContext, 0)
	children, _ := bearerIE.Children()
	ebiIE, _ := gtpv2.NewEBIIE(ebi, 0)
	userIE, _ := gtpv2.NewFTEIDIE(2, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8SGWGTPU, TEID: userTEID, IPv4: netip.MustParseAddr("10.200.0.11"),
	})
	children = gtpv2.UpsertIE(children, ebiIE)
	children = gtpv2.UpsertIE(children, userIE)
	bearerIE, _ = gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, children...)
	request.IEs = gtpv2.UpsertIE(request.IEs, bearerIE)
	pcoIE, _ := request.Find(gtpv2.IEPCO, 0)
	pco, _ := pcoIE.PCO()
	pco.Containers = append(pco.Containers, gtpv2.PCOContainer{ID: gtpv2.PCOContainerPCSCFIPv4})
	pcoIE, _ = gtpv2.NewPCOIE(0, pco)
	request.IEs = gtpv2.UpsertIE(request.IEs, pcoIE)
	return request
}

func responsePAA(t *testing.T, response gtpv2.Message) netip.Addr {
	t.Helper()
	paaIE, ok := response.Find(gtpv2.IEPAA, 0)
	if !ok {
		t.Fatal("response omitted PAA")
	}
	address, err := paaIE.PAAIPv4()
	if err != nil {
		t.Fatal(err)
	}
	return address
}

func responsePCOIPv4(t *testing.T, response gtpv2.Message, containerID uint16) []netip.Addr {
	t.Helper()
	pcoIE, ok := response.Find(gtpv2.IEPCO, 0)
	if !ok {
		t.Fatal("response omitted PCO")
	}
	pco, err := pcoIE.PCO()
	if err != nil {
		t.Fatal(err)
	}
	addresses := make([]netip.Addr, 0, 2)
	for _, container := range pco.Containers {
		if container.ID != containerID {
			continue
		}
		if len(container.Contents) != 4 {
			t.Fatalf("PCO container %#x has %d bytes", containerID, len(container.Contents))
		}
		addresses = append(addresses, netip.AddrFrom4([4]byte(container.Contents)))
	}
	return addresses
}

func responseCause(t *testing.T, response gtpv2.Message) uint8 {
	t.Helper()
	causeIE, ok := response.Find(gtpv2.IECause, 0)
	if !ok {
		t.Fatal("response omitted Cause IE")
	}
	cause, err := causeIE.Cause()
	if err != nil {
		t.Fatal(err)
	}
	return cause.Value
}
