package epc

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	gtptransport "github.com/lodestarnetworks/cups/internal/gtpv2/transport"
	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	pgwcgateway "github.com/lodestarnetworks/cups/internal/pgwc/gateway"
	"github.com/lodestarnetworks/cups/internal/pgwc/ipam"
	pgwcpfcp "github.com/lodestarnetworks/cups/internal/pgwc/pfcpclient"
	pgwcsession "github.com/lodestarnetworks/cups/internal/pgwc/session"
	pgwupfcp "github.com/lodestarnetworks/cups/internal/pgwu/pfcpserver"
	pgwurules "github.com/lodestarnetworks/cups/internal/pgwu/rules"
	sgwcgateway "github.com/lodestarnetworks/cups/internal/sgwc/gateway"
	sgwcpfcp "github.com/lodestarnetworks/cups/internal/sgwc/pfcpclient"
	sgwcsession "github.com/lodestarnetworks/cups/internal/sgwc/session"
	sgwupfcp "github.com/lodestarnetworks/cups/internal/sgwu/pfcpserver"
	sgwurules "github.com/lodestarnetworks/cups/internal/sgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

type cupsMME struct {
	mu             sync.Mutex
	sgwControlTEID uint32
	enodebIP       netip.Addr
	created        int
	updated        int
	deleted        int
	rejectDelete   bool
}

func (m *cupsMME) setSGWControlTEID(teid uint32) {
	m.mu.Lock()
	m.sgwControlTEID = teid
	m.mu.Unlock()
}

func (m *cupsMME) counts() (int, int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.created, m.updated, m.deleted
}

func (m *cupsMME) rejectNextDelete() {
	m.mu.Lock()
	m.rejectDelete = true
	m.mu.Unlock()
}

func (m *cupsMME) handle(_ context.Context, _ netip.AddrPort, request gtpv2.Message) (*gtpv2.Message, error) {
	m.mu.Lock()
	sgwControlTEID := m.sgwControlTEID
	m.mu.Unlock()
	if sgwControlTEID == 0 {
		return nil, fmt.Errorf("CUPS MME: SGW control TEID is unknown")
	}
	switch request.Header.MessageType {
	case gtpv2.MessageCreateBearerRequest:
		children, err := bearerChildren(request)
		if err != nil {
			return nil, err
		}
		ebiIE, ebiOK := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
		sgwAccessIE, accessOK := gtpv2.FindIE(children, gtpv2.IEFTEID, 0)
		if !ebiOK || !accessOK {
			return nil, fmt.Errorf("CUPS MME: Create Bearer omitted EBI or SGW S1-U F-TEID")
		}
		ebi, err := ebiIE.EBI()
		if err != nil {
			return nil, err
		}
		sgwAccess, err := sgwAccessIE.FTEID()
		if err != nil || sgwAccess.InterfaceType != gtpv2.InterfaceS1USGWGTPU {
			return nil, fmt.Errorf("CUPS MME: invalid SGW S1-U F-TEID")
		}
		enodeb, _ := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
			InterfaceType: gtpv2.InterfaceS1UENodeBGTPU, TEID: 0x6200 + uint32(ebi), IPv4: m.enodebIP,
		})
		bearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), enodeb)
		m.mu.Lock()
		m.created++
		m.mu.Unlock()
		return &gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateBearerResponse, TEID: sgwControlTEID},
			IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), bearer},
		}, nil
	case gtpv2.MessageUpdateBearerRequest:
		children, err := bearerChildren(request)
		if err != nil {
			return nil, err
		}
		ebiIE, ebiOK := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
		qosIE, qosOK := gtpv2.FindIE(children, gtpv2.IEBearerQoS, 0)
		if !ebiOK || !qosOK {
			return nil, fmt.Errorf("CUPS MME: Update Bearer omitted EBI or QoS")
		}
		qos, err := qosIE.BearerQoSDetails()
		if err != nil || qos.QCI != 2 || qos.UplinkMBR != 10_000_000 || qos.DownlinkMBR != 14_000_000 {
			return nil, fmt.Errorf("CUPS MME: unexpected updated QoS")
		}
		bearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0))
		m.mu.Lock()
		m.updated++
		m.mu.Unlock()
		return &gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageUpdateBearerResponse, TEID: sgwControlTEID},
			IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), bearer},
		}, nil
	case gtpv2.MessageDeleteBearerRequest:
		ebiIE, ok := request.Find(gtpv2.IEEBI, 1)
		if !ok {
			return nil, fmt.Errorf("CUPS MME: Delete Bearer omitted EBI")
		}
		m.mu.Lock()
		reject := m.rejectDelete
		m.rejectDelete = false
		if !reject {
			m.deleted++
		}
		m.mu.Unlock()
		cause := uint8(gtpv2.CauseRequestAccepted)
		if reject {
			cause = gtpv2.CauseSystemFailure
		}
		bearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, gtpv2.NewCauseIE(cause, 0))
		return &gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteBearerResponse, TEID: sgwControlTEID},
			IEs:    []gtpv2.IE{gtpv2.NewCauseIE(cause, 0), bearer},
		}, nil
	default:
		return nil, fmt.Errorf("CUPS MME: unsupported request %d", request.Header.MessageType)
	}
}

func TestFullSGWCPGWCSignallingAndDedicatedBearerRules(t *testing.T) {
	const enterpriseID uint16 = 65000
	addresses := struct {
		mme, s11, s5, pgwc, sgwcPFCP, sgwuPFCP, pgwcPFCP, pgwuPFCP netip.Addr
		access, enodeb, core, pgwuUser                             netip.Addr
	}{
		mme: netip.MustParseAddr("127.111.0.1"), s11: netip.MustParseAddr("127.111.0.2"),
		s5: netip.MustParseAddr("127.112.0.1"), pgwc: netip.MustParseAddr("127.112.0.2"),
		sgwcPFCP: netip.MustParseAddr("127.113.0.1"), sgwuPFCP: netip.MustParseAddr("127.113.0.2"),
		pgwcPFCP: netip.MustParseAddr("127.114.0.1"), pgwuPFCP: netip.MustParseAddr("127.114.0.2"),
		access: netip.MustParseAddr("127.115.0.1"), enodeb: netip.MustParseAddr("127.115.0.2"),
		core: netip.MustParseAddr("127.116.0.1"), pgwuUser: netip.MustParseAddr("127.117.0.1"),
	}
	gtpConfig := gtptransport.DefaultConfig()
	gtpConfig.RetransmitTimeout = 50 * time.Millisecond
	gtpConfig.MaxRetransmits = 2
	pfcpConfig := pfcptransport.DefaultConfig()
	pfcpConfig.RetransmitTimeout = 50 * time.Millisecond
	pfcpConfig.MaxRetransmits = 2

	ctx, cancel := context.WithCancel(context.Background())
	var closers []func()
	t.Cleanup(func() {
		cancel()
		for index := len(closers) - 1; index >= 0; index-- {
			closers[index]()
		}
	})
	start := func(serve func(context.Context) error) { go func() { _ = serve(ctx) }() }

	sgwuStore := sgwurules.NewStore()
	sgwuServer, err := sgwupfcp.New(sgwupfcp.Config{
		Listen: netip.AddrPortFrom(addresses.sgwuPFCP, 0), Advertise: addresses.sgwuPFCP,
		AccessUserIP: addresses.access, CoreUserIP: addresses.core, AllowedCP: []netip.Addr{addresses.sgwcPFCP},
		EnterpriseID: enterpriseID, Transport: pfcpConfig,
	}, sgwuStore)
	if err != nil {
		t.Fatal(err)
	}
	closers = append(closers, func() { _ = sgwuServer.Close() })
	start(sgwuServer.Serve)
	sgwcPFCP, err := sgwcpfcp.New(sgwcpfcp.Config{
		Listen: netip.AddrPortFrom(addresses.sgwcPFCP, 0), Advertise: addresses.sgwcPFCP,
		Remote: sgwuServer.LocalAddr(), EnterpriseID: enterpriseID, Transport: pfcpConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	closers = append(closers, func() { _ = sgwcPFCP.Close() })
	start(sgwcPFCP.Serve)

	pgwuStore := pgwurules.NewStore()
	pgwuServer, err := pgwupfcp.New(pgwupfcp.Config{
		Listen: netip.AddrPortFrom(addresses.pgwuPFCP, 0), Advertise: addresses.pgwuPFCP,
		UserIP: addresses.pgwuUser, AllowedCP: []netip.Addr{addresses.pgwcPFCP}, EnterpriseID: enterpriseID, Transport: pfcpConfig,
	}, pgwuStore)
	if err != nil {
		t.Fatal(err)
	}
	closers = append(closers, func() { _ = pgwuServer.Close() })
	start(pgwuServer.Serve)
	pgwcPFCP, err := pgwcpfcp.New(pgwcpfcp.Config{
		Listen: netip.AddrPortFrom(addresses.pgwcPFCP, 0), Advertise: addresses.pgwcPFCP,
		Remote: pgwuServer.LocalAddr(), EnterpriseID: enterpriseID, Transport: pfcpConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	closers = append(closers, func() { _ = pgwcPFCP.Close() })
	start(pgwcPFCP.Serve)

	operation, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	if err := sgwcPFCP.Associate(operation); err != nil {
		t.Fatalf("associate SGW-U: %v", err)
	}
	if err := pgwcPFCP.Associate(operation); err != nil {
		t.Fatalf("associate PGW-U: %v", err)
	}

	pool, err := ipam.New(netip.MustParsePrefix("10.92.0.0/24"), netip.MustParseAddr("10.92.0.1"), 100)
	if err != nil {
		t.Fatal(err)
	}
	pgwc, err := pgwcgateway.New(pgwcgateway.Config{
		S5Listen: netip.AddrPortFrom(addresses.pgwc, 2123), S5Advertise: addresses.pgwc,
		PGWUUserIP: addresses.pgwuUser, AllowedSGW: []netip.Addr{addresses.s5}, APN: "lodestartest",
		APNAMBRUplinkBPS: 1_000_000_000, APNAMBRDownlinkBPS: 1_000_000_000,
		ProcedureTimeout: time.Second, SubscriberSalt: []byte("full-cups-test"), Transport: gtpConfig,
	}, pgwcsession.NewStore(), pool, pgwcPFCP)
	if err != nil {
		t.Fatal(err)
	}
	closers = append(closers, func() { _ = pgwc.Close() })
	start(pgwc.Serve)

	sgwc, err := sgwcgateway.New(sgwcgateway.Config{
		S11Listen: netip.AddrPortFrom(addresses.s11, 2123), S11Advertise: addresses.s11,
		S5Listen: netip.AddrPortFrom(addresses.s5, 2123), S5Advertise: addresses.s5,
		PGWControl: pgwc.S5Addr(), SGWUAccessIP: addresses.access, SGWUCoreIP: addresses.core,
		AllowedMME: []netip.Addr{addresses.mme}, ProcedureTimeout: time.Second,
		SubscriberSalt: []byte("full-cups-test"), Transport: gtpConfig,
	}, sgwcsession.NewStore(), sgwcPFCP)
	if err != nil {
		t.Fatal(err)
	}
	closers = append(closers, func() { _ = sgwc.Close() })
	start(sgwc.Serve)

	mmeHarness := &cupsMME{enodebIP: addresses.enodeb}
	mme, err := gtptransport.Listen(netip.AddrPortFrom(addresses.mme, 2123), mmeHarness.handle, gtpConfig)
	if err != nil {
		t.Fatal(err)
	}
	closers = append(closers, func() { _ = mme.Close() })
	start(mme.Serve)
	labConfig := Config{
		MMEControl: mme.LocalAddr(), SGWS11: sgwc.S11Addr(), ENBUser: netip.AddrPortFrom(addresses.enodeb, 2152),
		IMSI: "001010123456789", APN: "lodestartest", EBI: 5,
	}
	create, err := createRequest(labConfig, 0x4101)
	if err != nil {
		t.Fatal(err)
	}
	createResponse, err := mme.Do(operation, sgwc.S11Addr(), create)
	if err != nil || accepted(createResponse) != nil {
		t.Fatalf("full CUPS Create Session response=%#v error=%v", createResponse, err)
	}
	sgwControl, err := findFTEID(createResponse.IEs, 0)
	if err != nil {
		t.Fatal(err)
	}
	mmeHarness.setSGWControlTEID(sgwControl.TEID)
	modify, err := modifyRequest(labConfig, sgwControl.TEID, 0x5101)
	if err != nil {
		t.Fatal(err)
	}
	modifyResponse, err := mme.Do(operation, sgwc.S11Addr(), modify)
	if err != nil || accepted(modifyResponse) != nil {
		t.Fatalf("full CUPS Modify Bearer response=%#v error=%v", modifyResponse, err)
	}
	if len(sgwc.Sessions()) != 1 || len(pgwc.Sessions()) != 1 || len(sgwuStore.Snapshot()) != 1 || len(pgwuStore.Snapshot()) != 1 {
		t.Fatalf("default bearer did not span all four CUPS nodes")
	}

	pgwcSession := pgwc.Sessions()[0]
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
	dedicated, err := pgwc.CreateDedicatedBearer(operation, pgwcSession.ID, pgwcgateway.DedicatedBearerPlan{
		EBI: 6, QCI: 1, ARP: 2, UplinkMBR: 8_000_000, DownlinkMBR: 12_000_000,
		UplinkGBR: 3_000_000, DownlinkGBR: 4_000_000, TFT: tft,
	})
	if err != nil {
		t.Fatal(err)
	}
	sgwcSession := sgwc.Sessions()[0]
	if _, ok := sgwcSession.Bearers[dedicated.EBI]; !ok || len(pgwc.Sessions()[0].DedicatedBearers) != 1 {
		t.Fatalf("dedicated bearer did not commit in both control planes")
	}
	sgwuRules := sgwuStore.Snapshot()[0]
	pgwuRules := pgwuStore.Snapshot()[0]
	if len(sgwuRules.PDRs) != 4 || len(sgwuRules.QERs) != 2 || len(pgwuRules.DedicatedBearers) != 1 || len(pgwuRules.DedicatedBearers[0].Filters) != 2 {
		t.Fatalf("dedicated bearer rules SGW-U=%#v PGW-U=%#v", sgwuRules, pgwuRules)
	}
	voice := downlinkUDPPacket(pgwcSession.UEIPv4, 5060, 5061)
	selected, ok := pgwuStore.LookupDownlinkPacket(pgwcSession.UEIPv4, voice)
	if !ok || selected.Default || selected.Remote.TEID != sgwcSession.Bearers[dedicated.EBI].SGWUCore.TEID {
		t.Fatalf("PGW-U voice classifier selected %#v, %v", selected, ok)
	}

	updated, err := pgwc.UpdateDedicatedBearer(operation, pgwcSession.ID, dedicated.EBI, pgwcgateway.DedicatedBearerQoS{
		QCI: 2, ARP: 3, UplinkMBR: 10_000_000, DownlinkMBR: 14_000_000,
		UplinkGBR: 3_000_000, DownlinkGBR: 4_000_000,
	})
	if err != nil || updated.QCI != 2 {
		t.Fatalf("full CUPS Update Bearer=%#v error=%v", updated, err)
	}
	sgwuRules = sgwuStore.Snapshot()[0]
	pgwuRules = pgwuStore.Snapshot()[0]
	if sgwuRules.QERs[2].MaxUplinkBitsPerSecond != 10_000_000 || pgwuRules.DedicatedBearers[0].MaxDownlinkBitsPerSecond != 14_000_000 {
		t.Fatalf("QoS update did not reach both user planes")
	}
	mmeHarness.rejectNextDelete()
	if err := pgwc.DeleteDedicatedBearer(operation, pgwcSession.ID, dedicated.EBI); err == nil {
		t.Fatal("MME-rejected Delete Bearer was reported as successful")
	}
	if len(pgwc.Sessions()[0].DedicatedBearers) != 1 ||
		len(sgwc.Sessions()[0].Bearers) != 2 ||
		len(pgwuStore.Snapshot()[0].DedicatedBearers) != 1 ||
		len(sgwuStore.Snapshot()[0].PDRs) != 4 {
		t.Fatal("rejected Delete Bearer was not rolled back on all four CUPS nodes")
	}
	if err := pgwc.DeleteDedicatedBearer(operation, pgwcSession.ID, dedicated.EBI); err != nil {
		t.Fatal(err)
	}
	if len(pgwc.Sessions()[0].DedicatedBearers) != 0 || len(sgwc.Sessions()[0].Bearers) != 1 || len(pgwuStore.Snapshot()[0].DedicatedBearers) != 0 || len(sgwuStore.Snapshot()[0].PDRs) != 2 {
		t.Fatalf("dedicated bearer deletion left state on a CUPS node")
	}
	createdCount, updatedCount, deletedCount := mmeHarness.counts()
	if createdCount != 1 || updatedCount != 1 || deletedCount != 1 {
		t.Fatalf("MME bearer procedures=%d/%d/%d", createdCount, updatedCount, deletedCount)
	}

	ebiIE, _ := gtpv2.NewEBIIE(5, 0)
	sender, _ := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{InterfaceType: gtpv2.InterfaceS11MMEGTPC, TEID: 0x4101, IPv4: addresses.mme})
	deleteResponse, err := mme.Do(operation, sgwc.S11Addr(), gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteSessionRequest, TEID: sgwControl.TEID},
		IEs:    []gtpv2.IE{ebiIE, sender},
	})
	if err != nil || accepted(deleteResponse) != nil {
		t.Fatalf("full CUPS Delete Session response=%#v error=%v", deleteResponse, err)
	}
	if len(sgwc.Sessions()) != 0 || len(pgwc.Sessions()) != 0 || len(sgwuStore.Snapshot()) != 0 || len(pgwuStore.Snapshot()) != 0 {
		t.Fatal("full CUPS detach left session state behind")
	}

	// Establish the MME's recovery identity, recreate one complete PDN, then
	// change the counter as a restarted MME would. SGW-C must not forget only
	// its half of the context: the recovery transaction must drain SGW-U,
	// PGW-C, and PGW-U before acknowledging the Echo Request.
	recoveryOperation, recoveryStop := context.WithTimeout(ctx, 5*time.Second)
	defer recoveryStop()
	baselineEcho, err := mme.Do(recoveryOperation, sgwc.S11Addr(), gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, MessageType: gtpv2.MessageEchoRequest},
		IEs:    []gtpv2.IE{gtpv2.NewRecoveryIE(40)},
	})
	if err != nil || baselineEcho.Header.MessageType != gtpv2.MessageEchoResponse {
		t.Fatalf("baseline MME Echo response=%#v error=%v", baselineEcho, err)
	}
	recoveryCreate, err := createRequest(labConfig, 0x4102)
	if err != nil {
		t.Fatal(err)
	}
	recoveryCreateResponse, err := mme.Do(recoveryOperation, sgwc.S11Addr(), recoveryCreate)
	if err != nil || accepted(recoveryCreateResponse) != nil {
		t.Fatalf("recovery-test Create Session response=%#v error=%v", recoveryCreateResponse, err)
	}
	recoverySGWControl, err := findFTEID(recoveryCreateResponse.IEs, 0)
	if err != nil {
		t.Fatal(err)
	}
	recoveryModify, err := modifyRequest(labConfig, recoverySGWControl.TEID, 0x5102)
	if err != nil {
		t.Fatal(err)
	}
	recoveryModifyResponse, err := mme.Do(recoveryOperation, sgwc.S11Addr(), recoveryModify)
	if err != nil || accepted(recoveryModifyResponse) != nil {
		t.Fatalf("recovery-test Modify Bearer response=%#v error=%v", recoveryModifyResponse, err)
	}
	if len(sgwc.Sessions()) != 1 || len(pgwc.Sessions()) != 1 || len(sgwuStore.Snapshot()) != 1 || len(pgwuStore.Snapshot()) != 1 {
		t.Fatal("recovery-test bearer did not span all four CUPS nodes")
	}
	restartEcho, err := mme.Do(recoveryOperation, sgwc.S11Addr(), gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, MessageType: gtpv2.MessageEchoRequest},
		IEs:    []gtpv2.IE{gtpv2.NewRecoveryIE(41)},
	})
	if err != nil || restartEcho.Header.MessageType != gtpv2.MessageEchoResponse {
		t.Fatalf("MME restart Echo response=%#v error=%v", restartEcho, err)
	}
	if len(sgwc.Sessions()) != 0 || len(pgwc.Sessions()) != 0 || len(sgwuStore.Snapshot()) != 0 || len(pgwuStore.Snapshot()) != 0 {
		t.Fatalf("MME restart left state SGW-C=%d PGW-C=%d SGW-U=%d PGW-U=%d", len(sgwc.Sessions()), len(pgwc.Sessions()), len(sgwuStore.Snapshot()), len(pgwuStore.Snapshot()))
	}
	if counters := sgwc.Counters(); counters.PeerRestarts != 1 || counters.PeerRestartPurgeFailures != 0 {
		t.Fatalf("unexpected SGW-C recovery counters: %#v", counters)
	}
}

func downlinkUDPPacket(ue netip.Addr, localPort, remotePort uint16) []byte {
	remote := netip.MustParseAddr("203.0.113.9")
	packet := make([]byte, 24)
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	remoteRaw, ueRaw := remote.As4(), ue.As4()
	copy(packet[12:16], remoteRaw[:])
	copy(packet[16:20], ueRaw[:])
	binary.BigEndian.PutUint16(packet[20:22], remotePort)
	binary.BigEndian.PutUint16(packet[22:24], localPort)
	return packet
}
