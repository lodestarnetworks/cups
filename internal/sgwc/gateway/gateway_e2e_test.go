package gateway_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	gtptransport "github.com/lodestarnetworks/cups/internal/gtpv2/transport"
	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	"github.com/lodestarnetworks/cups/internal/sgwc/gateway"
	"github.com/lodestarnetworks/cups/internal/sgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/sgwc/session"
	"github.com/lodestarnetworks/cups/internal/sgwu/dataplane"
	"github.com/lodestarnetworks/cups/internal/sgwu/pfcpserver"
	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpu"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

func TestLTEAttachBidirectionalTrafficIdleResumeAndDetach(t *testing.T) {
	const testEnterpriseID uint16 = 65000
	addresses := struct {
		mme, s11, s5, pgwControl, imsPGWControl, imsPGWAdvertise, pfcpCP, pfcpUP, access, enodeb, core, pgwUser netip.Addr
	}{
		mme: netip.MustParseAddr("127.81.0.1"), s11: netip.MustParseAddr("127.81.0.2"),
		s5: netip.MustParseAddr("127.82.0.1"), pgwControl: netip.MustParseAddr("127.82.0.2"),
		imsPGWControl: netip.MustParseAddr("127.82.0.3"), imsPGWAdvertise: netip.MustParseAddr("127.82.0.4"),
		pfcpCP: netip.MustParseAddr("127.83.0.1"), pfcpUP: netip.MustParseAddr("127.83.0.2"),
		access: netip.MustParseAddr("127.84.0.1"), enodeb: netip.MustParseAddr("127.84.0.2"),
		core: netip.MustParseAddr("127.85.0.1"), pgwUser: netip.MustParseAddr("127.85.0.2"),
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErrors := make(chan error, 8)
	running := 0
	start := func(serve func(context.Context) error) {
		running++
		go func() { runErrors <- serve(ctx) }()
	}
	defer func() {
		cancel()
		deadline := time.After(3 * time.Second)
		for index := 0; index < running; index++ {
			select {
			case err := <-runErrors:
				if err != nil {
					t.Errorf("component stopped with error: %v", err)
				}
			case <-deadline:
				t.Errorf("timed out stopping lab components")
				return
			}
		}
	}()

	ruleStore := rules.NewStore()
	upServer, err := pfcpserver.New(pfcpserver.Config{
		Listen: netip.AddrPortFrom(addresses.pfcpUP, 0), Advertise: addresses.pfcpUP,
		AccessUserIP: addresses.access, CoreUserIP: addresses.core,
		AllowedCP: []netip.Addr{addresses.pfcpCP}, StartedAt: time.Unix(1_700_100_000, 0),
		EnterpriseID: testEnterpriseID,
		Transport:    testPFCPTransport(),
	}, ruleStore)
	if err != nil {
		t.Fatal(err)
	}
	start(upServer.Serve)

	upClient, err := pfcpclient.New(pfcpclient.Config{
		Listen: netip.AddrPortFrom(addresses.pfcpCP, 0), Advertise: addresses.pfcpCP,
		Remote: upServer.LocalAddr(), StartedAt: time.Unix(1_700_100_100, 0),
		EnterpriseID: testEnterpriseID,
		Transport:    testPFCPTransport(),
	})
	if err != nil {
		t.Fatal(err)
	}
	start(upClient.Serve)
	opCtx, opCancel := context.WithTimeout(ctx, 2*time.Second)
	if err := upClient.Associate(opCtx); err != nil {
		opCancel()
		t.Fatalf("associate SGW-U: %v", err)
	}
	opCancel()

	forwarder, err := dataplane.Listen(dataplane.Config{
		Access:             netip.AddrPortFrom(addresses.access, dataplane.GTPUPort),
		Core:               netip.AddrPortFrom(addresses.core, dataplane.GTPUPort),
		AllowedAccessPeers: []netip.Addr{addresses.enodeb},
		AllowedCorePeers:   []netip.Addr{addresses.pgwUser},
	}, ruleStore)
	if err != nil {
		t.Fatal(err)
	}
	forwarder.SetDownlinkReporter(upServer)
	upServer.SetSessionObserver(forwarder)
	start(forwarder.Serve)

	enodeb := listenUDP(t, addresses.enodeb, dataplane.GTPUPort)
	defer enodeb.Close()
	pgwUser := listenUDP(t, addresses.pgwUser, dataplane.GTPUPort)
	defer pgwUser.Close()

	pgwHarness := &fakePGW{
		controlIP: addresses.pgwControl, userIP: addresses.pgwUser,
		controlTEID: 0x7000_0001, userTEID: 0x7000_1001, expectedRecovery: 7,
	}
	pgwEndpoint, err := gtptransport.Listen(netip.AddrPortFrom(addresses.pgwControl, 0), pgwHarness.handle, testGTPTransport())
	if err != nil {
		t.Fatal(err)
	}
	start(pgwEndpoint.Serve)
	imsPGWHarness := &fakePGW{
		// Model a multi-homed PGW that receives transactions on one routed
		// endpoint while advertising another address in its control F-TEID.
		controlIP: addresses.imsPGWAdvertise, userIP: addresses.pgwUser,
		controlTEID: 0x7100_0001, userTEID: 0x7100_1001, expectedRecovery: 7,
	}
	imsPGWEndpoint, err := gtptransport.Listen(netip.AddrPortFrom(addresses.imsPGWControl, 0), imsPGWHarness.handle, testGTPTransport())
	if err != nil {
		t.Fatal(err)
	}
	start(imsPGWEndpoint.Serve)

	sessionStore := session.NewStore()
	sgw, err := gateway.New(gateway.Config{
		S11Listen: netip.AddrPortFrom(addresses.s11, 0), S11Advertise: addresses.s11,
		S5Listen: netip.AddrPortFrom(addresses.s5, 0), S5Advertise: addresses.s5,
		PGWControl: pgwEndpoint.LocalAddr(), PGWRoutes: map[string]netip.AddrPort{"ims": imsPGWEndpoint.LocalAddr()},
		SGWUAccessIP: addresses.access, SGWUCoreIP: addresses.core,
		AllowedMME: []netip.Addr{addresses.mme}, RecoveryCounter: 7,
		ProcedureTimeout: 2 * time.Second, SubscriberSalt: []byte("unit-test-salt"),
		Transport: testGTPTransport(),
	}, sessionStore, upClient)
	if err != nil {
		t.Fatal(err)
	}
	start(sgw.Serve)

	mmeControlTEID := uint32(0x1000_0001)
	mmeHarness := newFakeMME(addresses.enodeb, mmeControlTEID)
	mme, err := gtptransport.Listen(netip.AddrPortFrom(addresses.mme, 2123), mmeHarness.handle, testGTPTransport())
	if err != nil {
		t.Fatal(err)
	}
	start(mme.Serve)
	start(func(ctx context.Context) error {
		for {
			select {
			case report := <-upClient.Reports():
				if err := sgw.HandleDownlinkReport(ctx, report); err != nil && ctx.Err() == nil {
					return err
				}
			case <-ctx.Done():
				return nil
			}
		}
	})

	ebi := uint8(5)
	create := createSessionRequest(t, addresses.mme, mmeControlTEID, ebi)
	create.Upsert(gtpv2.NewRecoveryIE(99))
	opCtx, opCancel = context.WithTimeout(ctx, 3*time.Second)
	createResponse, err := mme.Do(opCtx, sgw.S11Addr(), create)
	opCancel()
	if err != nil {
		t.Fatalf("Create Session: %v", err)
	}
	assertAccepted(t, createResponse)
	if createResponse.Header.TEID != mmeControlTEID {
		t.Fatalf("Create Session response TEID=%#x, want %#x", createResponse.Header.TEID, mmeControlTEID)
	}
	sgwControl := mustFTEID(t, createResponse.IEs, 0)
	if sgwControl.InterfaceType != gtpv2.InterfaceS11SGWGTPC || sgwControl.IPv4 != addresses.s11 {
		t.Fatalf("invalid SGW S11 F-TEID: %#v", sgwControl)
	}
	mmeHarness.setSGWControlTEID(sgwControl.TEID)
	createdBearer := mustBearerChildren(t, createResponse)
	sgwAccess := mustFTEID(t, createdBearer, 0)
	if sgwAccess.InterfaceType != gtpv2.InterfaceS1USGWGTPU || sgwAccess.IPv4 != addresses.access {
		t.Fatalf("invalid SGW S1-U F-TEID: %#v", sgwAccess)
	}
	if sessions := sgw.Sessions(); len(sessions) != 1 || sessions[0].SubscriberKey == "001010123456789" {
		t.Fatalf("session was not created with a hashed subscriber key: %#v", sessions)
	}
	createdS5User := pgwHarness.createdSGWUserTunnel(t, ebi)
	if createdS5User.InterfaceType != gtpv2.InterfaceS5S8SGWGTPU || createdS5User.IPv4 != addresses.core {
		t.Fatalf("Create Session did not contain a valid SGW S5-U F-TEID: %#v", createdS5User)
	}

	enodebTEID := uint32(0x2000_0001)
	modify := modifyBearerRequest(t, sgwControl.TEID, addresses.enodeb, enodebTEID, ebi)
	opCtx, opCancel = context.WithTimeout(ctx, 3*time.Second)
	modifyResponse, err := mme.Do(opCtx, sgw.S11Addr(), modify)
	opCancel()
	if err != nil {
		t.Fatalf("Modify Bearer: %v", err)
	}
	assertAccepted(t, modifyResponse)

	imsEBI := uint8(6)
	imsCreate := createSessionRequestForPDN(t, addresses.mme, mmeControlTEID, sgwControl.TEID, "ims", imsEBI, 5)
	opCtx, opCancel = context.WithTimeout(ctx, 3*time.Second)
	imsCreateResponse, err := mme.Do(opCtx, sgw.S11Addr(), imsCreate)
	opCancel()
	if err != nil {
		t.Fatalf("Create IMS Session: %v", err)
	}
	assertAccepted(t, imsCreateResponse)
	imsSGWControl := mustFTEID(t, imsCreateResponse.IEs, 0)
	if imsSGWControl != sgwControl {
		t.Fatalf("IMS SGW S11 F-TEID=%#v, want shared %#v", imsSGWControl, sgwControl)
	}
	imsCreatedBearer := mustBearerChildren(t, imsCreateResponse)
	imsSGWAccess := mustFTEID(t, imsCreatedBearer, 0)
	if imsSGWAccess.TEID == 0 || imsSGWAccess.TEID == sgwAccess.TEID || imsSGWAccess.IPv4 != addresses.access {
		t.Fatalf("invalid or reused IMS S1-U F-TEID: %#v", imsSGWAccess)
	}
	if sessions := sgw.Sessions(); len(sessions) != 2 || sessions[0].S11Control.TEID != sessions[1].S11Control.TEID {
		t.Fatalf("internet and IMS did not share one S11 context: %#v", sessions)
	}
	imsCreatedS5User := imsPGWHarness.createdSGWUserTunnel(t, imsEBI)
	if imsCreatedS5User.TEID == 0 || imsCreatedS5User.TEID == createdS5User.TEID || imsCreatedS5User.IPv4 != addresses.core {
		t.Fatalf("invalid or reused IMS S5-U F-TEID: %#v", imsCreatedS5User)
	}

	imsENodeBTEID := uint32(0x2000_0002)
	imsModify := modifyBearerRequest(t, sgwControl.TEID, addresses.enodeb, imsENodeBTEID, imsEBI)
	opCtx, opCancel = context.WithTimeout(ctx, 3*time.Second)
	imsModifyResponse, err := mme.Do(opCtx, sgw.S11Addr(), imsModify)
	opCancel()
	if err != nil {
		t.Fatalf("Modify IMS Bearer: %v", err)
	}
	assertAccepted(t, imsModifyResponse)

	// Exercise a PGW-initiated IMS dedicated bearer across S5-C, S11, PFCP,
	// S1-U, and S5-U. Open5GS sends an unassigned EBI in Create Bearer and the
	// MME assigns the established EBI in its response.
	dedicatedEBI := uint8(7)
	imsS5Control := imsPGWHarness.sgwControlTunnel(t, imsEBI)
	linkedIMS, _ := gtpv2.NewEBIIE(imsEBI, 0)
	pgwDedicatedUser := gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8PGWGTPU,
		TEID:          imsPGWHarness.userTEIDForEBI(dedicatedEBI), IPv4: addresses.pgwUser,
	}
	pgwDedicatedIE, _ := gtpv2.NewFTEIDIE(1, pgwDedicatedUser)
	dedicatedQoS, _ := gtpv2.NewBearerQoSIEWithBitrates(0, 1, 2, 8_000_000, 12_000_000, 3_000_000, 4_000_000)
	dedicatedContext, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0,
		gtpv2.IE{Type: gtpv2.IEEBI, Value: []byte{0}},
		gtpv2.IE{Type: gtpv2.IEBearerTFT, Value: []byte{0x21, 0x31, 0x10, 0x02, 0x30, 0x11}},
		pgwDedicatedIE, dedicatedQoS,
	)
	createDedicated := gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateBearerRequest, TEID: imsS5Control.TEID},
		IEs:    []gtpv2.IE{linkedIMS, dedicatedContext},
	}
	opCtx, opCancel = context.WithTimeout(ctx, 3*time.Second)
	createDedicatedResponse, err := imsPGWEndpoint.Do(opCtx, sgw.S5Addr(), createDedicated)
	opCancel()
	if err != nil {
		t.Fatalf("Create Dedicated Bearer: %v", err)
	}
	assertAccepted(t, createDedicatedResponse)
	if createDedicatedResponse.Header.TEID != imsPGWHarness.controlTEID+uint32(imsEBI-5) {
		t.Fatalf("Create Dedicated Bearer response TEID=%#x", createDedicatedResponse.Header.TEID)
	}
	dedicatedResponseChildren := mustBearerChildren(t, createDedicatedResponse)
	dedicatedSGWCore := mustFTEID(t, dedicatedResponseChildren, 2)
	returnedPGWUser := mustFTEID(t, dedicatedResponseChildren, 3)
	if dedicatedSGWCore.InterfaceType != gtpv2.InterfaceS5S8SGWGTPU || dedicatedSGWCore.IPv4 != addresses.core || returnedPGWUser != pgwDedicatedUser {
		t.Fatalf("invalid dedicated S5-U response: SGW=%#v PGW=%#v", dedicatedSGWCore, returnedPGWUser)
	}
	dedicatedSGWAccess := mmeHarness.sgwAccessTunnel(t, dedicatedEBI)
	var imsSession session.Session
	for _, candidate := range sgw.Sessions() {
		if candidate.APN == "ims" {
			imsSession = candidate
		}
	}
	createdDedicated, ok := imsSession.Bearers[dedicatedEBI]
	if !ok || createdDedicated.QCI != 1 || createdDedicated.UplinkMBR != 8_000_000 || createdDedicated.DownlinkMBR != 12_000_000 {
		t.Fatalf("dedicated bearer was not committed with QoS: %#v", imsSession)
	}

	dedicatedUplink := []byte{0x45, 0x00, 0x00, 0x14, 0xd1, 0xd2, 0xd3, 0xd4}
	sendGPDU(t, enodeb, forwarder.AccessAddr(), dedicatedSGWAccess.TEID, dedicatedUplink)
	assertGPDU(t, pgwUser, pgwDedicatedUser.TEID, dedicatedUplink)
	dedicatedDownlink := []byte{0x45, 0x00, 0x00, 0x14, 0xe1, 0xe2, 0xe3, 0xe4}
	sendGPDU(t, pgwUser, forwarder.CoreAddr(), dedicatedSGWCore.TEID, dedicatedDownlink)
	assertGPDU(t, enodeb, 0x2000_0007, dedicatedDownlink)

	dedicatedEBIIE, _ := gtpv2.NewEBIIE(dedicatedEBI, 0)
	updatedQoS, _ := gtpv2.NewBearerQoSIEWithBitrates(0, 1, 2, 10_000_000, 14_000_000, 3_000_000, 4_000_000)
	updateContext, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, dedicatedEBIIE, updatedQoS)
	updateDedicated := gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageUpdateBearerRequest, TEID: imsS5Control.TEID},
		IEs:    []gtpv2.IE{updateContext},
	}
	opCtx, opCancel = context.WithTimeout(ctx, 3*time.Second)
	updateDedicatedResponse, err := imsPGWEndpoint.Do(opCtx, sgw.S5Addr(), updateDedicated)
	opCancel()
	if err != nil {
		t.Fatalf("Update Dedicated Bearer: %v", err)
	}
	assertAccepted(t, updateDedicatedResponse)
	for _, candidate := range sgw.Sessions() {
		if bearer, exists := candidate.Bearers[dedicatedEBI]; exists && (bearer.UplinkMBR != 10_000_000 || bearer.DownlinkMBR != 14_000_000) {
			t.Fatalf("dedicated bearer QoS was not updated: %#v", bearer)
		}
	}

	dedicatedDeleteEBI, _ := gtpv2.NewEBIIE(dedicatedEBI, 1)
	deleteDedicated := gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteBearerRequest, TEID: imsS5Control.TEID},
		IEs:    []gtpv2.IE{dedicatedDeleteEBI},
	}
	opCtx, opCancel = context.WithTimeout(ctx, 3*time.Second)
	deleteDedicatedResponse, err := imsPGWEndpoint.Do(opCtx, sgw.S5Addr(), deleteDedicated)
	opCancel()
	if err != nil {
		t.Fatalf("Delete Dedicated Bearer: %v", err)
	}
	assertAccepted(t, deleteDedicatedResponse)
	for _, candidate := range sgw.Sessions() {
		if _, exists := candidate.Bearers[dedicatedEBI]; exists {
			t.Fatalf("dedicated bearer survived deletion: %#v", candidate)
		}
	}
	if _, _, ok := ruleStore.Lookup(rules.SourceAccess, dedicatedSGWAccess.TEID); ok {
		t.Fatal("dedicated S1-U PDR survived deletion")
	}
	if _, _, ok := ruleStore.Lookup(rules.SourceCore, dedicatedSGWCore.TEID); ok {
		t.Fatal("dedicated S5-U PDR survived deletion")
	}

	innerUplink := []byte{0x45, 0x00, 0x00, 0x14, 0xaa, 0xbb, 0xcc, 0xdd}
	sendGPDU(t, enodeb, forwarder.AccessAddr(), sgwAccess.TEID, innerUplink)
	assertGPDU(t, pgwUser, pgwHarness.userTEIDForEBI(ebi), innerUplink)

	sgwCore := pgwHarness.sgwUserTunnel(t, ebi)
	innerDownlink := []byte{0x45, 0x00, 0x00, 0x14, 0x11, 0x22, 0x33, 0x44}
	sendGPDU(t, pgwUser, forwarder.CoreAddr(), sgwCore.TEID, innerDownlink)
	assertGPDU(t, enodeb, enodebTEID, innerDownlink)

	imsUplink := []byte{0x45, 0x00, 0x00, 0x14, 0x60, 0x61, 0x62, 0x63}
	sendGPDU(t, enodeb, forwarder.AccessAddr(), imsSGWAccess.TEID, imsUplink)
	assertGPDU(t, pgwUser, imsPGWHarness.userTEIDForEBI(imsEBI), imsUplink)
	imsSGWCore := imsPGWHarness.sgwUserTunnel(t, imsEBI)
	imsDownlink := []byte{0x45, 0x00, 0x00, 0x14, 0x70, 0x71, 0x72, 0x73}
	sendGPDU(t, pgwUser, forwarder.CoreAddr(), imsSGWCore.TEID, imsDownlink)
	assertGPDU(t, enodeb, imsENodeBTEID, imsDownlink)

	release := gtpv2.Message{Header: gtpv2.Header{
		Version: gtpv2.Version, HasTEID: true,
		MessageType: gtpv2.MessageReleaseAccessBearersRequest, TEID: sgwControl.TEID,
	}}
	opCtx, opCancel = context.WithTimeout(ctx, 3*time.Second)
	releaseResponse, err := mme.Do(opCtx, sgw.S11Addr(), release)
	opCancel()
	if err != nil {
		t.Fatalf("Release Access Bearers: %v", err)
	}
	assertAccepted(t, releaseResponse)
	for _, current := range sgw.Sessions() {
		if current.State != session.StateIdle {
			t.Fatalf("Release Access Bearers left PDN active: %#v", current)
		}
	}
	sendGPDU(t, pgwUser, forwarder.CoreAddr(), sgwCore.TEID, innerDownlink)
	assertNoPacket(t, enodeb, 150*time.Millisecond)
	select {
	case gotEBI := <-mmeHarness.ddn:
		if gotEBI != ebi {
			t.Fatalf("DDN EBI=%d, want %d", gotEBI, ebi)
		}
	case <-time.After(time.Second):
		t.Fatal("MME did not receive Downlink Data Notification")
	}

	// A service request resumes every PDN in one S11 Modify Bearer Request.
	// Regression: processing only the first repeated Bearer Context restored
	// internet but left the IMS QCI-5 bearer without an eNodeB tunnel, causing
	// the next voice call to fail until the UE was detached and reattached.
	resumeModify := modify.Clone()
	resumeModify.IEs = append(resumeModify.IEs, imsModify.IEs...)

	// If a later PGW rejects its per-PDN transaction, the operation must be
	// atomic from the MME and SGW-U perspectives. In particular, internet must
	// not remain forwarding merely because its PGW accepted before IMS failed.
	imsPGWHarness.rejectNextModify(gtpv2.CauseSystemFailure)
	opCtx, opCancel = context.WithTimeout(ctx, 3*time.Second)
	rejectedResume, err := mme.Do(opCtx, sgw.S11Addr(), resumeModify)
	opCancel()
	if err != nil {
		t.Fatalf("rejected multi-PDN resume Modify Bearer: %v", err)
	}
	rejectedCauseIE, ok := rejectedResume.Find(gtpv2.IECause, 0)
	if !ok {
		t.Fatal("rejected multi-PDN Modify Bearer response has no Cause IE")
	}
	rejectedCause, err := rejectedCauseIE.Cause()
	if err != nil || rejectedCause.Value != gtpv2.CauseSystemFailure {
		t.Fatalf("rejected multi-PDN Modify Bearer cause=%#v error=%v", rejectedCause, err)
	}
	for _, current := range sgw.Sessions() {
		defaultBearer := current.Bearers[map[string]uint8{"internet": ebi, "ims": imsEBI}[current.APN]]
		if current.State != session.StateIdle || defaultBearer.State != session.BearerIdle {
			t.Fatalf("failed multi-PDN resume partially committed APN %q: %#v", current.APN, current)
		}
	}
	for name, tunnel := range map[string]uint32{"internet": sgwCore.TEID, "ims": imsSGWCore.TEID} {
		_, far, found := ruleStore.Lookup(rules.SourceCore, tunnel)
		if !found || far.ApplyAction&rules.ActionForward != 0 || far.ApplyAction&rules.ActionBuffer == 0 {
			t.Fatalf("failed multi-PDN resume left %s downlink forwarding: found=%v FAR=%#v", name, found, far)
		}
	}

	opCtx, opCancel = context.WithTimeout(ctx, 3*time.Second)
	modifyResponse, err = mme.Do(opCtx, sgw.S11Addr(), resumeModify)
	opCancel()
	if err != nil {
		t.Fatalf("multi-PDN resume Modify Bearer: %v", err)
	}
	assertAccepted(t, modifyResponse)
	if contexts := gtpv2.FindAllIEs(modifyResponse.IEs, gtpv2.IEBearerContext, 0); len(contexts) != 2 {
		t.Fatalf("multi-PDN Modify Bearer response contexts=%d, want 2", len(contexts))
	}
	for _, current := range sgw.Sessions() {
		defaultBearer := current.Bearers[map[string]uint8{"internet": ebi, "ims": imsEBI}[current.APN]]
		if current.State != session.StateActive || defaultBearer.State != session.BearerActive || defaultBearer.ENBUser.TEID == 0 {
			t.Fatalf("multi-PDN resume left APN %q inactive: %#v", current.APN, current)
		}
	}
	// The first packet that triggered paging is retained and released as soon
	// as the access FAR commits; it must not rely on a PGW retransmission.
	assertGPDU(t, enodeb, enodebTEID, innerDownlink)
	sendGPDU(t, pgwUser, forwarder.CoreAddr(), sgwCore.TEID, innerDownlink)
	assertGPDU(t, enodeb, enodebTEID, innerDownlink)
	resumedIMSDownlink := []byte{0x45, 0x00, 0x00, 0x14, 0x81, 0x82, 0x83, 0x84}
	sendGPDU(t, pgwUser, forwarder.CoreAddr(), imsSGWCore.TEID, resumedIMSDownlink)
	assertGPDU(t, enodeb, imsENodeBTEID, resumedIMSDownlink)
	// UDP delivery can wake the synthetic eNodeB immediately after sendmmsg
	// returns but just before the SGW-U worker records successful forwarding
	// and URR telemetry. Wait for that post-send accounting before exercising
	// PFCP teardown so the assertion measures the completed packet path.
	accountingDeadline := time.Now().Add(time.Second)
	for {
		accounted := forwarder.Counters()
		if accounted.ForwardedPackets == 9 && accounted.URRMeteredPackets == 9 {
			break
		}
		if time.Now().After(accountingDeadline) {
			t.Fatalf("SGW-U post-send accounting did not settle: %#v", accounted)
		}
		time.Sleep(time.Millisecond)
	}

	mmeSender, _ := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS11MMEGTPC,
		TEID:          mmeControlTEID,
		IPv4:          addresses.mme,
	})
	imsEBIIE, _ := gtpv2.NewEBIIE(imsEBI, 0)
	imsDeleteRequest := gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteSessionRequest, TEID: sgwControl.TEID},
		IEs:    []gtpv2.IE{mmeSender, imsEBIIE},
	}
	opCtx, opCancel = context.WithTimeout(ctx, 3*time.Second)
	imsDeleteResponse, err := mme.Do(opCtx, sgw.S11Addr(), imsDeleteRequest)
	opCancel()
	if err != nil {
		t.Fatalf("Delete IMS Session: %v", err)
	}
	assertAccepted(t, imsDeleteResponse)
	remaining := sgw.Sessions()
	if sessionStore.Count() != 1 || len(ruleStore.Snapshot()) != 1 || len(remaining) != 1 || remaining[0].APN != "internet" || remaining[0].S11Control.TEID != sgwControl.TEID {
		t.Fatalf("IMS detach damaged shared internet context: sessions=%#v rules=%d", remaining, len(ruleStore.Snapshot()))
	}
	if !imsPGWHarness.wasDeleted(imsEBI) {
		t.Fatal("PGW did not receive IMS Delete Session")
	}

	ebiIE, _ := gtpv2.NewEBIIE(ebi, 0)
	deleteRequest := gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteSessionRequest, TEID: sgwControl.TEID},
		IEs:    []gtpv2.IE{mmeSender, ebiIE},
	}
	opCtx, opCancel = context.WithTimeout(ctx, 3*time.Second)
	deleteResponse, err := mme.Do(opCtx, sgw.S11Addr(), deleteRequest)
	opCancel()
	if err != nil {
		t.Fatalf("Delete Session: %v", err)
	}
	assertAccepted(t, deleteResponse)
	if sessionStore.Count() != 0 || len(ruleStore.Snapshot()) != 0 {
		t.Fatalf("detach left state behind: sgwc=%d sgwu=%d", sessionStore.Count(), len(ruleStore.Snapshot()))
	}
	if !pgwHarness.wasDeleted(ebi) {
		t.Fatal("PGW did not receive Delete Session")
	}

	counters := sgw.Counters()
	if counters.CreateAccepted != 2 || counters.ModifyAccepted != 3 || counters.ModifyRejected != 1 || counters.ReleaseAccepted != 1 || counters.DDNAccepted != 1 || counters.DDNPeerTEIDFallbacks != 1 || counters.S11PeerTEIDFallbacks != 4 || counters.DeleteAccepted != 2 ||
		counters.CreateBearerAccepted != 1 || counters.UpdateBearerAccepted != 1 || counters.DeleteBearerAccepted != 1 || counters.Rejected != 1 {
		t.Fatalf("unexpected SGW-C counters: %#v", counters)
	}
	dataCounters := forwarder.Counters()
	if dataCounters.ForwardedPackets != 9 || dataCounters.DroppedPackets != 0 || dataCounters.DownlinkReports != 1 || dataCounters.BufferedPackets != 0 || dataCounters.BufferEnqueued != 1 || dataCounters.BufferFlushed != 1 || dataCounters.URRMeteredPackets != 9 || dataCounters.URRActiveMeters != 0 || dataCounters.QERRateDrops != 0 {
		t.Fatalf("unexpected SGW-U counters: %#v", dataCounters)
	}
	paging, pendingPaging := sgw.PagingLatencyHistograms()
	if pendingPaging != 0 || len(paging) != 1 || paging[0].QCI != 9 || paging[0].ENB != addresses.enodeb.String() || paging[0].Count != 1 || paging[0].SumSeconds <= 0 {
		t.Fatalf("unexpected DDN-to-paging histogram: pending=%d histograms=%#v", pendingPaging, paging)
	}

	// A repeated initial Create Session for the same [IMSI, EBI] represents a
	// new session. It must replace stale SGW-C/SGW-U state instead of rejecting
	// the UE with "subscriber/APN context already exists".
	staleMMETEID := uint32(0x1000_0011)
	staleCreate := createSessionRequest(t, addresses.mme, staleMMETEID, ebi)
	opCtx, opCancel = context.WithTimeout(ctx, 3*time.Second)
	staleResponse, err := mme.Do(opCtx, sgw.S11Addr(), staleCreate)
	opCancel()
	if err != nil {
		t.Fatalf("stale-context setup Create Session: %v", err)
	}
	assertAccepted(t, staleResponse)
	staleControl := mustFTEID(t, staleResponse.IEs, 0)
	staleSessions := sgw.Sessions()
	if len(staleSessions) != 1 || len(ruleStore.Snapshot()) != 1 {
		t.Fatalf("stale-context setup failed: sessions=%#v rules=%d", staleSessions, len(ruleStore.Snapshot()))
	}
	staleSessionID := staleSessions[0].ID

	replacementMMETEID := uint32(0x1000_0012)
	replacementCreate := createSessionRequest(t, addresses.mme, replacementMMETEID, ebi)
	opCtx, opCancel = context.WithTimeout(ctx, 3*time.Second)
	replacementResponse, err := mme.Do(opCtx, sgw.S11Addr(), replacementCreate)
	opCancel()
	if err != nil {
		t.Fatalf("replacement Create Session: %v", err)
	}
	assertAccepted(t, replacementResponse)
	if replacementResponse.Header.TEID != replacementMMETEID {
		t.Fatalf("replacement response TEID=%#x, want %#x", replacementResponse.Header.TEID, replacementMMETEID)
	}
	replacementControl := mustFTEID(t, replacementResponse.IEs, 0)
	replacementSessions := sgw.Sessions()
	if len(replacementSessions) != 1 || sessionStore.Count() != 1 || len(ruleStore.Snapshot()) != 1 {
		t.Fatalf("replacement leaked stale state: sessions=%#v SGW-C=%d SGW-U=%d", replacementSessions, sessionStore.Count(), len(ruleStore.Snapshot()))
	}
	if replacementSessions[0].ID == staleSessionID || replacementSessions[0].MMEControl.TEID != replacementMMETEID {
		t.Fatalf("stale session was not replaced: old-control=%#v sessions=%#v", staleControl, replacementSessions)
	}
	if got := sgw.Counters(); got.CreateReplacements != 1 || got.CreateAccepted != 4 || got.CreateRejected != 0 {
		t.Fatalf("unexpected collision replacement counters: %#v", got)
	}

	replacementSender, _ := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS11MMEGTPC,
		TEID:          replacementMMETEID,
		IPv4:          addresses.mme,
	})
	replacementDelete := gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteSessionRequest, TEID: replacementControl.TEID},
		IEs:    []gtpv2.IE{replacementSender, ebiIE},
	}
	opCtx, opCancel = context.WithTimeout(ctx, 3*time.Second)
	replacementDeleteResponse, err := mme.Do(opCtx, sgw.S11Addr(), replacementDelete)
	opCancel()
	if err != nil {
		t.Fatalf("replacement Delete Session: %v", err)
	}
	assertAccepted(t, replacementDeleteResponse)
	if sessionStore.Count() != 0 || len(ruleStore.Snapshot()) != 0 {
		t.Fatalf("replacement cleanup left state behind: SGW-C=%d SGW-U=%d", sessionStore.Count(), len(ruleStore.Snapshot()))
	}
}

type fakeMME struct {
	mu               sync.Mutex
	sgwControlTEID   uint32
	ddn              chan uint8
	enodebIP         netip.Addr
	ddnResponseTEID  uint32
	sgwAccessByEBI   map[uint8]gtpv2.FTEID
	expectedRecovery uint8
}

func newFakeMME(enodebIP netip.Addr, ddnResponseTEID uint32) *fakeMME {
	return &fakeMME{ddn: make(chan uint8, 4), enodebIP: enodebIP, ddnResponseTEID: ddnResponseTEID, sgwAccessByEBI: make(map[uint8]gtpv2.FTEID), expectedRecovery: 7}
}

func (m *fakeMME) setSGWControlTEID(teid uint32) {
	m.mu.Lock()
	m.sgwControlTEID = teid
	m.mu.Unlock()
}

func (m *fakeMME) handle(_ context.Context, _ netip.AddrPort, request gtpv2.Message) (*gtpv2.Message, error) {
	m.mu.Lock()
	sgwTEID := m.sgwControlTEID
	m.mu.Unlock()
	if sgwTEID == 0 {
		return nil, errors.New("fake MME: SGW control TEID is unknown")
	}
	recoveryIE, ok := request.Find(gtpv2.IERecovery, 0)
	if !ok {
		return nil, errors.New("fake MME: request omitted SGW recovery counter")
	}
	counter, err := recoveryIE.Recovery()
	if err != nil || counter != m.expectedRecovery {
		return nil, fmt.Errorf("fake MME: recovery counter=%d error=%v, want %d", counter, err, m.expectedRecovery)
	}
	switch request.Header.MessageType {
	case gtpv2.MessageDownlinkDataNotification:
		ebiIE, ok := request.Find(gtpv2.IEEBI, 0)
		if !ok {
			return nil, errors.New("fake MME: DDN missing EBI")
		}
		ebi, err := ebiIE.EBI()
		if err != nil {
			return nil, err
		}
		arpIE, ok := request.Find(gtpv2.IEARP, 0)
		if !ok {
			return nil, errors.New("fake MME: DDN missing Allocation/Retention Priority")
		}
		arp, err := arpIE.AllocationRetentionPriority()
		if err != nil || arp.Priority != 8 {
			return nil, fmt.Errorf("fake MME: DDN ARP=%#v error=%v", arp, err)
		}
		select {
		case m.ddn <- ebi:
		default:
		}
		return &gtpv2.Message{
			Header: gtpv2.Header{
				Version: gtpv2.Version, HasTEID: true,
				MessageType: gtpv2.MessageDownlinkDataNotificationAck, TEID: m.ddnResponseTEID,
			},
			IEs: []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0)},
		}, nil
	case gtpv2.MessageCreateBearerRequest:
		children, err := mustBearerChildrenNoTest(request)
		if err != nil {
			return nil, err
		}
		sgwAccess, err := mustFTEIDNoTestE(children, 0)
		if err != nil || sgwAccess.InterfaceType != gtpv2.InterfaceS1USGWGTPU {
			return nil, errors.New("fake MME: invalid SGW S1-U F-TEID")
		}
		pgwUser, err := mustFTEIDNoTestE(children, 1)
		if err != nil || pgwUser.InterfaceType != gtpv2.InterfaceS5S8PGWGTPU {
			return nil, errors.New("fake MME: missing relayed PGW S5-U F-TEID")
		}
		assignedEBI := uint8(7)
		ebiIE, _ := gtpv2.NewEBIIE(assignedEBI, 0)
		enodeb, _ := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{InterfaceType: gtpv2.InterfaceS1UENodeBGTPU, TEID: 0x2000_0007, IPv4: m.enodebIP})
		bearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), enodeb)
		m.mu.Lock()
		m.sgwAccessByEBI[assignedEBI] = sgwAccess
		m.mu.Unlock()
		return &gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateBearerResponse, TEID: m.ddnResponseTEID},
			IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), bearer},
		}, nil
	case gtpv2.MessageUpdateBearerRequest:
		children, err := mustBearerChildrenNoTest(request)
		if err != nil {
			return nil, err
		}
		ebiIE, ok := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
		if !ok {
			return nil, errors.New("fake MME: Update Bearer missing EBI")
		}
		bearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0))
		return &gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageUpdateBearerResponse, TEID: m.ddnResponseTEID},
			IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), bearer},
		}, nil
	case gtpv2.MessageDeleteBearerRequest:
		ebiIE, ok := request.Find(gtpv2.IEEBI, 1)
		if !ok {
			ebiIE, ok = request.Find(gtpv2.IEEBI, 0)
		}
		if !ok {
			return nil, errors.New("fake MME: Delete Bearer missing EBI")
		}
		bearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0))
		return &gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteBearerResponse, TEID: m.ddnResponseTEID},
			IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), bearer},
		}, nil
	default:
		return nil, errors.New("fake MME: unsupported request")
	}
}

func (m *fakeMME) sgwAccessTunnel(t *testing.T, ebi uint8) gtpv2.FTEID {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	tunnel := m.sgwAccessByEBI[ebi]
	if tunnel.TEID == 0 {
		t.Fatalf("MME did not receive SGW S1-U tunnel for EBI %d", ebi)
	}
	return tunnel
}

type fakePGW struct {
	mu               sync.Mutex
	controlIP        netip.Addr
	userIP           netip.Addr
	controlTEID      uint32
	userTEID         uint32
	sgwControlByEBI  map[uint8]gtpv2.FTEID
	createdUserByEBI map[uint8]gtpv2.FTEID
	sgwUserByEBI     map[uint8]gtpv2.FTEID
	deletedByEBI     map[uint8]bool
	nextModifyCause  uint8
	expectedRecovery uint8
}

func (p *fakePGW) handle(_ context.Context, _ netip.AddrPort, request gtpv2.Message) (*gtpv2.Message, error) {
	if request.Header.MessageType != gtpv2.MessageEchoRequest {
		recoveryIE, ok := request.Find(gtpv2.IERecovery, 0)
		if !ok {
			return nil, errors.New("fake PGW: request omitted SGW recovery counter")
		}
		counter, err := recoveryIE.Recovery()
		if err != nil || counter != p.expectedRecovery {
			return nil, fmt.Errorf("fake PGW: recovery counter=%d error=%v, want %d", counter, err, p.expectedRecovery)
		}
	}
	switch request.Header.MessageType {
	case gtpv2.MessageEchoRequest:
		return &gtpv2.Message{Header: gtpv2.Header{Version: gtpv2.Version, MessageType: gtpv2.MessageEchoResponse}, IEs: []gtpv2.IE{gtpv2.NewRecoveryIE(3)}}, nil
	case gtpv2.MessageCreateSessionRequest:
		sgwControl := mustFTEIDNoTest(request.IEs, 0)
		bearer, err := mustBearerChildrenNoTest(request)
		if err != nil {
			return nil, err
		}
		sgwUser := mustFTEIDNoTest(bearer, 2)
		if sgwUser.InterfaceType != gtpv2.InterfaceS5S8SGWGTPU {
			return nil, errors.New("fake PGW: invalid SGW S5-U F-TEID")
		}
		ebiIE, ok := gtpv2.FindIE(bearer, gtpv2.IEEBI, 0)
		if !ok {
			return nil, errors.New("fake PGW: missing EBI")
		}
		ebi, err := ebiIE.EBI()
		if err != nil {
			return nil, err
		}
		pgwControlTEID := p.controlTEID + uint32(ebi-5)
		pgwUserTEID := p.userTEID + uint32(ebi-5)
		control, _ := gtpv2.NewFTEIDIE(1, gtpv2.FTEID{InterfaceType: gtpv2.InterfaceS5S8PGWGTPC, TEID: pgwControlTEID, IPv4: p.controlIP})
		user, _ := gtpv2.NewFTEIDIE(2, gtpv2.FTEID{InterfaceType: gtpv2.InterfaceS5S8PGWGTPU, TEID: pgwUserTEID, IPv4: p.userIP})
		responseBearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), user)
		p.mu.Lock()
		p.ensureMapsLocked()
		p.sgwControlByEBI[ebi] = sgwControl
		p.createdUserByEBI[ebi] = sgwUser
		p.mu.Unlock()
		return &gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateSessionResponse, TEID: sgwControl.TEID},
			IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), control, responseBearer},
		}, nil
	case gtpv2.MessageModifyBearerRequest:
		bearer, err := mustBearerChildrenNoTest(request)
		if err != nil {
			return nil, err
		}
		sgwUser := mustFTEIDNoTest(bearer, 1)
		ebiIE, ok := gtpv2.FindIE(bearer, gtpv2.IEEBI, 0)
		if !ok {
			return nil, errors.New("fake PGW: missing EBI")
		}
		ebi, err := ebiIE.EBI()
		if err != nil {
			return nil, err
		}
		p.mu.Lock()
		p.ensureMapsLocked()
		p.sgwUserByEBI[ebi] = sgwUser
		sgwControl := p.sgwControlByEBI[ebi]
		responseCause := p.nextModifyCause
		p.nextModifyCause = 0
		p.mu.Unlock()
		if responseCause == 0 {
			responseCause = gtpv2.CauseRequestAccepted
		}
		responseBearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, gtpv2.NewCauseIE(responseCause, 0))
		if request.Header.TEID != p.controlTEID+uint32(ebi-5) || sgwControl.TEID == 0 {
			return nil, errors.New("fake PGW: Modify Bearer routed to wrong PDN control tunnel")
		}
		return &gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageModifyBearerResponse, TEID: sgwControl.TEID},
			IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), responseBearer},
		}, nil
	case gtpv2.MessageDeleteSessionRequest:
		ebiIE, ok := request.Find(gtpv2.IEEBI, 0)
		if !ok {
			return nil, errors.New("fake PGW: Delete Session missing linked EBI")
		}
		ebi, err := ebiIE.EBI()
		if err != nil {
			return nil, err
		}
		p.mu.Lock()
		p.ensureMapsLocked()
		sgwControl := p.sgwControlByEBI[ebi]
		p.mu.Unlock()
		if request.Header.TEID != p.controlTEID+uint32(ebi-5) || sgwControl.TEID == 0 {
			return nil, errors.New("fake PGW: Delete Session routed to wrong PDN control tunnel")
		}
		sender, err := mustFTEIDNoTestE(request.IEs, 0)
		if err != nil {
			return nil, fmt.Errorf("fake PGW: Delete Session missing Sender F-TEID: %w", err)
		}
		if sender != sgwControl || sender.InterfaceType != gtpv2.InterfaceS5S8SGWGTPC {
			return nil, fmt.Errorf("fake PGW: invalid Delete Session Sender F-TEID: got %#v, want %#v", sender, sgwControl)
		}
		p.mu.Lock()
		p.deletedByEBI[ebi] = true
		p.mu.Unlock()
		return &gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteSessionResponse, TEID: sgwControl.TEID},
			IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0)},
		}, nil
	default:
		return nil, errors.New("fake PGW: unsupported request")
	}
}

func (p *fakePGW) ensureMapsLocked() {
	if p.sgwControlByEBI == nil {
		p.sgwControlByEBI = make(map[uint8]gtpv2.FTEID)
		p.createdUserByEBI = make(map[uint8]gtpv2.FTEID)
		p.sgwUserByEBI = make(map[uint8]gtpv2.FTEID)
		p.deletedByEBI = make(map[uint8]bool)
	}
}

func (p *fakePGW) createdSGWUserTunnel(t *testing.T, ebi uint8) gtpv2.FTEID {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	created := p.createdUserByEBI[ebi]
	if created.TEID == 0 {
		t.Fatal("PGW did not receive SGW S5-U tunnel in Create Session")
	}
	return created
}

func (p *fakePGW) sgwUserTunnel(t *testing.T, ebi uint8) gtpv2.FTEID {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	tunnel := p.sgwUserByEBI[ebi]
	if tunnel.TEID == 0 {
		t.Fatal("PGW did not receive SGW S5-U tunnel")
	}
	return tunnel
}

func (p *fakePGW) sgwControlTunnel(t *testing.T, ebi uint8) gtpv2.FTEID {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	tunnel := p.sgwControlByEBI[ebi]
	if tunnel.TEID == 0 {
		t.Fatalf("PGW did not receive SGW S5-C tunnel for EBI %d", ebi)
	}
	return tunnel
}

func (p *fakePGW) userTEIDForEBI(ebi uint8) uint32 {
	return p.userTEID + uint32(ebi-5)
}

func (p *fakePGW) wasDeleted(ebi uint8) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.deletedByEBI[ebi]
}

func (p *fakePGW) rejectNextModify(cause uint8) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextModifyCause = cause
}

func createSessionRequest(t *testing.T, mmeIP netip.Addr, mmeTEID uint32, ebi uint8) gtpv2.Message {
	return createSessionRequestForPDN(t, mmeIP, mmeTEID, 0, "internet", ebi, 9)
}

func createSessionRequestForPDN(t *testing.T, mmeIP netip.Addr, mmeTEID, sgwTEID uint32, apnName string, ebi, qci uint8) gtpv2.Message {
	t.Helper()
	imsi, _ := gtpv2.NewIMSIIE("001010123456789")
	apn, _ := gtpv2.NewAPNIE(apnName)
	mme, _ := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{InterfaceType: gtpv2.InterfaceS11MMEGTPC, TEID: mmeTEID, IPv4: mmeIP})
	ebiIE, _ := gtpv2.NewEBIIE(ebi, 0)
	qos, _ := gtpv2.NewBearerQoSIE(0, qci, 8)
	bearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, qos)
	return gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateSessionRequest, TEID: sgwTEID},
		IEs:    []gtpv2.IE{imsi, apn, mme, bearer},
	}
}

func modifyBearerRequest(t *testing.T, sgwTEID uint32, enodebIP netip.Addr, enodebTEID uint32, ebi uint8) gtpv2.Message {
	t.Helper()
	ebiIE, _ := gtpv2.NewEBIIE(ebi, 0)
	enodeb, _ := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{InterfaceType: gtpv2.InterfaceS1UENodeBGTPU, TEID: enodebTEID, IPv4: enodebIP})
	bearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, enodeb)
	return gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageModifyBearerRequest, TEID: sgwTEID},
		IEs:    []gtpv2.IE{bearer},
	}
}

func mustBearerChildren(t *testing.T, message gtpv2.Message) []gtpv2.IE {
	t.Helper()
	children, err := mustBearerChildrenNoTest(message)
	if err != nil {
		t.Fatal(err)
	}
	return children
}

func mustBearerChildrenNoTest(message gtpv2.Message) ([]gtpv2.IE, error) {
	grouped, ok := message.Find(gtpv2.IEBearerContext, 0)
	if !ok {
		return nil, errors.New("missing Bearer Context")
	}
	return grouped.Children()
}

func mustFTEID(t *testing.T, ies []gtpv2.IE, instance uint8) gtpv2.FTEID {
	t.Helper()
	fteid, err := mustFTEIDNoTestE(ies, instance)
	if err != nil {
		t.Fatal(err)
	}
	return fteid
}

func mustFTEIDNoTest(ies []gtpv2.IE, instance uint8) gtpv2.FTEID {
	fteid, _ := mustFTEIDNoTestE(ies, instance)
	return fteid
}

func mustFTEIDNoTestE(ies []gtpv2.IE, instance uint8) (gtpv2.FTEID, error) {
	ie, ok := gtpv2.FindIE(ies, gtpv2.IEFTEID, instance)
	if !ok {
		return gtpv2.FTEID{}, errors.New("missing F-TEID")
	}
	return ie.FTEID()
}

func assertAccepted(t *testing.T, message gtpv2.Message) {
	t.Helper()
	ie, ok := message.Find(gtpv2.IECause, 0)
	if !ok {
		t.Fatal("response has no Cause IE")
	}
	cause, err := ie.Cause()
	if err != nil || cause.Value != gtpv2.CauseRequestAccepted {
		t.Fatalf("response cause=%#v err=%v", cause, err)
	}
}

func listenUDP(t *testing.T, ip netip.Addr, port uint16) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, port)))
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func sendGPDU(t *testing.T, conn *net.UDPConn, destination netip.AddrPort, teid uint32, payload []byte) {
	t.Helper()
	wire, err := gtpu.Marshal(gtpu.Header{Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: teid}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteToUDPAddrPort(wire, destination); err != nil {
		t.Fatal(err)
	}
}

func assertGPDU(t *testing.T, conn *net.UDPConn, expectedTEID uint32, expectedPayload []byte) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 65_535)
	n, _, err := conn.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	header, payload, err := gtpu.Parse(buffer[:n])
	if err != nil {
		t.Fatal(err)
	}
	if header.TEID != expectedTEID || string(payload) != string(expectedPayload) {
		t.Fatalf("unexpected GTP-U packet: TEID=%#x payload=%x", header.TEID, payload)
	}
}

func assertNoPacket(t *testing.T, conn *net.UDPConn, wait time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	buffer := make([]byte, 1500)
	_, _, err := conn.ReadFromUDPAddrPort(buffer)
	var netError net.Error
	if !errors.As(err, &netError) || !netError.Timeout() {
		t.Fatalf("expected no packet, got error %v", err)
	}
}

func testGTPTransport() gtptransport.Config {
	config := gtptransport.DefaultConfig()
	config.RetransmitTimeout = 100 * time.Millisecond
	config.MaxRetransmits = 2
	return config
}

func testPFCPTransport() pfcptransport.Config {
	config := pfcptransport.DefaultConfig()
	config.RetransmitTimeout = 100 * time.Millisecond
	config.MaxRetransmits = 2
	return config
}
