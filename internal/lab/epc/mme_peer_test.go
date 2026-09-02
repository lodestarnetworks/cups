package epc

import (
	"context"
	"net/netip"
	"testing"

	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

func TestMMEPeerDedicatedBearerLifecycle(t *testing.T) {
	const (
		sgwControlTEID = uint32(0x6100_0001)
		ebi            = uint8(6)
	)
	peer := &mmePeer{
		sgwControlTEID: sgwControlTEID,
		enodebIP:       netip.MustParseAddr("127.220.0.2"),
		dedicated:      make(map[uint8]uint32),
		ddn:            make(chan uint8, 1),
	}
	ebiIE, err := gtpv2.NewEBIIE(ebi, 0)
	if err != nil {
		t.Fatal(err)
	}
	sgwAccess, err := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS1USGWGTPU,
		TEID:          0x6200_0006,
		IPv4:          netip.MustParseAddr("127.220.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, sgwAccess)
	if err != nil {
		t.Fatal(err)
	}
	create := gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateBearerRequest, TEID: 0x6000_0001},
		IEs:    []gtpv2.IE{bearer},
	}
	response, err := peer.handle(context.Background(), netip.AddrPort{}, create)
	if err != nil {
		t.Fatal(err)
	}
	if err := accepted(*response); err != nil {
		t.Fatalf("Create Bearer response: %v", err)
	}
	children, err := bearerChildren(*response)
	if err != nil {
		t.Fatal(err)
	}
	enodebIE, ok := gtpv2.FindIE(children, gtpv2.IEFTEID, 0)
	if !ok {
		t.Fatal("Create Bearer response omitted eNodeB F-TEID")
	}
	enodeb, err := enodebIE.FTEID()
	if err != nil || enodeb.InterfaceType != gtpv2.InterfaceS1UENodeBGTPU || enodeb.IPv4 != peer.enodebIP || enodeb.TEID == 0 {
		t.Fatalf("Create Bearer eNodeB F-TEID = %#v, error = %v", enodeb, err)
	}

	duplicate, err := peer.handle(context.Background(), netip.AddrPort{}, create)
	if err != nil {
		t.Fatal(err)
	}
	assertMessageCause(t, duplicate, gtpv2.CauseNoResourcesAvailable)

	updateBearer, err := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE)
	if err != nil {
		t.Fatal(err)
	}
	update := gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageUpdateBearerRequest, TEID: 0x6000_0001},
		IEs:    []gtpv2.IE{updateBearer},
	}
	response, err = peer.handle(context.Background(), netip.AddrPort{}, update)
	if err != nil {
		t.Fatal(err)
	}
	if err := accepted(*response); err != nil {
		t.Fatalf("Update Bearer response: %v", err)
	}

	deleteEBI, err := gtpv2.NewEBIIE(ebi, 1)
	if err != nil {
		t.Fatal(err)
	}
	deleteRequest := gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteBearerRequest, TEID: 0x6000_0001},
		IEs:    []gtpv2.IE{deleteEBI},
	}
	response, err = peer.handle(context.Background(), netip.AddrPort{}, deleteRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := accepted(*response); err != nil {
		t.Fatalf("Delete Bearer response: %v", err)
	}
	response, err = peer.handle(context.Background(), netip.AddrPort{}, update)
	if err != nil {
		t.Fatal(err)
	}
	assertMessageCause(t, response, gtpv2.CauseContextNotFound)
}

func assertMessageCause(t *testing.T, message *gtpv2.Message, expected uint8) {
	t.Helper()
	causeIE, ok := message.Find(gtpv2.IECause, 0)
	if !ok {
		t.Fatal("response omitted Cause IE")
	}
	cause, err := causeIE.Cause()
	if err != nil {
		t.Fatal(err)
	}
	if cause.Value != expected {
		t.Fatalf("response cause = %d, want %d", cause.Value, expected)
	}
}
