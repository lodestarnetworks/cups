package gateway

import (
	"context"
	"net/netip"
	"testing"

	"github.com/lodestarnetworks/cups/internal/sgwc/session"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

func TestCreateSessionAdmissionDrainRejectsBeforeAllocatingState(t *testing.T) {
	peer := netip.MustParseAddrPort("10.250.10.10:2123")
	imsi, _ := gtpv2.NewIMSIIE("001010123456789")
	apn, _ := gtpv2.NewAPNIE("internet")
	mme, _ := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS11MMEGTPC, TEID: 100, IPv4: peer.Addr(),
	})
	ebi, _ := gtpv2.NewEBIIE(5, 0)
	qos, _ := gtpv2.NewBearerQoSIEWithBitrates(0, 9, 8, 100_000_000, 100_000_000, 0, 0)
	bearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebi, qos)
	ambr, _ := gtpv2.NewAMBRIE(0, 100_000_000, 100_000_000)
	var event Event
	gateway := &Gateway{config: Config{
		AllowNewSessions: func() bool { return false },
		OnEvent:          func(current Event) { event = current },
	}}
	response := gateway.createSession(context.Background(), peer, gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateSessionRequest},
		IEs:    []gtpv2.IE{imsi, apn, mme, ambr, bearer},
	})
	cause, err := messageCause(*response)
	if err != nil || cause != gtpv2.CauseNoResourcesAvailable {
		t.Fatalf("drained Create Session cause=%d error=%v response=%#v", cause, err, response)
	}
	counters := gateway.Counters()
	if counters.CreateRejected != 1 || counters.CreateAdmissionRejected != 1 || counters.Rejected != 1 {
		t.Fatalf("drain counters = %#v", counters)
	}
	if event.Severity != "warning" || event.Procedure != "create-session" {
		t.Fatalf("drain event = %#v", event)
	}
}

func TestParseCreateRequestAppliesAPNAMBRToDefaultBearer(t *testing.T) {
	peer := netip.MustParseAddrPort("10.250.10.10:2123")
	imsi, _ := gtpv2.NewIMSIIE("001010123456789")
	apn, _ := gtpv2.NewAPNIE("lodestartest")
	mme, _ := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS11MMEGTPC, TEID: 100, IPv4: peer.Addr(),
	})
	ebi, _ := gtpv2.NewEBIIE(5, 0)
	qos, _ := gtpv2.NewBearerQoSIEWithBitrates(0, 9, 8, 800_000_000, 1_900_000_000, 0, 0)
	bearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebi, qos)
	ambr, _ := gtpv2.NewAMBRIE(0, 900_000_000, 1_800_000_000)

	parsed, cause, err := parseCreateRequest(peer, gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateSessionRequest},
		IEs:    []gtpv2.IE{imsi, apn, mme, ambr, bearer},
	})
	if err != nil || cause != 0 {
		t.Fatalf("parse failed: cause=%d err=%v", cause, err)
	}
	if parsed.uplinkBitrate != 800_000_000 || parsed.downlinkBitrate != 1_800_000_000 {
		t.Fatalf("effective default bearer MBR = %d/%d bps", parsed.uplinkBitrate, parsed.downlinkBitrate)
	}
	if parsed.qos.DownlinkMBR != 1_900_000_000 {
		t.Fatalf("original bearer QoS was not preserved: %#v", parsed.qos)
	}
}

func TestCreateResponseForMMEPreservesPGWPCOAndAMBR(t *testing.T) {
	pco, _ := gtpv2.NewPCOIE(0, gtpv2.PCO{Extension: true, Containers: []gtpv2.PCOContainer{{
		ID: gtpv2.PCOContainerDNSServerIPv4, Contents: []byte{10, 250, 70, 1},
	}}})
	ambr, _ := gtpv2.NewAMBRIE(0, 900_000_000, 1_800_000_000)
	ebi, _ := gtpv2.NewEBIIE(5, 0)
	pgwUser, _ := gtpv2.NewFTEIDIE(2, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS5S8PGWGTPU, TEID: 200, IPv4: netip.MustParseAddr("10.250.50.20"),
	})
	bearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebi, gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), pgwUser)
	response := gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateSessionResponse, TEID: 300},
		IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), ambr, pco, bearer},
	}
	current := session.Session{
		MMEControl: session.FTEID{TEID: 400, IP: netip.MustParseAddr("10.250.10.10")},
		S11Control: session.FTEID{TEID: 500, IP: netip.MustParseAddr("10.250.10.11")},
		Bearers: map[uint8]session.Bearer{5: {
			EBI: 5, SGWUAccess: session.FTEID{TEID: 600, IP: netip.MustParseAddr("10.250.40.12")},
		}},
	}

	out, err := (&Gateway{}).createResponseForMME(response, current, 5)
	if err != nil {
		t.Fatal(err)
	}
	gotPCO, ok := out.Find(gtpv2.IEPCO, 0)
	if !ok || string(gotPCO.Value) != string(pco.Value) {
		t.Fatalf("PCO changed across SGW-C: got=%x want=%x", gotPCO.Value, pco.Value)
	}
	gotAMBR, ok := out.Find(gtpv2.IEAMBR, 0)
	if !ok || string(gotAMBR.Value) != string(ambr.Value) {
		t.Fatalf("APN-AMBR changed across SGW-C: got=%x want=%x", gotAMBR.Value, ambr.Value)
	}
}
